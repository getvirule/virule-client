// Virule-Setup.exe - the disposable one-shot installer.
//
// ONE JOB: install, register and start virule-client.exe. Setup does not
// decide what the user came for. It does not know or care whether the flow
// began at "Get VIRULE" on the homepage, at a QA invitation, or anywhere
// else: THE BROWSER OWNS THAT INTENT, and Setup's whole responsibility is to
// make the local client exist and then get the browser back in front of the
// user. There is no wizard, no destination picker, no component list, no
// license page and no user choice of any kind.
//
// Per-user throughout: %LOCALAPPDATA%\Programs\VIRULE, HKCU registration.
// No elevation, no machine-wide state, no service, no login task.
//
// VISIBLE SURFACE (setup_window.hpp): one small native card, "Setting up
// VIRULE..." then "VIRULE is ready" / "Return to your browser to finish.",
// then it closes itself. Running and vanishing with no window at all was
// technically correct and read as untrustworthy; finishing without saying
// what to do next read as a dead end (owner spec 2026-09-03).
//
// BROWSER HANDOFF (the normal path, then the recovery):
//   1. Setup starts the client.
//   2. It waits a short grace period for a virule.app page to reach the
//      client's bridge. That is the NORMAL first-install outcome: the page
//      that sent the user here is still open and picks the flow back up.
//      When it happens Setup opens NOTHING; a duplicate tab would be a bug.
//   3. If no page connects, the browser (or just that tab) is gone, so
//      Setup reopens the resume URL: the ORIGINATING browser when it can be
//      identified (see origin_browser.hpp), the Windows default only as a
//      last resort. The page then resumes the intent the browser persisted.
//
// CLIENT ACQUISITION (Setup and the client are INDEPENDENT signed
// artifacts; Setup embeds nothing):
//   1. fetch manifest.json from the getvirule/virule-client LATEST GitHub
//      Release - the small mutable pointer to the approved client release
//      (publishing a release is what moves it);
//   2. validate it structurally (version grammar, an HTTPS
//      github.com/getvirule/virule-client/releases/download/ url, a 64-hex
//      SHA-256, a bounded size);
//   3. download the approved client binary, capped at the manifest's own
//      declared size;
//   4. the downloaded bytes must match the manifest SHA-256 EXACTLY;
//   5. the staged file must carry a valid Authenticode signature AND the
//      expected VIRULE signing identity.
// Any failure refuses the install. The hash gate always holds;
// --dev-unsigned (development only) waives only the signature gates.
// GitHub is a HOST, not a trust anchor: nothing is weakened because the
// bytes come from a public release; the manifest hash + Authenticode +
// signer identity remain the whole trust decision.

#include <filesystem>
#include <fstream>
#include <string>

#include "client/bridge.hpp"     // loopback client half (talk to the client)
#include "setup/origin_browser.hpp"
#include "setup/setup_window.hpp"
#include "shared/client_state.hpp"
#include "shared/http_client.hpp"
#include "shared/json_scan.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"
#include "shared/protocol_reg.hpp"
#include "shared/uninstall.hpp"  // register_uninstall_entry
#include "shared/verify_binary.hpp"
#include "shared/version.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

namespace {

// The GitHub-Releases-backed VIRULE distribution surface
// (getvirule/virule-client). The LATEST release's manifest is the mutable
// pointer; every client binary lives at its release's own immutable
// versioned asset URL. GitHub serves release assets through an
// https -> https redirect to its CDN, which WinHTTP's default redirect
// policy follows.
constexpr wchar_t kManifestUrl[] =
    L"https://github.com/getvirule/virule-client/releases/latest/download/manifest.json";

// The prefix every manifest client url must carry in production: a DIRECT
// versioned release-asset URL of this repository, nothing else.
constexpr char kClientUrlPrefix[] =
    "https://github.com/getvirule/virule-client/releases/download/";

// The identity every downloaded client must be signed with. Public
// certificate subject material, not a secret; authenticode_valid remains
// the trust decision and this pins WHO signed on top of it.
constexpr wchar_t kExpectedSigner[] = L"CN=Heath Michaels";

constexpr size_t kMaxManifestBytes = 16 * 1024;
constexpr size_t kMaxClientBytes = 64 * 1024 * 1024;

// Where a lost browser is sent back to. Same-origin resume STATE, not a
// second surface: virule.app reads the intent the browser persisted before
// the download and continues it (a QA invitation resumes at its own page).
// Setup deliberately knows nothing about which intent that is.
constexpr wchar_t kResumeUrl[] = L"https://virule.app/?resume=setup";

// How long an already-open virule.app page gets to find the freshly
// installed client before Setup's card completes. The page's own reconnect
// loop runs every 1.5 s, so this is several attempts plus room for the
// browser's local-network-access permission ask.
constexpr DWORD kPageGraceMs = 12000;

// The QUIET extension after the card has closed, before Setup concludes no
// page exists. A live page can be much slower than kPageGraceMs: browsers
// throttle timers in background tabs (the user is watching Setup's card,
// not the tab), Brave gates or blocks loopback WebSockets entirely, and a
// permission ask may sit unanswered. Observed in production 2026-09-03: a
// live Brave page finished the QA flow 21 s after the client started, 9 s
// after the old 12 s decision had already opened a wrong browser. During
// this window Setup also accepts NATIVE progress (status qa_last_s) as
// proof the page is alive, since a bridge-blocked page drives the flow
// through virule:// without ever appearing in the pages count.
constexpr DWORD kExtendedGraceMs = 48000;

// The completion state now carries an instruction ("VIRULE is ready" /
// "Return to your browser to finish."), so it stays long enough to read,
// still brief, then gone.
constexpr DWORD kCompleteVisibleMs = 2600;

std::string narrow(const std::wstring& w) {
    if (w.empty()) return "";
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), n,
                        nullptr, nullptr);
    return out;
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(),
                                      nullptr, 0);
    if (n <= 0) return L"";
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

// Native fallback error UI: one minimal, human-readable line. The
// technical reason goes to the log, never to the user.
int fail(const wchar_t* human_line, const std::string& log_line) {
    vclient::log::setup("FAIL: " + log_line);
    // The card is created on its own thread; give it the moment it needs
    // rather than falling back to a message box in a race.
    for (int i = 0; i < 20 && vclient::setup_window::g_hwnd.load() == nullptr; ++i) {
        Sleep(25);
    }
    if (vclient::setup_window::g_hwnd.load() != nullptr) {
        vclient::setup_window::set_failed(human_line);
        vclient::setup_window::wait_closed(
            vclient::setup_window::kFailureLifeMs + 5000);
    } else {
        // The card could not be created: never fail silently.
        MessageBoxW(nullptr, human_line, L"VIRULE Setup",
                    MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
    }
    return 1;
}

// ---- the release manifest ----

struct Url {
    bool secure = true;
    std::wstring host;
    unsigned short port = 443;
    std::wstring path = L"/";
};

// Minimal absolute-URL parse for exactly the two forms this program
// fetches: https://host[:port]/path (production) and, through the
// --manifest-url= development seam only, http:// as well.
bool parse_url(const std::wstring& s, Url& out) {
    std::wstring rest;
    if (s.rfind(L"https://", 0) == 0) {
        out.secure = true;
        out.port = 443;
        rest = s.substr(8);
    } else if (s.rfind(L"http://", 0) == 0) {
        out.secure = false;
        out.port = 80;
        rest = s.substr(7);
    } else {
        return false;
    }
    const size_t slash = rest.find(L'/');
    std::wstring authority = slash == std::wstring::npos ? rest : rest.substr(0, slash);
    out.path = slash == std::wstring::npos ? L"/" : rest.substr(slash);
    const size_t colon = authority.find(L':');
    if (colon != std::wstring::npos) {
        unsigned long port = 0;
        for (size_t i = colon + 1; i < authority.size(); ++i) {
            const wchar_t c = authority[i];
            if (c < L'0' || c > L'9') return false;
            port = port * 10 + (unsigned long)(c - L'0');
            if (port > 65535) return false;
        }
        if (port == 0) return false;
        out.port = (unsigned short)port;
        authority = authority.substr(0, colon);
    }
    if (authority.empty()) return false;
    out.host = authority;
    return true;
}

struct Manifest {
    std::string version;
    std::string url;
    std::string sha256; // lowercase 64 hex
    long long size = 0;
};

bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (const char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

bool is_version_grammar(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    for (const char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

// Structural validation IS the manifest contract: anything that does not
// parse into exactly this shape is refused before a single payload byte is
// fetched. `pin_host` is the production rule (the url must be a direct
// versioned release asset under kClientUrlPrefix); the --manifest-url=
// development seam relaxes only the pin, never the grammar and never the
// hash gate.
bool parse_manifest(const std::string& body, bool pin_host, Manifest& out,
                    std::string& why) {
    if (!vclient::json_scan::find_string_in(body, 0, body.size(), "version", out.version) ||
        !is_version_grammar(out.version)) {
        why = "manifest version missing or malformed";
        return false;
    }
    if (!vclient::json_scan::find_string_in(body, 0, body.size(), "url", out.url) ||
        out.url.empty() || out.url.size() > 512) {
        why = "manifest url missing or malformed";
        return false;
    }
    if (!vclient::json_scan::find_string_in(body, 0, body.size(), "sha256", out.sha256)) {
        why = "manifest sha256 missing";
        return false;
    }
    for (auto& c : out.sha256) {
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
    }
    if (!is_hex64(out.sha256)) {
        why = "manifest sha256 is not 64 hex digits";
        return false;
    }
    if (!vclient::json_scan::find_number_in(body, 0, body.size(), "size", out.size) ||
        out.size <= 0 || out.size > (long long)kMaxClientBytes) {
        why = "manifest size missing or out of bounds";
        return false;
    }
    if (pin_host) {
        if (out.url.rfind(kClientUrlPrefix, 0) != 0) {
            why = std::string("manifest url is not under ") + kClientUrlPrefix;
            return false;
        }
    }
    return true;
}

// Ask a running client (old version) to exit so its exe can be replaced.
void stop_running_client() {
    std::string response;
    (void)vclient::bridge::loopback_roundtrip(
        vclient::bridge::kPort, nullptr, "\"virule_client\"",
        "{\"type\":\"shutdown\"}", response);
    // Give it a moment to release the file whether or not it answered.
    for (int i = 0; i < 20; ++i) {
        Sleep(100);
    }
}

// One status probe against the freshly installed client, over Setup's own
// local (no-Origin, never-counted) connection. `pages` is how many
// virule.app pages are connected (-1 = no client answered); `qa_last_s` is
// how many seconds ago the client last handled a QA verification (-1 =
// never, or an older client without the field).
bool probe_client(long long& pages, long long& qa_last_s) {
    pages = -1;
    qa_last_s = -1;
    std::string response;
    if (!vclient::bridge::loopback_roundtrip(
            vclient::bridge::kPort, nullptr, "\"virule_client\"",
            "{\"type\":\"status\"}", response)) {
        return false;
    }
    (void)vclient::json_scan::find_number_in(response, 0, response.size(),
                                             "pages", pages);
    (void)vclient::json_scan::find_number_in(response, 0, response.size(),
                                             "qa_last_s", qa_last_s);
    return true;
}

// THE HANDOFF DECISION. True when the browser is demonstrably still driving
// the flow, in either of two ways: a virule.app page reached the client's
// bridge, OR the client handled a QA verification since it started (a page
// in a bridge-blocked browser progresses through virule:// and never shows
// up in the pages count). Either way Setup must not open anything.
bool wait_for_browser_signal(DWORD grace_ms) {
    const ULONGLONG deadline = GetTickCount64() + grace_ms;
    for (;;) {
        long long pages = -1, qa_last_s = -1;
        if (probe_client(pages, qa_last_s)) {
            if (pages > 0) return true;
            // The client just got installed, so ANY QA activity it reports
            // belongs to the flow that ran this Setup.
            if (qa_last_s >= 0) return true;
        }
        if (GetTickCount64() >= deadline) return false;
        Sleep(400);
    }
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool allow_unsigned = false; // development only; the hash gate always holds
    std::wstring resume_url = kResumeUrl;
    std::wstring manifest_url; // development seam; empty = production
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--dev-unsigned") {
            allow_unsigned = true;
        } else if (arg.rfind(L"--resume-url=", 0) == 0) {
            // Development seam (like --dev-unsigned and the client's
            // --no-register): point the recovery at a local site build.
            // Not a privilege: a local process can open any URL already.
            resume_url = arg.substr(13);
        } else if (arg.rfind(L"--manifest-url=", 0) == 0) {
            // Development seam: fetch the release manifest from a local
            // server instead of the GitHub release. Relaxes only the
            // repository pin; the hash gate and (without --dev-unsigned) the
            // signature gates hold exactly as in production.
            manifest_url = arg.substr(15);
        }
    }
    LocalFree(argv);

    vclient::log::setup(std::string("setup start, version ") + VIRULE_CLIENT_VERSION_STRING);

    // FIRST, before any work that takes time: who launched us. The browser
    // may be closed by the time the install finishes, and this is the only
    // moment its process is certain to still exist.
    auto origin = vclient::origin_browser::capture();
    {
        std::string line = "ancestry: " + narrow(origin.chain);
        if (origin.found) {
            line += "; originating browser=" + narrow(origin.exe_name) +
                " pid=" + std::to_string(origin.pid) +
                (origin.exe_path.empty() ? " (no path)" : " path known");
        } else {
            line += "; no recognized browser ancestor";
        }
        vclient::log::setup(line);
    }

    vclient::setup_window::show();

    // 1. The release manifest: the small mutable pointer to the approved
    // client release.
    const bool dev_manifest = !manifest_url.empty();
    Url murl;
    if (dev_manifest) {
        if (!parse_url(manifest_url, murl)) {
            return fail(L"VIRULE couldn't be downloaded. Try again later.",
                        "unparseable --manifest-url");
        }
        vclient::log::setup("DEV manifest url: " + narrow(manifest_url));
    } else if (!parse_url(kManifestUrl, murl)) {
        // A compile-time constant; unreachable unless the constant rots.
        return fail(L"VIRULE couldn't be downloaded. Try again later.",
                    "built-in manifest url unparseable");
    }
    unsigned long status = 0;
    std::string manifest_body;
    if (!vclient::http::http_get(murl.host.c_str(), murl.port, murl.secure,
                                 murl.path.c_str(), kMaxManifestBytes, status,
                                 manifest_body) ||
        status != 200) {
        return fail(L"VIRULE couldn't be downloaded. Check your internet connection and try again.",
                    "manifest fetch failed, status=" + std::to_string(status));
    }
    Manifest manifest;
    std::string why;
    if (!parse_manifest(manifest_body, /*pin_host=*/!dev_manifest, manifest, why)) {
        return fail(L"The VIRULE download couldn't be verified. Try again later.",
                    "manifest rejected: " + why);
    }
    vclient::log::setup("manifest: version=" + manifest.version +
                        " size=" + std::to_string(manifest.size) +
                        " sha256=" + manifest.sha256);

    // 2. The approved client binary, capped at the manifest's declared size.
    Url curl;
    if (!parse_url(widen(manifest.url), curl) ||
        (!dev_manifest && !curl.secure)) {
        return fail(L"The VIRULE download couldn't be verified. Try again later.",
                    "manifest url unparseable: " + manifest.url);
    }
    std::string payload;
    if (!vclient::http::http_get(curl.host.c_str(), curl.port, curl.secure,
                                 curl.path.c_str(), (size_t)manifest.size,
                                 status, payload) ||
        status != 200) {
        return fail(L"VIRULE couldn't be downloaded. Check your internet connection and try again.",
                    "client download failed, status=" + std::to_string(status));
    }

    // 3. The downloaded bytes must match the manifest EXACTLY: declared
    // size, then SHA-256. This is the gate that never has a waiver.
    if ((long long)payload.size() != manifest.size) {
        return fail(L"The VIRULE download couldn't be verified. Try again later.",
                    "client size mismatch: got " + std::to_string(payload.size()) +
                        ", manifest says " + std::to_string(manifest.size));
    }
    const std::string hash = vclient::verify_binary::sha256_hex(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    if (hash.empty() || hash != manifest.sha256) {
        return fail(L"The VIRULE download couldn't be verified. Try again later.",
                    "client sha256 mismatch: " + hash);
    }

    // 4. Directories.
    const auto install_dir = vclient::paths::install_dir();
    const auto target = vclient::paths::installed_client_exe();
    if (install_dir.empty()) {
        return fail(L"VIRULE couldn't be installed on this computer.",
                    "no LOCALAPPDATA/USERPROFILE");
    }
    std::error_code ec;
    std::filesystem::create_directories(install_dir, ec);
    std::filesystem::create_directories(vclient::paths::client_state_dir(), ec);
    if (!std::filesystem::exists(install_dir, ec)) {
        return fail(L"VIRULE couldn't be installed on this computer.",
                    "create_directories failed: " + install_dir.string());
    }

    // 5. Stage the verified bytes beside the target, verify Authenticode
    // AND the signing identity on the staged file, then move it into place
    // (replacing any older client safely).
    const auto staged = install_dir / L"virule-client.exe.new";
    {
        std::ofstream out(staged, std::ios::binary | std::ios::trunc);
        if (!out || !out.write(payload.data(),
                               (std::streamsize)payload.size()).good()) {
            return fail(L"VIRULE couldn't be installed on this computer.",
                        "staged write failed");
        }
    }
    if (!vclient::verify_binary::authenticode_valid(staged)) {
        if (allow_unsigned) {
            vclient::log::setup("payload is unsigned; proceeding (--dev-unsigned)");
        } else {
            std::filesystem::remove(staged, ec);
            return fail(L"The VIRULE download couldn't be verified. Try again later.",
                        "client Authenticode verification failed");
        }
    } else if (!vclient::verify_binary::signed_by(staged, kExpectedSigner)) {
        if (allow_unsigned) {
            vclient::log::setup("payload signer is not the VIRULE identity; proceeding (--dev-unsigned)");
        } else {
            const std::wstring subject = vclient::verify_binary::signer_subject(staged);
            std::filesystem::remove(staged, ec);
            return fail(L"The VIRULE download couldn't be verified. Try again later.",
                        "client signer is not the VIRULE identity: " + narrow(subject));
        }
    }

    ec.clear();
    std::filesystem::rename(staged, target, ec);
    if (ec) {
        // An older client may be running with the file mapped: ask it to
        // exit, then replace.
        stop_running_client();
        ec.clear();
        std::filesystem::remove(target, ec);
        ec.clear();
        std::filesystem::rename(staged, target, ec);
        if (ec) {
            std::error_code ec2;
            std::filesystem::remove(staged, ec2);
            return fail(L"VIRULE couldn't be installed. Close VIRULE and run Setup again.",
                        "replace failed: " + ec.message());
        }
    }

    // 6. Per-user registration: virule:// and the uninstall entry. The
    // installed client is the canonical virule:// handler; the VIRULE Admin
    // defers to it rather than taking the scheme back.
    vclient::protocol_reg::register_protocol(target.wstring());
    vclient::uninstall::register_uninstall_entry(
        target.wstring(), widen(manifest.version));

    // 7. Record the installed version (the manifest's, i.e. the client
    // release that was actually installed; Setup has its own version).
    {
        auto s = vclient::state::load();
        s.installed_version = manifest.version;
        (void)vclient::state::save(s);
    }

    // 8. Start the client.
    {
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::wstring cmd = L"\"" + target.wstring() + L"\"";
        if (CreateProcessW(target.wstring().c_str(), cmd.data(), nullptr, nullptr,
                           FALSE, 0, nullptr, nullptr, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            // Installed but not started: virule:// still wakes it, so this
            // is a log line, not a failure dialog.
            vclient::log::setup("installed but could not start the client");
        }
    }

    // 9. THE BROWSER. An existing virule.app page is always the first
    // choice; recovery happens only when Setup is genuinely convinced no
    // page is left. The card completes after the short grace; the extended
    // wait is quiet (card already gone) so a truly-gone browser costs the
    // user nothing visible, only a delayed resume tab.
    bool browser_owns_flow = wait_for_browser_signal(kPageGraceMs);
    vclient::setup_window::set_complete();
    Sleep(kCompleteVisibleMs);
    vclient::setup_window::close();

    if (!browser_owns_flow) {
        // A live page may just be slow (throttled background tab, a
        // pending permission ask, a bridge-blocked browser working through
        // virule://). Only an originating browser KNOWN to have exited
        // proves the page cannot exist; everything else earns the quiet
        // extended wait before any browser is opened.
        const bool origin_gone =
            origin.found && !vclient::origin_browser::still_alive(origin);
        if (!origin_gone) {
            browser_owns_flow = wait_for_browser_signal(kExtendedGraceMs);
        }
    }

    if (browser_owns_flow) {
        vclient::log::setup("a virule.app page (or native QA progress) owns the flow; opening nothing");
    } else {
        const bool alive = vclient::origin_browser::still_alive(origin);
        const auto opened =
            vclient::origin_browser::open_resume_url(origin, resume_url);
        std::string how = "recovery: no page connected; ";
        how += origin.found ? (alive ? "originating browser alive"
                                     : "originating browser exited")
                            : "originating browser unknown";
        how += opened == vclient::origin_browser::Opened::SameBrowser
                   ? "; opened resume URL in it"
               : opened == vclient::origin_browser::Opened::DefaultBrowser
                   ? "; opened resume URL in the default browser"
                   : "; could not open a browser";
        vclient::log::setup(how);
    }
    vclient::origin_browser::release(origin);

    vclient::log::setup("setup complete");
    return 0;
}
