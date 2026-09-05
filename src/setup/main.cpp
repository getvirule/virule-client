// Virule-Setup.exe - the visible bootstrapper and temporary courier.
//
// ONE JOB: install, register and start virule-client.exe, carry the
// browser's pending operation to it, and stay visible until the client has
// demonstrably taken over. Setup does not decide what the user came for and
// does not understand the operation semantically: THE BROWSER OWNS THAT
// INTENT, and Setup carries it as an opaque validated envelope. There is no
// wizard, no destination picker, no component list, no license page and no
// user choice of any kind.
//
// Per-user throughout: %LOCALAPPDATA%\Programs\VIRULE, HKCU registration.
// No elevation, no machine-wide state, no service, no login task.
//
// VISIBLE SURFACE (setup_window.hpp): one small native card, "Setting up
// VIRULE..." until the client acknowledges ownership, then a brief
// "Setup is complete.", then it closes itself. A VIRULE surface must never
// disappear until the next VIRULE surface is ready (owner invariant): Setup
// closes ONLY after the client reports that the next feedback surface (a
// live virule.app page, or a client-owned native card) is already visible.
//
// THE HANDOFF MODEL (superseding the retired originating-browser guessing;
// PID ancestry, browser families and default-browser fallback are GONE):
//   1. Setup opens the temporary loopback handoff listener FIRST
//      (handoff_listener.hpp). A still-open virule.app page hands its one
//      pending operation over directly while Setup runs.
//   2. Setup installs and starts the client.
//   3. Setup transfers the envelope (or the explicit absence of one) to the
//      client over a local bridge connection (setup_takeover).
//   4. Setup polls setup_wait until the client reports the takeover is
//      complete and the next surface is ready. Only then does the card
//      complete and the process leave. Setup NEVER opens a browser.
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
#include "setup/handoff_listener.hpp"
#include "setup/setup_window.hpp"
#include "shared/client_state.hpp"
#include "shared/http_client.hpp"
#include "shared/json_scan.hpp"
#include "shared/lifecycle_intent.hpp"
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

// How long Setup gives the freshly started client to answer the takeover
// transfer. A just-started client binds its bridge within a couple of
// seconds; this is many attempts.
constexpr DWORD kTransferTimeoutMs = 20000;

// The overall backstop on the release wait. The client releases Setup the
// moment the next surface is confirmed (typically a few seconds); this
// bound exists only so a wedged client can never hold a window open
// forever. The Admin install the client may be performing does NOT hold
// Setup: the client releases as soon as its feedback surface exists, long
// before that work finishes.
constexpr DWORD kReleaseTimeoutMs = 240000;

// A client that stops answering the release poll for this long is gone
// (crashed, killed); Setup leaves rather than lingering uselessly.
constexpr DWORD kReleasePollDeadMs = 15000;

// The brief completion state ("Setup is complete."). The next surface is
// already visible by the time this shows, so it only needs a beat.
constexpr DWORD kCompleteVisibleMs = 1400;

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

// Ask a running client (old version) to exit so its exe can be replaced
// and so the NEW client (which understands the takeover protocol) is the
// one that serves. Waits for the file lock only when something answered.
void stop_running_client() {
    std::string response;
    const bool answered = vclient::bridge::loopback_roundtrip(
        vclient::bridge::kPort, nullptr, "\"virule_client\"",
        "{\"type\":\"shutdown\"}", response);
    if (!answered) return;
    for (int i = 0; i < 20; ++i) {
        Sleep(100);
    }
}

// Build the setup_takeover message for the current envelope snapshot. An
// absent envelope is transferred EXPLICITLY: "no pending handoff" is a
// real state the client acts on (the standalone completion surface).
std::string takeover_message(const vclient::setup_handoff::Envelope& env) {
    namespace js = vclient::json_scan;
    std::string msg = "{\"type\":\"setup_takeover\"";
    if (env.present) {
        msg += ",\"op\":\"" + env.op + "\"";
        if (env.op == "QA_ACCEPT") {
            msg += ",\"token\":\"" + env.token + "\"";
            if (!env.game.empty()) {
                msg += ",\"game\":\"" + js::json_escape(env.game) + "\"";
            }
        } else if (env.op == "INSTALL_ADMIN") {
            msg += std::string(",\"shortcut\":") + (env.shortcut ? "true" : "false");
        }
    }
    msg += "}";
    return msg;
}

// One takeover transfer attempt. True when the client acknowledged.
bool transfer_takeover(const vclient::setup_handoff::Envelope& env) {
    std::string response;
    if (!vclient::bridge::loopback_roundtrip(
            vclient::bridge::kPort, nullptr, "\"virule_client\"",
            takeover_message(env), response)) {
        return false;
    }
    return response.find("\"takeover\"") != std::string::npos;
}

// One release poll. `answered` = the client responded at all;
// returns whether the client has released Setup.
bool poll_release(bool& answered) {
    std::string response;
    answered = vclient::bridge::loopback_roundtrip(
        vclient::bridge::kPort, nullptr, "\"virule_client\"",
        "{\"type\":\"setup_wait\"}", response);
    if (!answered) return false;
    return response.find("\"released\":true") != std::string::npos;
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool allow_unsigned = false; // development only; the hash gate always holds
    std::wstring manifest_url; // development seam; empty = production
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--dev-unsigned") {
            allow_unsigned = true;
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

    // FIRST, before any work that takes time: the handoff listener. A
    // still-open virule.app page hands its pending operation over while
    // the install runs; a browser that closed before Setup ever ran simply
    // never connects, and that absence is itself the signal (standalone).
    vclient::setup_handoff::start();

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

    // A running older client would both hold the exe and, worse, keep
    // serving a bridge that predates the takeover protocol; ask it to exit
    // before the replacement so the freshly installed client is the one
    // that answers. Costs nothing when no client is running.
    stop_running_client();
    ec.clear();
    std::filesystem::rename(staged, target, ec);
    if (ec) {
        // Still locked: one more explicit stop, then replace.
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

    // Setup just placed the approved client itself, so any client
    // SELF-UPDATE residue (staged binary, swap leftovers, the transaction
    // record) describes a world that no longer exists. Reconcile it away
    // deterministically; Setup's own install is the one client-acquisition
    // transaction while Setup runs.
    std::filesystem::remove(vclient::paths::client_update_staged_exe(), ec);
    ec.clear();
    std::filesystem::remove(vclient::paths::client_old_exe(), ec);
    ec.clear();
    std::filesystem::remove(vclient::paths::self_update_state_file(), ec);
    ec.clear();

    // 6. Per-user registration: virule:// and the uninstall entry. The
    // installed client is the canonical virule:// handler; the VIRULE Admin
    // defers to it rather than taking the scheme back.
    vclient::protocol_reg::register_protocol(target.wstring());
    vclient::uninstall::register_uninstall_entry(
        target.wstring(), widen(manifest.version));

    // An EXPLICIT install supersedes any standing uninstall intent (the
    // durable latch a failed or interrupted uninstall leaves behind so
    // self-heal stands down). The user just asked for VIRULE again; clear
    // it, or the freshly started client would refuse to serve.
    vclient::lifecycle::clear_uninstall_intent();

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

    // 9. THE TAKEOVER TRANSFER. Hand the client whatever the browser
    // handed us: the one pending-operation envelope, or its explicit
    // absence. A page that is a beat slow delivering its envelope gets a
    // short extra window; after that, an absence transfers as absence and
    // a late envelope is forwarded as an upgrade while Setup waits.
    bool transferred = false;
    bool envelope_sent = false;
    {
        // Give a slow page a moment to land its envelope before deciding
        // "none": the page retries the handoff channel every ~2 s.
        const ULONGLONG env_grace = GetTickCount64() + 4000;
        while (!vclient::setup_handoff::snapshot().present &&
               GetTickCount64() < env_grace) {
            Sleep(200);
        }
        const ULONGLONG deadline = GetTickCount64() + kTransferTimeoutMs;
        for (;;) {
            const auto env = vclient::setup_handoff::snapshot();
            if (transfer_takeover(env)) {
                transferred = true;
                envelope_sent = env.present;
                vclient::log::setup(std::string("takeover transferred (") +
                                    (env.present ? env.op : "no envelope") + ")");
                break;
            }
            if (GetTickCount64() >= deadline) break;
            Sleep(400);
        }
    }
    if (!transferred) {
        vclient::setup_handoff::stop();
        return fail(L"VIRULE was installed but couldn't start. Run Virule-Setup again.",
                    "takeover transfer failed; client never acknowledged");
    }

    // 10. THE RELEASE WAIT. The card stays visible until the client says
    // the next feedback surface is ready. This is a real ownership
    // transition, not a timer: no dead air between Setup and whatever
    // comes next. A late-arriving envelope (slow page) is forwarded as an
    // upgrade so the intent is never lost.
    bool released = false;
    {
        const ULONGLONG deadline = GetTickCount64() + kReleaseTimeoutMs;
        ULONGLONG last_answer = GetTickCount64();
        for (;;) {
            if (!envelope_sent) {
                const auto env = vclient::setup_handoff::snapshot();
                if (env.present && transfer_takeover(env)) {
                    envelope_sent = true;
                    vclient::log::setup("takeover upgraded with late envelope (" + env.op + ")");
                }
            }
            bool answered = false;
            if (poll_release(answered)) {
                released = true;
                break;
            }
            const ULONGLONG now = GetTickCount64();
            if (answered) {
                last_answer = now;
            } else if (now - last_answer > kReleasePollDeadMs) {
                vclient::log::setup("release wait: client stopped answering");
                break;
            }
            if (now >= deadline) {
                vclient::log::setup("release wait: backstop timeout");
                break;
            }
            Sleep(500);
        }
    }
    vclient::setup_handoff::stop();

    vclient::setup_window::set_complete();
    Sleep(kCompleteVisibleMs);
    vclient::setup_window::close();

    vclient::log::setup(std::string("setup complete (") +
                        (released ? "client released" : "left on backstop") + ")");
    return 0;
}
