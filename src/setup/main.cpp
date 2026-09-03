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
// VIRULE..." then "Setup is complete.", then it closes itself. Running and
// vanishing with no window at all was technically correct and read as
// untrustworthy.
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
// PAYLOAD VERIFICATION (build/sign order is a hard rule):
//   1. virule-client.exe is built and SIGNED first;
//   2. its SHA-256 is baked into this executable together with its bytes
//      (helpers/build.ps1 generates src/setup/payload/payload_hash.h);
//   3. Setup is built and signed last.
// At run time the embedded bytes must match the baked hash, and the
// extracted file must carry a valid Authenticode signature, before the
// install proceeds. A modified or unsigned payload is refused.

#include <filesystem>
#include <fstream>
#include <string>

#include "client/bridge.hpp"     // loopback client half (talk to the client)
#include "setup/origin_browser.hpp"
#include "setup/setup_window.hpp"
#include "shared/client_state.hpp"
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

#include "setup/payload/payload_hash.h" // generated: kClientPayloadSha256Hex

namespace {

constexpr int kPayloadResourceId = 1001;

// Where a lost browser is sent back to. Same-origin resume STATE, not a
// second surface: virule.app reads the intent the browser persisted before
// the download and continues it (a QA invitation resumes at its own page).
// Setup deliberately knows nothing about which intent that is.
constexpr wchar_t kResumeUrl[] = L"https://virule.app/?resume=setup";

// How long an already-open virule.app page gets to find the freshly
// installed client before Setup decides the browser is gone. The page's own
// reconnect loop runs every 1.5 s, so this is several attempts plus room for
// the browser's local-network-access permission ask.
constexpr DWORD kPageGraceMs = 12000;

// The completion state is seen, not read: brief and then gone.
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

bool load_payload(const unsigned char*& data_out, size_t& size_out) {
    data_out = nullptr;
    size_out = 0;
    HMODULE self = GetModuleHandleW(nullptr);
    HRSRC res = FindResourceW(self, MAKEINTRESOURCEW(kPayloadResourceId), RT_RCDATA);
    if (!res) return false;
    HGLOBAL handle = LoadResource(self, res);
    if (!handle) return false;
    const DWORD size = SizeofResource(self, res);
    const void* data = LockResource(handle);
    if (!data || size == 0) return false;
    data_out = static_cast<const unsigned char*>(data);
    size_out = size;
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

// How many virule.app PAGES are connected to the client right now, or -1
// when no client answered at all. Setup's own connection carries no Origin,
// so it is a local control connection and is never counted.
int connected_pages() {
    std::string response;
    if (!vclient::bridge::loopback_roundtrip(
            vclient::bridge::kPort, nullptr, "\"virule_client\"",
            "{\"type\":\"status\"}", response)) {
        return -1;
    }
    long long pages = 0;
    if (!vclient::json_scan::find_number_in(response, 0, response.size(),
                                            "pages", pages)) {
        return -1;
    }
    return (int)pages;
}

// THE HANDOFF DECISION. True when a virule.app page reached the client
// inside the grace window, which means the browser is still driving the
// flow and Setup must not open anything.
bool wait_for_page(DWORD grace_ms) {
    const ULONGLONG deadline = GetTickCount64() + grace_ms;
    for (;;) {
        const int pages = connected_pages();
        if (pages > 0) return true;
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
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--dev-unsigned") {
            allow_unsigned = true;
        } else if (arg.rfind(L"--resume-url=", 0) == 0) {
            // Development seam (like --dev-unsigned and the client's
            // --no-register): point the recovery at a local site build.
            // Not a privilege: a local process can open any URL already.
            resume_url = arg.substr(13);
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

    // 1. The embedded payload, verified against the baked hash.
    const unsigned char* payload = nullptr;
    size_t payload_size = 0;
    if (!load_payload(payload, payload_size)) {
        return fail(L"VIRULE Setup is damaged. Download it again.",
                    "embedded payload missing");
    }
    const std::string hash = vclient::verify_binary::sha256_hex(payload, payload_size);
    if (hash.empty() || hash != kClientPayloadSha256Hex) {
        return fail(L"VIRULE Setup is damaged. Download it again.",
                    "payload hash mismatch: " + hash);
    }

    // 2. Directories.
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

    // 3. Stage the payload beside the target, verify its signature, then
    // move it into place (replacing any older client safely).
    const auto staged = install_dir / L"virule-client.exe.new";
    {
        std::ofstream out(staged, std::ios::binary | std::ios::trunc);
        if (!out || !out.write(reinterpret_cast<const char*>(payload),
                               (std::streamsize)payload_size).good()) {
            return fail(L"VIRULE couldn't be installed on this computer.",
                        "staged write failed");
        }
    }
    if (!vclient::verify_binary::authenticode_valid(staged)) {
        if (allow_unsigned) {
            vclient::log::setup("payload is unsigned; proceeding (--dev-unsigned)");
        } else {
            std::filesystem::remove(staged, ec);
            return fail(L"VIRULE Setup is damaged. Download it again.",
                        "payload Authenticode verification failed");
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

    // 4. Per-user registration: virule:// and the uninstall entry. The
    // installed client is the canonical virule:// handler; the VIRULE Admin
    // defers to it rather than taking the scheme back.
    vclient::protocol_reg::register_protocol(target.wstring());
    vclient::uninstall::register_uninstall_entry(
        target.wstring(), VIRULE_CLIENT_VERSION_WSTRING);

    // 5. Record the installed version.
    {
        auto s = vclient::state::load();
        s.installed_version = VIRULE_CLIENT_VERSION_STRING;
        (void)vclient::state::save(s);
    }

    // 6. Start the client.
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

    // 7. THE BROWSER. An existing virule.app page is always the first
    // choice; recovery happens only when none appears.
    const bool page_connected = wait_for_page(kPageGraceMs);
    vclient::setup_window::set_complete();
    if (page_connected) {
        vclient::log::setup("a virule.app page connected; the browser owns the flow");
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

    Sleep(kCompleteVisibleMs);
    vclient::setup_window::close();

    vclient::log::setup("setup complete");
    return 0;
}
