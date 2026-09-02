// Virule-Setup.exe - the disposable one-shot installer.
//
// EXTREMELY BORING BY DESIGN. Normal successful execution: verify the
// embedded signed client payload, create the per-user directories, install
// virule-client.exe, register virule:// and the uninstall entry, start the
// client, exit. No wizard, no pages, no choices, no windows at all on
// success. The browser owns visible progress: it polls for the freshly
// installed client and continues the user's original task.
//
// Per-user throughout: %LOCALAPPDATA%\Programs\VIRULE, HKCU registration.
// No elevation, no machine-wide state, no service, no login task.
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

#include "client/bridge.hpp"     // loopback client half (ask a running client to exit)
#include "shared/client_state.hpp"
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
#pragma comment(lib, "advapi32.lib")
#endif

#include "setup/payload/payload_hash.h" // generated: kClientPayloadSha256Hex

namespace {

constexpr int kPayloadResourceId = 1001;

// Native fallback error UI: one minimal, human-readable line. The
// technical reason goes to the log, never the dialog.
void fail(const wchar_t* human_line, const std::string& log_line) {
    vclient::log::setup("FAIL: " + log_line);
    MessageBoxW(nullptr, human_line, L"VIRULE Setup",
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
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

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool allow_unsigned = false; // development only; the hash gate always holds
    for (int i = 1; i < argc; ++i) {
        if (std::wstring(argv[i]) == L"--dev-unsigned") allow_unsigned = true;
    }
    LocalFree(argv);

    vclient::log::setup(std::string("setup start, version ") + VIRULE_CLIENT_VERSION_STRING);

    // 1. The embedded payload, verified against the baked hash.
    const unsigned char* payload = nullptr;
    size_t payload_size = 0;
    if (!load_payload(payload, payload_size)) {
        fail(L"VIRULE Setup is damaged. Download it again.",
             "embedded payload missing");
        return 1;
    }
    const std::string hash = vclient::verify_binary::sha256_hex(payload, payload_size);
    if (hash.empty() || hash != kClientPayloadSha256Hex) {
        fail(L"VIRULE Setup is damaged. Download it again.",
             "payload hash mismatch: " + hash);
        return 1;
    }

    // 2. Directories.
    const auto install_dir = vclient::paths::install_dir();
    const auto target = vclient::paths::installed_client_exe();
    if (install_dir.empty()) {
        fail(L"VIRULE couldn't be installed on this computer.",
             "no LOCALAPPDATA/USERPROFILE");
        return 1;
    }
    std::error_code ec;
    std::filesystem::create_directories(install_dir, ec);
    std::filesystem::create_directories(vclient::paths::client_state_dir(), ec);
    if (!std::filesystem::exists(install_dir, ec)) {
        fail(L"VIRULE couldn't be installed on this computer.",
             "create_directories failed: " + install_dir.string());
        return 1;
    }

    // 3. Stage the payload beside the target, verify its signature, then
    // move it into place (replacing any older client safely).
    const auto staged = install_dir / L"virule-client.exe.new";
    {
        std::ofstream out(staged, std::ios::binary | std::ios::trunc);
        if (!out || !out.write(reinterpret_cast<const char*>(payload),
                               (std::streamsize)payload_size).good()) {
            fail(L"VIRULE couldn't be installed on this computer.",
                 "staged write failed");
            return 1;
        }
    }
    if (!vclient::verify_binary::authenticode_valid(staged)) {
        if (allow_unsigned) {
            vclient::log::setup("payload is unsigned; proceeding (--dev-unsigned)");
        } else {
            std::filesystem::remove(staged, ec);
            fail(L"VIRULE Setup is damaged. Download it again.",
                 "payload Authenticode verification failed");
            return 1;
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
            fail(L"VIRULE couldn't be installed. Close VIRULE and run Setup again.",
                 "replace failed: " + ec.message());
            return 1;
        }
    }

    // 4. Per-user registration: virule:// and the uninstall entry.
    vclient::protocol_reg::register_protocol(target.wstring());
    vclient::uninstall::register_uninstall_entry(
        target.wstring(), VIRULE_CLIENT_VERSION_WSTRING);

    // 5. Record the installed version.
    {
        auto s = vclient::state::load();
        s.installed_version = VIRULE_CLIENT_VERSION_STRING;
        (void)vclient::state::save(s);
    }

    // 6. Start the client and leave. The browser reconnects on its own.
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

    vclient::log::setup("setup complete");
    return 0;
}
