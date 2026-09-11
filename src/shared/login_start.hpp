#pragma once
// THE PER-USER LOGIN START (client residency, 2026-09-10).
//
// An installed VIRULE keeps virule-client.exe running, so the loopback
// bridge (127.0.0.1:47612) is normally always there for the browser and
// virule:// is only a fallback wake. Two small per-user Windows mechanisms
// give that residency without a service, a scheduled task or elevation:
//
//   1. this Run value, which starts the managed client at every login and
//      after every reboot;
//   2. Windows Error Reporting's application restart
//      (RegisterApplicationRestart in client/main.cpp), which brings the
//      client back after a crash.
//
//   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
//     VIRULE   REG_SZ   "<%LOCALAPPDATA%\Programs\VIRULE\virule-client.exe>"
//
// The value name carries no environment: a staging and a production client
// install to the same path, so whichever one is installed is the one that
// starts, and a stale entry can never start a machine into the other
// environment. Written ONLY for the managed installation (a development
// tree never registers itself), by Virule-Setup at install time and by the
// client's own startup self-heal (the virule:// posture), under the same
// machine-registration guard (paths::environment_redirected: a sandboxed
// harness run never stamps the real hive). Removed by the uninstall
// inventory with the other REGISTRATIONS, last, and only while it points
// into the removed tree (the virule:// rule), so a foreign entry that
// happens to share the name is never touched.

#include <string>

#include "shared/paths.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace vclient::login_start {

inline constexpr const wchar_t* kRunKey =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
inline constexpr const wchar_t* kRunValue = L"VIRULE";

// The registered login-start command, or empty.
inline std::wstring registered_command() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0, KEY_QUERY_VALUE,
                      &key) != ERROR_SUCCESS) {
        return L"";
    }
    wchar_t buf[1024] = {};
    DWORD size = sizeof(buf) - sizeof(wchar_t);
    DWORD type = 0;
    std::wstring out;
    if (RegQueryValueExW(key, kRunValue, nullptr, &type,
                         reinterpret_cast<BYTE*>(buf), &size) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        out = buf;
    }
    RegCloseKey(key);
    return out;
}

// Register (or heal) the login start for `exe_path`. Idempotent: an entry
// that already names this command is left untouched. Refuses under a
// redirected environment exactly like every other machine-registration
// write.
inline void register_login_start(const std::wstring& exe_path) {
    if (exe_path.empty()) return;
    if (paths::environment_redirected()) return;
    const std::wstring command = L"\"" + exe_path + L"\"";
    if (registered_command() == command) return;
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return;
    }
    RegSetValueExW(key, kRunValue, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(command.c_str()),
                   (DWORD)((command.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
}

// Case-insensitive: does the registered command point anywhere into `dir`?
inline bool registered_under(const std::wstring& dir) {
    if (dir.empty()) return false;
    std::wstring cmd = registered_command();
    if (cmd.empty()) return false;
    auto lower = [](std::wstring s) {
        for (auto& c : s) c = static_cast<wchar_t>(towlower(c));
        return s;
    };
    return lower(cmd).find(lower(dir)) != std::wstring::npos;
}

// Remove the login start (only call after registered_under()).
inline void unregister_login_start() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0, KEY_SET_VALUE,
                      &key) != ERROR_SUCCESS) {
        return;
    }
    RegDeleteValueW(key, kRunValue);
    RegCloseKey(key);
}

} // namespace vclient::login_start
