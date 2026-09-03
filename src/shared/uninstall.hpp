#pragma once
// VIRULE uninstall, TWO EXPLICIT MODES (owner spec 2026-09-03), both
// driven by an EXPLICIT ownership inventory. Nothing here recurses outside
// VIRULE-owned paths.
//
// DEFAULT UNINSTALL (delete_data = false) removes the SOFTWARE and its
// integration and PRESERVES every piece of user-owned VIRULE data:
//   1. %LOCALAPPDATA%\VIRULE\client\            (recursive; client-only
//      software state: state.json, client logs)
//   2. HKCU\Software\Classes\virule ONLY while it points at this client
//   3. the HKCU uninstall entry
//   4. the desktop VIRULE.lnk ONLY when the client created it
//      (state.json provenance; a shortcut the user made stays)
//   5. %LOCALAPPDATA%\Programs\VIRULE\          (the installed program,
//      including the managed Admin\ installation under it - Phase 2)
//   6. %LOCALAPPDATA%\VIRULE\ itself only if left empty
//   PRESERVED: virule.db, workspace\, logs\, backup.json, security\
//   (dev_machine.cred AND the QA tester credentials), and anything else
//   under the user-data root. A reinstall finds all of it in place.
//
// UNINSTALL & DELETE DATA (delete_data = true; the explicit destructive
// option behind the "Delete local data" toggle and its "cannot be undone"
// warning) removes everything above PLUS the whole VIRULE user-data root,
// %LOCALAPPDATA%\VIRULE\ (virule.db, workspace\, logs\, backup.json,
// security\ with every credential, the qa_test_mode flag). That root is
// VIRULE-owned by definition (paths.hpp); nothing outside it is touched.
//
// Development trees (the VIRULE repository, its virule\publish\Virule
// folder) and the user's chosen build root are outside every inventory
// root and can never be touched: every deletion above is an explicit
// VIRULE-owned path under %LOCALAPPDATA%.
//
// SELF-REMOVAL: a running executable cannot delete itself, so the client
// copies itself to %TEMP% and runs that copy with --finish-uninstall
// <parent pid>. The copy waits for the parent to exit, performs the whole
// inventory (idempotent), removes the install directory, and schedules its
// own deletion. No broken half-installed executable is left behind.
//
// FUTURE RULE (recorded here on purpose): a full VIRULE uninstall and
// removing an individual installed game are SEPARATE actions. When managed
// game installs exist they will have their own records and their own
// removal operations; this inventory must never grow a recursive delete of
// a game-library directory.

#include <filesystem>
#include <string>

#include "shared/client_state.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"
#include "shared/protocol_reg.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace vclient::uninstall {

inline constexpr const wchar_t* kUninstallKey =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ViruleClient";

// ---- uninstall registration (Apps & Features) ----

inline void register_uninstall_entry(const std::wstring& exe_path,
                                     const std::wstring& version) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kUninstallKey, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return;
    }
    auto set_str = [&](const wchar_t* name, const std::wstring& value) {
        RegSetValueExW(key, name, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(value.c_str()),
                       (DWORD)((value.size() + 1) * sizeof(wchar_t)));
    };
    auto set_dword = [&](const wchar_t* name, DWORD value) {
        RegSetValueExW(key, name, 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&value), sizeof(value));
    };
    set_str(L"DisplayName", L"VIRULE");
    set_str(L"DisplayVersion", version);
    set_str(L"Publisher", L"VIRULE");
    set_str(L"DisplayIcon", L"\"" + exe_path + L"\",0");
    set_str(L"InstallLocation", paths::install_dir().wstring());
    set_str(L"UninstallString", L"\"" + exe_path + L"\" --uninstall");
    set_dword(L"NoModify", 1);
    set_dword(L"NoRepair", 1);
    RegCloseKey(key);
}

inline void remove_uninstall_entry() {
    RegDeleteTreeW(HKEY_CURRENT_USER, kUninstallKey);
}

// ---- the inventory removal (idempotent; called by the %TEMP% helper) ----

inline void remove_file_quiet(const std::filesystem::path& p) {
    if (p.empty()) return;
    std::error_code ec;
    std::filesystem::remove(p, ec);
}

inline void remove_dir_if_empty(const std::filesystem::path& p) {
    if (p.empty()) return;
    std::error_code ec;
    if (std::filesystem::exists(p, ec) && !ec &&
        std::filesystem::is_directory(p, ec) && !ec &&
        std::filesystem::is_empty(p, ec) && !ec) {
        std::filesystem::remove(p, ec);
    }
}

// Everything except the install directory (which only the %TEMP% helper may
// remove, after the installed process has exited). `delete_data` is the
// explicit destructive mode; the default PRESERVES user-owned data.
inline void remove_owned_state(const std::wstring& installed_exe,
                               bool delete_data) {
    // Provenance first, while state.json still exists to consult.
    const state::State s = state::load();
    std::error_code ec;

    // The desktop shortcut, ONLY when this client created it (a shortcut
    // the user made themselves stays, in both modes).
    if (s.created_desktop_shortcut) {
        remove_file_quiet(paths::desktop_shortcut());
    }

    // The client state directory (state.json, client logs): software
    // state, strictly ours, removed in both modes.
    const auto client_dir = paths::client_state_dir();
    if (!client_dir.empty()) {
        ec.clear();
        std::filesystem::remove_all(client_dir, ec);
    }

    if (delete_data) {
        // The explicit Uninstall & Delete Data mode: the whole VIRULE
        // user-data root goes (virule.db, workspace\, logs\, backup.json,
        // security\ with every credential, the qa_test_mode flag). The
        // root is VIRULE-owned by definition; nothing outside it is
        // touched, so unrelated files and development trees stay.
        const auto root = paths::virule_data_root();
        if (!root.empty()) {
            ec.clear();
            std::filesystem::remove_all(root, ec);
        }
    } else {
        // Default: PRESERVE user data. Every credential (dev_machine.cred
        // AND qa_tester*.cred), virule.db, workspace\, logs\ and
        // backup.json stay exactly where a reinstall expects them; the
        // shared parents are removed only when nothing is left in them.
        remove_dir_if_empty(paths::security_dir());
        remove_dir_if_empty(paths::virule_data_root());
    }

    // virule:// only while it is OURS. A registration the Admin has
    // taken over stays.
    if (protocol_reg::registered_to(installed_exe)) {
        protocol_reg::unregister_protocol();
    }

    // The Apps & Features entry.
    remove_uninstall_entry();
}

// The %TEMP% helper's whole job: wait out the parent, remove everything,
// remove the installed program, then schedule this copy's own deletion.
inline int finish_uninstall(unsigned long parent_pid, bool delete_data) {
    if (parent_pid != 0) {
        if (HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, parent_pid)) {
            WaitForSingleObject(h, 30000);
            CloseHandle(h);
        }
    }
    const std::wstring installed_exe = paths::installed_client_exe().wstring();
    remove_owned_state(installed_exe, delete_data);

    // 7. The installed program directory. Bounded retries cover the small
    // window where the parent's handles are still closing.
    const auto dir = paths::install_dir();
    for (int i = 0; i < 20; ++i) {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        if (!std::filesystem::exists(dir, ec)) break;
        Sleep(250);
    }

    // Remove this %TEMP% copy after exit (cmd waits, then deletes).
    wchar_t self[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, self, MAX_PATH)) {
        std::wstring cmd = L"cmd.exe /c ping -n 3 127.0.0.1 >nul & del /f /q \"";
        cmd += self;
        cmd += L"\"";
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        std::wstring mutable_cmd = cmd;
        if (CreateProcessW(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
    return 0;
}

// Start the uninstall from the running (installed) client: copy self to
// %TEMP%, launch the copy, and let the caller exit promptly. Returns false
// when the helper could not be started (nothing was removed yet).
inline bool spawn_uninstall_helper(bool delete_data) {
    wchar_t self[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH)) return false;
    wchar_t temp_dir[MAX_PATH] = {};
    const DWORD n = GetTempPathW(MAX_PATH, temp_dir);
    if (n == 0 || n >= MAX_PATH) return false;
    std::wstring helper = std::wstring(temp_dir) + L"virule-uninstall-" +
        std::to_wstring(GetTickCount64()) + L".exe";
    if (!CopyFileW(self, helper.c_str(), FALSE)) return false;
    std::wstring cmd = L"\"" + helper + L"\" --finish-uninstall " +
        std::to_wstring(GetCurrentProcessId());
    if (delete_data) cmd += L" --delete-data";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring mutable_cmd = cmd;
    if (!CreateProcessW(helper.c_str(), mutable_cmd.data(), nullptr, nullptr,
                        FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        DeleteFileW(helper.c_str());
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

} // namespace vclient::uninstall
