#pragma once
// VIRULE uninstall, TWO EXPLICIT MODES (owner spec 2026-09-03), both
// driven by an EXPLICIT ownership inventory. Nothing here recurses outside
// VIRULE-owned paths.
//
// THE ORDER IS THE CONTRACT (owner corrective spec 2026-09-04):
//
//   1.  the durable uninstall-intent latch is written BEFORE any teardown
//       (lifecycle_intent.hpp; every automatic resurrection path honors it);
//   2.  new lifecycle operations stop being accepted;
//   3.  an active Admin update is cancelled back to a known-good
//       filesystem state (never finished merely because it started first);
//   4.  the Admin is closed GRACEFULLY and every managed Admin-directory
//       process must be gone;
//   5.  the client exits and the visible %TEMP% helper takes over
//       ("Removing VIRULE…" - a destructive operation never runs silent);
//   6.  software-owned FILES are removed;
//   7.  software-owned REGISTRATIONS (virule://, the Apps & Features
//       entry) are removed LAST, only after file removal succeeded, so a
//       partial failure always leaves a Windows-recoverable retry path;
//   8.  terminal state is verified, the intent latch is cleared LAST, and
//       the user sees the outcome.
//
//   A failure at any point keeps the latch, keeps the registrations that
//   still had work to do, and surfaces a retry. It never half-removes
//   silently and never lets self-heal "fix" an explicit removal.
//
// DEFAULT UNINSTALL (delete_data = false) removes the SOFTWARE and its
// integration and PRESERVES every piece of user-owned VIRULE data:
//   - %LOCALAPPDATA%\VIRULE\client\           (client software state)
//   - %LOCALAPPDATA%\Programs\VIRULE\         (client + managed Admin\)
//   - the desktop / Start Menu VIRULE.lnk when VIRULE-owned: recorded
//     provenance OR a stored target inside the managed install tree
//     (never a VIRULE-named shortcut pointing elsewhere)
//   - virule:// ONLY while it points into the removed tree
//   - the HKCU uninstall entry
//   - %LOCALAPPDATA%\VIRULE\ itself only if left empty
//   PRESERVED: virule.db, workspace\, logs\, backup.json, security\
//   (dev_machine.cred AND the QA tester credentials), and anything else
//   under the user-data root. A reinstall finds all of it in place.
//
// UNINSTALL & DELETE DATA (delete_data = true; the explicit destructive
// option behind the "Delete local data" toggle and its "cannot be undone"
// warning) removes everything above PLUS the whole VIRULE user-data root.
// That root is VIRULE-owned by definition (paths.hpp); nothing outside it
// is touched. The Admin is closed FIRST in both modes, so virule.db is
// never deleted under a live Admin.
//
// Development trees (the VIRULE repository, its virule\publish\Virule
// folder) and the user's chosen build root are outside every inventory
// root and can never be touched: every deletion above is an explicit
// VIRULE-owned path under %LOCALAPPDATA%.
//
// SELF-REMOVAL: a running executable cannot delete itself, so the client
// copies itself to %TEMP% and runs that copy with --finish-uninstall
// <parent pid>. The copy waits for every managed process to exit, OWNS THE
// VISIBLE REMOVAL SURFACE (the branded "Removing VIRULE…" card and its
// terminal outcome - main.cpp orchestrates it over these primitives),
// performs the inventory (idempotent), and schedules its own deletion.
//
// LOGGING: the client's own log directory is part of what gets removed, so
// the helper appends to %TEMP%\virule-uninstall.log instead - small,
// capped, and it survives the removal for inspection.
//
// FUTURE RULE (recorded here on purpose): a full VIRULE uninstall and
// removing an individual installed game are SEPARATE actions. When managed
// game installs exist they will have their own records and their own
// removal operations; this inventory must never grow a recursive delete of
// a game-library directory.

#include <filesystem>
#include <fstream>
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
#include <tlhelp32.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <objbase.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#endif

namespace vclient::uninstall {

inline constexpr const wchar_t* kUninstallKey =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ViruleClient";

// ---- helper-side logging (%TEMP%; survives the removal) ----

inline void temp_log(const std::string& what) {
    wchar_t temp_dir[MAX_PATH] = {};
    const DWORD n = GetTempPathW(MAX_PATH, temp_dir);
    if (n == 0 || n >= MAX_PATH) return;
    const std::filesystem::path file =
        std::filesystem::path(temp_dir) / L"virule-uninstall.log";
    std::error_code ec;
    if (std::filesystem::exists(file, ec) &&
        std::filesystem::file_size(file, ec) > 256 * 1024) {
        std::filesystem::remove(file, ec);
    }
    std::ofstream out(file, std::ios::app);
    if (!out) return;
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char stamp[40] = {};
    std::snprintf(stamp, sizeof(stamp), "%04u-%02u-%02uT%02u:%02u:%02uZ ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                  st.wSecond);
    out << stamp << what << "\n";
}

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

// ---- process accounting ----

// Any process (other than this one) whose image path sits under the
// installed program directory: the serving client, the managed Admin's
// virule.exe, ViruleAdminHost.exe and its CEF children. These must all be
// gone before file removal can succeed.
inline bool any_install_dir_process_running() {
    const auto dir = paths::install_dir();
    if (dir.empty()) return false;
    std::wstring prefix = dir.wstring();
    if (prefix.empty()) return false;
    if (prefix.back() != L'\\') prefix += L'\\';
    for (wchar_t& c : prefix) c = (wchar_t)towlower(c);

    const DWORD self = GetCurrentProcessId();
    bool found = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ProcessID == self) continue;
            HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                      entry.th32ProcessID);
            if (!proc) continue;
            wchar_t image[MAX_PATH * 2] = {};
            DWORD n = (DWORD)(sizeof(image) / sizeof(image[0]));
            if (QueryFullProcessImageNameW(proc, 0, image, &n)) {
                std::wstring path(image, n);
                for (wchar_t& c : path) c = (wchar_t)towlower(c);
                if (path.rfind(prefix, 0) == 0) found = true;
            }
            CloseHandle(proc);
        } while (!found && Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}

// Wait until every managed-directory process is gone (bounded). True =
// clear to remove files.
inline bool wait_install_dir_processes_gone(unsigned long long wait_ms) {
    const ULONGLONG deadline = GetTickCount64() + wait_ms;
    for (;;) {
        if (!any_install_dir_process_running()) return true;
        if (GetTickCount64() >= deadline) return false;
        Sleep(250);
    }
}

// ---- update-residue reconciliation ----
// An uninstall may intersect an interrupted or cancelled Admin update.
// Before removal (and before any failure leaves the machine waiting for a
// retry), bring the managed tree back to ONE unambiguous known-good state:
// a stranded Admin.previous with no live Admin\ is the known-good install
// and is restored; staging and the download are debris.
inline void reconcile_admin_update_residue() {
    std::error_code ec;
    const auto admin_dir = paths::admin_install_dir();
    const auto previous = paths::admin_previous_dir();
    if (!admin_dir.empty() && !previous.empty() &&
        !std::filesystem::exists(admin_dir, ec) &&
        std::filesystem::exists(previous, ec)) {
        ec.clear();
        std::filesystem::rename(previous, admin_dir, ec);
        if (!ec) temp_log("reconciled: Admin.previous restored as Admin");
    }
    ec.clear();
    std::filesystem::remove_all(paths::admin_staging_dir(), ec);
    ec.clear();
    std::filesystem::remove(paths::admin_download_zip(), ec);
}

// ---- the inventory removal (idempotent) ----

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

// Bounded-retry recursive removal: a single remove_all loses races with
// antivirus scanners, indexers and sync clients holding transient handles
// on freshly written files. True = the tree is gone.
inline bool remove_tree_with_retries(const std::filesystem::path& p,
                                     int attempts = 20) {
    if (p.empty()) return true;
    for (int i = 0; i < attempts; ++i) {
        std::error_code ec;
        std::filesystem::remove_all(p, ec);
        ec.clear();
        if (!std::filesystem::exists(p, ec)) return true;
        Sleep(250);
    }
    std::error_code ec;
    return !std::filesystem::exists(p, ec);
}

// ---- shortcut ownership (P1 corrective pass 2026-09-04) ----

// Does this .lnk's STORED target path point into the managed VIRULE
// install tree (%LOCALAPPDATA%\Programs\VIRULE\...: the managed
// virule.exe, virule-client.exe, anything under Admin\)? SLGP_RAWPATH
// reads the stored path without shell resolution, so the answer is
// correct even after the target files were already removed. False for a
// missing/unreadable shortcut and for anything pointing elsewhere.
inline bool shortcut_targets_managed_install(const std::filesystem::path& lnk) {
    if (lnk.empty()) return false;
    std::error_code ec;
    if (!std::filesystem::exists(lnk, ec) || ec) return false;

    std::wstring prefix = paths::install_dir().wstring();
    if (prefix.empty()) return false;
    if (prefix.back() != L'\\') prefix += L'\\';
    for (wchar_t& c : prefix) c = (wchar_t)towlower(c);

    const HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(init);
    bool owned = false;
    IShellLinkW* link = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_IShellLinkW, (void**)&link))) {
        IPersistFile* file = nullptr;
        if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, (void**)&file))) {
            if (SUCCEEDED(file->Load(lnk.wstring().c_str(), STGM_READ))) {
                wchar_t target[MAX_PATH * 2] = {};
                if (SUCCEEDED(link->GetPath(target,
                                            (int)(sizeof(target) / sizeof(target[0])),
                                            nullptr, SLGP_RAWPATH))) {
                    std::wstring path(target);
                    for (wchar_t& c : path) c = (wchar_t)towlower(c);
                    if (!path.empty() && path.rfind(prefix, 0) == 0) owned = true;
                }
            }
            file->Release();
        }
        link->Release();
    }
    if (uninit) CoUninitialize();
    return owned;
}

// FILES ONLY: the software-owned files and directories. Registrations are
// deliberately NOT touched here; they go last, through
// remove_registrations(), and only after this reports success. True = the
// installed program directory and the client state directory are gone.
inline bool remove_files(bool delete_data) {
    // Provenance first, while state.json still exists to consult.
    const state::State s = state::load();
    std::error_code ec;

    // VIRULE-owned shortcuts. A shortcut is VIRULE-owned when this client
    // recorded creating it (state.json provenance) OR when its stored
    // target resolves into the managed install tree (the target-based
    // supplement: a 2026-09-04 incident destroyed the provenance record
    // and a real uninstall then stranded the shortcut). A VIRULE-named
    // shortcut pointing anywhere else is the user's and stays, in both
    // modes. Desktop first, then any Start Menu VIRULE shortcut
    // (target-owned only; the client never creates one, so it has no
    // provenance by definition).
    {
        const auto desktop = paths::desktop_shortcut();
        if (s.created_desktop_shortcut ||
            shortcut_targets_managed_install(desktop)) {
            remove_file_quiet(desktop);
            temp_log("removed desktop shortcut (VIRULE-owned)");
        }
        const auto start_menu = paths::start_menu_shortcut();
        if (shortcut_targets_managed_install(start_menu)) {
            remove_file_quiet(start_menu);
            temp_log("removed Start Menu shortcut (VIRULE-owned)");
        }
    }

    // The client state directory (state.json, client logs): software
    // state, strictly ours, removed in both modes.
    const auto client_dir = paths::client_state_dir();
    (void)remove_tree_with_retries(client_dir);

    if (delete_data) {
        // The explicit Uninstall & Delete Data mode: the whole VIRULE
        // user-data root goes (virule.db, workspace\, logs\, backup.json,
        // security\ with every credential, the qa_test_mode flag). The
        // root is VIRULE-owned by definition; nothing outside it is
        // touched, so unrelated files and development trees stay. The
        // Admin was closed before this runs (the order contract), so the
        // database is never deleted under a live Admin.
        (void)remove_tree_with_retries(paths::virule_data_root());
    } else {
        // Default: PRESERVE user data. Every credential (dev_machine.cred
        // AND qa_tester*.cred), virule.db, workspace\, logs\ and
        // backup.json stay exactly where a reinstall expects them; the
        // shared parents are removed only when nothing is left in them.
        remove_dir_if_empty(paths::security_dir());
        remove_dir_if_empty(paths::virule_data_root());
    }

    // The installed program directory (client + the managed Admin\ under
    // it). Bounded retries cover the small window where the last exiting
    // process's handles are still closing.
    const bool program_gone = remove_tree_with_retries(paths::install_dir());

    ec.clear();
    const bool state_gone = client_dir.empty() ||
                            !std::filesystem::exists(client_dir, ec);
    bool data_gone = true;
    if (delete_data) {
        ec.clear();
        data_gone = !std::filesystem::exists(paths::virule_data_root(), ec);
    }
    return program_gone && state_gone && data_gone;
}

// REGISTRATIONS LAST (the audit's H1 fix): virule:// and the Apps &
// Features entry are removed only after remove_files() succeeded, so a
// locked or failing removal always keeps a Windows-visible retry path.
inline void remove_registrations(const std::wstring& installed_exe) {
    // virule:// while it points anywhere into the removed tree: the
    // installed client (the canonical handler) or the managed Admin's
    // virule.exe (which held the scheme on client-less machines). A
    // registration pointing outside the tree (a dev tree, a foreign app)
    // stays.
    const std::wstring command = protocol_reg::registered_command();
    if (!command.empty()) {
        std::wstring lower_cmd = command;
        for (wchar_t& c : lower_cmd) c = (wchar_t)towlower(c);
        std::wstring lower_root = paths::install_dir().wstring();
        for (wchar_t& c : lower_root) c = (wchar_t)towlower(c);
        if (!lower_root.empty() &&
            lower_cmd.find(lower_root) != std::wstring::npos) {
            protocol_reg::unregister_protocol();
        } else if (protocol_reg::registered_to(installed_exe)) {
            protocol_reg::unregister_protocol();
        }
    }

    // The Apps & Features entry.
    remove_uninstall_entry();
}

// Remove this %TEMP% helper copy after exit (cmd waits, then deletes).
inline void schedule_self_delete() {
    wchar_t self[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH)) return;
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

// Start the uninstall helper from the running (installed) client: copy self
// to %TEMP%, launch the copy, and let the caller exit promptly. Returns
// false when the helper could not be started (nothing was removed yet).
// The helper owns the visible removal surface from the moment the parent
// exits (main.cpp run_finish_uninstall).
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
    // No CREATE_NO_WINDOW mystery: the helper is a windowed process that
    // shows the branded "Removing VIRULE…" card (the zero-dead-air rule);
    // it owns no console either way.
    if (!CreateProcessW(helper.c_str(), mutable_cmd.data(), nullptr, nullptr,
                        FALSE, 0, nullptr, nullptr, &si, &pi)) {
        DeleteFileW(helper.c_str());
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

} // namespace vclient::uninstall
