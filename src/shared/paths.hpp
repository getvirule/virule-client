#pragma once
// VIRULE-owned filesystem locations, resolved from the environment only
// (LOCALAPPDATA, then USERPROFILE - the same resolution order the VIRULE
// product uses for its user-data root). No database, no registry.
//
// Ownership map (Phase 2):
//   %LOCALAPPDATA%\Programs\VIRULE\           the installed program
//       virule-client.exe
//       Admin\                                the managed VIRULE Admin
//           virule.exe, .resources\, ...      installation (Phase 2; the
//                                             development publish folder is
//                                             NEVER an installed Admin)
//   %LOCALAPPDATA%\VIRULE\client\             VIRULE Client state
//       state.json, logs\
//   %LOCALAPPDATA%\VIRULE\security\           shared credential store
//       dev_machine.cred   (this machine's VIRULE identity; shared with
//                           the VIRULE Admin when it is installed)
//       qa_tester.cred     (the native QA tester credential)
//       qa_tester_test.cred
//   %LOCALAPPDATA%\VIRULE\qa_test_mode        the Super Admin QA TEST MODE
//                                             flag file (Admin-owned)
//
// Everything else under %LOCALAPPDATA%\VIRULE (virule.db, workspace\,
// logs\, backup.json, .resources anywhere) belongs to the VIRULE Admin and
// is NEVER touched by the client or its uninstall.

#include <filesystem>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#endif

namespace vclient::paths {

inline std::filesystem::path env_path(const wchar_t* name) {
    wchar_t buf[MAX_PATH * 4];
    const DWORD cap = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
    const DWORD n = GetEnvironmentVariableW(name, buf, cap);
    if (n == 0 || n >= cap) return {};
    return std::filesystem::path(std::wstring(buf, n));
}

// %LOCALAPPDATA%, falling back to %USERPROFILE%\AppData\Local (the exact
// resolution dev_machine_proof.hpp uses, so both agree on every machine).
inline std::filesystem::path local_appdata() {
    const auto local = env_path(L"LOCALAPPDATA");
    if (!local.empty()) return local;
    const auto profile = env_path(L"USERPROFILE");
    if (!profile.empty()) return profile / L"AppData" / L"Local";
    return {};
}

// %LOCALAPPDATA%\VIRULE - the shared VIRULE user-data root.
inline std::filesystem::path virule_data_root() {
    const auto base = local_appdata();
    if (base.empty()) return {};
    return base / L"VIRULE";
}

inline std::filesystem::path security_dir()      { const auto r = virule_data_root(); return r.empty() ? r : r / L"security"; }
inline std::filesystem::path client_state_dir()  { const auto r = virule_data_root(); return r.empty() ? r : r / L"client"; }
inline std::filesystem::path client_logs_dir()   { const auto r = client_state_dir(); return r.empty() ? r : r / L"logs"; }
inline std::filesystem::path client_state_file() { const auto r = client_state_dir(); return r.empty() ? r : r / L"state.json"; }

// The QA TEST MODE flag file (Admin-owned, machine-local; presence = on).
inline std::filesystem::path qa_test_mode_flag() { const auto r = virule_data_root(); return r.empty() ? r : r / L"qa_test_mode"; }

// The Admin's database. Its EXISTENCE is the "VIRULE Admin is installed
// here" signal the uninstall uses to protect Admin-owned identity state.
inline std::filesystem::path admin_db_file()     { const auto r = virule_data_root(); return r.empty() ? r : r / L"virule.db"; }

// %LOCALAPPDATA%\Programs\VIRULE - where Virule-Setup installs the client.
inline std::filesystem::path install_dir() {
    const auto base = local_appdata();
    if (base.empty()) return {};
    return base / L"Programs" / L"VIRULE";
}

inline std::filesystem::path installed_client_exe() {
    const auto d = install_dir();
    return d.empty() ? d : d / L"virule-client.exe";
}

// The managed VIRULE Admin installation. ONLY this location counts as "Admin
// installed": a development tree or a manually extracted copy elsewhere is
// never reported or launched by the client.
inline std::filesystem::path admin_install_dir() {
    const auto d = install_dir();
    return d.empty() ? d : d / L"Admin";
}

inline std::filesystem::path installed_admin_exe() {
    const auto d = admin_install_dir();
    return d.empty() ? d : d / L"virule.exe";
}

// Admin install/update staging, beside the target on the same volume so the
// final placement is an atomic directory rename.
inline std::filesystem::path admin_staging_dir() {
    const auto d = install_dir();
    return d.empty() ? d : d / L"Admin.staging";
}

inline std::filesystem::path admin_previous_dir() {
    const auto d = install_dir();
    return d.empty() ? d : d / L"Admin.previous";
}

inline std::filesystem::path admin_download_zip() {
    const auto d = install_dir();
    return d.empty() ? d : d / L"admin-download.zip";
}

// The desktop shortcut the client creates for the installed Admin when the
// browser's install intent asked for one. Removed by uninstall when
// client-created (state.json provenance) OR when its stored target
// resolves into the managed install tree (P1 corrective pass 2026-09-04:
// provenance can be lost - a pre-fix incident destroyed state.json - so
// target-based ownership supplements it; a shortcut pointing anywhere
// else is the user's and stays).
inline std::filesystem::path desktop_shortcut() {
    PWSTR desktop = nullptr;
    std::filesystem::path out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &desktop))) {
        out = std::filesystem::path(desktop) / L"VIRULE.lnk";
    }
    if (desktop) CoTaskMemFree(desktop);
    return out;
}

// The per-user Start Menu Programs location a VIRULE shortcut would live
// at. The client does not currently create one, but uninstall still
// removes a VIRULE.lnk here when its target resolves into the managed
// install tree (same target-based ownership rule as the desktop).
inline std::filesystem::path start_menu_shortcut() {
    PWSTR programs = nullptr;
    std::filesystem::path out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Programs, 0, nullptr, &programs))) {
        out = std::filesystem::path(programs) / L"VIRULE.lnk";
    }
    if (programs) CoTaskMemFree(programs);
    return out;
}

} // namespace vclient::paths
