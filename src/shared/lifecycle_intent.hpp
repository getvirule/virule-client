#pragma once
// THE DURABLE UNINSTALL-INTENT LATCH (owner invariant 2026-09-04).
//
// EXPLICIT USER UNINSTALL OUTRANKS EVERY AUTOMATIC RECOVERY BEHAVIOR:
// client self-heal, client restart, repair/reinstall, update, launch,
// admin_open, admin_launch, protocol re-registration, shortcut repair.
// Once an uninstall begins, VIRULE may not repair or reinstall itself.
//
// The latch is a VIRULE-owned Windows registry value:
//
//   HKCU\Software\VIRULE\Lifecycle
//     UninstallInProgress   REG_DWORD 1
//     UninstallStartedUtc   REG_SZ    (inspection/forensics only)
//
// Chosen properties (all required by the owner spec):
//   - written BEFORE any destructive teardown starts;
//   - survives Client exit, Admin exit and partial uninstall failure
//     (the registry lives outside every directory uninstall removes);
//   - easy to inspect and log;
//   - removed LAST, only after successful uninstall completion.
//
// It is deliberately NOT "the absence of the Apps & Features key": absence
// is fragile against third-party cleaners and cannot distinguish a fresh
// machine from a removal in progress.
//
// WHO CLEARS IT: (1) the uninstall helper, as its final step after a fully
// successful removal; (2) Virule-Setup at install time, because an explicit
// later install is newer explicit user intent in the opposite direction
// (this is also the recovery path for a latch stranded by a failed or
// interrupted uninstall).
//
// The VIRULE Admin (admin_host client_health, virule.exe launch
// cooperation) reads the same location with its own copy of this check;
// the key path and value name are a cross-repo contract.

#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace vclient::lifecycle {

inline constexpr const wchar_t* kLifecycleKey = L"Software\\VIRULE\\Lifecycle";
inline constexpr const wchar_t* kUninstallValue = L"UninstallInProgress";
inline constexpr const wchar_t* kUninstallStampValue = L"UninstallStartedUtc";

// True while an explicit uninstall has begun and has not completed.
inline bool uninstall_intent_active() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kLifecycleKey, 0, KEY_QUERY_VALUE,
                      &key) != ERROR_SUCCESS) {
        return false;
    }
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    const LSTATUS status = RegQueryValueExW(key, kUninstallValue, nullptr,
                                            &type,
                                            reinterpret_cast<BYTE*>(&value),
                                            &size);
    RegCloseKey(key);
    return status == ERROR_SUCCESS && type == REG_DWORD && value != 0;
}

// Record the intent. Must run before anything destructive; idempotent.
// False = the registry write itself failed (callers refuse to proceed with
// removal rather than uninstalling without the latch).
inline bool set_uninstall_intent() {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kLifecycleKey, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    const DWORD one = 1;
    const bool ok = RegSetValueExW(key, kUninstallValue, 0, REG_DWORD,
                                   reinterpret_cast<const BYTE*>(&one),
                                   sizeof(one)) == ERROR_SUCCESS;
    SYSTEMTIME st{};
    GetSystemTime(&st);
    wchar_t stamp[40] = {};
    swprintf_s(stamp, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    RegSetValueExW(key, kUninstallStampValue, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(stamp),
                   (DWORD)((wcslen(stamp) + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return ok;
}

// Clear the intent: ONLY after a fully successful uninstall, or from
// Virule-Setup when an explicit install supersedes it.
inline void clear_uninstall_intent() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kLifecycleKey, 0,
                      KEY_SET_VALUE | KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return;
    }
    RegDeleteValueW(key, kUninstallValue);
    RegDeleteValueW(key, kUninstallStampValue);
    RegCloseKey(key);
    // Remove the Lifecycle key itself when nothing else lives in it (a
    // clean machine keeps a clean registry); harmless if values remain.
    RegDeleteKeyW(HKEY_CURRENT_USER, kLifecycleKey);
}

} // namespace vclient::lifecycle
