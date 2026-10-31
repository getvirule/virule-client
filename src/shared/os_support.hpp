#pragma once
// THE SUPPORTED WINDOWS VERSIONS (owner decision 2026-10-30,
// VIRULE/docs/specs/evaluation-security.md "Windows support"): VIRULE
// supports Windows 10 and later; anything earlier is unsupported and its
// installation is refused. Virule-Setup.exe is the AUTHORITATIVE enforcement
// point (src/setup/main.cpp checks first, before reading its command line,
// so no flag, direct download or other ordinary path skips it); the
// website's notice (v1_mvp_site src/platform.ts) only discourages the
// download where the browser says enough, and is never the boundary.
//
// THE VERSION IS READ WITH RtlGetVersion (ntdll), which reports the real
// version. GetVersionEx and the VersionHelpers (IsWindows10OrGreater) answer
// from the executable's manifest: without a Windows 10 <supportedOS> entry
// they report Windows 8 (6.2) on Windows 10 and 11, which would refuse every
// supported computer. Windows 11 reports major version 10 (build 22000 and
// later), so "major >= 10" admits Windows 10 and 11 alike.
//
// An answer that cannot be read is NOT treated as unsupported: ntdll exports
// RtlGetVersion on every Windows NT since 2000, so a missing export is not a
// real pre-Windows-10 computer, and refusing there could only block a
// supported one. (A pre-Windows-10 computer may also fail to load Setup at
// all, before this check runs, because of the toolset; that is a refusal
// too, without VIRULE's sentence.)

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace vclient::os_support {

inline constexpr unsigned long kMinimumMajorVersion = 10;

// The one sentence an unsupported computer is told: the owner's (brief
// 2026-10-31, VIRULE/docs/specs/evaluation-security.md decision 14; no em
// dash).
inline constexpr const wchar_t* kUnsupportedSentence = L"VIRULE requires Windows 10 or later.";

struct WindowsVersion {
    bool known = false;
    unsigned long major = 0;
    unsigned long minor = 0;
    unsigned long build = 0;
};

/** The pure rule (tested): only a version KNOWN to be earlier than
 *  Windows 10 is unsupported. */
inline bool is_supported(const WindowsVersion& v) {
    return !v.known || v.major >= kMinimumMajorVersion;
}

/** The running Windows' real version (header). */
inline WindowsVersion current_windows() {
    WindowsVersion v;
#if defined(_WIN32)
    using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return v;
    const auto fn = reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")));
    if (!fn) return v;
    OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof info;
    if (fn(&info) != 0) return v;   // STATUS_SUCCESS is 0
    v.known = true;
    v.major = info.dwMajorVersion;
    v.minor = info.dwMinorVersion;
    v.build = info.dwBuildNumber;
#endif
    return v;
}

} // namespace vclient::os_support
