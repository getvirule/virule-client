#pragma once
// ORIGINATING-BROWSER RECOVERY (UX metadata only, never security input).
//
// The normal first install keeps the browser: the virule.app page that told
// the user to run Setup is still open, it reconnects to the freshly
// installed client, and Setup opens nothing at all. This file exists for the
// case where that page is gone (the tab was closed, the whole browser was
// closed) and the user would otherwise be left staring at a completed Setup
// with no way back into the flow they started.
//
// WHAT IS CAPTURED, AND WHEN: at Setup startup, before any install work and
// before the browser has a chance to exit, the process ancestry is walked
// upward looking for a browser we recognize. Downloaded-file launches vary
// (the browser process itself, a Windows shell hop, an Explorer launch from
// the Downloads folder), so the IMMEDIATE parent is never assumed to be the
// browser. Recorded: the ancestor's image name, its full executable path
// where it can be read safely, its PID, and a LIVE HANDLE on the process, so
// later liveness checks can never be fooled by PID reuse.
//
// ANCESTRY IS NOT ENOUGH ON ITS OWN: Windows routinely launches a
// downloaded exe through the shell, so the whole ancestry reads
// "Virule-Setup.exe <- explorer.exe" even when the user clicked the
// download inside Brave (observed in production, 2026-09-03). When no
// browser appears in the ancestry, capture() falls back to the running
// browsers themselves: if exactly ONE recognized browser family currently
// has a visible top-level window, that browser is the originator for all
// practical purposes and is recorded the same way. A browser process with
// no visible window (Edge startup boost keeps msedge.exe resident) is not
// an open browser and never counts. Zero or several open families =
// genuinely unknown, and only then does the Windows default get the URL.
//
// HOW IT IS USED (the owner's hierarchy):
//   A. the originating browser process is still alive -> open the resume URL
//      through that browser's executable, so it lands as a tab/window in
//      that same running instance;
//   B. that process is gone but its executable was captured -> launch that
//      same browser application with the resume URL;
//   C. the originating browser cannot be determined -> the Windows default
//      browser, and only then.
// The point of the hierarchy is that a flow begun in Brave comes back in
// Brave, even when Edge is the machine default.
//
// SECURITY: none of this is an input to any decision that matters. Browser
// identity authorizes nothing, is never sent anywhere, and is never written
// into installed state; it only decides which application shows a URL that
// is a compile-time constant. A wrong guess costs the user one tab.

#include <cwctype>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#endif

namespace vclient::origin_browser {

// Browsers this flow actually encounters. A name here only means "if the
// flow came from this, bring the user back to it"; an unlisted browser
// simply falls through to the Windows default.
inline const wchar_t* kKnownBrowsers[] = {
    L"brave.exe",
    L"msedge.exe",
    L"chrome.exe",
    L"firefox.exe",
    L"opera.exe",
    L"opera_gx.exe",
    L"vivaldi.exe",
};

// How far up the ancestry to look before giving up.
constexpr int kMaxAncestryDepth = 8;

struct Origin {
    bool found = false;          // a recognized browser ancestor
    std::wstring exe_name;       // "brave.exe"
    std::wstring exe_path;       // full path when it could be read
    DWORD pid = 0;
    HANDLE handle = nullptr;     // held open: liveness without PID reuse risk
    std::wstring chain;          // ancestry, for the log
};

enum class Opened { No, SameBrowser, DefaultBrowser };

inline std::wstring lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

inline bool is_known_browser(const std::wstring& exe_name) {
    const std::wstring name = lower(exe_name);
    for (const wchar_t* known : kKnownBrowsers) {
        if (name == known) return true;
    }
    return false;
}

struct ProcEntry {
    DWORD pid = 0;
    DWORD parent = 0;
    std::wstring name;
};

inline std::vector<ProcEntry> snapshot_processes() {
    std::vector<ProcEntry> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            out.push_back(ProcEntry{ entry.th32ProcessID,
                                     entry.th32ParentProcessID,
                                     entry.szExeFile });
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return out;
}

inline const ProcEntry* find_entry(const std::vector<ProcEntry>& all, DWORD pid) {
    for (const auto& e : all) {
        if (e.pid == pid) return &e;
    }
    return nullptr;
}

inline bool creation_time(HANDLE process, ULONGLONG& out) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return false;
    ULARGE_INTEGER v{};
    v.LowPart = created.dwLowDateTime;
    v.HighPart = created.dwHighDateTime;
    out = v.QuadPart;
    return true;
}

inline std::wstring image_path(HANDLE process) {
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD size = (DWORD)(sizeof(buf) / sizeof(buf[0]));
    if (!QueryFullProcessImageNameW(process, 0, buf, &size)) return L"";
    return std::wstring(buf, size);
}

// PIDs owning at least one visible, unowned top-level window right now.
// This is what separates an OPEN browser from a resident background one.
inline std::vector<DWORD> pids_with_visible_windows() {
    std::vector<DWORD> pids;
    EnumWindows(
        [](HWND hwnd, LPARAM lp) -> BOOL {
            auto* out = (std::vector<DWORD>*)lp;
            if (!IsWindowVisible(hwnd)) return TRUE;
            if (GetWindow(hwnd, GW_OWNER) != nullptr) return TRUE;
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid != 0) out->push_back(pid);
            return TRUE;
        },
        (LPARAM)&pids);
    return pids;
}

// The running-browser fallback: when the ancestry names no browser, the one
// browser family that is visibly open (if there is exactly one) is taken as
// the originator. Fills `origin` and returns true only on that unambiguous
// case.
inline bool capture_unique_open_browser(const std::vector<ProcEntry>& all,
                                        Origin& origin) {
    const auto visible = pids_with_visible_windows();
    auto has_visible_window = [&](DWORD pid) {
        for (const DWORD v : visible) {
            if (v == pid) return true;
        }
        return false;
    };
    std::wstring family;           // the one open family seen so far
    const ProcEntry* pick = nullptr; // one visible-window process of it
    for (const auto& e : all) {
        if (!is_known_browser(e.name)) continue;
        if (!has_visible_window(e.pid)) continue;
        const std::wstring name = lower(e.name);
        if (family.empty()) {
            family = name;
            pick = &e;
        } else if (family != name) {
            origin.chain += L"; open browsers ambiguous (" + family + L", " +
                            name + L")";
            return false; // two different browsers open: cannot pick
        }
    }
    if (pick == nullptr) {
        origin.chain += L"; no open browser found";
        return false;
    }
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                           FALSE, pick->pid);
    if (h == nullptr) {
        origin.chain += L"; open browser " + pick->name + L" unreadable";
        return false;
    }
    origin.found = true;
    origin.exe_name = pick->name;
    origin.exe_path = image_path(h);
    origin.pid = pick->pid;
    origin.handle = h; // kept open on purpose
    origin.chain += L"; unique open browser " + pick->name;
    return true;
}

// Walk the ancestry now, while the browser is still certain to be there.
inline Origin capture() {
    Origin origin;
    const auto all = snapshot_processes();
    if (all.empty()) return origin;

    DWORD cur_pid = GetCurrentProcessId();
    ULONGLONG cur_created = 0;
    if (!creation_time(GetCurrentProcess(), cur_created)) return origin;
    origin.chain = L"Virule-Setup.exe";

    for (int depth = 0; depth < kMaxAncestryDepth; ++depth) {
        const ProcEntry* child = find_entry(all, cur_pid);
        if (child == nullptr || child->parent == 0 || child->parent == cur_pid) break;
        const ProcEntry* parent = find_entry(all, child->parent);
        if (parent == nullptr) break;

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                               FALSE, parent->pid);
        if (h == nullptr) {
            origin.chain += L" <- " + parent->name + L" (unreadable)";
            break;
        }
        // PID REUSE GUARD: a recorded parent PID can name a process that
        // started AFTER its child, which then is not an ancestor at all.
        ULONGLONG parent_created = 0;
        const std::wstring path = image_path(h);
        const bool sane = creation_time(h, parent_created) &&
                          parent_created <= cur_created;
        if (!sane) {
            CloseHandle(h);
            origin.chain += L" <- " + parent->name + L" (stale pid)";
            break;
        }
        origin.chain += L" <- " + parent->name;

        if (is_known_browser(parent->name)) {
            origin.found = true;
            origin.exe_name = parent->name;
            origin.exe_path = path;
            origin.pid = parent->pid;
            origin.handle = h;   // kept open on purpose
            return origin;
        }
        CloseHandle(h);
        cur_pid = parent->pid;
        cur_created = parent_created;
    }
    // No browser in the ancestry (the shell-hop launch): fall back to the
    // one visibly open browser when that is unambiguous.
    (void)capture_unique_open_browser(all, origin);
    return origin;
}

// Is the originating browser process still running? A held handle makes
// this exact: a recycled PID can never masquerade as the captured process.
inline bool still_alive(const Origin& origin) {
    if (origin.handle == nullptr) return false;
    return WaitForSingleObject(origin.handle, 0) == WAIT_TIMEOUT;
}

inline void release(Origin& origin) {
    if (origin.handle != nullptr) {
        CloseHandle(origin.handle);
        origin.handle = nullptr;
    }
}

inline bool launch_with_url(const std::wstring& exe_path, const std::wstring& url) {
    if (exe_path.empty()) return false;
    std::wstring cmd = L"\"" + exe_path + L"\" \"" + url + L"\"";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe_path.c_str(), cmd.data(), nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &si, &pi)) {
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// The recovery hierarchy (A / B / C above). Same browser whenever we can
// name it; the Windows default only when we cannot.
inline Opened open_resume_url(const Origin& origin, const std::wstring& url) {
    if (origin.found && launch_with_url(origin.exe_path, url)) {
        // Alive: a running Chromium/Gecko instance takes the URL as a new
        // tab in itself. Gone: this starts that same browser fresh.
        return Opened::SameBrowser;
    }
    const HINSTANCE r = ShellExecuteW(nullptr, L"open", url.c_str(), nullptr,
                                      nullptr, SW_SHOWNORMAL);
    return ((INT_PTR)r > 32) ? Opened::DefaultBrowser : Opened::No;
}

} // namespace vclient::origin_browser
