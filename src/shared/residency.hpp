#pragma once
// CORE SERVICES RESIDENCY (owner decision 2026-10-06).
//
// An installed VIRULE normally runs exactly two resident processes in the
// user's session, and they protect one another:
//
//   virule-client.exe   "VIRULE Core Services"   the machine coordinator
//   ViruleService.exe   "VIRULE Service"         the residency companion
//
// The service exists to close one hole: Core Services ended while the Admin
// is not running (End task, a clean kill) used to stay gone until the next
// login. The service waits on the Core Services process handle and restores
// it when it exits unexpectedly; Core Services waits on the service the same
// way and restores it. Neither is a Windows SCM service, neither is
// elevated, neither has a window: both are ordinary per-user processes.
//
// THIS HEADER IS THE WHOLE CONTRACT BETWEEN THEM, shared by the client, the
// service and Setup. Everything here is a Windows kernel object whose
// lifetime follows the process that holds it, so a crash can never strand a
// "maintenance" or "intentional exit" state on disk:
//
//   Local\ViruleClient.Singleton        mutex   Core Services single instance
//                                               (the existing name, unchanged)
//   Local\VIRULE.Service.Singleton      mutex   VIRULE Service single instance
//   Local\VIRULE.Residency.Maintenance  mutex   HELD by whoever is replacing or
//                                               updating a resident binary
//                                               (Setup, the client self-update
//                                               helper, the client's service
//                                               update). While it is held
//                                               neither peer restores the
//                                               other; released (or abandoned
//                                               by a crashed holder) residency
//                                               resumes.
//   Local\VIRULE.Service.Stop           event   manual reset, created by the
//                                               service: "exit now". Set by a
//                                               maintenance holder or by an
//                                               uninstall (with the latch set).
//   Local\VIRULE.Service.Wake           event   auto reset, created by the
//                                               service: Core Services sets
//                                               it once it is serving, so the
//                                               service binds at once.
//   Local\VIRULE.CoreServices.Wake      event   auto reset, created by Core
//                                               Services: the service sets it
//                                               once it is resident.
//   Local\VIRULE.CoreServices.ExitIntent event  manual reset, created by the
//                                               service: Core Services sets it
//                                               right before an INTENTIONAL
//                                               exit (Setup's shutdown, the
//                                               self-update swap), so the
//                                               service holds off instead of
//                                               fighting the replacement.
//
// WHAT COUNTS AS INTENTIONAL, in the order a watcher decides it:
//   1. the durable uninstall latch (lifecycle_intent.hpp): stand down
//      entirely; the service exits;
//   2. the maintenance mutex is held: wait for it, then give the
//      maintainer's own restart kPostMaintenanceGraceMs before re-evaluating;
//   3. Core Services announced its exit (ExitIntent): hold off
//      kIntentHoldoffMs for the replacement to appear, then re-evaluate;
//   4. anything else is unexpected: restore, with the bounded backoff below.
//
// A RACE MAY START A PROCESS, NEVER LEAVE TWO: every launch goes through the
// target's own singleton, so a duplicate start exits at once (Core Services
// forwards a wake to the running instance; a second service just leaves).
//
// IDLE COST IS ZERO: watchers block in WaitForMultipleObjects on the peer's
// process handle plus the events above. Nothing polls; a timed wait exists
// only while a backoff or hold-off window is actually running.
//
// ONLY THE MANAGED BINARIES ARE EVER LAUNCHED: the exact executable under
// %LOCALAPPDATA%\Programs\VIRULE (paths.hpp), no path, executable or command
// line is accepted from anywhere. The only arguments passed on are the
// client's own fixed development seams (forward_seams below).

#include <filesystem>
#include <string>
#include <vector>

#include "shared/lifecycle_intent.hpp"
#include "shared/paths.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace vclient::residency {

inline constexpr const wchar_t* kClientSingleton   = L"Local\\ViruleClient.Singleton";
inline constexpr const wchar_t* kServiceSingleton  = L"Local\\VIRULE.Service.Singleton";
inline constexpr const wchar_t* kMaintenanceMutex  = L"Local\\VIRULE.Residency.Maintenance";
inline constexpr const wchar_t* kServiceStopEvent  = L"Local\\VIRULE.Service.Stop";
inline constexpr const wchar_t* kServiceWakeEvent  = L"Local\\VIRULE.Service.Wake";
inline constexpr const wchar_t* kCoreWakeEvent     = L"Local\\VIRULE.CoreServices.Wake";
inline constexpr const wchar_t* kCoreExitIntent    = L"Local\\VIRULE.CoreServices.ExitIntent";

inline constexpr const wchar_t* kClientImage  = L"virule-client.exe";
inline constexpr const wchar_t* kServiceImage = L"ViruleService.exe";

// ---- timings (documented in docs/ARCHITECTURE.md, "Core Services residency")

// A peer that ran at least this long was healthy: its exit resets the
// failure ladder. The same 60 s Windows Error Reporting uses before it will
// restart a crashed client.
inline constexpr unsigned long long kSustainMs = 60000;

// The first restore after a healthy peer exits unexpectedly. Long enough for
// the departed process's singleton to be released, short enough that the
// browser's bridge reconnects without anyone noticing.
inline constexpr unsigned long long kRestoreDelayMs = 1000;

// Consecutive short-lived exits climb this ladder, then stay at its cap:
// at most two launches an hour, forever, with no process storm and no log
// flood. One sustained run resets it.
inline constexpr unsigned long long kBackoffLadderMs[] = {
    5000ull,                 // 1st short-lived exit
    30000ull,                // 2nd
    2ull * 60ull * 1000ull,  // 3rd
    10ull * 60ull * 1000ull, // 4th
    30ull * 60ull * 1000ull, // 5th and every one after (the cap)
};

// How long a watcher holds off after Core Services announced an intentional
// exit (Setup replacing it, the self-update swap). The replacement normally
// appears in a few seconds and wakes the service itself; this bound only
// matters when the replacement never comes, and then residency resumes.
inline constexpr unsigned long long kIntentHoldoffMs = 60000;

// How long a watcher gives a process it just started to come up before it
// stops treating it as "starting".
inline constexpr unsigned long long kStartSettleMs = 15000;

// After maintenance ends, the maintainer has normally just started the
// replacement itself (Setup starts the new client, the self-update helper
// the new or known-good one, a service update the new service). The watcher
// gives that start this long to announce itself (it wakes the watcher the
// moment it serves) before it starts one of its own.
inline constexpr unsigned long long kPostMaintenanceGraceMs = 10000;

inline unsigned long long restore_delay_ms(int consecutive_failures) {
    if (consecutive_failures <= 0) return kRestoreDelayMs;
    const int n = (int)(sizeof(kBackoffLadderMs) / sizeof(kBackoffLadderMs[0]));
    const int i = consecutive_failures - 1 < n ? consecutive_failures - 1 : n - 1;
    return kBackoffLadderMs[i];
}

// ---- kernel-object primitives ----

// Does a named mutex exist (some process holds a handle to it)? For a
// singleton this is "an instance is running": the holder keeps its handle for
// its whole life. Never keeps a handle: a watcher holding the client's
// singleton open would make every new client believe another one runs.
inline bool mutex_exists(const wchar_t* name) {
    HANDLE h = OpenMutexW(SYNCHRONIZE, FALSE, name);
    if (h == nullptr) return false;
    CloseHandle(h);
    return true;
}

// Is the maintenance mutex HELD right now? Existence is not enough (a holder
// may keep its handle open after releasing), so this takes it for an instant:
// immediately available = not held.
inline bool maintenance_held() {
    HANDLE h = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, kMaintenanceMutex);
    if (h == nullptr) return false;
    const DWORD r = WaitForSingleObject(h, 0);
    const bool held = (r == WAIT_TIMEOUT);
    if (r == WAIT_OBJECT_0 || r == WAIT_ABANDONED) ReleaseMutex(h);
    CloseHandle(h);
    return held;
}

// A handle a watcher can WAIT on for the end of maintenance (nullptr when no
// maintenance object exists). Whoever's wait is satisfied by it owns the
// mutex at that moment and must release it at once (release_after_wait).
inline HANDLE open_maintenance_for_wait() {
    return OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, kMaintenanceMutex);
}

inline void release_after_wait(HANDLE maintenance) {
    if (maintenance) ReleaseMutex(maintenance);
}

// Held for the lifetime of the object; released (or abandoned with the
// process) when it goes away. Maintainers serialize on it: two replacements
// can never interleave.
class MaintenanceLock {
public:
    MaintenanceLock() = default;
    MaintenanceLock(const MaintenanceLock&) = delete;
    MaintenanceLock& operator=(const MaintenanceLock&) = delete;
    ~MaintenanceLock() { release(); }

    bool acquire(unsigned long wait_ms) {
        if (held_) return true;
        if (!handle_) handle_ = CreateMutexW(nullptr, FALSE, kMaintenanceMutex);
        if (!handle_) return false;
        const DWORD r = WaitForSingleObject(handle_, wait_ms);
        held_ = (r == WAIT_OBJECT_0 || r == WAIT_ABANDONED);
        return held_;
    }
    void release() {
        if (held_ && handle_) ReleaseMutex(handle_);
        held_ = false;
        if (handle_) CloseHandle(handle_);
        handle_ = nullptr;
    }
    bool held() const { return held_; }

private:
    HANDLE handle_ = nullptr;
    bool held_ = false;
};

// Set a named event if it exists (nobody listening = nothing to tell).
inline bool signal_event(const wchar_t* name) {
    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (h == nullptr) return false;
    const bool ok = SetEvent(h) != 0;
    CloseHandle(h);
    return ok;
}

// "Exit now" for the running service. Used by maintenance holders and by
// every uninstall entry point (the uninstall helper must find the install
// directory free of processes).
inline bool request_service_stop() { return signal_event(kServiceStopEvent); }

// Core Services: "this exit is intentional, do not fight it".
inline bool announce_client_exit_intent() { return signal_event(kCoreExitIntent); }

// ---- process discovery (only at a re-evaluation, never in a loop) ----

struct Peer {
    HANDLE handle = nullptr;
    DWORD pid = 0;
};

inline void close_peers(std::vector<Peer>& peers) {
    for (auto& p : peers) {
        if (p.handle) CloseHandle(p.handle);
    }
    peers.clear();
}

// Every process in THIS session whose image file name is `image` (other than
// this process), opened for waiting. Name only on purpose: waiting is
// harmless, and a peer started from another directory still holds the same
// singleton. LAUNCHING is the step that is path-pinned (launch_managed).
inline std::vector<Peer> open_peers(const wchar_t* image) {
    std::vector<Peer> out;
    DWORD my_session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &my_session);
    const DWORD self = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ProcessID == self) continue;
            if (_wcsicmp(entry.szExeFile, image) != 0) continue;
            DWORD session = 0;
            if (!ProcessIdToSessionId(entry.th32ProcessID, &session) ||
                session != my_session) {
                continue;
            }
            HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, entry.th32ProcessID);
            if (h == nullptr) continue;
            if (out.size() >= MAXIMUM_WAIT_OBJECTS - 8) { CloseHandle(h); break; }
            out.push_back(Peer{ h, entry.th32ProcessID });
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return out;
}

// How long an exited process lived, from its own creation/exit times.
inline unsigned long long lifetime_ms(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
    ULARGE_INTEGER c, e;
    c.LowPart = created.dwLowDateTime; c.HighPart = created.dwHighDateTime;
    e.LowPart = exited.dwLowDateTime;  e.HighPart = exited.dwHighDateTime;
    if (e.QuadPart <= c.QuadPart) return 0;
    return (e.QuadPart - c.QuadPart) / 10000ull;
}

// ---- the managed executables (paths.hpp is the only source) ----

inline std::wstring lower(std::wstring s) {
    for (wchar_t& c : s) c = (wchar_t)towlower(c);
    return s;
}

inline std::wstring self_path() {
    wchar_t buf[MAX_PATH * 2] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0])) return L"";
    return std::wstring(buf, n);
}

// Is this process running AS the managed executable `managed`?
inline bool running_as(const std::filesystem::path& managed) {
    if (managed.empty()) return false;
    const std::wstring self = self_path();
    return !self.empty() && lower(self) == lower(managed.wstring());
}

// THE CLIENT'S DEVELOPMENT SEAMS, and nothing else, may ride a residency
// launch, so a sandboxed test world keeps its posture when one peer restores
// the other. Manifest overrides are forwarded only when they point at the
// loopback interface (the only place the seams are ever used); anything else
// is dropped. Production runs carry none of these.
inline bool is_loopback_url(const std::wstring& url) {
    for (const wchar_t* p : { L"http://127.0.0.1:", L"http://localhost:",
                              L"https://127.0.0.1:", L"https://localhost:" }) {
        if (url.rfind(p, 0) == 0) {
            // no whitespace or quotes: the value becomes one argv element
            for (const wchar_t c : url) {
                if (c == L' ' || c == L'"' || c == L'\t') return false;
            }
            return true;
        }
    }
    return false;
}

inline std::wstring forward_seams(int argc, wchar_t** argv) {
    std::wstring out;
    for (int i = 1; i < argc; ++i) {
        const std::wstring a = argv[i];
        if (a == L"--no-register" || a == L"--dev-unsigned") {
            out += L" " + a;
        } else if (a.rfind(L"--self-manifest-url=", 0) == 0 &&
                   is_loopback_url(a.substr(20))) {
            out += L" " + a;
        } else if (a.rfind(L"--admin-manifest-url=", 0) == 0 &&
                   is_loopback_url(a.substr(21))) {
            out += L" " + a;
        }
    }
    return out;
}

// Start the managed executable `exe` (and only if it is one of the two
// managed residency binaries) with the fixed marker and the forwarded seams.
// Explicit working directory: the install dir (the 2026-09-04 CWD lesson).
// Returns the process handle (caller closes) or nullptr.
inline HANDLE launch_managed(const std::filesystem::path& exe,
                             const wchar_t* marker,
                             const std::wstring& seams) {
    const auto client = paths::installed_client_exe();
    const auto service = paths::installed_service_exe();
    const std::wstring want = lower(exe.wstring());
    if (exe.empty() ||
        (want != lower(client.wstring()) && want != lower(service.wstring()))) {
        return nullptr;
    }
    std::error_code ec;
    if (!std::filesystem::exists(exe, ec) || ec) return nullptr;
    std::wstring cmd = L"\"" + exe.wstring() + L"\"";
    if (marker && *marker) cmd += std::wstring(L" ") + marker;
    cmd += seams;
    const std::wstring dir = paths::install_dir().wstring();
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.wstring().c_str(), cmd.data(), nullptr, nullptr,
                        FALSE, 0, nullptr, dir.empty() ? nullptr : dir.c_str(),
                        &si, &pi)) {
        return nullptr;
    }
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

// Ask the running service to exit and wait (bounded) until no service
// process is left in the session. True = none running. The caller holds the
// maintenance lock (or the uninstall latch is set), so nothing restores it.
inline bool stop_service_and_wait(unsigned long wait_ms) {
    std::vector<Peer> peers = open_peers(kServiceImage);
    if (peers.empty() && !mutex_exists(kServiceSingleton)) return true;
    request_service_stop();
    const ULONGLONG deadline = GetTickCount64() + wait_ms;
    for (auto& p : peers) {
        const ULONGLONG now = GetTickCount64();
        const DWORD left = now >= deadline ? 0 : (DWORD)(deadline - now);
        WaitForSingleObject(p.handle, left);
    }
    close_peers(peers);
    // A service that was mid-start when we looked may hold the singleton
    // without having been enumerated; give it the rest of the bound.
    while (mutex_exists(kServiceSingleton) && GetTickCount64() < deadline) {
        Sleep(100);
    }
    return !mutex_exists(kServiceSingleton);
}

} // namespace vclient::residency
