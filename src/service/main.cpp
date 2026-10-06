// ViruleService.exe - "VIRULE Service", the Core Services residency companion.
//
// ONE JOB: keep the managed VIRULE Core Services (virule-client.exe) resident.
// It waits on the Core Services process handle and, when that process exits
// unexpectedly, starts the managed executable again. Core Services watches
// this process the same way (client/main.cpp), so the two protect one
// another. The whole contract, every named object and every timing, is
// shared/residency.hpp; the decision order is documented there and in
// docs/ARCHITECTURE.md ("Core Services residency").
//
// WHAT IT IS NOT: not a Windows SCM service (the product name is a name), not
// elevated, not a launcher, not an IPC surface. No window, no tray, no
// network, no telemetry, no CEF. It accepts no path, executable or command
// line from anywhere: the only process it ever starts is
// %LOCALAPPDATA%\Programs\VIRULE\virule-client.exe, and the only arguments it
// passes on are the client's own fixed development seams it was started with.
//
// IDLE IS A BLOCKED WAIT: WaitForMultipleObjects on {stop, wake, Core
// Services}. A timed wait exists only while a backoff or hold-off window is
// actually running.
//
// It runs only AS the managed install (a copy started from anywhere else
// exits at once), never while the uninstall latch is set, and one per session
// (Local\VIRULE.Service.Singleton; a duplicate leaves without doing anything).

#include <string>
#include <vector>

#include "shared/lifecycle_intent.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"
#include "shared/residency.hpp"
#include "shared/version.h"
#include "virule/core/launch_policy.hpp" // the environment, for the log line

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

namespace {

namespace rs = vclient::residency;

HANDLE g_stop = nullptr;   // manual reset: exit now
HANDLE g_wake = nullptr;   // auto reset: Core Services is serving, bind now
HANDLE g_intent = nullptr; // manual reset: Core Services is leaving on purpose
std::wstring g_seams;      // the client's dev seams, forwarded on restore

void log(const std::string& line) { vclient::log::service(line); }

std::string secs(unsigned long long ms) {
    return std::to_string(ms / 1000) + "s";
}

// Wait on stop + wake (+ extras) for at most `timeout`. Returns the
// WaitForMultipleObjects result.
DWORD wait_on(std::vector<HANDLE> extra, DWORD timeout) {
    std::vector<HANDLE> hs{ g_stop, g_wake };
    hs.insert(hs.end(), extra.begin(), extra.end());
    return WaitForMultipleObjects((DWORD)hs.size(), hs.data(), FALSE, timeout);
}

DWORD remaining(unsigned long long until) {
    const unsigned long long now = GetTickCount64();
    if (until <= now) return 0;
    const unsigned long long left = until - now;
    return left > 0x7FFFFFFFull ? 0x7FFFFFFF : (DWORD)left;
}

int run() {
    int failures = 0;                     // consecutive short-lived exits
    unsigned long long next_attempt = 0;  // earliest restore (tick)
    unsigned long long holdoff_until = 0; // intentional-exit hold-off (tick)
    bool pending_exit = false;            // an unexpected exit awaiting a verdict
    unsigned long long pending_life = 0;
    unsigned long long unseen_wait = 2000;
    bool said_missing = false;
    bool said_maintenance = false;

    for (;;) {
        // 1. EXPLICIT UNINSTALL WINS, and an explicit stop is obeyed.
        if (vclient::lifecycle::uninstall_intent_active()) {
            log("uninstall in progress; VIRULE Service is standing down");
            return 0;
        }
        if (WaitForSingleObject(g_stop, 0) == WAIT_OBJECT_0) {
            log("stop requested; VIRULE Service is exiting");
            return 0;
        }

        // 2. Core Services is there: wait on it.
        if (rs::mutex_exists(rs::kClientSingleton)) {
            pending_exit = false; // whatever left was replaced
            said_missing = false;
            said_maintenance = false;
            std::vector<rs::Peer> peers = rs::open_peers(rs::kClientImage);
            std::vector<HANDLE> hs;
            for (const auto& p : peers) hs.push_back(p.handle);
            // The singleton's holder not yet enumerable (mid-start) is the
            // only timed case here, and it backs off quickly.
            DWORD timeout = INFINITE;
            if (peers.empty()) {
                timeout = (DWORD)unseen_wait;
                unseen_wait = unseen_wait * 2 > 300000 ? 300000 : unseen_wait * 2;
            } else {
                unseen_wait = 2000;
            }
            const DWORD r = wait_on(hs, timeout);
            if (r >= WAIT_OBJECT_0 + 2 && r < WAIT_OBJECT_0 + 2 + hs.size()) {
                HANDLE gone = hs[r - WAIT_OBJECT_0 - 2];
                const unsigned long long life = rs::lifetime_ms(gone);
                if (WaitForSingleObject(g_intent, 0) == WAIT_OBJECT_0) {
                    ResetEvent(g_intent);
                    holdoff_until = GetTickCount64() + rs::kIntentHoldoffMs;
                    log("Core Services exited intentionally; holding off up to " +
                        secs(rs::kIntentHoldoffMs) + " for its replacement");
                } else {
                    pending_exit = true;
                    pending_life = life;
                }
            }
            rs::close_peers(peers);
            continue;
        }

        // 3. No Core Services. Maintenance (Setup, the self-update swap, a
        // service update) owns the gap: wait for it to end.
        if (rs::maintenance_held()) {
            if (!said_maintenance) {
                log("maintenance in progress; waiting for it to finish");
                said_maintenance = true;
            }
            pending_exit = false; // the departure belonged to the maintenance
            if (HANDLE m = rs::open_maintenance_for_wait()) {
                const DWORD r = wait_on({ m }, INFINITE);
                if (r == WAIT_OBJECT_0 + 2 || r == WAIT_ABANDONED_0 + 2) {
                    rs::release_after_wait(m);
                    // The maintainer normally starts the replacement itself:
                    // let it announce itself before starting one of ours.
                    holdoff_until = GetTickCount64() + rs::kPostMaintenanceGraceMs;
                }
                CloseHandle(m);
            }
            continue;
        }
        said_maintenance = false;

        // 4. An announced intentional exit: give the replacement its window.
        if (GetTickCount64() < holdoff_until) {
            pending_exit = false;
            wait_on({}, remaining(holdoff_until));
            continue;
        }

        // 5. An unexpected exit: decide the restore delay once.
        if (pending_exit) {
            failures = pending_life >= rs::kSustainMs ? 0 : failures + 1;
            const unsigned long long delay = rs::restore_delay_ms(failures);
            next_attempt = GetTickCount64() + delay;
            pending_exit = false;
            log("Core Services exited unexpectedly after " + secs(pending_life) +
                "; restoring in " + secs(delay) +
                (failures > 0 ? " (consecutive short runs: " +
                                    std::to_string(failures) + ")"
                              : ""));
        }

        const auto client = vclient::paths::installed_client_exe();
        std::error_code ec;
        if (client.empty() || !std::filesystem::exists(client, ec) || ec) {
            // Nothing to restore (Setup will place it and its start wakes us).
            if (!said_missing) {
                log("Core Services executable is not installed; waiting");
                said_missing = true;
            }
            wait_on({}, INFINITE);
            continue;
        }
        if (GetTickCount64() < next_attempt) {
            wait_on({}, remaining(next_attempt));
            continue;
        }
        // The session is ending: everything is about to be closed, and a
        // process started now would only be killed with it.
        if (GetSystemMetrics(SM_SHUTTINGDOWN)) {
            wait_on({}, 30000);
            continue;
        }

        HANDLE h = rs::launch_managed(client, L"--restored", g_seams);
        if (h == nullptr) {
            failures += 1;
            const unsigned long long delay = rs::restore_delay_ms(failures);
            next_attempt = GetTickCount64() + delay;
            log("Core Services could not be started (error " +
                std::to_string(GetLastError()) + "); next attempt in " + secs(delay));
            continue;
        }
        log("Core Services restored (pid " + std::to_string(GetProcessId(h)) + ")");
        // Settle: it serves (and wakes us), it exits, or the bound passes.
        const DWORD r = wait_on({ h }, (DWORD)rs::kStartSettleMs);
        if (r == WAIT_OBJECT_0 + 2 && !rs::mutex_exists(rs::kClientSingleton)) {
            // Died on the way up (a duplicate that lost the singleton race
            // leaves a running instance behind and is no failure).
            pending_exit = true;
            pending_life = rs::lifetime_ms(h);
        }
        CloseHandle(h);
        next_attempt = 0;
    }
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    // Own the working directory: never hold a handle on a directory someone
    // else may rename (the client's 2026-09-04 lesson, kept here too).
    {
        const std::wstring self = rs::self_path();
        const size_t slash = self.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            SetCurrentDirectoryW(self.substr(0, slash).c_str());
        }
    }

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        g_seams = rs::forward_seams(argc, argv);
        LocalFree(argv);
    }

    // Only the managed install keeps anything resident. A copy run from a
    // build tree or anywhere else has nothing to watch.
    if (!rs::running_as(vclient::paths::installed_service_exe())) return 0;
    if (vclient::lifecycle::uninstall_intent_active()) return 0;

    HANDLE singleton = CreateMutexW(nullptr, TRUE, rs::kServiceSingleton);
    if (singleton == nullptr || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (singleton) CloseHandle(singleton);
        return 0; // one VIRULE Service per session; this one leaves quietly
    }

    g_stop = CreateEventW(nullptr, TRUE, FALSE, rs::kServiceStopEvent);
    g_wake = CreateEventW(nullptr, FALSE, FALSE, rs::kServiceWakeEvent);
    g_intent = CreateEventW(nullptr, TRUE, FALSE, rs::kCoreExitIntent);
    if (!g_stop || !g_wake || !g_intent) {
        log("could not create the residency events; exiting");
        ReleaseMutex(singleton);
        CloseHandle(singleton);
        return 1;
    }
    // Anything signaled before this instance existed is not addressed to it.
    ResetEvent(g_stop);
    ResetEvent(g_wake);
    ResetEvent(g_intent);

    // The environment's service host in the start line is diagnostic, and it
    // is also what lets publish_staging_client.ps1 prove from the bytes that
    // a staging service is a staging build (the client's structural guard).
    log(std::string("VIRULE Service ") + VIRULE_CLIENT_VERSION_STRING +
        " resident (" + virule::core::launch_policy::kEmbargoApiHost + ")");
    // Tell a running Core Services we are here (it binds its watch at once).
    rs::signal_event(rs::kCoreWakeEvent);

    const int code = run();

    CloseHandle(g_intent);
    CloseHandle(g_wake);
    CloseHandle(g_stop);
    ReleaseMutex(singleton);
    CloseHandle(singleton);
    return code;
}
