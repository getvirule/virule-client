#pragma once
// CORE SERVICES' HALF OF MUTUAL RECOVERY (2026-10-06). One thread, started by
// serve() for the managed install only, that keeps VIRULE Service resident
// exactly the way the service keeps this process resident
// (src/service/main.cpp); the shared contract and timings are
// shared/residency.hpp.
//
// Decision order on every wake: uninstall (stand down for good) -> a service
// is running (wait on its process handle) -> maintenance is held (wait for
// it) -> an unexpected exit (restore delay from the backoff ladder) -> the
// executable is missing (ask the update check to repair it, then wait) ->
// start the managed ViruleService.exe and let it settle.
//
// The service never announces an intentional exit of its own: it leaves on
// purpose only on the stop event, which is set only under the maintenance
// lock (a replacement) or with the uninstall latch already written, and both
// are seen here first.

#include <atomic>
#include <string>
#include <vector>

#include "client/bridge.hpp"
#include "client/self_update.hpp"
#include "client/service_install.hpp"
#include "shared/lifecycle_intent.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"
#include "shared/residency.hpp"

namespace vclient::service_watch {

namespace rs = residency;

// A missing service executable asks the client's update check (the trusted
// distribution path) to repair it, at once and then at most once per this
// window, which is what keeps a broken network from being hammered.
constexpr unsigned long long kRepairFreshMs = 30ull * 60ull * 1000ull;

inline HANDLE g_core_wake = nullptr; // auto reset: the service is resident
inline HANDLE g_kick = nullptr;      // in-process: re-evaluate now
inline std::wstring g_seams;         // forwarded to the started service

inline void kick() {
    if (g_kick) SetEvent(g_kick);
}

inline DWORD wait_on(const std::vector<HANDLE>& extra, DWORD timeout) {
    std::vector<HANDLE> hs{ g_core_wake, g_kick };
    hs.insert(hs.end(), extra.begin(), extra.end());
    return WaitForMultipleObjects((DWORD)hs.size(), hs.data(), FALSE, timeout);
}

inline DWORD remaining(unsigned long long until) {
    const unsigned long long now = GetTickCount64();
    if (until <= now) return 0;
    const unsigned long long left = until - now;
    return left > 0x7FFFFFFFull ? 0x7FFFFFFF : (DWORD)left;
}

inline std::string secs(unsigned long long ms) {
    return std::to_string(ms / 1000) + "s";
}

// Kicks the watch only when the repair actually produced the executable, so
// a failed repair can never turn into a wake-request-fail loop.
inline void request_repair() {
    if (HANDLE t = CreateThread(nullptr, 0,
            [](LPVOID) -> DWORD {
                // Forced (0): the watch's next_repair window is the limiter.
                self_update::refresh_check(0);
                std::error_code ec;
                if (std::filesystem::exists(paths::installed_service_exe(), ec)) kick();
                return 0;
            },
            nullptr, 0, nullptr)) {
        CloseHandle(t);
    }
}

inline DWORD WINAPI watch_thread(LPVOID) {
    int failures = 0;
    unsigned long long next_attempt = 0;
    bool pending_exit = false;
    unsigned long long pending_life = 0;
    unsigned long long unseen_wait = 2000;
    unsigned long long next_repair = 0; // earliest repair request (tick)
    unsigned long long holdoff_until = 0; // post-maintenance grace (tick)
    bool said_missing = false;
    bool said_maintenance = false;

    for (;;) {
        if (bridge::g_uninstalling.load() || lifecycle::uninstall_intent_active()) {
            log::client("service watch: uninstall in progress; standing down");
            return 0;
        }

        if (rs::mutex_exists(rs::kServiceSingleton)) {
            pending_exit = false;
            said_missing = false;
            said_maintenance = false;
            std::vector<rs::Peer> peers = rs::open_peers(rs::kServiceImage);
            std::vector<HANDLE> hs;
            for (const auto& p : peers) hs.push_back(p.handle);
            DWORD timeout = INFINITE;
            if (peers.empty()) {
                timeout = (DWORD)unseen_wait;
                unseen_wait = unseen_wait * 2 > 300000 ? 300000 : unseen_wait * 2;
            } else {
                unseen_wait = 2000;
            }
            const DWORD r = wait_on(hs, timeout);
            if (r >= WAIT_OBJECT_0 + 2 && r < WAIT_OBJECT_0 + 2 + hs.size()) {
                pending_exit = true;
                pending_life = rs::lifetime_ms(hs[r - WAIT_OBJECT_0 - 2]);
            }
            rs::close_peers(peers);
            continue;
        }

        if (rs::maintenance_held()) {
            if (!said_maintenance) {
                log::client("service watch: maintenance in progress; waiting");
                said_maintenance = true;
            }
            pending_exit = false;
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

        if (GetTickCount64() < holdoff_until) {
            pending_exit = false;
            wait_on({}, remaining(holdoff_until));
            continue;
        }

        if (pending_exit) {
            failures = pending_life >= rs::kSustainMs ? 0 : failures + 1;
            const unsigned long long delay = rs::restore_delay_ms(failures);
            next_attempt = GetTickCount64() + delay;
            pending_exit = false;
            log::client("service watch: VIRULE Service exited unexpectedly after " +
                        secs(pending_life) + "; restoring in " + secs(delay) +
                        (failures > 0 ? " (consecutive short runs: " +
                                            std::to_string(failures) + ")"
                                      : ""));
        }

        const auto exe = paths::installed_service_exe();
        std::error_code ec;
        if (exe.empty() || !std::filesystem::exists(exe, ec) || ec) {
            if (!said_missing) {
                log::client("service watch: VIRULE Service is not installed; asking the update check to repair it");
                said_missing = true;
            }
            // At most one repair request per kRepairFreshMs. The repair (or
            // Setup) starts the service, which wakes us at once; otherwise
            // the next request waits out the window.
            if (GetTickCount64() >= next_repair) {
                next_repair = GetTickCount64() + kRepairFreshMs;
                request_repair();
            }
            wait_on({}, remaining(next_repair));
            continue;
        }
        if (GetTickCount64() < next_attempt) {
            wait_on({}, remaining(next_attempt));
            continue;
        }
        if (GetSystemMetrics(SM_SHUTTINGDOWN)) {
            wait_on({}, 30000);
            continue;
        }

        HANDLE h = rs::launch_managed(exe, L"", g_seams);
        if (h == nullptr) {
            failures += 1;
            const unsigned long long delay = rs::restore_delay_ms(failures);
            next_attempt = GetTickCount64() + delay;
            log::client("service watch: VIRULE Service could not be started (error " +
                        std::to_string(GetLastError()) + "); next attempt in " + secs(delay));
            continue;
        }
        log::client("service watch: VIRULE Service started (pid " +
                    std::to_string(GetProcessId(h)) + ")");
        const DWORD r = wait_on({ h }, (DWORD)rs::kStartSettleMs);
        if (r == WAIT_OBJECT_0 + 2 && !rs::mutex_exists(rs::kServiceSingleton)) {
            pending_exit = true;
            pending_life = rs::lifetime_ms(h);
        }
        CloseHandle(h);
        next_attempt = 0;
    }
}

// Start the watch (managed installs only; main.cpp decides). Idempotent.
inline void start(const std::wstring& seams) {
    static std::atomic<bool> started{ false };
    if (started.exchange(true)) return;
    g_seams = seams;
    g_core_wake = CreateEventW(nullptr, FALSE, FALSE, rs::kCoreWakeEvent);
    g_kick = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_core_wake || !g_kick) {
        log::client("service watch: could not create its events; residency watch disabled");
        return;
    }
    if (HANDLE t = CreateThread(nullptr, 0, watch_thread, nullptr, 0, nullptr)) {
        CloseHandle(t);
    }
}

} // namespace vclient::service_watch
