#pragma once
// THE LAUNCHER (2026-10-22; docs/ARCHITECTURE.md "The launcher"; v2_mvp
// docs/EVALUATION_VIRULE.md section 9). The VIRULE Client is the ONE local
// authority over whether an installed game is RUNNING, and the one place a
// launch is started. The Admin presents what this says; it never keeps a
// running flag of its own.
//
// WHAT "RUNNING" IS. An assignment's game is running while ANY of these
// holds, each read from the system, never remembered:
//   - a process this Client started for it (the wrapper) is alive (its
//     handle, waited on: an exit is seen the moment it happens);
//   - a process whose image lives inside the assignment's own game folder
//     is alive (the wrapper started some other way, the game it started,
//     or either of them after this Client restarted: ADOPTED by a scan of
//     the process list, then waited on like the first);
//   - the wrapper's presence mutex exists (evaluation_evidence.hpp
//     running_mutex_name: held from its first look at the assignment
//     through its post-session panel, released by the system with the
//     process, so a crash never leaves it held);
//   - a launch of it is being started right now (the latch below).
// So the pre-game panel, the game and the post-game panel all read running,
// and running ends exactly when the last of them is gone. Nothing here is
// a timer standing in for a lifecycle; the periodic scan only DISCOVERS
// processes this Client did not start.
//
// ONE LAUNCH AT A TIME PER ASSIGNMENT. `launch` refuses while the
// assignment is running or a launch of it is already being started, while
// its install job is anything but installed (an update, a removal), and
// when the revision on disk is not the one the service requires. The
// transfer driver asks `busy` before it replaces or removes a game folder,
// so an update never touches a game whose wrapper, panels or process are
// up. Every transition (started, exited, adopted) bumps the change counter
// the Admin reads (evaluation_changes), so the Admin learns it locally.

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "client/assignment_cleanup.hpp"
#include "shared/json_scan.hpp"
#include "virule/core/evaluation_distribution.hpp"
#include "virule/core/evaluation_evidence.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>

namespace vclient::launcher {

namespace ed = virule::core::evaluation_distribution;
namespace ev = virule::core::evaluation_evidence;
namespace js = vclient::json_scan;
namespace fs = std::filesystem;

// The working sentences of a refused launch (the Admin's controls' note).
inline constexpr const char* kNotInstalled = "This game isn't installed yet.";
inline constexpr const char* kUpdating = "This game is being updated.";
inline constexpr const char* kUpdateRequired = "Update the game first.";
inline constexpr const char* kMissing = "The installed game is missing. Install it again.";
inline constexpr const char* kAlreadyRunning = "This game is already running.";
inline constexpr const char* kNotStarted = "The game could not be started.";
// The assignment truly expired (client/assignment_cleanup.hpp).
inline constexpr const char* kExpired = "This assignment has expired.";

// How often processes this Client did not start are looked for.
inline constexpr DWORD kDiscoverMs = 5000;

struct Config {
    fs::path root;                                            // %LOCALAPPDATA%\VIRULE (or a sandbox)
    std::function<void()> on_change;                          // the change counter
    // The service's progress for the assignment, fetched and kept (bounded;
    // false = not reached). Called before every launch so the wrapper's
    // panel states the assignment's whole progress (a fresh installation).
    std::function<bool(const std::string&)> refresh_progress;
    std::function<void(const std::string&)> log;
    HANDLE stop_event = nullptr;
    // THE GAME'S LAST PROCESS EXITED (2026-10-22): an assignment left the
    // running set (wrapper, game and panels all gone). main.cpp: the session
    // recovery check (client/evaluation_recovery.hpp). Called on the monitor
    // thread; must not block.
    std::function<void(const std::string& assignment_id)> on_stopped;
};

namespace detail {

inline std::wstring lower(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(std::towlower(c));
    return s;
}

// The folder as a comparable prefix: absolute, lower case, one trailing
// separator, so "<installs>\\abc" never matches "<installs>\\abcd".
inline std::wstring folder_key(const std::string& utf8_dir) {
    if (utf8_dir.empty()) return {};
    std::error_code ec;
    fs::path p = fs::absolute(fs::path(std::u8string(utf8_dir.begin(), utf8_dir.end())), ec);
    if (ec) return {};
    std::wstring w = lower(p.lexically_normal().wstring());
    while (!w.empty() && (w.back() == L'\\' || w.back() == L'/')) w.pop_back();
    if (w.size() < 4) return {};   // never a drive root
    return w + L"\\";
}

inline std::wstring image_of(HANDLE h) {
    wchar_t buf[32768];
    DWORD n = static_cast<DWORD>(std::size(buf));
    if (!QueryFullProcessImageNameW(h, 0, buf, &n)) return {};
    return lower(std::wstring(buf, n));
}

inline bool alive(HANDLE h) { return h && WaitForSingleObject(h, 0) == WAIT_TIMEOUT; }

} // namespace detail

class Launcher {
public:
    explicit Launcher(Config cfg) : cfg_(std::move(cfg)) {
        wake_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }
    ~Launcher() {
        std::lock_guard<std::mutex> lock(m_);
        for (auto& t : tracked_) if (t.process) CloseHandle(t.process);
        tracked_.clear();
        if (wake_) CloseHandle(wake_);
    }
    Launcher(const Launcher&) = delete;
    Launcher& operator=(const Launcher&) = delete;

    // Is the assignment's game up in any form (see the header)? The
    // transfer driver's check before it touches a game folder.
    bool busy(const std::string& assignment_id) {
        if (!ev::is_hex32(assignment_id)) return false;
        std::lock_guard<std::mutex> lock(m_);
        return busy_locked(assignment_id);
    }

    // The same, after a fresh scan of the process list (2026-10-22): the
    // session recovery asks it before starting anything from a game
    // folder, so a game started some other way and not adopted yet counts.
    bool busy_scanned(const std::string& assignment_id) {
        if (!ev::is_hex32(assignment_id)) return false;
        std::lock_guard<std::mutex> lock(m_);
        adopt_locked();
        return busy_locked(assignment_id);
    }

    // The bridge's game_launch: {"assignment_id", "required_revision_id"?}.
    std::string launch(const std::string& payload) {
        std::string assignment, required;
        (void)js::find_string_in(payload, 0, payload.size(), "assignment_id", assignment);
        (void)js::find_string_in(payload, 0, payload.size(), "required_revision_id", required);
        if (!ev::is_hex32(assignment)) return "{\"type\":\"error\"}";
        ed::Job job;
        std::string code, why;
        std::string result;
        bool started = false;
        {
            std::lock_guard<std::mutex> lock(m_);
            adopt_locked();
            if (!launchable(assignment, required, job, code, why)) return refusal(code, why);
            if (busy_locked(assignment)) return refusal("running", kAlreadyRunning);
            // The latch covers the start itself (a busy() asked meanwhile reads running).
            launching_.insert(assignment);
            const fs::path dir = path_of(job.install_dir);
            const fs::path exe = dir / path_of(job.launch_exe);
            STARTUPINFOW si{};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            std::wstring cmd = L"\"" + exe.wstring() + L"\"";
            if (!CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, dir.c_str(), &si, &pi)) {
                say("launch: CreateProcess failed (" + std::to_string(GetLastError()) + ") for " + assignment);
                result = refusal("failed", kNotStarted);
            } else {
                CloseHandle(pi.hThread);
                // The Admin the person just clicked handed on Windows' permission
                // to come to the front (host AllowSetForegroundWindow); pass it to
                // the wrapper so its panel opens in front, never behind.
                (void)AllowSetForegroundWindow(pi.dwProcessId);
                tracked_.push_back(Tracked{ pi.hProcess, pi.dwProcessId, assignment, true });
                say("launch: started the wrapper of " + assignment + " (pid " + std::to_string(pi.dwProcessId) + ")");
                result = "{\"type\":\"game_launch\",\"ok\":true,\"pid\":" + std::to_string(pi.dwProcessId) + "}";
                started = true;
            }
            launching_.erase(assignment);
        }
        // The assignment's whole progress, for the wrapper's panel: best
        // effort, beside the start and never delaying it (the panel reads it
        // only after its online check; the document is normally current
        // already, kept from every service answer).
        if (started && cfg_.refresh_progress) {
            auto refresh = cfg_.refresh_progress;
            auto log = cfg_.log;
            try {
                std::thread([refresh, log, assignment]() {
                    bool ok = false;
                    try { ok = refresh(assignment); } catch (...) { ok = false; }   // never takes the Client down
                    if (!ok && log) log("launch: the service's progress was not refreshed for " + assignment);
                }).detach();
            } catch (...) { /* no thread: the document stays as the last answer left it */ }
        }
        if (wake_) SetEvent(wake_);
        changed();
        return result;
    }

    // AN EXPIRED ASSIGNMENT'S GAME IS CLOSED (owner brief 2026-10-28;
    // client/assignment_cleanup.hpp): every process of the assignment this
    // Client started or found in its game folder is terminated, and the
    // exits are waited for (up to five seconds). True when none is left.
    bool terminate(const std::string& assignment_id) {
        if (!ev::is_hex32(assignment_id)) return true;
        std::vector<HANDLE> waits;
        {
            std::lock_guard<std::mutex> lock(m_);
            adopt_locked();
            for (const auto& t : tracked_) {
                if (t.assignment != assignment_id || !detail::alive(t.process)) continue;
                HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, t.pid);
                if (!h) { say("launcher: pid " + std::to_string(t.pid) + " of " + assignment_id + " could not be opened to close it"); continue; }
                if (TerminateProcess(h, 1)) say("launcher: closed pid " + std::to_string(t.pid) + " of expired " + assignment_id);
                waits.push_back(h);
            }
        }
        for (HANDLE h : waits) {
            (void)WaitForSingleObject(h, 5000);
            CloseHandle(h);
        }
        reap();
        if (wake_) SetEvent(wake_);
        std::lock_guard<std::mutex> lock(m_);
        adopt_locked();
        return !busy_locked(assignment_id);
    }

    // The bridge's launcher_state: every assignment this computer has an
    // install job for, and whether its game is running.
    std::string state_json() {
        std::vector<std::string> ids;
        for (const auto& j : ed::list_jobs(cfg_.root)) {
            if (ed::is_install(j) && ev::is_hex32(j.assignment_id) &&
                std::find(ids.begin(), ids.end(), j.assignment_id) == ids.end()) ids.push_back(j.assignment_id);
        }
        std::string out = "{\"type\":\"launcher_state\",\"assignments\":[";
        std::lock_guard<std::mutex> lock(m_);
        for (const auto& t : tracked_) {
            if (std::find(ids.begin(), ids.end(), t.assignment) == ids.end()) ids.push_back(t.assignment);
        }
        bool first = true;
        for (const auto& id : ids) {
            if (!first) out += ",";
            first = false;
            const bool launching = launching_.count(id) > 0;
            out += "{\"assignment_id\":\"" + id + "\",\"running\":" + (busy_locked(id) ? "true" : "false") +
                   ",\"launching\":" + (launching ? "true" : "false") + "}";
        }
        return out + "]}";
    }

    // The monitor's whole life: waits on every tracked process (an exit is
    // seen at once), discovers the ones it did not start, and notes every
    // change of what is running. Returns when the stop event is set.
    void run() {
        std::vector<std::string> last = running_set();
        for (;;) {
            std::vector<HANDLE> handles;
            if (cfg_.stop_event) handles.push_back(cfg_.stop_event);
            if (wake_) handles.push_back(wake_);
            {
                std::lock_guard<std::mutex> lock(m_);
                adopt_locked();
                for (const auto& t : tracked_) {
                    if (handles.size() >= MAXIMUM_WAIT_OBJECTS) break;
                    handles.push_back(t.process);
                }
            }
            const std::vector<std::string> now_running = running_set();
            if (now_running != last) { stopped(last, now_running); last = now_running; changed(); }
            const DWORD w = handles.empty() ? WAIT_TIMEOUT
                : WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE, kDiscoverMs);
            if (cfg_.stop_event && w == WAIT_OBJECT_0) return;
            if (w == WAIT_FAILED) Sleep(1000);
            reap();
            const std::vector<std::string> after = running_set();
            if (after != last) { stopped(last, after); last = after; changed(); }
        }
    }

private:
    struct Tracked {
        HANDLE process = nullptr;
        DWORD pid = 0;
        std::string assignment;
        bool started_here = false;
    };

    static fs::path path_of(const std::string& utf8) { return fs::path(std::u8string(utf8.begin(), utf8.end())); }

    static std::string refusal(const std::string& code, const std::string& why) {
        return "{\"type\":\"game_launch\",\"ok\":false,\"code\":" + ev::json::quote(code) +
               ",\"message\":" + ev::json::quote(why) + "}";
    }

    bool launchable(const std::string& assignment, const std::string& required, ed::Job& job, std::string& code, std::string& why) {
        // A truly expired assignment is never launched again.
        if (vclient::assignment_cleanup::is_expired(cfg_.root, assignment)) { code = "expired"; why = kExpired; return false; }
        if (!ed::install_for_assignment(cfg_.root, assignment, job)) { code = "not_installed"; why = kNotInstalled; return false; }
        if (job.state != "installed") {
            const bool on_disk = !ed::installed_revision(job).empty();
            code = on_disk ? "updating" : "not_installed";
            why = on_disk ? kUpdating : kNotInstalled;
            return false;
        }
        if (!required.empty() && ev::is_hex32(required) && ed::installed_revision(job) != required) {
            code = "update_required";
            why = kUpdateRequired;
            return false;
        }
        std::error_code ec;
        if (job.install_dir.empty() || job.launch_exe.empty() ||
            !fs::is_regular_file(path_of(job.install_dir) / path_of(job.launch_exe), ec) || ec) {
            code = "missing";
            why = kMissing;
            return false;
        }
        return true;
    }

    bool busy_locked(const std::string& id) {
        if (launching_.count(id)) return true;
        for (const auto& t : tracked_) if (t.assignment == id && detail::alive(t.process)) return true;
        return ev::session_running(id);
    }

    // Processes whose image lives inside an installed assignment's own
    // game folder, not yet tracked, are tracked from now on.
    void adopt_locked() {
        std::vector<std::pair<std::wstring, std::string>> folders;
        for (const auto& j : ed::list_jobs(cfg_.root)) {
            if (!ed::is_install(j) || j.state == "removed" || !ev::is_hex32(j.assignment_id)) continue;
            const std::wstring key = detail::folder_key(j.install_dir);
            if (!key.empty()) folders.emplace_back(key, j.assignment_id);
        }
        if (folders.empty()) return;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        const DWORD self = GetCurrentProcessId();
        for (BOOL more = Process32FirstW(snap, &pe); more; more = Process32NextW(snap, &pe)) {
            const DWORD pid = pe.th32ProcessID;
            if (pid == 0 || pid == self) continue;
            bool known = false;
            for (const auto& t : tracked_) if (t.pid == pid && detail::alive(t.process)) { known = true; break; }
            if (known) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
            if (!h) continue;
            const std::wstring image = detail::image_of(h);
            const auto hit = std::find_if(folders.begin(), folders.end(), [&](const auto& f) {
                return !image.empty() && image.compare(0, f.first.size(), f.first) == 0;
            });
            if (hit == folders.end() || !detail::alive(h)) { CloseHandle(h); continue; }
            tracked_.push_back(Tracked{ h, pid, hit->second, false });
            say("launcher: found a running process (pid " + std::to_string(pid) + ") of " + hit->second);
        }
        CloseHandle(snap);
    }

    // Tracked processes that exited are let go.
    void reap() {
        std::lock_guard<std::mutex> lock(m_);
        for (auto it = tracked_.begin(); it != tracked_.end();) {
            if (!detail::alive(it->process)) {
                DWORD code = 0;
                (void)GetExitCodeProcess(it->process, &code);
                say("launcher: pid " + std::to_string(it->pid) + " of " + it->assignment + " exited (" + std::to_string(code) + ")");
                CloseHandle(it->process);
                it = tracked_.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::vector<std::string> running_set() {
        std::vector<std::string> ids;
        for (const auto& j : ed::list_jobs(cfg_.root)) {
            if (ed::is_install(j) && ev::is_hex32(j.assignment_id)) ids.push_back(j.assignment_id);
        }
        std::vector<std::string> out;
        std::lock_guard<std::mutex> lock(m_);
        for (const auto& t : tracked_) ids.push_back(t.assignment);
        std::sort(ids.begin(), ids.end());
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        for (const auto& id : ids) if (busy_locked(id)) out.push_back(id);
        return out;
    }

    void changed() { if (cfg_.on_change) cfg_.on_change(); }
    // Every assignment that was running and no longer is.
    void stopped(const std::vector<std::string>& before, const std::vector<std::string>& after) {
        if (!cfg_.on_stopped) return;
        for (const auto& id : before) {
            if (std::find(after.begin(), after.end(), id) == after.end()) cfg_.on_stopped(id);
        }
    }
    void say(const std::string& t) { if (cfg_.log) cfg_.log(t); }

    Config cfg_;
    std::mutex m_;
    std::vector<Tracked> tracked_;
    std::set<std::string> launching_;
    HANDLE wake_ = nullptr;
};

} // namespace vclient::launcher
