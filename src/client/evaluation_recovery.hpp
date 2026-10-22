#pragma once
// RECOVERY OF A FINISHED SESSION LEFT WITHOUT A PACKAGE (2026-10-22;
// docs/ARCHITECTURE.md "Session recovery"; OWNER RULING 2026-10-22: the
// Client runs the wrapper's own recovery in a windowless recovery-only mode).
//
// A wrapper that died between a session and its handoff (a crash, a kill, a
// Windows restart) leaves either its checkpoint (open_session.json) or a
// ledger session that never became a package. The wrapper's own recovery
// (evaluation_ledger recover + the handoff) turns either into a package; the
// Client never builds evidence itself. So for each INSTALLED evaluator
// assignment, at Client start and whenever the launcher sees the game's
// last process exit, the Client starts
//
//     "<install dir>\<launch exe>" --virule-evaluation-recover
//
// hidden (CREATE_NO_WINDOW, the game folder as working directory), waits up
// to 120 s, logs the exit code (0 = done or nothing to do, nonzero =
// failed) and wakes the evidence delivery, when ALL of these hold:
//   - recovery is needed: evaluator\assignments\<id>\open_session.json
//     exists, OR ledger.json lists a session id with no evidence\outbox\<id>,
//     no evidence\.incoming\<id>, no evidence\receipts\<id>.json, and not
//     among the service's received[] session ids
//     (evidence\progress\<assignment>.json);
//   - no process of the game is running (the launcher's busy check);
//   - the INSTALLED wrapper binary carries the ASCII marker
//     VIRULE_EVALUATION_RECOVER_CLI_V1 (the native side compiles it into
//     wrappers that have the mode; an older wrapper is NEVER started this
//     way: it would open its game);
//   - this assignment was not tried in the last five minutes.
//
// While the recovery runs, its process lives in the game folder, so the
// launcher adopts it and the game reads running (Play is refused, an
// update waits) until it exits; its exit is a "last process exit" again,
// which the five-minute limit and the now-satisfied rule keep from looping.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "virule/core/evaluation_distribution.hpp"
#include "virule/core/evaluation_evidence.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace vclient::evaluation_recovery {

namespace fs = std::filesystem;
namespace ed = virule::core::evaluation_distribution;
namespace ee = virule::core::evaluation_evidence;

inline constexpr const char* kMarker = "VIRULE_EVALUATION_RECOVER_CLI_V1";
inline constexpr const wchar_t* kRecoverArg = L"--virule-evaluation-recover";
inline constexpr DWORD kRecoverWaitMs = 120000;
inline constexpr std::int64_t kMinIntervalSeconds = 300;

inline fs::path path_of(const std::string& utf8) { return fs::path(std::u8string(utf8.begin(), utf8.end())); }
inline fs::path assignment_dir(const fs::path& root, const std::string& id) {
    return root / L"evaluator" / L"assignments" / fs::path(id);
}

// Whether the file's bytes contain the marker (streamed, the marker may
// straddle two reads). False when unreadable.
inline bool binary_has_marker(const fs::path& exe) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, exe.wstring().c_str(), L"rb") != 0 || !f) return false;
    const std::string marker(kMarker);
    std::vector<char> buf(1 << 20);
    std::string carry;
    bool found = false;
    for (;;) {
        const size_t n = fread(buf.data(), 1, buf.size(), f);
        if (n == 0) break;
        std::string window = carry;
        window.append(buf.data(), n);
        if (window.find(marker) != std::string::npos) { found = true; break; }
        carry = window.size() >= marker.size() ? window.substr(window.size() - (marker.size() - 1)) : window;
    }
    fclose(f);
    return found;
}

// The ledger's session ids (ledger.json `sessions[].session_id`), read with
// the vendored tolerant reader (the wrapper's ledger header is not vendored).
inline std::vector<std::string> ledger_sessions(const fs::path& root, const std::string& assignment_id) {
    std::vector<std::string> out;
    const std::string text = ee::read_document(assignment_dir(root, assignment_id) / L"ledger.json");
    std::string_view raw;
    std::vector<std::string_view> items;
    if (text.empty() || !ee::json::member(text, "sessions", raw) || !ee::json::items(raw, items)) return out;
    for (const auto& it : items) {
        std::string id;
        if (ee::json::get_string(it, "session_id", id) && ee::is_hex32(id)) out.push_back(id);
    }
    return out;
}

// Is recovery needed for the assignment? `why` names the reason.
inline bool needs_recovery(const fs::path& root, const std::string& assignment_id, std::string& why) {
    why.clear();
    if (!ee::is_hex32(assignment_id)) return false;
    if (ee::exists_quiet(assignment_dir(root, assignment_id) / L"open_session.json")) {
        why = "an open session checkpoint";
        return true;
    }
    const ee::Root er = ee::root_under(root);
    const ee::ServiceProgress svc = ee::parse_service_progress(ee::read_document(ee::progress_path(er, assignment_id)));
    std::set<std::string> received;
    for (const auto& f : svc.received) received.insert(f.session_id);
    for (const auto& id : ledger_sessions(root, assignment_id)) {
        if (ee::exists_quiet(ee::outbox_dir(er, id))) continue;
        if (ee::exists_quiet(ee::incoming_dir(er, id))) continue;
        if (ee::exists_quiet(ee::receipt_path(er, id))) continue;
        if (received.count(id)) continue;
        why = "session " + id + " has no package";
        return true;
    }
    return false;
}

enum class Verdict { NotInstalled, NotNeeded, Running, NoMarker, TooSoon, Start, Deferred };

inline const char* verdict_name(Verdict v) {
    switch (v) {
    case Verdict::NotInstalled: return "not_installed";
    case Verdict::NotNeeded:    return "not_needed";
    case Verdict::Running:      return "running";
    case Verdict::NoMarker:     return "no_marker";
    case Verdict::TooSoon:      return "too_soon";
    case Verdict::Start:        return "start";
    case Verdict::Deferred:     return "deferred";
    }
    return "?";
}

struct Config {
    fs::path root;                                              // %LOCALAPPDATA%\VIRULE (or a sandbox)
    std::function<bool(const std::string&)> busy;               // the launcher's busy check
    // Start the recovery and wait; the exit code, or -1 = not started,
    // -2 = still running after the wait. Default: CreateProcess hidden.
    std::function<long(const fs::path& exe, const fs::path& dir, DWORD wait_ms)> run;
    std::function<void()> on_done;                              // the evidence wake
    std::function<void(const std::string&)> log;
    std::function<std::int64_t()> now;                          // UTC seconds; default time()
    std::int64_t min_interval_s = kMinIntervalSeconds;
    bool synchronous = false;                                   // the tests: run on the caller's thread
};

// The default start: the installed wrapper in its recovery-only mode, no
// window, the game folder as working directory.
inline long run_hidden(const fs::path& exe, const fs::path& dir, DWORD wait_ms) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + exe.wstring() + L"\" " + kRecoverArg;
    if (!CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        dir.c_str(), &si, &pi)) {
        return -1;
    }
    CloseHandle(pi.hThread);
    long code = -2;
    if (WaitForSingleObject(pi.hProcess, wait_ms) == WAIT_OBJECT_0) {
        DWORD c = 0;
        if (GetExitCodeProcess(pi.hProcess, &c)) code = (long)c;
    }
    CloseHandle(pi.hProcess);
    return code;
}

class Recovery {
public:
    explicit Recovery(Config cfg) : cfg_(std::move(cfg)) {}

    // The rule for one assignment (records the attempt time on Start).
    Verdict evaluate(const std::string& assignment_id, fs::path& exe, fs::path& dir, std::string& why) {
        ed::Job job;
        if (!ed::install_for_assignment(cfg_.root, assignment_id, job) || job.state != "installed" ||
            job.install_dir.empty() || job.launch_exe.empty()) {
            return Verdict::NotInstalled;
        }
        dir = path_of(job.install_dir);
        exe = dir / path_of(job.launch_exe);
        std::error_code ec;
        if (!fs::is_regular_file(exe, ec) || ec) return Verdict::NotInstalled;
        if (!needs_recovery(cfg_.root, assignment_id, why)) return Verdict::NotNeeded;
        if (cfg_.busy && cfg_.busy(assignment_id)) return Verdict::Running;
        if (!marker_cached(exe)) return Verdict::NoMarker;
        const std::int64_t t = now();
        std::lock_guard<std::mutex> lock(m_);
        if (running_.count(assignment_id)) return Verdict::TooSoon;
        const auto last = last_try_.find(assignment_id);
        if (last != last_try_.end() && t - last->second < cfg_.min_interval_s && t >= last->second) return Verdict::TooSoon;
        last_try_[assignment_id] = t;
        running_.insert(assignment_id);
        return Verdict::Start;
    }

    // Look at one assignment. The look itself (it reads the wrapper's bytes
    // for the marker) and a recovery that starts (it may take 120 s) run on
    // their own thread, never the caller's (the launcher monitor): the
    // answer is then Deferred. `synchronous` (the tests) answers the verdict.
    Verdict check(const std::string& assignment_id) {
        if (cfg_.synchronous) return check_now(assignment_id);
        try {
            std::thread([this, assignment_id]() { (void)check_now(assignment_id); }).detach();
        } catch (...) {}
        return Verdict::Deferred;
    }

    Verdict check_now(const std::string& assignment_id) {
        fs::path exe, dir;
        std::string why;
        const Verdict v = evaluate(assignment_id, exe, dir, why);
        if (v == Verdict::NoMarker) say_once("nomarker:" + assignment_id,
            "recovery: " + assignment_id + " needs recovery (" + why + ") but its wrapper has no recovery mode; not started");
        if (v != Verdict::Start) return v;
        say("recovery: " + assignment_id + " (" + why + "): starting the wrapper's recovery");
        auto work = [this, assignment_id, exe, dir]() {
            const long code = cfg_.run ? cfg_.run(exe, dir, kRecoverWaitMs) : run_hidden(exe, dir, kRecoverWaitMs);
            if (code == -1) say("recovery: " + assignment_id + ": the wrapper could not be started");
            else if (code == -2) say("recovery: " + assignment_id + ": still running after 120 s");
            else say("recovery: " + assignment_id + (code == 0 ? ": done (exit 0)" : ": failed (exit " + std::to_string(code) + ")"));
            {
                std::lock_guard<std::mutex> lock(m_);
                running_.erase(assignment_id);
            }
            if (cfg_.on_done) cfg_.on_done();
        };
        work();
        return v;
    }

    // Every installed evaluator assignment (Client start).
    void check_all() {
        std::set<std::string> seen;
        for (const auto& j : ed::list_jobs(cfg_.root)) {
            if (!ed::is_install(j) || j.state != "installed" || !ee::is_hex32(j.assignment_id)) continue;
            if (seen.insert(j.assignment_id).second) (void)check_now(j.assignment_id);
        }
    }

private:
    std::int64_t now() const { return cfg_.now ? cfg_.now() : (std::int64_t)std::time(nullptr); }
    void say(const std::string& t) { if (cfg_.log) cfg_.log(t); }
    void say_once(const std::string& key, const std::string& t) {
        {
            std::lock_guard<std::mutex> lock(m_);
            if (!logged_.insert(key).second) return;
        }
        say(t);
    }

    // The marker scan, remembered per file (path, size, write time).
    bool marker_cached(const fs::path& exe) {
        std::error_code ec;
        const auto size = fs::file_size(exe, ec);
        const auto when = fs::last_write_time(exe, ec);
        const std::wstring key = exe.wstring() + L"|" + std::to_wstring(size) + L"|" +
                                 std::to_wstring((long long)when.time_since_epoch().count());
        {
            std::lock_guard<std::mutex> lock(m_);
            const auto hit = markers_.find(key);
            if (hit != markers_.end()) return hit->second;
        }
        const bool has = binary_has_marker(exe);
        std::lock_guard<std::mutex> lock(m_);
        markers_[key] = has;
        return has;
    }

    Config cfg_;
    std::mutex m_;
    std::map<std::string, std::int64_t> last_try_;
    std::set<std::string> running_;
    std::set<std::string> logged_;
    std::map<std::wstring, bool> markers_;
};

} // namespace vclient::evaluation_recovery
