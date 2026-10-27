#pragma once
// THE RUNTIME REPORT (owner decision 2026-10-26; docs/ARCHITECTURE.md "The
// runtime report"; the service half is VIRULE_BACKEND
// src/evaluations/expiry.ts).
//
// WHY. An evaluator has six days from acceptance. Four hours past that
// deadline (148 h, a buffer never shown) an unfinished assignment whose
// game is NOT running expires and its order goes to another evaluator; a
// game running at that mark keeps the assignment until Day 7. The service
// cannot see this computer, so this Client, the one local authority over
// whether a game is running (client/launcher.hpp), TELLS it: for every
// assignment installed here,
//
//   POST /v1/assignments/<id>/runtime
//   {"machine_key", "running", "timestamp", "machine_signature"}
//
// signed with THIS MACHINE'S identity (dev_machine.cred, the key its
// evaluator credential binds and its wrapper's launch proof uses) over
//
//   virule-evaluation-runtime.v1|<assignment>|<evaluator>|<machine_key>|<1|0>|<timestamp>
//
// The service keeps the newest observation per machine, never after the
// 148 h mark, and treats anything it cannot prove (no report, a report too
// close to a launch, a running report) as UNKNOWN, which keeps the
// assignment until Day 7. A report can therefore never shorten an
// assignment below the owner's 148 h, and a missing one only keeps it
// longer. An older Client sends nothing, with the same result.
//
// WHEN. Every RUNNING change the launcher sees (a start, the last exit, a
// job state change: its change hook wakes this thread), at Client start,
// and every 30 minutes. The state is SAMPLED at the moment each report is
// signed, never queued: a retry is a new observation (a stale sample must
// never arrive after a launch). A report that fails is simply sent again
// at the next wake or interval.
//
// WHOSE. Only under the evaluator's own account (the same owner decision
// as the evidence queue, client/evidence_owner.hpp): signed out or another
// account signed in, nothing is sent. The evaluator id is the one the
// service signed into this assignment's ticket.json.

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "virule/core/evaluation_distribution.hpp"
#include "virule/core/evaluation_evidence.hpp"

namespace vclient::runtime_report {

namespace fs = std::filesystem;
namespace ed = virule::core::evaluation_distribution;
namespace ee = virule::core::evaluation_evidence;

// How often every installed assignment is reported without a change.
inline constexpr DWORD kIntervalMs = 30 * 60 * 1000;
// A burst of changes (a wrapper and its game starting) is one report.
inline constexpr DWORD kSettleMs = 2000;

// The service's canonical UTC instant, `YYYY-MM-DDTHH:MM:SSZ`.
inline std::string canonical_utc(std::time_t t) {
    std::tm g{};
    gmtime_s(&g, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &g);
    return buf;
}

// The signed message (domain separated from every other signature the
// machine key makes).
inline std::string message(const std::string& assignment_id, const std::string& evaluator_id,
                           const std::string& machine_key, bool running, const std::string& timestamp) {
    return "virule-evaluation-runtime.v1|" + assignment_id + "|" + evaluator_id + "|" + machine_key + "|" +
           (running ? "1" : "0") + "|" + timestamp;
}

inline std::string body(const std::string& machine_key, bool running, const std::string& timestamp,
                        const std::string& signature) {
    return "{\"machine_key\":" + ee::json::quote(machine_key) + ",\"running\":" + (running ? "true" : "false") +
           ",\"timestamp\":" + ee::json::quote(timestamp) + ",\"machine_signature\":" + ee::json::quote(signature) + "}";
}

// One assignment this computer reports on: installed here (an install job
// that is not being removed) with the service's ticket naming its evaluator.
struct Target {
    std::string assignment_id;
    std::string evaluator_id;
};

inline std::vector<Target> targets(const fs::path& root) {
    std::vector<Target> out;
    for (const auto& j : ed::list_jobs(root)) {
        if (!ed::is_install(j) || !ee::is_hex32(j.assignment_id) || j.state == "removing" || j.state == "removed") continue;
        bool seen = false;
        for (const auto& t : out) if (t.assignment_id == j.assignment_id) { seen = true; break; }
        if (seen) continue;
        const std::string evaluator = ee::json::opt_string(
            ee::read_document(root / L"evaluator" / L"assignments" / fs::path(j.assignment_id) / L"ticket.json"), "evaluator_id");
        if (ee::is_hex32(evaluator)) out.push_back(Target{ j.assignment_id, evaluator });
    }
    return out;
}

struct Config {
    fs::path root;                                                          // %LOCALAPPDATA%\VIRULE (or a sandbox)
    std::function<bool(const std::string& assignment_id)> running;           // the launcher's busy()
    // Send only for the signed-in evaluator's own assignments (false =
    // signed out, or another account).
    std::function<bool(const std::string& assignment_id, const std::string& evaluator_id)> may_report;
    std::function<std::string()> machine_key;                               // "" = no usable identity
    std::function<std::string(const std::string& message)> sign;            // 128 hex, "" on failure
    std::function<unsigned long(const std::string& path, const std::string& body)> post;   // HTTP status, 0 = no answer
    std::function<std::time_t()> now = [] { return std::time(nullptr); };
    std::function<void(const std::string&)> log;
    HANDLE stop_event = nullptr;
};

class Reporter {
public:
    explicit Reporter(Config cfg) : cfg_(std::move(cfg)) { wake_ = CreateEventW(nullptr, FALSE, FALSE, nullptr); }
    ~Reporter() { if (wake_) CloseHandle(wake_); }
    Reporter(const Reporter&) = delete;
    Reporter& operator=(const Reporter&) = delete;

    // Something about what runs changed (the launcher's change hook).
    void wake() { if (wake_) SetEvent(wake_); }

    // One report per installed assignment of the signed-in evaluator, each
    // sampled as it is signed. Returns how many the service accepted.
    int cycle() {
        const std::string key = cfg_.machine_key ? cfg_.machine_key() : std::string();
        if (key.size() != 64 || !cfg_.sign || !cfg_.post) return 0;
        int accepted = 0;
        for (const auto& t : targets(cfg_.root)) {
            if (cfg_.may_report && !cfg_.may_report(t.assignment_id, t.evaluator_id)) continue;
            const bool running = cfg_.running ? cfg_.running(t.assignment_id) : true;
            const std::string ts = canonical_utc(cfg_.now());
            const std::string sig = cfg_.sign(message(t.assignment_id, t.evaluator_id, key, running, ts));
            if (sig.size() != 128) { say("runtime report: the machine identity could not sign"); return accepted; }
            const unsigned long status = cfg_.post("/v1/assignments/" + t.assignment_id + "/runtime", body(key, running, ts, sig));
            if (status == 200) {
                ++accepted;
            } else {
                say("runtime report: " + t.assignment_id + " answered " + std::to_string(status));
            }
        }
        return accepted;
    }

    // The thread's whole life: a cycle at start, at every wake (settled)
    // and every interval, until the stop event.
    void run() {
        for (;;) {
            (void)cycle();
            HANDLE handles[2];
            DWORD n = 0;
            if (cfg_.stop_event) handles[n++] = cfg_.stop_event;
            if (wake_) handles[n++] = wake_;
            const DWORD w = n ? WaitForMultipleObjects(n, handles, FALSE, kIntervalMs) : (Sleep(kIntervalMs), WAIT_TIMEOUT);
            if (cfg_.stop_event && w == WAIT_OBJECT_0) return;
            if (w == WAIT_TIMEOUT) continue;
            if (!cfg_.stop_event) Sleep(kSettleMs);
            else if (WaitForSingleObject(cfg_.stop_event, kSettleMs) == WAIT_OBJECT_0) return;
        }
    }

private:
    void say(const std::string& t) { if (cfg_.log) cfg_.log(t); }

    Config cfg_;
    HANDLE wake_ = nullptr;
};

} // namespace vclient::runtime_report
