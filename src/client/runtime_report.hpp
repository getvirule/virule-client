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
//
// THE ANSWER CARRIES THE ASSIGNMENT'S STATE (owner brief 2026-10-28):
// `{"ok": true, "state": "active" | "completed" | "expired"}`. "expired"
// (the service truly expired it, at either threshold) starts the mandatory
// cleanup (client/assignment_cleanup.hpp: the game closed and removed, the
// unsubmitted draft deleted). THE SERVICE DECIDES whenever it answers.
//
// THE ABSOLUTE DEADLINE WITHOUT THE SERVICE. 24 hours past the six-day
// deadline (168 h from the service-signed acceptance in ticket.json) an
// assignment expires whatever the game is doing, and no session may go on.
// A report is sent just after that instant (the next wake is set for it),
// so an online Client hears "expired" at once. When the service cannot be
// asked (no answer, signed out, another account, no machine identity), the
// Client applies the cut itself once the absolute instant is more than
// kLocalMarginSeconds behind its own clock (the launch proof's clock
// allowance), so a local clock running fast cannot remove a game the
// service still holds by more than that margin. The 4-hour expiry is never
// decided locally (it needs the service's records): signed out, it waits
// for the next sign-in, and the launch check refuses the game meanwhile.

#include <algorithm>
#include <cstdint>
#include <cstdio>
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
// The absolute deadline, from the service's acceptance (VIRULE_BACKEND
// src/evaluations/policy.ts ABSOLUTE_DEADLINE_SECONDS; the two must agree).
inline constexpr std::int64_t kAbsoluteSeconds = 7 * 86400;
// How far past the absolute instant the local cut waits (the service's
// clock allowance, AUTHORIZE_SKEW_SECONDS).
inline constexpr std::int64_t kLocalMarginSeconds = 15 * 60;
// A report is sent this long after the absolute instant, so the service's
// own check (it expires strictly after the instant) has passed.
inline constexpr std::int64_t kAbsoluteAskSeconds = 60;

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
    std::int64_t accepted = -1;   // the ticket's accepted_utc, epoch seconds (-1 unknown)
};

// The service's canonical instant as epoch seconds; -1 if malformed.
inline std::int64_t parse_utc(const std::string& s) {
    int y, mo, d, h, mi, se;
    if (s.size() != 20 || s[19] != 'Z' || sscanf_s(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ", &y, &mo, &d, &h, &mi, &se) != 6) return -1;
    std::tm tm{};
    tm.tm_year = y - 1900; tm.tm_mon = mo - 1; tm.tm_mday = d; tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = se;
    const std::time_t t = _mkgmtime(&tm);
    return t == (std::time_t)-1 ? -1 : (std::int64_t)t;
}

// The answer's `state` is "expired".
inline bool says_expired(const std::string& body) {
    return body.find("\"state\":\"expired\"") != std::string::npos;
}

// What the service answered: its HTTP status (0 = no answer) and body.
struct Answer {
    unsigned long status = 0;
    std::string body;
};

inline std::vector<Target> targets(const fs::path& root) {
    std::vector<Target> out;
    for (const auto& j : ed::list_jobs(root)) {
        if (!ed::is_install(j) || !ee::is_hex32(j.assignment_id) || j.state == "removing" || j.state == "removed") continue;
        bool seen = false;
        for (const auto& t : out) if (t.assignment_id == j.assignment_id) { seen = true; break; }
        if (seen) continue;
        const std::string ticket = ee::read_document(root / L"evaluator" / L"assignments" / fs::path(j.assignment_id) / L"ticket.json");
        const std::string evaluator = ee::json::opt_string(ticket, "evaluator_id");
        if (ee::is_hex32(evaluator)) out.push_back(Target{ j.assignment_id, evaluator, parse_utc(ee::json::opt_string(ticket, "accepted_utc")) });
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
    std::function<Answer(const std::string& path, const std::string& body)> post;
    // The assignment truly expired: mark it and clean it up
    // (client/assignment_cleanup.hpp). `source` "service" or "local".
    std::function<void(const std::string& assignment_id, const std::string& source)> expired;
    // Resume every cleanup a mark left unfinished (each cycle).
    std::function<void()> resume_cleanups;
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
    // sampled as it is signed; the answer's state acted on; the local
    // absolute cut where the service could not be asked. Returns how many
    // reports the service accepted.
    int cycle() {
        if (cfg_.resume_cleanups) cfg_.resume_cleanups();
        const std::string key = cfg_.machine_key ? cfg_.machine_key() : std::string();
        const bool can_sign = key.size() == 64 && cfg_.sign && cfg_.post;
        int accepted = 0;
        bool signing_failed = false;
        for (const auto& t : targets(cfg_.root)) {
            // The service DECIDES whenever it answers at all: a 200, and
            // every refusal (a 4xx: above all the 400 that says this clock is
            // off). Only no answer (0) or an unavailable service (5xx), or
            // not asking (signed out, another account, no identity), leaves
            // the absolute cut to this computer.
            bool answered = false;
            if (can_sign && !signing_failed && (!cfg_.may_report || cfg_.may_report(t.assignment_id, t.evaluator_id))) {
                const bool running = cfg_.running ? cfg_.running(t.assignment_id) : true;
                const std::string ts = canonical_utc(cfg_.now());
                const std::string sig = cfg_.sign(message(t.assignment_id, t.evaluator_id, key, running, ts));
                if (sig.size() != 128) {
                    say("runtime report: the machine identity could not sign");
                    signing_failed = true;
                } else {
                    const Answer a = cfg_.post("/v1/assignments/" + t.assignment_id + "/runtime", body(key, running, ts, sig));
                    if (a.status == 200) {
                        ++accepted;
                        answered = true;
                        if (says_expired(a.body)) {
                            say("runtime report: " + t.assignment_id + " expired (service)");
                            if (cfg_.expired) cfg_.expired(t.assignment_id, "service");
                        }
                    } else {
                        if (a.status >= 400 && a.status < 500) answered = true;
                        say("runtime report: " + t.assignment_id + " answered " + std::to_string(a.status));
                    }
                }
            }
            if (!answered && local_cut_due(t)) {
                say("runtime report: " + t.assignment_id + " passed its absolute deadline with the service unreachable; expiring locally");
                if (cfg_.expired) cfg_.expired(t.assignment_id, "local");
            }
        }
        return accepted;
    }

    // The absolute deadline passed by more than the local margin (the
    // local clock), for an assignment whose acceptance is known.
    bool local_cut_due(const Target& t) const {
        return t.accepted > 0 && (std::int64_t)cfg_.now() > t.accepted + kAbsoluteSeconds + kLocalMarginSeconds;
    }

    // Milliseconds until the next instant a report or the local cut is due
    // (just after an absolute deadline, and past its margin), capped at the
    // interval.
    DWORD next_wait_ms() const {
        const std::int64_t now = (std::int64_t)cfg_.now();
        std::int64_t best = (std::int64_t)kIntervalMs / 1000;
        for (const auto& t : targets(cfg_.root)) {
            if (t.accepted <= 0) continue;
            for (const std::int64_t at : { t.accepted + kAbsoluteSeconds + kAbsoluteAskSeconds,
                                           t.accepted + kAbsoluteSeconds + kLocalMarginSeconds + 1 }) {
                if (at > now && at - now < best) best = at - now;
            }
        }
        return (DWORD)(std::max<std::int64_t>(1, best) * 1000);
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
            const DWORD wait = next_wait_ms();
            const DWORD w = n ? WaitForMultipleObjects(n, handles, FALSE, wait) : (Sleep(wait), WAIT_TIMEOUT);
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
