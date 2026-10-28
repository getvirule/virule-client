#pragma once
// AN EXPIRED ASSIGNMENT'S MANDATORY CLEANUP (owner brief 2026-10-28;
// docs/ARCHITECTURE.md "Expired assignment cleanup"; the service half is
// VIRULE_BACKEND src/evaluations/expiry.ts).
//
// A truly expired assignment must not leave the developer's game on the
// evaluator's computer, and must never be played again. The Client learns
// the expiry from the service (the runtime report's answer, `state:
// "expired"`, client/runtime_report.hpp) or, at the ABSOLUTE deadline with
// the service unreachable, from the service-signed acceptance instant in
// the assignment's ticket. Either way the cleanup is the same, and it is
// RE-ENTRANT: every step can be repeated, so a crash, a locked file or a
// Client restart at any point only means it runs again.
//
//   1. THE MARK (first: it is the revoke). evaluator\assignments\<id>\
//      expired.json, written atomically and never removed. From then on the
//      launcher refuses a launch (client/launcher.hpp `launchable`), the
//      transfer driver installs or updates nothing for it
//      (client/transfers.hpp run_install), and every cleanup pass resumes
//      from it. A failed later step never restores anything.
//   2. CLOSE THE GAME: every process of the assignment (the wrapper this
//      Client started, any process whose image lives in its game folder) is
//      terminated (launcher `terminate`). At the absolute deadline no
//      session may continue.
//   3. FINALIZE THE EVIDENCE: the wrapper's own windowless recovery
//      (client/evaluation_recovery.hpp) packages a session the termination
//      left without a package, while the wrapper binary is still on disk.
//      The package is delivered like any other; the service keeps it as
//      record only (it never reactivates the assignment).
//   4. REMOVE THE GAME: only the job's own folder, directly inside the
//      installs location and named by the game's id (the same guards as the
//      report's removal), and the download's temp file; the job becomes
//      `removed`. A folder still in use is left for the next pass.
//   5. DELETE THE UNSUBMITTED DRAFT: evaluator\assignments\<id>\
//      report_draft.json (its prose and scores are never evaluation data).
//      The Admin, if open, forgets its copy and deletes it too.
//
// KEPT: the rest of evaluator\assignments\<id>\ (the ticket, the ledger,
// the evidence outbox and receipts), so evidence still on its way is
// delivered, and nothing outside VIRULE's own assignment folders is ever
// touched.

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "virule/core/evaluation_distribution.hpp"
#include "virule/core/evaluation_evidence.hpp"

namespace vclient::assignment_cleanup {

namespace fs = std::filesystem;
namespace ed = virule::core::evaluation_distribution;
namespace ee = virule::core::evaluation_evidence;

inline fs::path assignment_dir(const fs::path& root, const std::string& id) {
    return root / L"evaluator" / L"assignments" / fs::path(id);
}
inline fs::path marker_path(const fs::path& root, const std::string& id) { return assignment_dir(root, id) / L"expired.json"; }
inline fs::path draft_path(const fs::path& root, const std::string& id) { return assignment_dir(root, id) / L"report_draft.json"; }

// The assignment is expired on this computer (the mark exists).
inline bool is_expired(const fs::path& root, const std::string& id) {
    if (!ee::is_hex32(id)) return false;
    std::error_code ec;
    return fs::exists(marker_path(root, id), ec);
}

inline std::string utc_of(std::time_t t) {
    std::tm g{};
    gmtime_s(&g, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &g);
    return buf;
}

// The service's canonical instant `YYYY-MM-DDTHH:MM:SSZ` as epoch seconds; -1 if malformed.
inline std::int64_t parse_utc(const std::string& s) {
    int y, mo, d, h, mi, se;
    if (s.size() != 20 || s[19] != 'Z' || std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ", &y, &mo, &d, &h, &mi, &se) != 6) return -1;
    std::tm tm{};
    tm.tm_year = y - 1900; tm.tm_mon = mo - 1; tm.tm_mday = d; tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = se;
    const std::time_t t = _mkgmtime(&tm);
    return t == (std::time_t)-1 ? -1 : (std::int64_t)t;
}

// Step 1, the revoke. `source` is "service" (the service said expired) or
// "local" (the absolute deadline passed with the service unreachable).
// True when the mark exists afterwards.
inline bool mark(const fs::path& root, const std::string& id, const std::string& source, std::time_t now) {
    if (!ee::is_hex32(id)) return false;
    if (is_expired(root, id)) return true;
    const std::string body = "{\"version\":1,\"source\":" + ee::json::quote(source) + ",\"marked_utc\":" + ee::json::quote(utc_of(now)) + "}";
    return ee::write_file_atomic(marker_path(root, id), body);
}

// Every assignment marked on this computer.
inline std::vector<std::string> marked(const fs::path& root) {
    std::vector<std::string> out;
    std::error_code ec;
    const fs::path base = root / L"evaluator" / L"assignments";
    for (fs::directory_iterator it(base, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string id = it->path().filename().string();
        if (ee::is_hex32(id) && is_expired(root, id)) out.push_back(id);
    }
    return out;
}

struct Config {
    fs::path root;                                                        // %LOCALAPPDATA%\VIRULE (or a sandbox)
    // Step 2: terminate every process of the assignment; true when none is left.
    std::function<bool(const std::string& assignment_id)> terminate;
    // Step 3: the wrapper's recovery for the assignment, synchronous.
    std::function<void(const std::string& assignment_id)> recover;
    // Is anything of the game still running (the launcher's scanned busy)?
    std::function<bool(const std::string& assignment_id)> busy;
    std::function<void(const std::string&)> log;
    // Something the Admin shows changed (the change counter).
    std::function<void()> on_change;
};

// Steps 2 to 5 for a MARKED assignment. True when nothing is left to do
// (the game removed, or never installed here, and the draft gone).
inline bool run(const Config& cfg, const std::string& id) {
    if (!is_expired(cfg.root, id)) return true;
    const auto say = [&](const std::string& t) { if (cfg.log) cfg.log("expired assignment " + id + ": " + t); };
    bool done = true;
    bool changed = false;
    ed::Job j;
    if (ed::install_for_assignment(cfg.root, id, j) && j.state != "removed") {
        const bool all_closed = cfg.terminate ? cfg.terminate(id) : true;
        if (!all_closed) say("a process could not be closed yet");
        if (j.state == "installed" && cfg.recover) cfg.recover(id);
        if (cfg.busy && cfg.busy(id)) {
            say("the game is still running; removal waits");
            done = false;
        } else {
            std::error_code ec;
            const fs::path dst = fs::path(std::u8string(j.install_dir.begin(), j.install_dir.end()));
            const fs::path inst_root = fs::path(std::u8string(j.install_root.begin(), j.install_root.end()));
            bool removed = true;
            // Only the job's own folder, directly inside the installs location.
            if (!dst.empty() && !inst_root.empty() && dst.parent_path() == inst_root && dst.filename().string() == j.game_uuid) {
                fs::remove_all(dst, ec);
                if (ec && fs::exists(dst)) { removed = false; say("the game folder could not be removed yet"); }
            }
            if (removed) {
                if (!j.temp_path.empty()) fs::remove(fs::path(std::u8string(j.temp_path.begin(), j.temp_path.end())), ec);
                // The job may have moved meanwhile (the driver): written from its current record.
                ed::Job cur;
                if (ed::install_for_assignment(cfg.root, id, cur)) j = cur;
                j.state = "removed";
                j.error.clear();
                j.attempts = 0;
                j.updated_utc = utc_of(std::time(nullptr));
                if (ed::write_job(cfg.root, j)) { say("the game was removed"); changed = true; }
                else done = false;
            } else {
                done = false;
            }
        }
    }
    std::error_code ec;
    if (fs::exists(draft_path(cfg.root, id), ec)) {
        fs::remove(draft_path(cfg.root, id), ec);
        if (fs::exists(draft_path(cfg.root, id), ec)) done = false; else { say("the unsubmitted draft was deleted"); changed = true; }
    }
    if (changed && cfg.on_change) cfg.on_change();
    return done;
}

} // namespace vclient::assignment_cleanup
