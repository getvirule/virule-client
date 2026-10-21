#pragma once
// THE DEVELOPER'S EVALUATION INBOX (2026-10-21; docs/ARCHITECTURE.md
// "Evaluation evidence delivery", developer half; v2_mvp
// docs/EVALUATION_VIRULE.md section 7; the service side is VIRULE_BACKEND
// src/evaluations/evidence.ts).
//
// The developer's VIRULE Client fetches the session evidence of the
// signed-in developer's evaluations in the background, Admin open or not,
// into evidence\received\<evaluation>\ (evaluation_evidence.hpp "THE
// DEVELOPER'S RECEIVED EVIDENCE"); the Admin takes a delivered evaluation's
// packages into its durable workspace when it shows them.
//
// NO POLLING OF ITS OWN. A pass runs only on communication the Client
// already has: at startup, on the scheduled update check's cadence (the
// same quiet six-hour check), and when the developer's own Evaluations read
// (the account relay's GET /v1/evaluations) answered something new. Each
// pass is ONE account-scoped request (GET /v1/evaluations/evidence, this
// installation's DPoP authorization) and then only the files this computer
// does not hold. Nothing private ever rides the public release manifest.
//
// GUARANTEES: a file is kept only after its SHA-256 equals the digest the
// service lists (a partial download is a `.part` file, replaced on the next
// try); a package is complete (its `.done` marker) only when every file is
// held; a held file or a marked package is never fetched again; another
// account's evaluations are never asked for (the service answers the
// caller's own) and a pass with nobody signed in does nothing; failures
// retry on the ladder (10 s to 30 min) and never give up.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "client/transfers.hpp"
#include "shared/evidence_queue.hpp"
#include "virule/core/evaluation_evidence.hpp"

namespace vclient::evaluation_inbox {

namespace fs = std::filesystem;
namespace ee = virule::core::evaluation_evidence;

using Log = std::function<void(const std::string&)>;

struct Config {
    fs::path root;                        // %LOCALAPPDATA%\VIRULE (or a sandbox)
    transfers::Service* service = nullptr;
    HANDLE stop_event = nullptr;
    HANDLE wake = nullptr;                // auto-reset: a pass now
    std::function<bool()> paused;         // an uninstall
    Log log;
};

struct PassResult {
    bool ok = false;                      // the service answered (or nobody is signed in)
    int fetched_files = 0;
    int completed_packages = 0;
    std::string error;
};

inline void say(const Config& c, const std::string& t) { if (c.log) c.log("inbox: " + t); }

// One file to `dst`, verified: downloaded to `dst.part`, its SHA-256
// compared, then renamed into place.
inline bool fetch_file(const Config& c, const std::string& path, std::int64_t bytes, const std::string& sha256,
                       const fs::path& dst, std::string& why) {
    std::error_code ec;
    const fs::path part = dst.wstring() + L".part";
    fs::remove(part, ec);
    FILE* out = nullptr;
    if (_wfopen_s(&out, part.wstring().c_str(), L"wb") != 0 || !out) { why = "a received file could not be written"; return false; }
    std::uint64_t got = 0;
    unsigned long status = 0;
    const bool okd = bytes > 0
        ? c.service->get_range_to_file(path, 0, (std::uint64_t)bytes - 1, out, got, status, [&]() { return true; })
        : true;
    const bool closed = fclose(out) == 0;
    if (!okd || !closed || (status != 200 && status != 206 && bytes > 0) || (std::int64_t)got != bytes) {
        fs::remove(part, ec);
        why = status == 0 ? "Couldn't reach our servers right now." : "a file could not be fetched (" + std::to_string(status) + ")";
        return false;
    }
    std::string actual;
    if (!transfers::sha256_file_hex(part, actual) || actual != sha256) {
        fs::remove(part, ec);
        why = "a fetched file did not verify";
        return false;
    }
    fs::rename(part, dst, ec);
    if (ec) { fs::remove(part, ec); why = "a received file could not be kept"; return false; }
    return true;
}

// Whether `p` holds exactly the listed file.
inline bool holds(const fs::path& p, std::int64_t bytes, const std::string& sha256) {
    std::error_code ec;
    if (!fs::is_regular_file(p, ec) || (std::int64_t)fs::file_size(p, ec) != bytes) return false;
    std::string actual;
    return transfers::sha256_file_hex(p, actual) && actual == sha256;
}

// ONE PASS: the service's list of the developer's received evidence, then
// whatever this computer does not hold.
inline PassResult run_pass(const Config& c) {
    PassResult res;
    std::string email;
    if (!c.service || !c.service->signed_in(email)) { res.ok = true; return res; }
    const transfers::Reply r = c.service->call("GET", "/v1/evaluations/evidence", "", "", {});
    if (r.status == 403 || r.status == 404) { res.ok = true; return res; }   // not a developer: nothing to fetch
    if (r.status != 200) {
        res.error = r.status == 0 ? "Couldn't reach our servers right now." : "the service answered " + std::to_string(r.status);
        return res;
    }
    const ee::Root er = ee::root_under(c.root);
    std::string_view list_raw;
    std::vector<std::string_view> evaluations;
    if (!ee::json::member(r.body, "evaluations", list_raw) || !ee::json::items(list_raw, evaluations)) {
        res.error = "an unreadable answer";
        return res;
    }
    bool failed = false;
    for (const auto& e : evaluations) {
        std::string eid, game, status;
        if (!ee::json::get_string(e, "evaluation_id", eid) || !ee::is_hex32(eid)) continue;
        game = ee::json::opt_string(e, "game_uuid");
        status = ee::json::opt_string(e, "status");
        const fs::path dir = ee::received_dir(er, eid);
        std::error_code ec;
        fs::create_directories(dir, ec);
        // The evaluation's record (its delivery), rewritten only when it changed.
        const std::string record = "{\"evaluation_id\":" + ee::json::quote(eid) + ",\"game_uuid\":" + ee::json::quote(game) +
            ",\"status\":" + ee::json::quote(status) + ",\"delivered_utc\":" + ee::json::quote(ee::json::opt_string(e, "delivered_utc")) +
            ",\"contest_until_utc\":" + ee::json::quote(ee::json::opt_string(e, "contest_until_utc")) + "}\n";
        if (ee::read_document(dir / L"evaluation.json") != record) {
            if (ee::write_file_atomic(dir / L"evaluation.json", record)) evidence::note_change();
        }
        std::string_view pk_raw;
        std::vector<std::string_view> packages;
        if (!ee::json::member(e, "packages", pk_raw) || !ee::json::items(pk_raw, packages)) continue;
        for (const auto& p : packages) {
            std::string pid, psha;
            std::int64_t pbytes = 0;
            if (!ee::json::get_string(p, "package_id", pid) || !ee::is_hex32(pid)) continue;
            if (!ee::json::get_string(p, "sha256", psha) || !ee::is_sha256_hex(psha)) continue;
            (void)ee::json::get_int(p, "bytes", pbytes);
            if (ee::exists_quiet(ee::received_marker_path(er, eid, pid))) continue;   // whole already
            const fs::path pdir = ee::received_package_dir(er, eid, pid);
            fs::create_directories(pdir, ec);
            const std::string base = "/v1/evaluations/" + eid + "/evidence/" + pid + "/files/";
            std::string why;
            bool whole = true;
            if (!holds(pdir / ee::kPackageFileName, pbytes, psha)) {
                if (!fetch_file(c, base + ee::kPackageFileName, pbytes, psha, pdir / ee::kPackageFileName, why)) {
                    say(c, eid + "/" + pid + ": " + why);
                    failed = true;
                    continue;
                }
                ++res.fetched_files;
            }
            std::string_view files_raw;
            std::vector<std::string_view> files;
            if (ee::json::member(p, "files", files_raw) && ee::json::items(files_raw, files)) {
                for (const auto& f : files) {
                    std::string name, fsha;
                    std::int64_t fbytes = 0;
                    bool available = true;
                    if (!ee::json::get_string(f, "file", name) || !ee::is_safe_file_name(name)) { whole = false; continue; }
                    if (!ee::json::get_string(f, "sha256", fsha) || !ee::is_sha256_hex(fsha)) { whole = false; continue; }
                    (void)ee::json::get_int(f, "bytes", fbytes);
                    (void)ee::json::get_bool(f, "available", available);
                    const fs::path dst = pdir / fs::path(name);
                    if (holds(dst, fbytes, fsha)) continue;
                    if (!available) { whole = false; continue; }   // the contest window's retention removed it
                    if (!fetch_file(c, base + name, fbytes, fsha, dst, why)) {
                        say(c, eid + "/" + pid + "/" + name + ": " + why);
                        whole = false;
                        failed = true;
                        break;
                    }
                    ++res.fetched_files;
                }
            }
            if (!whole) continue;
            // The package as received must be the one listed, and every
            // capture it lists held: then it is whole.
            ee::Package pkg;
            const std::string text = ee::read_document(pdir / ee::kPackageFileName);
            if (text.empty() || !ee::parse_package(text, pkg) || pkg.package_id != pid) { failed = true; continue; }
            bool all = true;
            for (const auto& pf : ee::package_files(pkg)) if (!holds(pdir / fs::path(pf.file), pf.bytes, pf.sha256)) { all = false; break; }
            if (!all) continue;
            const std::string marker = "{\"package_id\":" + ee::json::quote(pid) + ",\"sha256\":" + ee::json::quote(psha) + "}\n";
            if (ee::write_file_atomic(ee::received_marker_path(er, eid, pid), marker)) {
                ++res.completed_packages;
                evidence::note_change();
                say(c, eid + "/" + pid + " received whole");
            }
        }
    }
    res.ok = !failed;
    if (failed) res.error = "some files could not be fetched yet";
    return res;
}

// The inbox thread: one pass at startup, then a pass on each wake (the
// scheduled check's cadence, a changed Evaluations read), and the ladder
// after a failure. Idle costs nothing.
inline void run_driver(const Config& c) {
    if (!c.service || !c.stop_event) return;
    std::int64_t failures = 0;
    DWORD wait_ms = 0;   // the startup pass
    for (;;) {
        HANDLE hs[2] = { c.stop_event, c.wake };
        const DWORD w = WaitForMultipleObjects(c.wake ? 2 : 1, hs, FALSE, wait_ms);
        if (w == WAIT_OBJECT_0) break;
        if (c.paused && c.paused()) { wait_ms = 60000; continue; }
        const PassResult r = run_pass(c);
        if (r.ok) {
            failures = 0;
            wait_ms = INFINITE;
        } else {
            ++failures;
            wait_ms = (DWORD)(evidence::backoff_seconds(failures) * 1000);
            say(c, "pass incomplete (" + r.error + "); again in " + std::to_string(wait_ms / 1000) + " s");
        }
    }
}

} // namespace vclient::evaluation_inbox
