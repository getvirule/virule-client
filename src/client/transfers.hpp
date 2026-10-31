#pragma once
// THE TRANSFER DRIVER: the Client-owned, durable carrier of Build for
// Evaluation's upload and of an evaluator's install (docs/ARCHITECTURE.md,
// "Game distribution"; v2_mvp docs/EVALUATION_VIRULE.md sections 3 and 9;
// the shared job record is the vendored virule/core/evaluation_distribution.hpp).
//
// WHAT IT OWNS. Every job under %LOCALAPPDATA%\VIRULE\transfers whose stage
// is the Client's:
//
//   upload   packaged -> uploading -> registering -> done | failed
//            packaged | registering -> held -> packaged (2026-10-22)
//            The Admin host built and packaged the game and handed the job
//            over as `packaged`. This driver opens (or resumes) the upload
//            session, sends every part the service does not hold (32 MiB,
//            each with its SHA-256 and MD5; a part the storage did not
//            reproduce is sent again), completes the session, and the job
//            is done once the service registered the hosted build.
//   install  queued -> downloading (paused) -> verifying -> extracting -> installed | failed
//            The Admin's Install wrote the job. This driver asks the
//            service for the download, fetches the package in 64 MiB
//            ranges appended to a partial file (a restart continues from
//            its length), verifies the whole package's SHA-256, extracts
//            it into the game's folder, writes the assignment ticket and
//            the evaluator credential the wrapper needs, and reports the
//            verified completion.
//
// A job that is building or packaging belongs to the Admin host; when that
// stage lost its owner (the Admin closed) and no Admin is running, the
// driver starts the host headless (`--resume-delivery=<job id>`) to finish
// it, at most once every few minutes per job.
//
// GUARANTEES (tests/transfers, tools/transfer_test.mjs):
//   - the job record is written atomically after every step; a kill or a
//     Windows restart resumes from it (a forced pass at startup);
//   - an upload never resends a part the service holds (the session is
//     read back before sending) and never creates a second session for
//     the same build (the service answers the same one);
//   - a part the storage did not reproduce (409 integrity) is sent again;
//     a storage upload that expired (410) is renewed and sent again from
//     the record; a session the service no longer knows (404) is opened
//     again; everything else backs off (10 s, 1 min, 5 min, 15 min, 30 min,
//     then 30 min forever) and never gives up;
//   - UPLOAD ELIGIBILITY (owner brief 2026-10-22): an upload the service
//     refuses because no purchased evaluation of the game is still owed, or
//     none was ever bought (409 no_pending_evaluation), is HELD, never
//     failed: the package and the session stay, nothing is sent, and it is
//     asked again whenever the developer's evaluations change (a purchase;
//     main.cpp release_held_uploads) and every 30 minutes (each ask keeps
//     the service's session alive); once the service takes it, it continues
//     where it stood. A held job whose game has a NEWER upload job (a new
//     Build for Evaluation) is retired here, by its only writer;
//   - the package file must still be the one that was packaged (its size);
//     otherwise the job fails and says so, never mixing two builds;
//   - a job belongs to the account that started it: with another account
//     signed in, or signed out, it waits untouched;
//   - a download verifies the whole package's SHA-256 before anything is
//     extracted; a mismatch deletes the partial file, tells the service
//     (`failed`) and leaves the job failed with its reason (Install again);
//   - an install never overwrites anything but its own folder
//     (<installs>\<game uuid>), staged beside it and swapped in by one
//     rename; a previous revision's folder is replaced only at that moment;
//   - AN UPDATE (2026-10-21: the same job moved on to a newer revision) never
//     touches the installation while its game or panels are up (the
//     launcher's busy, client/launcher.hpp: the wrapper's presence, any
//     process inside the game folder, a launch being started), keeps
//     every file of the installed game the new package does not carry (its
//     saves), and swaps with a way back: if the new folder cannot be put in
//     place the previous one is put back, so the evaluator is never left
//     without a game;
//   - a game removes itself (removing -> removed) only after its report was
//     acknowledged, never while it runs, and only its own folder;
//   - nothing is reported installed without the verified completion the
//     service acknowledged; `installed_revision_id` then names the revision
//     on disk, and it stays while an update moves the job on (2026-10-22).
//
// The service is reached through `Service` (the account's DPoP calls in
// production; a loopback stand-in in the harness), so the driver's own
// logic is tested without a network.

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "client/assignment_cleanup.hpp"
#include "shared/json_scan.hpp"
#include "virule/core/evaluation_distribution.hpp"
#include "virule/core/evaluation_evidence.hpp"
#include "virule/core/malware_scan.hpp"
#include "virule/core/verified_content.hpp"
#include "miniz/miniz.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace vclient::transfers {

namespace ed = virule::core::evaluation_distribution;
namespace ev = virule::core::evaluation_evidence;
namespace js = vclient::json_scan;
namespace fs = std::filesystem;
namespace ms = virule::core::malware_scan;
namespace vc = virule::core::verified_content;

using Log = std::function<void(const std::string&)>;

inline fs::path path_of(const std::string& utf8) { return fs::path(std::u8string(utf8.begin(), utf8.end())); }
inline std::string utc_now() {
    const std::time_t t = std::time(nullptr);
    std::tm g{};
    gmtime_s(&g, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &g);
    return buf;
}

// ---- the retry ladder (seconds). The last step repeats forever.
inline constexpr std::int64_t kBackoffLadder[] = { 10, 60, 300, 900, 1800 };
inline constexpr std::int64_t kBackoffCap = 1800;
inline std::int64_t backoff_seconds(std::int64_t failures) {
    if (failures <= 0) return kBackoffLadder[0];
    const size_t steps = sizeof(kBackoffLadder) / sizeof(kBackoffLadder[0]);
    return kBackoffLadder[static_cast<size_t>(std::min<std::int64_t>(failures - 1, (std::int64_t)steps - 1))];
}
// A stalled Admin-side stage is resumed headless at most this often.
inline constexpr std::int64_t kResumeEverySeconds = 300;
// An installed game whose content was never scanned (installed before
// scanning existed) is scanned again at most this often while not clean.
inline constexpr std::int64_t kRescanEverySeconds = 1800;
inline constexpr DWORD kPollWithoutWakeMs = 60000;
inline constexpr DWORD kPausedPollMs = 60000;

// ------------------------------------------------------------ digests ----

#if defined(_WIN32)
inline std::string digest_hex(const wchar_t* alg_name, const unsigned char* data, size_t n) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, alg_name, nullptr, 0) != 0) return "";
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) != 0) { BCryptCloseAlgorithmProvider(alg, 0); return ""; }
    DWORD len = 0, cb = 0;
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&len, sizeof(len), &cb, 0);
    std::vector<unsigned char> digest(len ? len : 32);
    bool okd = BCryptHashData(h, const_cast<unsigned char*>(data), (ULONG)n, 0) == 0 &&
               BCryptFinishHash(h, digest.data(), (ULONG)digest.size(), 0) == 0;
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!okd) return "";
    static const char* kHex = "0123456789abcdef";
    std::string out(digest.size() * 2, '0');
    for (size_t i = 0; i < digest.size(); ++i) { out[i * 2] = kHex[(digest[i] >> 4) & 0xF]; out[i * 2 + 1] = kHex[digest[i] & 0xF]; }
    return out;
}
inline std::string sha256_hex(const std::string& s) { return digest_hex(BCRYPT_SHA256_ALGORITHM, (const unsigned char*)s.data(), s.size()); }
inline std::string md5_hex(const std::string& s) { return digest_hex(BCRYPT_MD5_ALGORITHM, (const unsigned char*)s.data(), s.size()); }

// Streaming SHA-256 of a file, 1 MiB reads.
inline bool sha256_file_hex(const fs::path& p, std::string& out, const std::function<bool()>& keep_going = {}) {
    out.clear();
    FILE* f = nullptr;
    if (_wfopen_s(&f, p.wstring().c_str(), L"rb") != 0 || !f) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) { fclose(f); return false; }
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) != 0) { BCryptCloseAlgorithmProvider(alg, 0); fclose(f); return false; }
    std::vector<unsigned char> buf(1024 * 1024);
    bool okd = true;
    for (;;) {
        const size_t n = fread(buf.data(), 1, buf.size(), f);
        if (n == 0) break;
        if (BCryptHashData(h, buf.data(), (ULONG)n, 0) != 0) { okd = false; break; }
        if (keep_going && !keep_going()) { okd = false; break; }
    }
    if (ferror(f)) okd = false;
    fclose(f);
    unsigned char digest[32];
    if (okd && BCryptFinishHash(h, digest, sizeof(digest), 0) != 0) okd = false;
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!okd) return false;
    static const char* kHex = "0123456789abcdef";
    out.resize(64);
    for (size_t i = 0; i < 32; ++i) { out[i * 2] = kHex[(digest[i] >> 4) & 0xF]; out[i * 2 + 1] = kHex[digest[i] & 0xF]; }
    return true;
}
#endif

// ------------------------------------------------------------ service ----

struct Reply {
    unsigned long status = 0;   // 0 = no HTTP answer
    std::string body;
};

struct Header { std::string name, value; };

// What the driver needs of the VIRULE service. Production: the account's
// DPoP calls (main.cpp AccountService); the harness: a loopback stand-in.
struct Service {
    virtual ~Service() = default;
    // The signed-in account's email (lower case), or false when signed out.
    virtual bool signed_in(std::string& email_out) = 0;
    // One bounded call with a small JSON or raw body; the answer is JSON.
    virtual Reply call(const char* method, const std::string& path, const std::string& body,
                       const std::string& content_type, const std::vector<Header>& headers) = 0;
    // One ranged GET appended to `out`; `status_out` 0 = no HTTP answer.
    // `keep_going` false aborts (a pause, a stop).
    virtual bool get_range_to_file(const std::string& path, std::uint64_t from, std::uint64_t to, FILE* out,
                                   std::uint64_t& bytes_out, unsigned long& status_out,
                                   const std::function<bool()>& keep_going) = 0;
    // THE WHOLE OBJECT from byte 0 (2026-10-22; a received evidence file,
    // client/evaluation_inbox.hpp): like a ranged GET of [0, bytes-1], but a
    // 200 whose Content-Length is exactly `bytes` is taken too
    // (http_client.hpp request_to_file `whole_length`). The default forwards
    // to the ranged GET (206 only); the game package's download never uses it.
    virtual bool get_whole_to_file(const std::string& path, std::uint64_t bytes, FILE* out,
                                   std::uint64_t& bytes_out, unsigned long& status_out) {
        if (bytes == 0) { bytes_out = 0; status_out = 0; return false; }
        return get_range_to_file(path, 0, bytes - 1, out, bytes_out, status_out, [] { return true; });
    }
    // This installation's machine identity (the evaluator credential binds to it).
    virtual std::string machine_key() = 0;
};

// ------------------------------------------------------------ control ----

// Pause / resume / retry requests from the Admin (bridge transfer_control),
// applied by the driver at its next step. Process-wide, tiny.
struct Controls {
    std::mutex m;
    std::set<std::string> paused;     // assignment ids
    std::set<std::string> retry;      // assignment ids whose failed install is tried again
    std::set<std::string> verify;     // installed games whose content is verified again now
    bool release_held = false;        // ask the service again for every held upload, now
};
inline Controls& controls() { static Controls c; return c; }

// THE INSTALLED CONTENT IS VERIFIED AGAIN (owner brief 2026-10-30 section 3;
// virule/core/verified_content.hpp): asked by the launcher when Play found
// files the record does not vouch for, and when the game's last process
// exited (its saves, its log). The caller wakes the driver.
inline void request_verification(const std::string& assignment_id) {
    std::lock_guard<std::mutex> lock(controls().m);
    controls().verify.insert(assignment_id);
}

// The developer's evaluations changed (main.cpp: their view read through
// this Client answered something new, as a purchase does): every held
// upload is asked again at the next pass. The caller wakes the driver.
inline void release_held_uploads() {
    std::lock_guard<std::mutex> lock(controls().m);
    controls().release_held = true;
}

inline bool is_paused(const std::string& assignment_id) {
    std::lock_guard<std::mutex> lock(controls().m);
    return controls().paused.count(assignment_id) > 0;
}

struct DriverConfig;
// The driver's configuration, for the one control that needs the service
// ("verify", below); set by main.cpp when the driver starts. Null = no
// service here (the unit harness), and verify answers ok:false.
inline const DriverConfig*& control_config() { static const DriverConfig* p = nullptr; return p; }
namespace detail {
inline bool refresh_launch_chain(const DriverConfig& cfg, const std::string& assignment_id, std::string& why);
}

// The bridge's transfer_control: answers the reply JSON.
//   pause | resume | retry   the evaluator's install job (the driver applies it)
//   verify                   (0.9.15) make the launch chain of an INSTALLED
//                            assignment current before the Admin launches
//                            its wrapper: the ticket asked again, the
//                            evaluator credential re-issued when the
//                            machine key it is bound to is not this
//                            computer's any more. Synchronous (the service
//                            is asked); never touches the job record.
inline std::string control(const std::string& payload, const fs::path& root) {
    std::string assignment, action;
    (void)js::find_string_in(payload, 0, payload.size(), "assignment_id", assignment);
    (void)js::find_string_in(payload, 0, payload.size(), "action", action);
    if (!ev::is_hex32(assignment) ||
        (action != "pause" && action != "resume" && action != "retry" && action != "verify")) {
        return "{\"type\":\"error\"}";
    }
    if (action == "verify") {
        std::string why;
        bool ok = false;
        if (const DriverConfig* cfg = control_config()) {
            ed::Job j;
            if (!ed::install_for_assignment(root, assignment, j) || j.state != "installed") why = "This game isn't installed yet.";
            else ok = detail::refresh_launch_chain(*cfg, assignment, why);
        } else {
            why = "No service here.";
        }
        return std::string("{\"type\":\"transfer_control\",\"ok\":") + (ok ? "true" : "false") +
               ",\"message\":" + ev::json::quote(why) + "}";
    }
    {
        std::lock_guard<std::mutex> lock(controls().m);
        if (action == "pause") controls().paused.insert(assignment);
        else controls().paused.erase(assignment);
        if (action == "retry") controls().retry.insert(assignment);
    }
    // A pause of a job that is only queued is recorded at once (nothing is
    // running to notice it); a running download notices at its next range.
    ed::Job j;
    if (ed::install_for_assignment(root, assignment, j)) {
        if (action == "pause" && (j.state == "queued" || j.state == "downloading")) {
            j.state = "paused"; j.paused = true; j.updated_utc = utc_now(); ed::write_job(root, j);
        } else if (action == "resume" && j.state == "paused") {
            j.state = "downloading"; j.paused = false; j.updated_utc = utc_now(); ed::write_job(root, j);
        } else if (action == "retry" && j.state == "failed" && !j.security_held) {
            j.state = "queued"; j.paused = false; j.error.clear(); j.attempts = 0; j.next_attempt_utc = 0;
            j.updated_utc = utc_now(); ed::write_job(root, j);
        }
    }
    return "{\"type\":\"transfer_control\",\"ok\":true}";
}

// ----------------------------------------------------------- the pass ----

struct DriverConfig {
    fs::path root;                    // %LOCALAPPDATA%\VIRULE (or a sandbox)
    Service* service = nullptr;
    std::wstring wake_name = ed::kWakeEventName;
    HANDLE stop_event = nullptr;
    std::function<bool()> paused;     // the whole driver (an uninstall)
    Log log;
    std::function<std::int64_t()> now;
    // Start the Admin host headless for a stalled Admin-side stage; false =
    // not started (an Admin is running, or no host is known).
    std::function<bool(const ed::Job&)> resume_headless;
    // THE LAUNCHER'S ANSWER (2026-10-22, client/launcher.hpp busy): is the
    // assignment's game up in any form (its wrapper, panels or process, or
    // a launch being started)? Never replaced or removed while it is.
    // Unset (the unit harness): the wrapper's presence alone.
    std::function<bool(const std::string&)> busy;
    // A job's state changed: the Admin's change counter (evaluation_changes).
    std::function<void()> on_change;
    // An install placed its revision (and, once per process, every
    // installed assignment): the service's progress is fetched and kept,
    // so a fresh installation knows the assignment's whole history.
    std::function<void(const std::string&)> after_install;
};

namespace detail {

inline std::int64_t now_of(const DriverConfig& cfg) { return cfg.now ? cfg.now() : (std::int64_t)std::time(nullptr); }

inline bool game_busy(const DriverConfig& cfg, const std::string& assignment_id) {
    return cfg.busy ? cfg.busy(assignment_id) : ev::session_running(assignment_id);
}

// Every write of a job; a CHANGED STATE is noted for the Admin (a byte count
// moving is not: the Admin reads a moving job on its own cadence).
inline void save(const DriverConfig& cfg, ed::Job& j) {
    static std::mutex m;
    static std::map<std::string, std::string> last;
    j.updated_utc = utc_now();
    ed::write_job(cfg.root, j);
    bool moved = false;
    {
        std::lock_guard<std::mutex> lock(m);
        auto it = last.find(j.id);
        moved = it == last.end() || it->second != j.state;
        last[j.id] = j.state;
    }
    if (moved && cfg.on_change) cfg.on_change();
}

inline void log(const DriverConfig& cfg, const std::string& t) { if (cfg.log) cfg.log("transfers: " + t); }

// A failed attempt: the ladder, never giving up.
inline void defer(const DriverConfig& cfg, ed::Job& j, const std::string& why) {
    j.attempts += 1;
    j.error = why;
    j.next_attempt_utc = now_of(cfg) + backoff_seconds(j.attempts);
    save(cfg, j);
    log(cfg, j.id + " deferred: " + why);
}

// A terminal failure: the job stays, says why, and does nothing more until
// the person acts (Build for Evaluation again; Install again).
inline void fail(const DriverConfig& cfg, ed::Job& j, const std::string& why) {
    j.state = "failed";
    j.error = why;
    j.owner_pid = 0;
    save(cfg, j);
    log(cfg, j.id + " failed: " + why);
}

inline bool stopping(const DriverConfig& cfg) {
    return cfg.stop_event && WaitForSingleObject(cfg.stop_event, 0) == WAIT_OBJECT_0;
}

// ------------------------------------------------ local malware scanning ----
// (owner brief 2026-10-30; virule/core/malware_scan.hpp). The evaluator's
// delivered build is scanned after extraction and before it is placed; the
// antivirus acting on the package or the game files at ANY stage (Windows
// refusing a file as infected, errno 225/226, or Defender's own record naming
// the path) is a security outcome, never a retry. A file that merely went
// missing or changed with NO such evidence is not one: a download is retried
// (defer) and a scan reads `incomplete`. A detection holds that revision on this computer
// for good (`security_held`), fails the job, tells the service the download
// was refused, and reports an INCIDENT the service records (which holds the
// game for every evaluator). Nothing here ever runs the game's files.

// The sentences (WORKING WORDING, PENDING OWNER DECISION). A detection
// names Windows Security; the rest is malware_scan.hpp unverified_sentence
// (owner brief 2026-10-30 section 2: verification could not be completed,
// enable Defender where that is the remedy, never an instruction about
// another antivirus).
inline constexpr const char* kInstallThreat = "Windows Security found a threat in this game, so it was not installed.";

inline std::string scan_sentence(const ms::Result& r) {
    if (ms::is_incident(r.outcome)) return kInstallThreat;
    return ms::unverified_sentence(r.outcome, r.why_unavailable, "Install");
}

/** Defender recorded acting on one of `paths` since `since_utc`. */
inline bool antivirus_acted(const std::vector<fs::path>& paths, const std::string& since_utc, std::vector<ms::Threat>& seen) {
    return ms::detail::defender_events(paths, since_utc, seen) && !seen.empty();
}

/** A scan that is not clean ends the install: VIRULE's own temporary files
 *  go (the antivirus already holds what it took), an incident is kept for
 *  the service, and the job fails with one sentence. */
inline void scan_failed(const DriverConfig& cfg, ed::Job& j, const ms::Result& r, const std::string& operation,
                        const fs::path& temp, const fs::path& staging) {
    std::error_code ec;
    if (!staging.empty()) fs::remove_all(staging, ec);
    j.scan_outcome = ms::outcome_name(r.outcome);
    if (ms::is_incident(r.outcome)) {
        fs::remove(temp, ec);
        j.security_held = true;
        j.incident = ms::incident_json(r, ed::random_hex32(), operation, "", j.revision_id);
        j.incident_reported = false;
        if (!j.download_id.empty()) {
            (void)cfg.service->call("POST", "/v1/assignments/" + j.assignment_id + "/download/" + j.download_id + "/failed",
                "{\"reason\":\"security\"}", "application/json", {});
        }
        j.bytes_done = 0;
    }
    log(cfg, j.id + " scan " + j.scan_outcome + " (" + operation + "): " + r.detail.substr(0, 400));
    fail(cfg, j, scan_sentence(r));
}

/** The removal Defender recorded (or a refused file), as a scan result. */
inline ms::Result removal_of(const std::vector<ms::Threat>& seen, const std::string& path, const std::string& detail_text) {
    ms::Result r = ms::removed_by_antivirus(path, detail_text);
    if (!seen.empty()) r.threats = seen;
    return r;
}

/** Another job of this assignment held this revision (this computer's own
 *  detection): it is never downloaded or installed here again. */
inline bool revision_held_here(const fs::path& root, const std::string& assignment_id, const std::string& revision_id) {
    for (const ed::Job& o : ed::list_jobs(root)) {
        if (ed::is_install(o) && o.assignment_id == assignment_id && o.security_held && o.revision_id == revision_id) return true;
    }
    return false;
}


inline std::string body_message(const std::string& body) {
    std::string m;
    (void)js::find_string_in(body, 0, body.size(), "message", m);
    return m.empty() ? "The service refused the request." : m;
}
inline std::string body_code(const std::string& body) {
    std::string c;
    (void)js::find_string_in(body, 0, body.size(), "code", c);
    return c;
}

/** Report a recorded incident to the service, once: the developer's on the
 *  game, the evaluator's on the assignment. A refusal the service will
 *  always give (4xx but 429) is logged and not sent again. */
inline void report_incident(const DriverConfig& cfg, ed::Job& j) {
    const std::string route = ed::is_upload(j)
        ? "/v1/evaluations/games/" + j.game_uuid + "/security/incident"
        : "/v1/assignments/" + j.assignment_id + "/security/incident";
    const Reply r = cfg.service->call("POST", route, j.incident, "application/json", {});
    if (r.status == 200 || r.status == 201 || (r.status >= 400 && r.status < 500 && r.status != 429)) {
        if (r.status >= 400) log(cfg, j.id + " incident refused by the service (" + std::to_string(r.status) + "): " + body_message(r.body));
        j.incident_reported = true;
        save(cfg, j);
        log(cfg, j.id + " incident reported");
    }
}

// The service will not take this upload yet (UPLOAD ELIGIBILITY): kept as it
// is, asked again when released or after the backoff cap.
inline void hold(const DriverConfig& cfg, ed::Job& j, const std::string& why) {
    j.state = "held";
    j.error = why;
    j.attempts = 0;
    j.next_attempt_utc = now_of(cfg) + kBackoffCap;
    save(cfg, j);
    log(cfg, j.id + " held: " + why);
}
inline bool refused_for_eligibility(const Reply& r) {
    return r.status == 409 && body_code(r.body) == "no_pending_evaluation";
}

inline std::vector<std::int64_t> uploaded_of(const std::string& body) {
    std::vector<std::int64_t> out;
    std::string_view raw;
    std::vector<std::string_view> items;
    if (ev::json::member(body, "uploaded", raw) && ev::json::items(raw, items)) {
        for (const auto& it : items) { std::int64_t n = 0; if (ev::json::as_int(it, n)) out.push_back(n); }
    }
    std::sort(out.begin(), out.end());
    return out;
}

// ---- upload

inline bool package_intact(const ed::Job& j) {
    std::error_code ec;
    const fs::path p = path_of(j.package_path);
    const auto sz = fs::file_size(p, ec);
    return !ec && static_cast<std::uint64_t>(sz) == j.package_bytes;
}

inline bool read_part(const ed::Job& j, std::int64_t n, std::string& out) {
    const std::uint64_t len = ed::part_bytes(j.package_bytes, static_cast<std::uint64_t>(n));
    const std::uint64_t off = static_cast<std::uint64_t>(n - 1) * ed::kPartBytes;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path_of(j.package_path).wstring().c_str(), L"rb") != 0 || !f) return false;
    out.resize(static_cast<size_t>(len));
    bool okd = _fseeki64(f, static_cast<__int64>(off), SEEK_SET) == 0 &&
               (len == 0 || fread(out.data(), 1, out.size(), f) == out.size());
    fclose(f);
    return okd;
}

// Open (or resume) the session; false = deferred or failed (the job says).
inline bool open_session(const DriverConfig& cfg, ed::Job& j) {
    const std::string body = "{\"build_uuid\":\"" + j.build_uuid + "\",\"built_utc\":\"" + j.built_utc +
        "\",\"file_count\":" + std::to_string(j.file_count) + ",\"content_bytes\":" + std::to_string(j.content_bytes) +
        ",\"package_bytes\":" + std::to_string(j.package_bytes) + ",\"package_sha256\":\"" + j.package_sha256 +
        "\",\"launch_exe\":" + ev::json::quote(j.launch_exe) + ",\"part_bytes\":" + std::to_string(ed::kPartBytes) + "}";
    const Reply r = cfg.service->call("POST", "/v1/evaluations/games/" + j.game_uuid + "/uploads", body, "application/json", {});
    if (r.status == 200 || r.status == 201) {
        std::string sid, state;
        (void)js::find_string_in(r.body, 0, r.body.size(), "session_id", sid);
        (void)js::find_string_in(r.body, 0, r.body.size(), "state", state);
        if (!ev::is_hex32(sid)) { defer(cfg, j, "The service answered without a session."); return false; }
        j.session_id = sid;
        j.parts_done = uploaded_of(r.body);
        j.bytes_done = 0;
        for (const auto n : j.parts_done) j.bytes_done += ed::part_bytes(j.package_bytes, static_cast<std::uint64_t>(n));
        j.state = state == "verified" ? "registering" : "uploading";
        j.error.clear();
        save(cfg, j);
        return true;
    }
    // Not eligible yet, or no purchase at all: held, never failed.
    if (refused_for_eligibility(r)) {
        hold(cfg, j, body_message(r.body));
        return false;
    }
    if (r.status == 400 || r.status == 404 || r.status == 403 || r.status == 409) {
        fail(cfg, j, body_message(r.body));
        return false;
    }
    defer(cfg, j, r.status == 0 ? "Couldn't reach our servers right now." : body_message(r.body));
    return false;
}

// Every part the service does not hold, in order. false = stopped early.
// The session is READ BACK first: the service's list of parts, never this
// record alone, decides what is sent (a part acknowledged after a crash is
// not sent again; one the storage lost is).
inline bool send_parts(const DriverConfig& cfg, ed::Job& j) {
    {
        const Reply rs = cfg.service->call("GET", "/v1/evaluations/uploads/" + j.session_id, "", "", {});
        if (rs.status == 200) {
            std::string state;
            (void)js::find_string_in(rs.body, 0, rs.body.size(), "state", state);
            if (state == "verified") { j.state = "registering"; save(cfg, j); return true; }
            j.parts_done = uploaded_of(rs.body);
            j.bytes_done = 0;
            for (const auto k : j.parts_done) j.bytes_done += ed::part_bytes(j.package_bytes, static_cast<std::uint64_t>(k));
            save(cfg, j);
        } else if (rs.status == 404) {
            j.session_id.clear(); j.parts_done.clear(); j.bytes_done = 0; j.state = "packaged";
            save(cfg, j);
            return false;
        } else {
            defer(cfg, j, rs.status == 0 ? "Couldn't reach our servers right now." : body_message(rs.body));
            return false;
        }
    }
    std::int64_t integrity_retries = 0;
    for (std::int64_t n = 1; n <= j.parts_total; ++n) {
        if (stopping(cfg)) return false;
        if (std::find(j.parts_done.begin(), j.parts_done.end(), n) != j.parts_done.end()) continue;
        if (!package_intact(j)) { fail(cfg, j, "The package changed since it was built. Build it again."); return false; }
        std::string part;
        if (!read_part(j, n, part)) { defer(cfg, j, "The package could not be read."); return false; }
        const std::string sha = sha256_hex(part);
        const std::string md5 = md5_hex(part);
        if (sha.empty() || md5.empty()) { defer(cfg, j, "The part could not be hashed."); return false; }
        const Reply r = cfg.service->call("PUT", "/v1/evaluations/uploads/" + j.session_id + "/parts/" + std::to_string(n),
            part, "application/octet-stream", { { "x-virule-part-sha256", sha }, { "x-virule-part-md5", md5 } });
        if (r.status == 200) {
            j.parts_done = uploaded_of(r.body);
            if (std::find(j.parts_done.begin(), j.parts_done.end(), n) == j.parts_done.end()) j.parts_done.push_back(n);
            j.bytes_done = 0;
            for (const auto k : j.parts_done) j.bytes_done += ed::part_bytes(j.package_bytes, static_cast<std::uint64_t>(k));
            j.attempts = 0;
            j.error.clear();
            save(cfg, j);
            integrity_retries = 0;
            continue;
        }
        if (r.status == 409 && body_code(r.body) == "integrity") {
            // The storage did not reproduce the part: send it again (a few
            // times in a row, then the ladder).
            if (++integrity_retries <= 3) { --n; continue; }
            defer(cfg, j, "A part did not arrive intact.");
            return false;
        }
        if (r.status == 410) {
            // The storage upload expired: renew the session, send every part again.
            const Reply rn = cfg.service->call("POST", "/v1/evaluations/uploads/" + j.session_id + "/renew", "{}", "application/json", {});
            if (rn.status == 200) {
                j.parts_done = uploaded_of(rn.body);
                j.bytes_done = 0;
                save(cfg, j);
                n = 0;
                continue;
            }
            if (rn.status == 404) { j.session_id.clear(); j.parts_done.clear(); j.bytes_done = 0; j.state = "packaged"; save(cfg, j); return false; }
            defer(cfg, j, rn.status == 0 ? "Couldn't reach our servers right now." : body_message(rn.body));
            return false;
        }
        if (r.status == 404) {
            // The session is gone: open again from the record.
            j.session_id.clear(); j.parts_done.clear(); j.bytes_done = 0; j.state = "packaged";
            save(cfg, j);
            return false;
        }
        if (r.status == 409 && body_code(r.body) == "conflict") {
            // Already complete at the service: go on to registering.
            j.state = "registering";
            save(cfg, j);
            return true;
        }
        if (r.status == 400 || r.status == 403) { fail(cfg, j, body_message(r.body)); return false; }
        defer(cfg, j, r.status == 0 ? "Couldn't reach our servers right now." : body_message(r.body));
        return false;
    }
    j.state = "registering";
    save(cfg, j);
    return true;
}

inline void complete_session(const DriverConfig& cfg, ed::Job& j) {
    const Reply r = cfg.service->call("POST", "/v1/evaluations/uploads/" + j.session_id + "/complete", "{}", "application/json", {});
    if (r.status == 200) {
        j.state = "done";
        j.bytes_done = j.package_bytes;
        j.permille = 1000;
        j.error.clear();
        j.attempts = 0;
        save(cfg, j);
        log(cfg, j.id + " done: the hosted build is registered");
        return;
    }
    if (r.status == 409 && body_code(r.body) == "incomplete") {
        // The service holds fewer parts than this record thought: read back.
        const Reply rs = cfg.service->call("GET", "/v1/evaluations/uploads/" + j.session_id, "", "", {});
        if (rs.status == 200) { j.parts_done = uploaded_of(rs.body); j.state = "uploading"; save(cfg, j); return; }
        defer(cfg, j, "Couldn't reach our servers right now.");
        return;
    }
    if (r.status == 410 || r.status == 404) { j.session_id.clear(); j.parts_done.clear(); j.bytes_done = 0; j.state = "packaged"; save(cfg, j); return; }
    // Every evaluation delivered while the parts travelled: the session is
    // kept and completed once the service takes it.
    if (refused_for_eligibility(r)) { hold(cfg, j, body_message(r.body)); return; }
    if (r.status == 400 || r.status == 403 || r.status == 409) { fail(cfg, j, body_message(r.body)); return; }
    defer(cfg, j, r.status == 0 ? "Couldn't reach our servers right now." : body_message(r.body));
}

inline void run_upload(const DriverConfig& cfg, ed::Job& j, const std::string& email) {
    if (j.account_email.empty()) { j.account_email = email; save(cfg, j); }
    if (j.account_email != email) return;   // another account: untouched
    if (j.state == "held") {
        // A new Build for Evaluation of the game replaced it: retired, never
        // carried (this driver is the held job's only writer).
        ed::Job newest;
        if (ed::newest_upload_for_game(cfg.root, j.game_id, newest) && newest.id != j.id) {
            fail(cfg, j, "Replaced by a newer build.");
            return;
        }
    }
    if (!package_intact(j)) { fail(cfg, j, "The package changed since it was built. Build it again."); return; }
    // A held upload asks again by opening its session: the service resumes
    // the same one (its parts kept) or answers it verified.
    if (j.state == "packaged" || j.state == "held" || j.session_id.empty()) {
        if (!open_session(cfg, j)) return;
    }
    if (j.state == "uploading") {
        if (!send_parts(cfg, j)) return;
    }
    if (j.state == "registering") complete_session(cfg, j);
}

// ---- install

// Zip-slip guarded extraction of the verified package into `dst` (miniz,
// wide-path IO, nothing buffered beyond one read).
struct FileReader { FILE* in = nullptr; };
inline size_t zip_read_cb(void* opaque, mz_uint64 ofs, void* buf, size_t n) {
    auto* r = static_cast<FileReader*>(opaque);
    if (_fseeki64(r->in, static_cast<__int64>(ofs), SEEK_SET) != 0) return 0;
    return fread(buf, 1, n, r->in);
}
inline size_t zip_write_cb(void* opaque, mz_uint64, const void* buf, size_t n) {
    return fwrite(buf, 1, n, static_cast<FILE*>(opaque));
}
inline bool safe_entry(const std::string& name, fs::path& rel_out) {
    if (name.empty() || name.size() > 1024) return false;
    fs::path rel;
    std::string part;
    for (size_t i = 0; i <= name.size(); ++i) {
        const char c = i < name.size() ? name[i] : '/';
        if (c == '/' || c == '\\') {
            if (part.empty()) { if (i == 0) return false; continue; }
            if (part == "." || part == ".." || part.find(':') != std::string::npos) return false;
            rel /= fs::path(std::u8string(part.begin(), part.end()));
            part.clear();
        } else part += c;
    }
    if (rel.empty()) return false;
    rel_out = rel;
    return true;
}
inline bool extract_zip(const fs::path& zip_path, const fs::path& dst, std::string& why, const std::function<bool()>& keep_going) {
    std::error_code ec;
    const auto size = fs::file_size(zip_path, ec);
    if (ec) { why = "The package could not be read."; return false; }
    FileReader reader;
    if (_wfopen_s(&reader.in, zip_path.wstring().c_str(), L"rb") != 0 || !reader.in) { why = "The package could not be opened."; return false; }
    mz_zip_archive zip{};
    zip.m_pRead = zip_read_cb;
    zip.m_pIO_opaque = &reader;
    if (!mz_zip_reader_init(&zip, size, 0)) { fclose(reader.in); why = "The package is not a valid archive."; return false; }
    bool okd = true;
    const mz_uint n = mz_zip_reader_get_num_files(&zip);
    for (mz_uint i = 0; i < n && okd; ++i) {
        if (keep_going && !keep_going()) { okd = false; why = "stopped"; break; }
        mz_zip_archive_file_stat st{};
        if (!mz_zip_reader_file_stat(&zip, i, &st)) { okd = false; why = "The package could not be listed."; break; }
        fs::path rel;
        if (!safe_entry(st.m_filename, rel)) { okd = false; why = "The package holds an unsafe file name."; break; }
        const fs::path target = dst / rel;
        if (mz_zip_reader_is_file_a_directory(&zip, i)) { fs::create_directories(target, ec); continue; }
        fs::create_directories(target.parent_path(), ec);
        FILE* out = nullptr;
        if (_wfopen_s(&out, target.wstring().c_str(), L"wb") != 0 || !out) { okd = false; why = "A game file could not be written."; break; }
        const bool got = mz_zip_reader_extract_to_callback(&zip, i, zip_write_cb, out, 0);
        const bool closed = fclose(out) == 0;
        if (!got || !closed) { okd = false; why = "A game file could not be written."; break; }
    }
    mz_zip_reader_end(&zip);
    fclose(reader.in);
    return okd;
}

inline fs::path assignments_dir(const fs::path& root) { return root / L"evaluator" / L"assignments"; }
inline fs::path ticket_path(const fs::path& root, const std::string& id) { return assignments_dir(root) / fs::path(id) / L"ticket.json"; }
inline fs::path credential_path(const fs::path& root) { return root / L"security" / L"evaluator.cred"; }

// The ticket and the credential the wrapper verifies at launch
// (v2_mvp docs/EVALUATION_VIRULE.md section 2): asked of the service, written
// as given (the signatures are the service's), with the install location
// and the launch file added for the Admin (not covered by the signature).
//
// THE CORE touches no job record: it is what the install writes once and
// what "verify" (control, 0.9.15) runs again before a launch. `retryable`
// says whether a failure is the service being unreachable or answering
// badly (the install defers and tries again) or this computer's (no
// identity: the install fails).
struct ChainOutcome { bool ok = false; bool retryable = true; std::string why; std::string code; };

inline ChainOutcome ensure_launch_chain(const DriverConfig& cfg, const std::string& assignment_id,
                                        const std::string& install_dir, const std::string& launch_exe,
                                        const std::string& revision_id) {
    ChainOutcome r;
    const Reply t = cfg.service->call("GET", "/v1/assignments/" + assignment_id + "/ticket", "", "", {});
    if (t.status != 200) {
        r.why = t.status == 0 ? "Couldn't reach our servers right now." : body_message(t.body);
        r.code = t.status == 0 ? std::string() : body_code(t.body);
        // A GAME UNDER A SECURITY HOLD (VIRULE_BACKEND security.ts) is a
        // final answer until it is released, never a retry.
        if (t.status == 409 && r.code == "security_hold") r.retryable = false;
        return r;
    }
    std::string_view ticket_raw;
    if (!ev::json::member(t.body, "ticket", ticket_raw)) { r.why = "The service answered without a ticket."; return r; }
    std::string ticket(ticket_raw);
    std::string aid, evid, guid, acc, sig;
    if (!ev::json::get_string(ticket, "assignment_id", aid) || aid != assignment_id ||
        !ev::json::get_string(ticket, "evaluator_id", evid) || !ev::json::get_string(ticket, "game_uuid", guid) ||
        !ev::json::get_string(ticket, "accepted_utc", acc) || !ev::json::get_string(ticket, "signature", sig)) {
        r.why = "The service answered with a malformed ticket.";
        return r;
    }
    const std::string ticket_doc = "{\"version\":1,\"assignment_id\":" + ev::json::quote(aid) + ",\"evaluator_id\":" + ev::json::quote(evid) +
        ",\"game_uuid\":" + ev::json::quote(guid) + ",\"accepted_utc\":" + ev::json::quote(acc) + ",\"signature\":" + ev::json::quote(sig) +
        ",\"install_path\":" + ev::json::quote(install_dir) + ",\"launch_exe\":" + ev::json::quote(launch_exe) +
        ",\"revision_id\":" + ev::json::quote(revision_id) + "}\n";
    std::error_code ec;
    fs::create_directories(ticket_path(cfg.root, aid).parent_path(), ec);
    if (!ev::write_file_atomic(ticket_path(cfg.root, aid), ticket_doc)) { r.why = "The ticket could not be written."; return r; }

    // THE MACHINE KEY IS READ NOW, never remembered: the Admin re-issues
    // this computer's identity (dev_machine.cred) on its first run, and the
    // credential must be bound to the key the wrapper will derive from
    // that file at launch.
    const std::string machine = cfg.service->machine_key();
    if (machine.empty()) { r.retryable = false; r.why = "This computer has no VIRULE identity."; return r; }
    // The credential held here, when it is this evaluator's for this machine, stays.
    {
        const std::string held = ev::read_document(credential_path(cfg.root));
        std::string hev, hkey;
        if (!held.empty() && ev::json::get_string(held, "evaluator_id", hev) && hev == evid &&
            ev::json::get_string(held, "machine_key", hkey) && hkey == machine) {
            r.ok = true;
            return r;
        }
    }
    const Reply c = cfg.service->call("POST", "/v1/assignments/credential", "{\"machine_key\":\"" + machine + "\"}", "application/json", {});
    if (c.status != 200 && c.status != 201) { r.why = c.status == 0 ? "Couldn't reach our servers right now." : body_message(c.body); return r; }
    std::string_view cred_raw;
    if (!ev::json::member(c.body, "credential", cred_raw)) { r.why = "The service answered without a credential."; return r; }
    std::string cred(cred_raw);
    std::string cev, ckey, bound, csig;
    if (!ev::json::get_string(cred, "evaluator_id", cev) || cev != evid || !ev::json::get_string(cred, "machine_key", ckey) ||
        ckey != machine || !ev::json::get_string(cred, "bound_utc", bound) || !ev::json::get_string(cred, "signature", csig)) {
        r.why = "The service answered with a malformed credential.";
        return r;
    }
    const std::string cred_doc = "{\"version\":1,\"evaluator_id\":" + ev::json::quote(cev) + ",\"machine_key\":" + ev::json::quote(ckey) +
        ",\"bound_utc\":" + ev::json::quote(bound) + ",\"signature\":" + ev::json::quote(csig) + "}\n";
    fs::create_directories(credential_path(cfg.root).parent_path(), ec);
    if (!ev::write_file_atomic(credential_path(cfg.root), cred_doc)) { r.why = "The credential could not be written."; return r; }
    r.ok = true;
    return r;
}

// "verify" (control): an INSTALLED assignment's chain made current; the
// job record is only read.
inline bool refresh_launch_chain(const DriverConfig& cfg, const std::string& assignment_id, std::string& why) {
    ed::Job j;
    if (!ed::install_for_assignment(cfg.root, assignment_id, j) || j.state != "installed") { why = "This game isn't installed yet."; return false; }
    const ChainOutcome r = ensure_launch_chain(cfg, assignment_id, j.install_dir, j.launch_exe, j.revision_id);
    why = r.why;
    if (r.ok) log(cfg, j.id + " launch chain verified for " + assignment_id);
    else log(cfg, j.id + " launch chain could not be made current: " + r.why);
    return r.ok;
}

// An update waiting for the game to close is looked at again this soon.
inline constexpr std::int64_t kWhileRunningSeconds = 15;

// Every regular file under `from` that `to` does not have, copied there at
// the same relative path (the installed game's own files on an update).
// Links are never followed; a file that cannot be copied fails the step
// (nothing is replaced then).
inline bool carry_over(const fs::path& from, const fs::path& to, std::string& why) {
    std::error_code ec;
    fs::recursive_directory_iterator it(from, fs::directory_options::skip_permission_denied, ec), end;
    if (ec) { why = "The installed game could not be read."; return false; }
    for (; it != end; it.increment(ec)) {
        if (ec) { why = "The installed game could not be read."; return false; }
        std::error_code sec;
        const auto st = it->symlink_status(sec);
        if (sec || fs::is_symlink(st)) { if (fs::is_directory(st)) it.disable_recursion_pending(); continue; }
        if (!fs::is_regular_file(st)) continue;
        const fs::path rel = fs::relative(it->path(), from, sec);
        if (sec || rel.empty()) continue;
        const fs::path target = to / rel;
        if (fs::exists(target, sec)) continue;
        fs::create_directories(target.parent_path(), sec);
        fs::copy_file(it->path(), target, fs::copy_options::none, sec);
        if (sec) { why = "A save or setting of the installed game could not be kept."; return false; }
    }
    return true;
}

// THE GAME REMOVES ITSELF (2026-10-21; UIUX.md Assignments: "after a
// successful report submission and confirmed upload the game removes
// itself"): only after the report's receipt (evidence_queue run_requests'
// acknowledgment, main.cpp), or once the assignment truly expired
// (run_install, client/assignment_cleanup.hpp), never while it runs, and
// only its own folder (<installs>\<game uuid>, as the job names it).
inline void run_removal(const DriverConfig& cfg, ed::Job& j) {
    if (game_busy(cfg, j.assignment_id)) {
        j.next_attempt_utc = now_of(cfg) + kWhileRunningSeconds;
        save(cfg, j);
        return;
    }
    std::error_code ec;
    const fs::path dst = path_of(j.install_dir);
    const fs::path root = path_of(j.install_root);
    // Only the job's own folder, directly inside the installs location.
    if (!dst.empty() && !root.empty() && dst.parent_path() == root && dst.filename().string() == j.game_uuid) {
        fs::remove_all(dst, ec);
        if (ec && fs::exists(dst)) { defer(cfg, j, "The game could not be removed yet."); return; }
    }
    if (!j.temp_path.empty()) fs::remove(path_of(j.temp_path), ec);
    j.state = "removed";
    j.error.clear();
    j.attempts = 0;
    save(cfg, j);
    log(cfg, j.id + (vclient::assignment_cleanup::is_expired(cfg.root, j.assignment_id)
        ? " removed: the assignment expired" : " removed after the report was acknowledged"));
}

/** THE INSTALLED CONTENT, VERIFIED (owner decisions 2026-10-30,
 *  VIRULE/docs/specs/evaluation-security.md "Scan cadence";
 *  virule/core/verified_content.hpp plan_scan). What the record of the last
 *  clean scan does not vouch for is scanned where it stands, before the
 *  launcher offers Play: ONLY the new or changed files (the game's saves,
 *  the wrapper's log, an executable it left behind; a new folder of only new
 *  files as one target), with the wrapper's original copied out beside them
 *  (never run) only when the launch file changed. Unchanged content is
 *  never scanned again. The whole folder is scanned only when there is no
 *  record of this revision (content installed before scanning existed, an
 *  update, a replacement build). Clean takes the scanned files into the record; a
 *  detection holds the revision here and reports an incident (the antivirus
 *  took what it found); anything else leaves them unverified, so Play stays
 *  refused, and is tried again at the next request. Never while it runs. */
inline void verify_installed(const DriverConfig& cfg, ed::Job& j) {
    const std::string revision = ed::installed_revision(j);
    const fs::path dir = path_of(j.install_dir);
    std::error_code ec;
    if (revision.empty() || !fs::is_directory(dir, ec) || j.security_held) return;
    vc::Record prior;
    const bool have = j.scan_revision_id == revision && vc::read_record(vc::record_path(cfg.root, j.id), prior);
    const vc::Unverified u = vc::unverified(dir, have ? &prior : nullptr, revision);
    if (!u.whole && u.files.empty()) {
        if (j.scan_revision_id != revision) { j.scan_revision_id = revision; save(cfg, j); }
        return;
    }
    const vc::ScanPlan plan = vc::plan_scan(u, j.launch_exe);
    const bool whole = plan.whole;
    const fs::path scan_dir = path_of(j.install_root) / L".virule-staging" / (dir.filename().wstring() + L".scan");
    fs::remove_all(scan_dir, ec);
    const std::string since = ms::detail::utc_now();
    const auto keep_going = [&]() { return !stopping(cfg) && !game_busy(cfg, j.assignment_id); };
    ms::Result r;
    if (whole) {
        const ms::Extracted x = ms::extract_wrapped_originals(dir, scan_dir, keep_going);
        if (!x.ok) {
            if (x.blocked) r = ms::removed_by_antivirus(j.launch_exe, x.why);
            else { r.outcome = ms::Outcome::error; r.detail = x.why; }
        } else {
            r = ms::scan({dir, scan_dir}, since, keep_going, {});
        }
    } else if (plan.launch_changed) {
        const ms::Extracted x = ms::extract_wrapped_originals(dir, scan_dir, keep_going);
        if (!x.ok) {
            if (x.blocked) r = ms::removed_by_antivirus(j.launch_exe, x.why);
            else { r.outcome = ms::Outcome::error; r.detail = x.why; }
        } else {
            std::vector<fs::path> targets = vc::paths_of(dir, plan.targets);
            targets.push_back(scan_dir);
            r = ms::scan(targets, since, keep_going, {});
        }
    } else {
        r = ms::scan(vc::paths_of(dir, plan.targets), since, keep_going, {});
    }
    fs::remove_all(scan_dir, ec);
    j.scan_outcome = ms::outcome_name(r.outcome);
    if (r.outcome == ms::Outcome::clean) {
        const vc::Record next = vc::after_clean_scan(dir, have ? &prior : nullptr, revision, u.now,
                                                     whole ? std::vector<std::string>{} : u.files);
        if (vc::write_record(vc::record_path(cfg.root, j.id), next)) j.scan_revision_id = revision;
        else log(cfg, j.id + " the verified content record could not be written");
    } else if (ms::is_incident(r.outcome)) {
        j.security_held = true;
        j.incident = ms::incident_json(r, ed::random_hex32(), "launch", "", revision);
        j.incident_reported = false;
        j.error = kInstallThreat;
    }
    save(cfg, j);
    log(cfg, j.id + " installed content " + (whole ? "scan " : "verification of " + std::to_string(u.files.size()) + " file(s) ") +
        j.scan_outcome + ": " + r.detail.substr(0, 300));
}

inline void run_install(const DriverConfig& cfg, ed::Job& j, const std::string& email) {
    // A TRULY EXPIRED ASSIGNMENT installs and updates nothing again (owner
    // brief 2026-10-28; client/assignment_cleanup.hpp): what is there is
    // removed instead.
    if (vclient::assignment_cleanup::is_expired(cfg.root, j.assignment_id)) {
        j.state = "removing";
        j.next_attempt_utc = 0;
        save(cfg, j);
        log(cfg, j.id + ": the assignment expired; removing instead of installing");
        return;
    }
    if (j.account_email.empty()) { j.account_email = email; save(cfg, j); }
    if (j.account_email != email) return;
    // Paused: by the bridge's live request, or as the record says (a pause
    // recorded while nothing was running, or before a restart). Only an
    // explicit Resume (transfer_control) clears both.
    if (is_paused(j.assignment_id) || j.paused) {
        if (j.state == "queued" || j.state == "downloading") { j.state = "paused"; j.paused = true; save(cfg, j); }
        return;
    }
    const fs::path temp = path_of(j.temp_path);
    std::error_code ec;
    if (j.state == "queued" || j.state == "paused" || j.state == "downloading") {
        // The authorization: the revision, its size and digest, this
        // download's id. Asked on every start (the service answers the
        // standing one while it lasts, a new one once it lapsed).
        const Reply a = cfg.service->call("POST", "/v1/assignments/" + j.assignment_id + "/download", "{}", "application/json", {});
        if (a.status != 200) {
            if (a.status == 409 && body_code(a.body) == "no_build") { fail(cfg, j, body_message(a.body)); return; }
            // THE GAME IS HELD after a security detection (VIRULE_BACKEND
            // security.ts): a final answer until it is released, never retried.
            if (a.status == 409 && body_code(a.body) == "security_hold") { fail(cfg, j, body_message(a.body)); return; }
            if (a.status == 404 || a.status == 403) { fail(cfg, j, body_message(a.body)); return; }
            defer(cfg, j, a.status == 0 ? "Couldn't reach our servers right now." : body_message(a.body));
            return;
        }
        std::string did, rid, sha, launch;
        std::int64_t pbytes = 0, cbytes = 0, rev = 0;
        (void)js::find_string_in(a.body, 0, a.body.size(), "download_id", did);
        (void)js::find_string_in(a.body, 0, a.body.size(), "revision_id", rid);
        (void)js::find_string_in(a.body, 0, a.body.size(), "package_sha256", sha);
        (void)js::find_string_in(a.body, 0, a.body.size(), "launch_exe", launch);
        (void)ev::json::get_int(a.body, "package_bytes", pbytes);
        (void)ev::json::get_int(a.body, "content_bytes", cbytes);
        (void)ev::json::get_int(a.body, "revision", rev);
        if (!ev::is_hex32(did) || !ev::is_hex32(rid) || !ev::is_sha256_hex(sha) || launch.empty()) {
            defer(cfg, j, "The service answered with a malformed download.");
            return;
        }
        // A revision this computer's own scan blocked is never fetched again.
        if (revision_held_here(cfg.root, j.assignment_id, rid)) { j.security_held = true; j.revision_id = rid; fail(cfg, j, kInstallThreat); return; }
        if (rid != j.revision_id || sha != j.package_sha256) {
            // The service names another revision than this job was made for
            // (the developer replaced the build before the download began):
            // start over with it; nothing of the old partial file is kept.
            fs::remove(temp, ec);
            j.revision_id = rid; j.package_sha256 = sha; j.package_bytes = static_cast<std::uint64_t>(pbytes);
            j.content_bytes = static_cast<std::uint64_t>(cbytes); j.launch_exe = launch; j.revision = rev;
            j.bytes_done = 0; j.bytes_total = j.package_bytes;
        }
        j.download_id = did;
        j.package_bytes = static_cast<std::uint64_t>(pbytes);
        j.bytes_total = j.package_bytes;
        j.state = "downloading";
        j.paused = false;
        j.error.clear();
        // Resume from the partial file's length (never past the package).
        const auto have = fs::file_size(temp, ec);
        j.bytes_done = ec ? 0 : std::min<std::uint64_t>(static_cast<std::uint64_t>(have), j.package_bytes);
        if (!ec && static_cast<std::uint64_t>(have) > j.package_bytes) { fs::remove(temp, ec); j.bytes_done = 0; }
        save(cfg, j);
        fs::create_directories(temp.parent_path(), ec);
        FILE* out = nullptr;
        if (_wfopen_s(&out, temp.wstring().c_str(), L"ab") != 0 || !out) {
            // Real-time protection refused the package: a security outcome.
            if (ms::detail::blocked_by_antivirus_errno()) {
                std::vector<ms::Threat> seen;
                (void)antivirus_acted({temp}, j.created_utc, seen);
                scan_failed(cfg, j, removal_of(seen, j.temp_path, "Windows refused the downloaded package."), "download", temp, {});
                return;
            }
            defer(cfg, j, "The download could not be written.");
            return;
        }
        bool stopped = false;
        while (j.bytes_done < j.package_bytes) {
            if (stopping(cfg) || is_paused(j.assignment_id)) { stopped = true; break; }
            const std::uint64_t to = std::min<std::uint64_t>(j.package_bytes - 1, j.bytes_done + ed::kDownloadRangeBytes - 1);
            std::uint64_t got = 0;
            unsigned long status = 0;
            const bool okd = cfg.service->get_range_to_file("/v1/assignments/" + j.assignment_id + "/download/" + j.download_id,
                j.bytes_done, to, out, got, status, [&]() { return !stopping(cfg) && !is_paused(j.assignment_id); });
            fflush(out);
            if (!okd || status != 206) {
                if (status == 410 || status == 404 || status == 409) { j.download_id.clear(); save(cfg, j); }
                else defer(cfg, j, status == 0 ? "Couldn't reach our servers right now." : "The download was interrupted.");
                stopped = true;
                break;
            }
            j.bytes_done += got;
            j.attempts = 0;
            save(cfg, j);
            if (got == 0) { defer(cfg, j, "The download was interrupted."); stopped = true; break; }
        }
        fclose(out);
        if (stopped) {
            if (is_paused(j.assignment_id)) { j.state = "paused"; j.paused = true; save(cfg, j); }
            return;
        }
        j.state = "verifying";
        save(cfg, j);
    }
    if (j.state == "verifying") {
        std::string sha;
        const bool hashed = sha256_file_hex(temp, sha, [&]() { return !stopping(cfg); });
        if (!hashed && stopping(cfg)) return;
        // THE ANTIVIRUS TOOK OR REFUSED THE PACKAGE (a stored zip with a
        // threat is removed whole), as Defender's record says: a security
        // outcome, never a re-download. A package that merely went missing
        // with no such record (a cleanup, the person) is retried as before.
        {
            std::vector<ms::Threat> seen;
            if (antivirus_acted({temp}, j.created_utc, seen)) {
                scan_failed(cfg, j, removal_of(seen, j.temp_path, "The downloaded package was removed or refused by the antivirus."), "download", temp, {});
                return;
            }
        }
        if (!hashed) { defer(cfg, j, "The download could not be verified."); return; }
        if (sha != j.package_sha256) {
            (void)cfg.service->call("POST", "/v1/assignments/" + j.assignment_id + "/download/" + j.download_id + "/failed",
                "{\"reason\":\"integrity\"}", "application/json", {});
            fs::remove(temp, ec);
            j.download_id.clear();
            j.bytes_done = 0;
            fail(cfg, j, "The downloaded game did not verify. Install it again.");
            return;
        }
        j.state = "extracting";
        save(cfg, j);
    }
    // A scan interrupted mid-way starts again from the verified package.
    if (j.state == "extracting" || j.state == "scanning") {
        const fs::path dst = path_of(j.install_dir);
        const fs::path staging = path_of(j.install_root) / L".virule-staging" / dst.filename();
        const bool updating = fs::exists(dst, ec);
        // NEVER WHILE IT RUNS: an update waits for the game and its panels
        // to close (looked at again shortly, not on the failure ladder).
        if (updating && game_busy(cfg, j.assignment_id)) {
            j.error = "Close the game to finish the update.";
            j.next_attempt_utc = now_of(cfg) + kWhileRunningSeconds;
            save(cfg, j);
            return;
        }
        fs::remove_all(staging, ec);
        fs::create_directories(staging, ec);
        std::string why;
        const std::string extract_since = ms::detail::utc_now();
        if (!extract_zip(temp, staging, why, [&]() { return !stopping(cfg); })) {
            if (stopping(cfg)) { fs::remove_all(staging, ec); return; }
            // The antivirus refused or took a file while it was written out.
            std::vector<ms::Threat> seen;
            if (antivirus_acted({staging, temp}, extract_since, seen)) {
                scan_failed(cfg, j, removal_of(seen, why, "A game file was refused or removed by the antivirus while it was extracted."), "install", temp, staging);
                return;
            }
            fs::remove_all(staging, ec);
            fail(cfg, j, why);
            return;
        }
        if (!fs::is_regular_file(staging / path_of(j.launch_exe), ec) || ec) {
            std::vector<ms::Threat> seen;
            if (antivirus_acted({staging, temp}, extract_since, seen)) {
                scan_failed(cfg, j, removal_of(seen, j.launch_exe, "The game's launch file was removed by the antivirus."), "install", temp, staging);
                return;
            }
            fs::remove_all(staging, ec);
            fail(cfg, j, "The installed game has no " + j.launch_exe + ".");
            return;
        }
        // SCAN THE DELIVERED BUILD before it is placed (header): every file
        // extracted, and the original executable copied out of the wrapper
        // (which the antivirus does not open), never run. Only clean goes on.
        // What it scanned is recorded once placed (verified_content.hpp).
        vc::Inventory delivered;
        {
            j.state = "scanning";
            save(cfg, j);
            (void)vc::inventory(staging, delivered);
            const fs::path scan_dir = path_of(j.install_root) / L".virule-staging" / (dst.filename().wstring() + L".scan");
            fs::remove_all(scan_dir, ec);
            const ms::Extracted x = ms::extract_wrapped_originals(staging, scan_dir, [&]() { return !stopping(cfg); });
            ms::Result r;
            if (!x.ok) {
                if (stopping(cfg)) { fs::remove_all(scan_dir, ec); fs::remove_all(staging, ec); return; }
                if (x.blocked) r = ms::removed_by_antivirus(j.launch_exe, x.why);
                else { r.outcome = ms::Outcome::error; r.detail = x.why; r.scanner = "Microsoft Defender Antivirus"; }
            } else {
                r = ms::scan({staging, scan_dir}, extract_since, [&]() { return !stopping(cfg); }, {});
            }
            fs::remove_all(scan_dir, ec);
            if (r.outcome == ms::Outcome::canceled && stopping(cfg)) { fs::remove_all(staging, ec); return; }
            if (r.outcome != ms::Outcome::clean) { scan_failed(cfg, j, r, "install", temp, staging); return; }
            // Recorded with the revision only once it is PLACED (below), so a
            // failed update never leaves the installed one looking unscanned.
            j.scan_outcome = "clean";
            save(cfg, j);
        }
        // The record of what was verified in the folder being replaced: the
        // evaluator's own files carried over (below) stay verified only if
        // they are exactly what that record vouched for.
        vc::Record previous;
        const bool had_previous = updating && vc::read_record(vc::record_path(cfg.root, j.id), previous);
        if (updating) {
            // THE GAME'S OWN FILES STAY: everything in the installed folder
            // the new package does not carry (saves, settings the game
            // wrote, the wrapper's log) is copied into the new folder before
            // it replaces the old one. What the package carries is the
            // developer's new version.
            if (!carry_over(dst, staging, why)) {
                fs::remove_all(staging, ec);
                defer(cfg, j, why);
                return;
            }
            if (game_busy(cfg, j.assignment_id)) {   // started meanwhile
                fs::remove_all(staging, ec);
                j.error = "Close the game to finish the update.";
                j.next_attempt_utc = now_of(cfg) + kWhileRunningSeconds;
                save(cfg, j);
                return;
            }
        }
        // THE SERVICE'S CURRENT WORD BEFORE ANYTHING IS PLACED (owner brief
        // 2026-10-30 section 3: a current authorization that the game is not
        // held, before installation): the launch chain is asked for now, and
        // a held game is refused here, the installed folder untouched.
        {
            const ChainOutcome chain = ensure_launch_chain(cfg, j.assignment_id, j.install_dir, j.launch_exe, j.revision_id);
            if (!chain.ok) {
                fs::remove_all(staging, ec);
                if (chain.code == "security_hold") { fs::remove(temp, ec); fail(cfg, j, chain.why); return; }
                if (chain.retryable) defer(cfg, j, chain.why); else fail(cfg, j, chain.why);
                return;
            }
        }
        // One rename into place, WITH A WAY BACK: the previous folder steps
        // aside, the new one moves in, and only then does the previous one
        // go; if the new one cannot move in, the previous one is put back.
        const fs::path old = path_of(j.install_root) / L".virule-staging" / (dst.filename().wstring() + L".old");
        if (updating) {
            fs::remove_all(old, ec);
            fs::rename(dst, old, ec);
            if (ec) { fs::remove_all(staging, ec); defer(cfg, j, "The previous installation is in use. Close the game and try again."); return; }
        }
        fs::rename(staging, dst, ec);
        if (ec) {
            std::error_code back;
            if (updating) fs::rename(old, dst, back);
            fs::remove_all(staging, ec);
            if (updating && !back) { defer(cfg, j, "The update could not be put in place. The installed game is unchanged."); return; }
            fail(cfg, j, "The game could not be placed in its folder.");
            return;
        }
        if (updating) fs::remove_all(old, ec);
        // THE VERIFIED CONTENT RECORD of what was just placed: the delivered
        // files as scanned, and the carried-over files the previous record
        // vouched for. Anything else carried over is verified below, before
        // Play is offered.
        {
            vc::Record placed = vc::after_clean_scan(dst, nullptr, j.revision_id, delivered, {});
            if (had_previous) {
                vc::Inventory now;
                if (vc::inventory(dst, now)) {
                    for (const auto& [k, seen] : now) {
                        if (placed.files.count(k) || delivered.count(k)) continue;
                        const auto p = previous.files.find(k);
                        if (p != previous.files.end() && p->second == seen) placed.files[k] = seen;
                    }
                }
            }
            if (!vc::write_record(vc::record_path(cfg.root, j.id), placed)) log(cfg, j.id + " the verified content record could not be written");
        }
        const Reply done = cfg.service->call("POST", "/v1/assignments/" + j.assignment_id + "/download/" + j.download_id + "/complete",
            "{\"sha256\":\"" + j.package_sha256 + "\",\"bytes\":" + std::to_string(j.package_bytes) + "}", "application/json", {});
        if (done.status != 200) {
            // THE GAME WAS HELD while this computer installed it: final, never
            // retried (the next pass would extract and scan it all again).
            if (done.status == 409 && body_code(done.body) == "security_hold") {
                fs::remove(temp, ec);
                fail(cfg, j, body_message(done.body));
                return;
            }
            if (done.status == 409 && body_code(done.body) == "conflict") {
                // The download row is over (a failure was recorded before);
                // ask again and report with the new id next pass.
                j.download_id.clear(); j.state = "queued"; save(cfg, j); return;
            }
            defer(cfg, j, done.status == 0 ? "Couldn't reach our servers right now." : body_message(done.body));
            return;
        }
        fs::remove(temp, ec);
        // The service's progress for the assignment first (bounded, best
        // effort), so an installed game's first launch already states the
        // assignment's whole history (a fresh installation).
        if (cfg.after_install) cfg.after_install(j.assignment_id);
        j.state = "installed";
        // The revision now on this computer's disk (ed::installed_revision):
        // what the Admin compares with the service's required one.
        j.installed_revision_id = j.revision_id;
        j.scan_revision_id = j.revision_id;   // scanned clean above, now placed
        j.bytes_done = j.package_bytes;
        j.permille = 1000;
        j.error.clear();
        j.attempts = 0;
        save(cfg, j);
        log(cfg, j.id + " installed: " + j.install_dir + " (revision " + j.revision_id + ")");
    }
}

} // namespace detail

struct PassResult {
    std::int64_t next_due_utc = 0;   // 0 = nothing pending
};

// One pass over every job that is the Client's to move.
inline PassResult run_pass(const DriverConfig& cfg, std::map<std::string, std::int64_t>& last_resume) {
    using namespace detail;
    PassResult pr;
    const std::int64_t t = now_of(cfg);
    std::string email;
    const bool signed_in = cfg.service->signed_in(email);
    // Once per process, signed in: every installed assignment's progress
    // from the service (a Client that just started, a fresh installation).
    static std::set<std::string> synced;
    // Released (the developer's evaluations changed): every held upload is
    // asked again in this pass, whatever its wait.
    bool release = false;
    {
        std::lock_guard<std::mutex> lock(controls().m);
        release = controls().release_held;
        controls().release_held = false;
    }
    for (const ed::Job& j : ed::list_jobs(cfg.root)) {
        if (!signed_in || !cfg.after_install || !ed::is_install(j) || j.state != "installed") continue;
        if (!synced.insert(j.assignment_id).second) continue;
        cfg.after_install(j.assignment_id);
    }
    for (ed::Job j : ed::list_jobs(cfg.root)) {
        if (stopping(cfg)) break;
        // SECURITY (2026-10-30): an incident the service has not recorded yet
        // is sent, a failed job's included (it is retried every pass until
        // the service answers).
        if (signed_in && !j.incident.empty() && !j.incident_reported) report_incident(cfg, j);
        // THE INSTALLED CONTENT IS VERIFIED before its next Play (the
        // launcher refuses until then; verified_content.hpp), never while it
        // runs: at once when asked (the launcher found unverified files, the
        // game's last process exited) and at this driver's first pass; a
        // game never scanned (installed before scanning existed) is also
        // tried at most every kRescanEverySeconds.
        if (ed::is_install(j) && j.state == "installed" && !j.security_held && !game_busy(cfg, j.assignment_id)) {
            static std::map<std::string, std::int64_t> last_scan;
            static std::set<std::string> looked;
            bool asked = false;
            {
                std::lock_guard<std::mutex> lock(controls().m);
                asked = controls().verify.erase(j.assignment_id) > 0;
            }
            const bool first = looked.insert(j.id).second;
            const auto it = last_scan.find(j.id);
            const bool legacy_due = j.scan_revision_id != ed::installed_revision(j) &&
                (it == last_scan.end() || t - it->second >= kRescanEverySeconds);
            if (asked || first || legacy_due) {
                last_scan[j.id] = t;
                verify_installed(cfg, j);
            }
        }
        if (ed::is_terminal(j)) continue;
        // A failed install the person asked to try again.
        {
            std::lock_guard<std::mutex> lock(controls().m);
            if (ed::is_install(j) && controls().retry.erase(j.assignment_id) && j.state == "failed" && !j.security_held) {
                j.state = "queued"; j.error.clear(); j.attempts = 0; j.next_attempt_utc = 0; save(cfg, j);
            }
        }
        if (ed::is_upload(j) && (j.state == "building" || j.state == "packaging" ||
                                 j.state == "scanning_source" || j.state == "scanning_package")) {
            // The Admin host's stage. Stalled: start the host headless, rarely.
            if (ed::process_alive(j.owner_pid)) continue;
            const auto it = last_resume.find(j.id);
            if (it != last_resume.end() && t - it->second < kResumeEverySeconds) {
                pr.next_due_utc = pr.next_due_utc ? std::min(pr.next_due_utc, it->second + kResumeEverySeconds) : it->second + kResumeEverySeconds;
                continue;
            }
            last_resume[j.id] = t;
            if (cfg.resume_headless && cfg.resume_headless(j)) log(cfg, j.id + ": the Admin host was started to finish the build");
            pr.next_due_utc = pr.next_due_utc ? std::min(pr.next_due_utc, t + kResumeEverySeconds) : t + kResumeEverySeconds;
            continue;
        }
        if (release && ed::is_held(j)) j.next_attempt_utc = 0;
        if (j.next_attempt_utc > t && j.next_attempt_utc - t <= kBackoffCap) {
            pr.next_due_utc = pr.next_due_utc ? std::min(pr.next_due_utc, j.next_attempt_utc) : j.next_attempt_utc;
            continue;
        }
        if (!signed_in) continue;   // the job waits for its account
        if (ed::is_upload(j)) run_upload(cfg, j, email);
        else if (ed::is_install(j) && j.state == "removing") run_removal(cfg, j);
        else if (ed::is_install(j)) run_install(cfg, j, email);
        if (!ed::is_terminal(j) && j.next_attempt_utc > t) {
            pr.next_due_utc = pr.next_due_utc ? std::min(pr.next_due_utc, j.next_attempt_utc) : j.next_attempt_utc;
        }
    }
    return pr;
}

// The transfer thread's whole life. Returns when stop_event is set.
inline void run_driver(const DriverConfig& cfg, HANDLE wake) {
    if (!cfg.service || !cfg.stop_event) return;
    std::map<std::string, std::int64_t> last_resume;
    for (;;) {
        if (cfg.paused && cfg.paused()) {
            if (WaitForSingleObject(cfg.stop_event, kPausedPollMs) == WAIT_OBJECT_0) break;
            continue;
        }
        const PassResult r = run_pass(cfg, last_resume);
        if (detail::stopping(cfg)) break;
        DWORD wait_ms = INFINITE;
        if (r.next_due_utc > 0) {
            const std::int64_t s = std::clamp<std::int64_t>(r.next_due_utc - detail::now_of(cfg), 1, kBackoffCap);
            wait_ms = (DWORD)(s * 1000);
        }
        if (!wake) wait_ms = std::min<DWORD>(wait_ms, kPollWithoutWakeMs);
        HANDLE hs[2] = { cfg.stop_event, wake };
        const DWORD w = WaitForMultipleObjects(wake ? 2 : 1, hs, FALSE, wait_ms);
        if (w == WAIT_OBJECT_0) break;
        if (w == WAIT_FAILED) Sleep(1000);
    }
}

// The report was acknowledged (main.cpp, from the evidence driver): the
// assignment's installed game starts removing itself. True when a job was
// set to remove.
inline bool begin_removal(const fs::path& root, const std::string& assignment_id) {
    ed::Job j;
    if (!ed::install_for_assignment(root, assignment_id, j)) return false;
    if (j.state == "removed" || j.state == "removing") return false;
    j.state = "removing";
    j.next_attempt_utc = 0;
    j.updated_utc = utc_now();
    return ed::write_job(root, j);
}

// The bridge's transfer_status (local only): every job, bounded.
inline std::string status_json(const fs::path& root) {
    std::string out = "{\"type\":\"transfer_status\",\"jobs\":[";
    bool first = true;
    size_t n = 0;
    for (const auto& j : ed::list_jobs(root)) {
        if (++n > 20) break;
        if (!first) out += ",";
        first = false;
        out += "{\"id\":" + ev::json::quote(j.id) + ",\"kind\":" + ev::json::quote(j.kind) + ",\"state\":" + ev::json::quote(j.state) +
            ",\"bytes_done\":" + std::to_string(j.bytes_done) + ",\"bytes_total\":" + std::to_string(j.bytes_total) +
            ",\"assignment_id\":" + ev::json::quote(j.assignment_id) + ",\"game_id\":" + ev::json::quote(j.game_id) + "}";
    }
    return out + "]}";
}

} // namespace vclient::transfers
