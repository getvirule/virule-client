#pragma once
// THE VERIFIED CONTENT RECORD of an installed evaluation game (owner brief
// 2026-10-30, "Finalize Malware Scanning", section 3: before every Play,
// "verification that the installed game content corresponds to the
// previously scanned content and has not been modified since
// verification"; docs/EVALUATION_VIRULE.md 9b). Header only, no antivirus
// code (the wrapper includes it), vendored byte-identical into virule-client
// as evaluation_distribution.hpp is.
//
// WHAT IT IS. When a scan of an installed game's folder comes back clean,
// the VIRULE Client writes, beside the install job
// (<root>\transfers\<job id>\verified.txt), every regular file under the
// folder that the scan covered: its path relative to the folder, its size
// and its last write time, and the revision the scan was for. Before every
// Play the folder is walked again (metadata only) and compared:
//   - a file NEW or CHANGED since the record is UNVERIFIED: Play waits until
//     it is scanned, and the record then takes it in. ONLY THOSE FILES are
//     scanned (plan_scan): a new folder whose every file is new is one
//     target, and the wrapper's original executable is copied out only when
//     the launch file itself changed. However many files a session wrote,
//     the unchanged files keep their verification and are never scanned
//     again (owner decisions 2026-10-30, VIRULE/docs/specs/
//     evaluation-security.md "Scan cadence": no full antivirus scan merely
//     because Play is clicked; changed content is verified again);
//   - a file GONE is not unscanned content and needs no scan;
//   - no record, a record of another revision (an update or a replacement
//     build), or one that cannot be read means nothing is verified: the
//     whole folder is scanned, the only full scan after the install's own.
// So the wrapper's own log, the game's saves and the executable the
// wrapper extracts at run time are scanned before the next Play after they
// change, never trusted because they were written by a game that once
// scanned clean, and an unchanged game is never scanned again.
//
// WHAT IT IS NOT (stated, never overstated). Size and write time are what a
// metadata walk can afford for a 100 GB game at every Play; they catch any
// ordinary change (a game, a tool, a person editing a file, a partial copy)
// but not a person who deliberately rewrites a file and restores its size
// and time on a computer they control. Nothing on an evaluator's own
// Windows account can stop deliberate local tampering by that person; this
// record makes accidental and ordinary modification impossible to miss.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include "virule/core/evaluation_distribution.hpp"
#include "virule/core/evaluation_evidence.hpp"

namespace virule::core::verified_content {

namespace fs = std::filesystem;

inline constexpr const char* kRecordFormat = "virule-verified-content.v1";
inline constexpr const wchar_t* kRecordFileName = L"verified.txt";
// A record is a line per file: a 100 GB game of a million files fits.
inline constexpr std::uintmax_t kMaxRecordBytes = 256u * 1024u * 1024u;

struct Seen {
    std::uint64_t size = 0;
    std::int64_t mtime = 0;
    bool operator==(const Seen& o) const { return size == o.size && mtime == o.mtime; }
};

// Relative path (lower case, '/' separators) -> what was seen.
using Inventory = std::map<std::string, Seen>;

struct Record {
    std::string revision_id;
    Inventory files;
};

inline fs::path record_path(const fs::path& virule_root, const std::string& job_id) {
    return virule::core::evaluation_distribution::job_dir(virule_root, job_id) / kRecordFileName;
}

namespace detail {

inline std::string key_of(const fs::path& rel) {
    const std::u8string u = rel.generic_u8string();
    std::string s(u.begin(), u.end());
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

inline fs::path path_of_key(const std::string& key) {
    return fs::path(std::u8string(key.begin(), key.end()));
}

} // namespace detail

/** Every regular file under `dir` (links never followed): size and write
 *  time by relative path. False when the folder cannot be walked whole. */
inline bool inventory(const fs::path& dir, Inventory& out) {
    out.clear();
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return false;
    for (auto it = fs::recursive_directory_iterator(dir, fs::directory_options::none, ec);
         !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        // An entry whose status cannot be read is never skipped: the walk
        // fails, so nothing is vouched for (a scan of the whole folder; the
        // wrapper's check refuses).
        std::error_code fec;
        const bool link = it->is_symlink(fec);
        if (fec) return false;
        if (link) { if (it->is_directory(fec)) it.disable_recursion_pending(); continue; }
        const bool regular = it->is_regular_file(fec);
        if (fec) return false;
        if (!regular) continue;
        Seen s;
        s.size = static_cast<std::uint64_t>(it->file_size(fec));
        if (fec) return false;
        s.mtime = static_cast<std::int64_t>(it->last_write_time(fec).time_since_epoch().count());
        if (fec) return false;
        out[detail::key_of(it->path().lexically_relative(dir))] = s;
    }
    return !ec;
}

inline bool write_record(const fs::path& path, const Record& r) {
    std::string o = std::string(kRecordFormat) + "\n" + r.revision_id + "\n";
    for (const auto& [k, s] : r.files) {
        o += std::to_string(s.size) + "\t" + std::to_string(s.mtime) + "\t" + k + "\n";
    }
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    return virule::core::evaluation_evidence::write_file_atomic(path, o);
}

/** False for a missing, foreign or damaged record (nothing is verified). */
inline bool read_record(const fs::path& path, Record& out) {
    out = Record{};
    std::error_code ec;
    const auto bytes = fs::file_size(path, ec);
    if (ec || bytes == 0 || bytes > kMaxRecordBytes) return false;
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (text.size() != bytes) return false;
    std::size_t at = 0;
    auto line = [&](std::string& l) -> bool {
        if (at >= text.size()) return false;
        const std::size_t nl = text.find('\n', at);
        if (nl == std::string::npos) return false;   // every line ends: a cut file is damaged
        l = text.substr(at, nl - at);
        if (!l.empty() && l.back() == '\r') l.pop_back();
        at = nl + 1;
        return true;
    };
    std::string l;
    if (!line(l) || l != kRecordFormat) return false;
    if (!line(out.revision_id) || out.revision_id.empty()) return false;
    while (at < text.size()) {
        if (!line(l)) return false;
        const std::size_t t1 = l.find('\t');
        const std::size_t t2 = t1 == std::string::npos ? std::string::npos : l.find('\t', t1 + 1);
        if (t2 == std::string::npos || t2 + 1 >= l.size()) return false;
        Seen s;
        try {
            s.size = std::stoull(l.substr(0, t1));
            s.mtime = std::stoll(l.substr(t1 + 1, t2 - t1 - 1));
        } catch (...) { return false; }
        out.files[l.substr(t2 + 1)] = s;
    }
    return true;
}

/** The files under `dir` that the record does not vouch for (new or
 *  changed), as relative keys. `whole` is true when nothing can be
 *  vouched for (no record, another revision, an unreadable folder). */
struct Unverified {
    bool whole = false;
    std::vector<std::string> files;
    Inventory now;   // the walk the answer was made from
};

inline Unverified unverified(const fs::path& dir, const Record* record, const std::string& revision_id) {
    Unverified u;
    if (!inventory(dir, u.now) || !record || record->revision_id != revision_id || revision_id.empty()) {
        u.whole = true;
        return u;
    }
    for (const auto& [k, s] : u.now) {
        const auto it = record->files.find(k);
        if (it == record->files.end() || !(it->second == s)) u.files.push_back(k);
    }
    return u;
}

/** Is the whole folder verified for `revision_id` right now? The check
 *  before every Play (the Client's launcher, the wrapper). */
inline bool verified_now(const fs::path& virule_root, const std::string& job_id, const fs::path& dir,
                         const std::string& revision_id) {
    Record r;
    const bool have = read_record(record_path(virule_root, job_id), r);
    const Unverified u = unverified(dir, have ? &r : nullptr, revision_id);
    return !u.whole && u.files.empty();
}

/**
 * THE WRAPPER'S LOCAL CHECK (owner brief 2026-10-30 section 3: no other
 * VIRULE entry point may bypass verification by accident; the double-click
 * of the launch file, the Admin host's development start and the post-game
 * Play all run the wrapper, never the Client's launcher). Run after the
 * wrapper's online authorization and before the game starts, from the
 * Client's own records on this computer:
 *   - the assignment has an install job, installed, in THIS folder;
 *   - neither this computer's detection (`security_held`) nor the service's
 *     hold marker (virule-client security_marks.hpp:
 *     <root>\evaluator\assignments\<id>\security_hold) is set;
 *   - the installed revision scanned clean and its record is this revision's;
 *   - every file the record vouches for is still exactly as recorded (one
 *     missing is not unscanned content).
 * Files the record never saw are NOT judged here: the Client's launcher
 * scans them before its Play, and its exit hook as soon as the game closes.
 * So the post-game Play in the wrapper's own panel, and a double-click after
 * a session, may start the game with files that game itself wrote in its
 * last session not yet scanned (reported; the strict check is the Client's).
 * The wrapper's own log (.virule/logs/), appended at every start before
 * this check runs, is never judged here.
 */
enum class LaunchCheck { ok, not_installed, elsewhere, updating, held, not_verified };

// The launch file is always a bare file name at the folder's root (the
// service refuses any other: VIRULE_BACKEND distribution.ts EXE_NAME), so
// the wrapper's own folder IS the installed folder.
inline LaunchCheck wrapper_launch_check(const fs::path& virule_root, const std::string& assignment_id, const fs::path& wrapper_dir) {
    namespace ed = virule::core::evaluation_distribution;
    ed::Job job;
    if (!ed::install_for_assignment(virule_root, assignment_id, job)) return LaunchCheck::not_installed;
    if (job.state != "installed") return LaunchCheck::updating;
    std::error_code ec;
    const fs::path dir = fs::path(std::u8string(job.install_dir.begin(), job.install_dir.end()));
    if (job.install_dir.empty() || !fs::equivalent(dir, wrapper_dir, ec) || ec) return LaunchCheck::elsewhere;
    if (job.security_held) return LaunchCheck::held;
    const fs::path marker = virule_root / L"evaluator" / L"assignments" /
        fs::path(std::wstring(assignment_id.begin(), assignment_id.end())) / L"security_hold";
    if (fs::exists(marker, ec)) return LaunchCheck::held;
    const std::string revision = ed::installed_revision(job);
    if (revision.empty() || job.scan_revision_id != revision) return LaunchCheck::not_verified;
    Record r;
    if (!read_record(record_path(virule_root, job.id), r) || r.revision_id != revision) return LaunchCheck::not_verified;
    Inventory now;
    if (!inventory(dir, now)) return LaunchCheck::not_verified;
    for (const auto& [k, s] : r.files) {
        if (k.rfind(".virule/logs/", 0) == 0) continue;
        const auto it = now.find(k);
        if (it != now.end() && !(it->second == s)) return LaunchCheck::not_verified;
    }
    return LaunchCheck::ok;
}

/**
 * WHAT A VERIFICATION SCANS (header, "only those files"). `whole`: no valid
 * record (the first verification of this revision): the folder and the
 * wrapper's original. Otherwise `targets` covers exactly the unverified
 * files: a file on its own, or the highest folder whose every file is
 * unverified (a new Saves or cache folder is one target, never hundreds),
 * and never a folder holding a file the record still vouches for.
 * `launch_changed`: the launch file is among them, so its wrapped original
 * is copied out and scanned too.
 */
struct ScanPlan {
    bool whole = false;
    bool launch_changed = false;
    std::vector<std::string> targets;   // relative keys: files or folders
};

inline ScanPlan plan_scan(const Unverified& u, const std::string& launch_exe) {
    ScanPlan p;
    if (u.whole) { p.whole = true; return p; }
    const std::string launch = detail::key_of(fs::path(std::u8string(launch_exe.begin(), launch_exe.end())));
    const std::set<std::string> unverified(u.files.begin(), u.files.end());
    // Folders holding at least one file that is still verified.
    std::set<std::string> mixed;
    for (const auto& [k, s] : u.now) {
        if (unverified.count(k)) continue;
        for (std::size_t at = k.find('/'); at != std::string::npos; at = k.find('/', at + 1)) mixed.insert(k.substr(0, at));
    }
    std::set<std::string> chosen;
    for (const auto& k : u.files) {
        if (k == launch) p.launch_changed = true;
        std::string target = k;
        for (std::size_t at = k.find('/'); at != std::string::npos; at = k.find('/', at + 1)) {
            const std::string folder = k.substr(0, at);
            if (!mixed.count(folder)) { target = folder; break; }   // the highest folder of only unverified files
        }
        chosen.insert(target);
    }
    p.targets.assign(chosen.begin(), chosen.end());
    return p;
}

/** The absolute paths of unverified files, for a scan of only those. */
inline std::vector<fs::path> paths_of(const fs::path& dir, const std::vector<std::string>& keys) {
    std::vector<fs::path> out;
    // Native separators: Defender's command line tool reads a path with a
    // forward slash as nothing to scan (it starts and stops without a word).
    for (const auto& k : keys) out.push_back((dir / detail::path_of_key(k)).make_preferred());
    return out;
}

/**
 * After a CLEAN scan: the record vouches for what the scan covered. `before`
 * is the walk taken before the scan; `covered` the keys it scanned (empty =
 * the whole folder). A file is taken in only if it is still exactly as it
 * was before the scan; one that changed meanwhile stays unverified, so the
 * next Play scans it.
 */
inline Record after_clean_scan(const fs::path& dir, const Record* prior, const std::string& revision_id,
                               const Inventory& before, const std::vector<std::string>& covered) {
    Record r;
    r.revision_id = revision_id;
    Inventory now;
    if (!inventory(dir, now)) return r;
    const std::set<std::string> scanned(covered.begin(), covered.end());
    const bool whole = covered.empty();
    for (const auto& [k, s] : now) {
        const auto b = before.find(k);
        const bool unchanged_since_scan = b != before.end() && b->second == s;
        if (unchanged_since_scan && (whole || scanned.count(k))) { r.files[k] = s; continue; }
        if (prior && prior->revision_id == revision_id) {
            const auto p = prior->files.find(k);
            if (p != prior->files.end() && p->second == s) r.files[k] = s;
        }
    }
    return r;
}

} // namespace virule::core::verified_content
