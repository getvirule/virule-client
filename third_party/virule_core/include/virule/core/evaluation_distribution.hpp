#pragma once
// EVALUATION GAME DISTRIBUTION: the one contract the Admin, the Admin host
// and the VIRULE Client share for Build for Evaluation's background job and
// the evaluator's install (docs/EVALUATION_VIRULE.md section 3 and 9;
// VIRULE_BACKEND docs/EVALUATIONS.md "Hosted evaluation builds").
//
// VENDORED BYTE-IDENTICAL into virule-client/third_party/virule_core. It
// includes nothing but the C++ standard library, evaluation_evidence.hpp
// (the tolerant JSON reader, the atomic writer, the data root) and, on
// Windows, <windows.h>. No other VIRULE header.
//
// THE FIGURES (the same values as the service's policy.ts):
//   kGameMaxBytes        20 GB, binary gigabytes, measured on the game's
//                        distributable CONTENTS before packaging: the one
//                        byte definition in the Admin, the Client and the
//                        service. A 22 GB game packaged to 15 GB is over it.
//   kPartBytes           32 MiB, every upload part but the last.
//   kDownloadRangeBytes  64 MiB, one ranged read of the package.
//
// THE JOB is the one durable record of a Build for Evaluation (kind
// "upload") or of an evaluator's install (kind "install"), at
// <virule_root>\transfers\<job_id>\job.json, written atomically by whoever
// owns the current stage: the Admin host builds and packages an upload job
// and hands it over as `packaged`; the Client carries it from there
// (uploading, registering, done) and owns an install job entirely. The
// Admin only ever reads jobs (GetEvaluationDelivery, GetAssignmentInstalls)
// and shows them on the one progress meter. One job per game at a time
// (the newest `upload` job of a game is the game's delivery); one install
// job per assignment.
//
// UPLOAD STATES   building -> packaging -> packaged -> uploading -> registering -> done | failed
// INSTALL STATES  queued -> downloading (paused) -> verifying -> extracting -> installed | failed
//                 installed -> queued (an UPDATE: the same job moves on to a newer revision;
//                              the installed revision stays on disk until the verified
//                              replacement is swapped in, and the game's own files that
//                              the new package does not carry, its saves, are kept)
//                 installed -> removing -> removed (the report acknowledged: the game
//                              removes itself, never while it runs)
//
// Whoever resumes a job after a crash restarts the stage it was in from
// the job's immutable inputs (the build output, the package), never from a
// guessed byte offset: an upload resumes by the parts the service holds, a
// download by the bytes of its partial file.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "virule/core/evaluation_evidence.hpp"

#if defined(_WIN32)
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace virule::core::evaluation_distribution {

namespace ev = virule::core::evaluation_evidence;
namespace js = virule::core::evaluation_evidence::json;

inline constexpr std::uint64_t kGiB = 1024ull * 1024ull * 1024ull;
inline constexpr std::uint64_t kGameMaxBytes = 20ull * kGiB;
inline constexpr std::uint64_t kPackageOverheadMaxBytes = 256ull * 1024ull * 1024ull;
inline constexpr std::uint64_t kPartBytes = 32ull * 1024ull * 1024ull;
inline constexpr std::uint64_t kDownloadRangeBytes = 64ull * 1024ull * 1024ull;
inline constexpr const char* kJobFormat = "virule-transfer-job.v1";
inline constexpr const char* kJobFileName = "job.json";
inline constexpr const wchar_t* kTransfersDirName = L"transfers";
// Signalled by whoever hands a job to the Client (the Admin host after
// packaging, the Admin's Install) so the Client's driver starts at once.
inline constexpr const wchar_t* kWakeEventName = L"Local\\VIRULE.Transfers.Wake";
// The manifest written beside the package (the file list, the launch file,
// the digests), kept with the build output for retries and inspection.
inline constexpr const char* kPackageManifestFormat = "virule-evaluation-package.v1";

// ---------------------------------------------------------- sizes ----

// "23 GB", "19.5 GB": whole binary gigabytes, one decimal where it matters
// (the service formats the same way).
inline std::string format_gb(std::uint64_t bytes) {
    const double gb = static_cast<double>(bytes) / static_cast<double>(kGiB);
    const long long tenths = static_cast<long long>(gb * 10.0 + 0.5);
    char buf[64];
    if (tenths % 10 == 0) std::snprintf(buf, sizeof(buf), "%lld GB", tenths / 10);
    else std::snprintf(buf, sizeof(buf), "%lld.%lld GB", tenths / 10, tenths % 10);
    return buf;
}

// The one sentence for a game over the cap (owner copy shape, 2026-10-20).
inline std::string too_large_sentence(std::uint64_t bytes) {
    return "This game is " + format_gb(bytes) + ". The limit is " + format_gb(kGameMaxBytes) + ".";
}

inline bool within_cap(std::uint64_t content_bytes) { return content_bytes <= kGameMaxBytes; }

inline std::uint64_t parts_total(std::uint64_t package_bytes) {
    return package_bytes == 0 ? 1 : (package_bytes + kPartBytes - 1) / kPartBytes;
}

inline std::uint64_t part_bytes(std::uint64_t package_bytes, std::uint64_t n) {
    const std::uint64_t total = parts_total(package_bytes);
    if (n < total) return kPartBytes;
    return package_bytes - (total - 1) * kPartBytes;
}

// ------------------------------------------------------------ the job ----

struct Job {
    std::string format = kJobFormat;
    std::string id;                 // 32 hex
    std::string kind;               // "upload" | "install"
    std::string state;
    std::string error;              // the last failure, one sentence
    std::string account_email;      // the signed-in account the job belongs to (lower case)
    std::string game_uuid;
    std::string build_uuid;
    std::string created_utc, updated_utc;
    std::int64_t attempts = 0;
    std::int64_t next_attempt_utc = 0;   // 0 = due now
    // The stage's progress: what has moved of what, and a per-mille figure
    // for a stage measured by other means (the build's own stages).
    std::uint64_t bytes_done = 0;
    std::uint64_t bytes_total = 0;
    std::int64_t permille = 0;
    // ---- upload (the Admin host writes these; the Client reads them)
    std::string game_id;            // the Admin's local game id
    std::string admin_host_exe;     // for a headless resume of a stalled build or packaging
    std::string admin_data_root;
    std::int64_t owner_pid = 0;     // the process building or packaging now
    std::string package_path;       // the zip
    std::string manifest_path;      // the package manifest beside it
    std::string launch_exe;
    std::string built_utc;
    std::uint64_t file_count = 0;
    std::uint64_t content_bytes = 0;
    std::uint64_t package_bytes = 0;
    std::string package_sha256;
    // ---- upload (the Client writes these)
    std::string session_id;
    std::int64_t parts_total = 0;
    std::vector<std::int64_t> parts_done;
    // ---- install (the Client owns these)
    std::string assignment_id;
    std::string revision_id;
    std::string download_id;
    std::int64_t revision = 0;
    std::string install_root;       // this computer's game installs location
    std::string install_dir;        // <install_root>\<game_uuid>
    std::string temp_path;          // the package being downloaded
    bool paused = false;
    // THE REVISION ON THIS COMPUTER'S DISK (2026-10-22): set when a revision
    // is placed (`installed`), kept while an update moves `revision_id` on
    // to the next one. The service decides which revision is REQUIRED; this
    // computer's installation is this field, never the account's download
    // history (an account can hold a newer download on another computer or
    // a previous installation). Empty on a record written before it existed:
    // installed_revision() reads it from the state.
    std::string installed_revision_id;
};

// The revision installed on this computer for an install job: the recorded
// one, else (a record older than the field) the job's revision once it is
// installed; "" while nothing is placed.
inline std::string installed_revision(const Job& j) {
    if (!j.installed_revision_id.empty()) return j.installed_revision_id;
    return j.state == "installed" ? j.revision_id : std::string();
}

inline bool is_upload(const Job& j) { return j.kind == "upload"; }
inline bool is_install(const Job& j) { return j.kind == "install"; }

inline bool is_terminal(const Job& j) {
    return j.state == "done" || j.state == "failed" || j.state == "installed" || j.state == "removed";
}

inline std::string parts_json(const std::vector<std::int64_t>& v) {
    std::string out = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += ",";
        out += std::to_string(v[i]);
    }
    return out + "]";
}

inline std::string job_json(const Job& j) {
    using js::quote;
    std::string o = "{";
    o += "\"format\":" + quote(j.format);
    o += ",\"id\":" + quote(j.id);
    o += ",\"kind\":" + quote(j.kind);
    o += ",\"state\":" + quote(j.state);
    o += ",\"error\":" + quote(j.error);
    o += ",\"account_email\":" + quote(j.account_email);
    o += ",\"game_uuid\":" + quote(j.game_uuid);
    o += ",\"build_uuid\":" + quote(j.build_uuid);
    o += ",\"created_utc\":" + quote(j.created_utc);
    o += ",\"updated_utc\":" + quote(j.updated_utc);
    o += ",\"attempts\":" + std::to_string(j.attempts);
    o += ",\"next_attempt_utc\":" + std::to_string(j.next_attempt_utc);
    o += ",\"bytes_done\":" + std::to_string(j.bytes_done);
    o += ",\"bytes_total\":" + std::to_string(j.bytes_total);
    o += ",\"permille\":" + std::to_string(j.permille);
    o += ",\"game_id\":" + quote(j.game_id);
    o += ",\"admin_host_exe\":" + quote(j.admin_host_exe);
    o += ",\"admin_data_root\":" + quote(j.admin_data_root);
    o += ",\"owner_pid\":" + std::to_string(j.owner_pid);
    o += ",\"package_path\":" + quote(j.package_path);
    o += ",\"manifest_path\":" + quote(j.manifest_path);
    o += ",\"launch_exe\":" + quote(j.launch_exe);
    o += ",\"built_utc\":" + quote(j.built_utc);
    o += ",\"file_count\":" + std::to_string(j.file_count);
    o += ",\"content_bytes\":" + std::to_string(j.content_bytes);
    o += ",\"package_bytes\":" + std::to_string(j.package_bytes);
    o += ",\"package_sha256\":" + quote(j.package_sha256);
    o += ",\"session_id\":" + quote(j.session_id);
    o += ",\"parts_total\":" + std::to_string(j.parts_total);
    o += ",\"parts_done\":" + parts_json(j.parts_done);
    o += ",\"assignment_id\":" + quote(j.assignment_id);
    o += ",\"revision_id\":" + quote(j.revision_id);
    o += ",\"download_id\":" + quote(j.download_id);
    o += ",\"revision\":" + std::to_string(j.revision);
    o += ",\"install_root\":" + quote(j.install_root);
    o += ",\"install_dir\":" + quote(j.install_dir);
    o += ",\"temp_path\":" + quote(j.temp_path);
    o += std::string(",\"paused\":") + (j.paused ? "true" : "false");
    o += ",\"installed_revision_id\":" + quote(j.installed_revision_id);
    return o + "}\n";
}

inline bool parse_job(std::string_view text, Job& j) {
    j = Job{};
    if (!js::get_string(text, "format", j.format) || j.format != kJobFormat) return false;
    if (!js::get_string(text, "id", j.id) || !ev::is_hex32(j.id)) return false;
    if (!js::get_string(text, "kind", j.kind) || (j.kind != "upload" && j.kind != "install")) return false;
    if (!js::get_string(text, "state", j.state) || j.state.empty()) return false;
    j.error = js::opt_string(text, "error");
    j.account_email = js::opt_string(text, "account_email");
    j.game_uuid = js::opt_string(text, "game_uuid");
    j.build_uuid = js::opt_string(text, "build_uuid");
    j.created_utc = js::opt_string(text, "created_utc");
    j.updated_utc = js::opt_string(text, "updated_utc");
    j.attempts = js::opt_int(text, "attempts");
    j.next_attempt_utc = js::opt_int(text, "next_attempt_utc");
    j.bytes_done = static_cast<std::uint64_t>(js::opt_int(text, "bytes_done"));
    j.bytes_total = static_cast<std::uint64_t>(js::opt_int(text, "bytes_total"));
    j.permille = js::opt_int(text, "permille");
    j.game_id = js::opt_string(text, "game_id");
    j.admin_host_exe = js::opt_string(text, "admin_host_exe");
    j.admin_data_root = js::opt_string(text, "admin_data_root");
    j.owner_pid = js::opt_int(text, "owner_pid");
    j.package_path = js::opt_string(text, "package_path");
    j.manifest_path = js::opt_string(text, "manifest_path");
    j.launch_exe = js::opt_string(text, "launch_exe");
    j.built_utc = js::opt_string(text, "built_utc");
    j.file_count = static_cast<std::uint64_t>(js::opt_int(text, "file_count"));
    j.content_bytes = static_cast<std::uint64_t>(js::opt_int(text, "content_bytes"));
    j.package_bytes = static_cast<std::uint64_t>(js::opt_int(text, "package_bytes"));
    j.package_sha256 = js::opt_string(text, "package_sha256");
    j.session_id = js::opt_string(text, "session_id");
    j.parts_total = js::opt_int(text, "parts_total");
    {
        std::string_view raw;
        std::vector<std::string_view> items;
        j.parts_done.clear();
        if (js::member(text, "parts_done", raw) && js::items(raw, items)) {
            for (const auto& it : items) {
                std::int64_t n = 0;
                if (js::as_int(it, n)) j.parts_done.push_back(n);
            }
        }
    }
    j.assignment_id = js::opt_string(text, "assignment_id");
    j.revision_id = js::opt_string(text, "revision_id");
    j.download_id = js::opt_string(text, "download_id");
    j.revision = js::opt_int(text, "revision");
    j.install_root = js::opt_string(text, "install_root");
    j.install_dir = js::opt_string(text, "install_dir");
    j.temp_path = js::opt_string(text, "temp_path");
    bool paused = false;
    j.paused = js::get_bool(text, "paused", paused) && paused;
    j.installed_revision_id = js::opt_string(text, "installed_revision_id");
    return true;
}

// --------------------------------------------------------- the files ----

inline std::filesystem::path transfers_dir(const std::filesystem::path& virule_root) {
    return virule_root.empty() ? std::filesystem::path() : virule_root / kTransfersDirName;
}

inline std::filesystem::path job_dir(const std::filesystem::path& virule_root, const std::string& id) {
    return transfers_dir(virule_root) / std::filesystem::path(id);
}

inline std::filesystem::path job_path(const std::filesystem::path& virule_root, const std::string& id) {
    return job_dir(virule_root, id) / kJobFileName;
}

inline bool read_job(const std::filesystem::path& virule_root, const std::string& id, Job& out) {
    const std::string text = ev::read_document(job_path(virule_root, id));
    return !text.empty() && parse_job(text, out) && out.id == id;
}

// Atomic and durable (evaluation_evidence::write_file_atomic): a reader
// sees the old job or the new one, never half of either.
inline bool write_job(const std::filesystem::path& virule_root, const Job& j) {
    std::error_code ec;
    std::filesystem::create_directories(job_dir(virule_root, j.id), ec);
    return ev::write_file_atomic(job_path(virule_root, j.id), job_json(j));
}

// Every readable job, newest created first.
inline std::vector<Job> list_jobs(const std::filesystem::path& virule_root) {
    std::vector<Job> out;
    std::error_code ec;
    const auto dir = transfers_dir(virule_root);
    if (dir.empty()) return out;
    for (std::filesystem::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string id = it->path().filename().string();
        if (!ev::is_hex32(id)) continue;
        Job j;
        if (read_job(virule_root, id, j)) out.push_back(std::move(j));
    }
    std::sort(out.begin(), out.end(), [](const Job& a, const Job& b) { return a.created_utc > b.created_utc; });
    return out;
}

// The game's delivery: its newest upload job, if any.
inline bool newest_upload_for_game(const std::filesystem::path& virule_root, const std::string& game_id, Job& out) {
    for (const auto& j : list_jobs(virule_root)) {
        if (is_upload(j) && j.game_id == game_id) { out = j; return true; }
    }
    return false;
}

// The assignment's install job, if any (the newest).
inline bool install_for_assignment(const std::filesystem::path& virule_root, const std::string& assignment_id, Job& out) {
    for (const auto& j : list_jobs(virule_root)) {
        if (is_install(j) && j.assignment_id == assignment_id) { out = j; return true; }
    }
    return false;
}

#if defined(_WIN32)
// A fresh 32-hex identity (BCryptGenRandom), the job id grammar.
inline std::string random_hex32() {
    unsigned char b[16];
    if (BCryptGenRandom(nullptr, b, sizeof(b), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return "";
    static const char* kHex = "0123456789abcdef";
    std::string out(32, '0');
    for (size_t i = 0; i < 16; ++i) { out[i * 2] = kHex[(b[i] >> 4) & 0xF]; out[i * 2 + 1] = kHex[b[i] & 0xF]; }
    return out;
}

// Signal the Client's driver (fire and forget; no event = nothing waits).
inline void wake_transfers() {
    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, kWakeEventName);
    if (h) { SetEvent(h); CloseHandle(h); }
}

// Is the process that owns a stage still alive?
inline bool process_alive(std::int64_t pid) {
    if (pid <= 0) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h) return GetLastError() == ERROR_ACCESS_DENIED;
    DWORD code = 0;
    const bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}
#endif

} // namespace virule::core::evaluation_distribution
