#pragma once
// THE ADMIN USAGE SPOOL: capture richly locally, transmit sparsely.
//
// The Admin appends one compact JSON line per meaningful action to a file on
// disk; nothing is sent when the action happens. Sealed files (batches) are
// picked up by the VIRULE Client and attached to its ordinary Admin update
// check; a batch is deleted only after the service acknowledged it. Nothing
// here ever touches the network.
//
// This header is vendored BYTE-IDENTICAL into
// virule-client\third_party\virule_core\include\virule\core\usage_spool.hpp.
// Keep the two copies in sync; they are one file with two homes. The Admin
// uses the WRITER half, the client the READER half.
//
// Layout, in <data root>\usage\ (the caller passes the directory):
//
//   open.jsonl            the batch being written (Admin only)
//   b-<32 hex>.jsonl      a sealed batch; the hex is the batch id
//
// A staging build uses `open-s.jsonl` / `s-<32 hex>.jsonl`, so a staging
// client never delivers production records and the reverse.
//
// Every file starts with one header line (`{"h":1,"w","s","av"}`: workspace,
// Admin session, Admin version) followed by event lines
// (`{"i","t","e","g","b","c","q","o","x"}`). A file never spans two Admin
// sessions: the leftover open file of an earlier run is sealed at start.
//
// DURABILITY: every append is written and flushed before `append` returns,
// so a crash loses at most the line being written; a torn last line is
// skipped by the service, never fatal.
//
// BOUNDS: an open file is sealed at kSealBytes / kSealLines / kSealAgeSeconds;
// at most kMaxSealed sealed batches are kept, the OLDEST dropped first, so a
// machine that never reaches the service holds well under 1 MB.
//
// Everything is fail-soft: a full disk or a locked file drops the record and
// returns false. Recording never throws and never blocks the caller on
// anything but a short local file write.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <system_error>
#include <vector>

namespace virule::usage_spool {

constexpr size_t kSealBytes = 16 * 1024;
constexpr size_t kSealLines = 200;
constexpr long long kSealAgeSeconds = 30 * 60;
constexpr size_t kMaxSealed = 48;
constexpr size_t kMaxLineBytes = 512;
constexpr size_t kMaxDetailChars = 120;
// A sealed file larger than this was not written by this code; the reader
// discards it rather than ever sending it.
constexpr size_t kMaxBatchFileBytes = 64 * 1024;

inline const char* open_name(bool staging) { return staging ? "open-s.jsonl" : "open.jsonl"; }
inline const char* sealed_prefix(bool staging) { return staging ? "s-" : "b-"; }

inline std::string random_hex(size_t chars) {
    static const char* kHex = "0123456789abcdef";
    thread_local std::mt19937_64 rng{ [] {
        std::random_device rd;
        return (static_cast<uint64_t>(rd()) << 32) ^ rd() ^
               static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    }() };
    std::string out;
    out.reserve(chars);
    uint64_t v = 0;
    for (size_t i = 0; i < chars; ++i) {
        if (i % 16 == 0) v = rng();
        out += kHex[v & 0xF];
        v >>= 4;
    }
    return out;
}

inline bool is_hex(const std::string& s, size_t chars) {
    if (s.size() != chars) return false;
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

// The ONE free-text field. Quotes, backslashes, braces, brackets and control
// characters are removed, so a line needs no escaping and stays one line.
inline std::string clean_detail(const std::string& s) {
    std::string out;
    for (const char c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f) continue;
        if (c == '"' || c == '\\' || c == '{' || c == '}' || c == '[' || c == ']') continue;
        out += c;
        if (out.size() >= kMaxDetailChars) break;
    }
    return out;
}

// One recorded action. `code` is a short lowercase name ([a-z][a-z0-9_]*);
// the ids are the product's existing 32-hex identifiers and are simply
// omitted when they do not apply or are not well formed.
struct Event {
    std::string code;
    std::string game_uuid;
    std::string build_uuid;
    std::string campaign_id;
    std::string tester_id;
    std::string organization_id;
    std::string detail;
};

inline bool valid_code(const std::string& code) {
    if (code.empty() || code.size() > 32) return false;
    if (code[0] < 'a' || code[0] > 'z') return false;
    for (const char c : code) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
    }
    return true;
}

inline std::string event_line(const Event& e, long long epoch_seconds) {
    std::string out = "{\"i\":\"" + random_hex(16) + "\",\"t\":" +
                      std::to_string(epoch_seconds) + ",\"e\":\"" + e.code + "\"";
    auto id = [&out](const char* key, const std::string& value) {
        if (is_hex(value, 32)) out += std::string(",\"") + key + "\":\"" + value + "\"";
    };
    id("g", e.game_uuid);
    id("b", e.build_uuid);
    id("c", e.campaign_id);
    id("q", e.tester_id);
    id("o", e.organization_id);
    const std::string detail = clean_detail(e.detail);
    if (!detail.empty()) out += ",\"x\":\"" + detail + "\"";
    out += "}";
    return out;
}

inline std::string header_line(const std::string& workspace_id,
                               const std::string& session_id,
                               const std::string& admin_version) {
    std::string out = "{\"h\":1";
    if (is_hex(workspace_id, 32)) out += ",\"w\":\"" + workspace_id + "\"";
    if (is_hex(session_id, 32)) out += ",\"s\":\"" + session_id + "\"";
    const std::string av = clean_detail(admin_version);
    if (!av.empty() && av.size() <= 40) out += ",\"av\":\"" + av + "\"";
    out += "}";
    return out;
}

inline long long now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

namespace detail {

inline std::mutex& mutex() {
    static std::mutex m;
    return m;
}

struct SealedFile {
    std::filesystem::path path;
    std::string id;
    std::filesystem::file_time_type written;
};

// Sealed batches of one environment, OLDEST first.
inline std::vector<SealedFile> list_sealed(const std::filesystem::path& dir, bool staging) {
    std::vector<SealedFile> out;
    std::error_code ec;
    const std::string prefix = sealed_prefix(staging);
    for (std::filesystem::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (name.size() != prefix.size() + 32 + 6) continue;
        if (name.rfind(prefix, 0) != 0) continue;
        if (name.compare(name.size() - 6, 6, ".jsonl") != 0) continue;
        const std::string id = name.substr(prefix.size(), 32);
        if (!is_hex(id, 32)) continue;
        std::error_code tec;
        const auto written = std::filesystem::last_write_time(it->path(), tec);
        if (tec) continue;
        out.push_back({ it->path(), id, written });
    }
    std::sort(out.begin(), out.end(), [](const SealedFile& a, const SealedFile& b) {
        if (a.written != b.written) return a.written < b.written;
        return a.id < b.id;
    });
    return out;
}

inline void enforce_bound(const std::filesystem::path& dir, bool staging) {
    auto sealed = list_sealed(dir, staging);
    for (size_t i = 0; sealed.size() - i > kMaxSealed; ++i) {
        std::error_code ec;
        std::filesystem::remove(sealed[i].path, ec);
    }
}

// Seal the open file under a fresh batch id. A file holding only its header
// carries nothing and is removed instead.
inline bool seal_locked(const std::filesystem::path& dir, bool staging, size_t open_lines) {
    const auto open = dir / open_name(staging);
    std::error_code ec;
    if (!std::filesystem::exists(open, ec) || ec) return false;
    if (open_lines <= 1) {
        // Unknown line count (an earlier run's file): count before deciding.
        std::ifstream f(open, std::ios::binary);
        std::string line;
        size_t n = 0;
        while (std::getline(f, line)) {
            if (!line.empty()) ++n;
        }
        if (n <= 1) {
            f.close();
            std::filesystem::remove(open, ec);
            return false;
        }
    }
    const auto target = dir / (std::string(sealed_prefix(staging)) + random_hex(32) + ".jsonl");
    std::filesystem::rename(open, target, ec);
    if (ec) return false;
    enforce_bound(dir, staging);
    return true;
}

} // namespace detail

// ---------------------------------------------------------------- writer ----

// The Admin's recorder. One instance per process; `append` may be called
// from any thread.
class Writer {
public:
    // `header` is header_line(...) for this Admin session. Seals whatever an
    // earlier run left open, so a crashed session's records become
    // deliverable the moment the next one starts.
    void start(const std::filesystem::path& dir, bool staging, const std::string& header) {
        std::lock_guard<std::mutex> lock(detail::mutex());
        dir_ = dir;
        staging_ = staging;
        header_ = header;
        started_ = !dir_.empty();
        if (!started_) return;
        std::error_code ec;
        std::filesystem::create_directories(dir_, ec);
        (void)detail::seal_locked(dir_, staging_, 0);
        detail::enforce_bound(dir_, staging_);
        open_lines_ = 0;
        open_bytes_ = 0;
    }

    bool append(const Event& e) { return append_at(e, now_epoch()); }

    // `now` is injectable so the age rule can be tested.
    bool append_at(const Event& e, long long now) {
        if (!valid_code(e.code)) return false;
        const std::string line = event_line(e, now);
        if (line.size() > kMaxLineBytes) return false;
        std::lock_guard<std::mutex> lock(detail::mutex());
        if (!started_) return false;
        if (open_lines_ > 0 &&
            (open_bytes_ + line.size() + 1 > kSealBytes || open_lines_ >= kSealLines ||
             now - open_since_ >= kSealAgeSeconds)) {
            (void)detail::seal_locked(dir_, staging_, open_lines_);
            open_lines_ = 0;
            open_bytes_ = 0;
        }
        std::string text;
        if (open_lines_ == 0) {
            // A stale open file can only exist if the seal above failed
            // (locked by a scanner); append to it rather than lose records.
            std::error_code ec;
            if (!std::filesystem::exists(dir_ / open_name(staging_), ec)) {
                text = header_ + "\n";
            }
            open_since_ = now;
        }
        text += line + "\n";
        std::ofstream f(dir_ / open_name(staging_), std::ios::binary | std::ios::app);
        if (!f) return false;
        f.write(text.data(), static_cast<std::streamsize>(text.size()));
        f.flush();
        if (!f) return false;
        open_lines_ += text.size() == line.size() + 1 ? 1 : 2;
        open_bytes_ += text.size();
        return true;
    }

    // Make everything recorded so far deliverable (Admin shutdown).
    void seal() {
        std::lock_guard<std::mutex> lock(detail::mutex());
        if (!started_) return;
        (void)detail::seal_locked(dir_, staging_, open_lines_);
        open_lines_ = 0;
        open_bytes_ = 0;
    }

private:
    std::filesystem::path dir_;
    std::string header_;
    bool staging_ = false;
    bool started_ = false;
    size_t open_lines_ = 0;
    size_t open_bytes_ = 0;
    long long open_since_ = 0;
};

// ---------------------------------------------------------------- reader ----

struct Batch {
    std::string id;
    std::vector<std::string> lines;
    std::filesystem::path path;
};

// The oldest sealed batches, up to `max_batches` and `max_bytes` of lines in
// total (always at least one when any exists). Never the open file.
inline std::vector<Batch> load_sealed(const std::filesystem::path& dir, bool staging,
                                      size_t max_batches, size_t max_bytes) {
    std::vector<Batch> out;
    if (dir.empty()) return out;
    size_t total = 0;
    for (const auto& s : detail::list_sealed(dir, staging)) {
        if (out.size() >= max_batches) break;
        std::error_code ec;
        const auto size = std::filesystem::file_size(s.path, ec);
        if (ec) continue;
        if (size > kMaxBatchFileBytes) {
            std::filesystem::remove(s.path, ec);
            continue;
        }
        if (!out.empty() && total + static_cast<size_t>(size) > max_bytes) break;
        std::ifstream f(s.path, std::ios::binary);
        if (!f) continue;
        Batch b;
        b.id = s.id;
        b.path = s.path;
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line.size() > kMaxLineBytes) continue;
            b.lines.push_back(line);
        }
        total += static_cast<size_t>(size);
        out.push_back(std::move(b));
    }
    return out;
}

// Delete a delivered batch. Only ever called for an id the service named in
// its acknowledgement.
inline bool remove_batch(const Batch& b) {
    std::error_code ec;
    return std::filesystem::remove(b.path, ec) && !ec;
}

inline size_t sealed_count(const std::filesystem::path& dir, bool staging) {
    return detail::list_sealed(dir, staging).size();
}

} // namespace virule::usage_spool
