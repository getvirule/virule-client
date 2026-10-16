#pragma once
// EVALUATION EVIDENCE: the package format, its handoff from the wrapper to
// the VIRULE Client, and the receipt (docs/EVALUATION_VIRULE.md section 6).
//
// VENDORED BYTE-IDENTICAL into virule-client/third_party/virule_core. It
// therefore includes nothing but the C++ standard library and, on Windows,
// <windows.h> and <bcrypt.h>: no other VIRULE header, no wrapper code. The
// wrapper writes and hands off; the Client reads, delivers and writes
// receipts; the Admin reads receipts to decide whether writing unlocks.
//
// LAYOUT, under %LOCALAPPDATA%\VIRULE\evidence (a root override serves the
// tests and the redirected-LOCALAPPDATA sandbox):
//   .incoming\<package_id>\   being written by the wrapper (the session owns it)
//   outbox\<package_id>\      handed off: package.json + <seq>.jpg (the Client owns it)
//   receipts\<package_id>.json  the service acknowledged it
//
// HANDOFF IS ONE DIRECTORY RENAME. The wrapper stages .incoming\<id>
// (moves the capture files in, writes package.json, flushes and hashes
// everything), then a single MoveFileExW renames it to outbox\<id>, then
// the named event Local\VIRULE.Evidence.Wake is signalled. Before the rename
// a crash leaves a partial .incoming that the next handoff of the same
// package completes in place; after it the Client owns the package. A
// package that already has an outbox entry or a receipt is never handed off
// twice.
//
// A RECEIPT is written atomically BEFORE the package payload is removed;
// without one nothing is reported as delivered. `simulated` receipts come
// from the test transport and count only in a staging build (the caller
// decides; this file only reports).
//
// JSON. Every document here is written by VIRULE code in a fixed shape, and
// read back by the tolerant member reader below: top-level members only,
// key order free, unknown members ignored, strings unescaped, nested values
// skipped by balanced scanning. Malformed text reads as absent, never as a
// partial record.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

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

namespace virule::core::evaluation_evidence {

inline constexpr const char* kPackageFormat = "virule-evaluation-evidence.v1";
inline constexpr const char* kPackageFileName = "package.json";
inline constexpr const wchar_t* kWakeEventName = L"Local\\VIRULE.Evidence.Wake";
inline constexpr std::uintmax_t kMaxDocumentBytes = 4u * 1024u * 1024u;

// The gap reasons of contract section 5. Anything else is recorded as
// capture_failed.
inline constexpr const char* kGapReasons[] = {
    "window_not_found", "minimized", "unsupported", "capture_failed", "blank_frame", "encode_failed",
};

inline bool is_gap_reason(const std::string& r) {
    for (const char* k : kGapReasons) {
        if (r == k) return true;
    }
    return false;
}

inline bool is_lower_hex(const std::string& s, size_t n) {
    if (s.size() != n) return false;
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

inline bool is_hex32(const std::string& s) { return is_lower_hex(s, 32); }
inline bool is_sha256_hex(const std::string& s) { return is_lower_hex(s, 64); }

// =============================================================== JSON ====
namespace json {

inline std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (const char raw : s) {
        const unsigned char c = static_cast<unsigned char>(raw);
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += raw;
            }
        }
    }
    return out;
}

inline std::string quote(const std::string& s) { return "\"" + escape(s) + "\""; }

namespace detail {

inline size_t skip_ws(std::string_view t, size_t p) {
    while (p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n' || t[p] == '\r')) ++p;
    return p;
}

// p at an opening quote; returns the index just past the closing quote, or
// npos when unterminated.
inline size_t skip_string(std::string_view t, size_t p) {
    if (p >= t.size() || t[p] != '"') return std::string_view::npos;
    for (++p; p < t.size(); ++p) {
        if (t[p] == '\\') { ++p; continue; }
        if (t[p] == '"') return p + 1;
    }
    return std::string_view::npos;
}

// p at the first character of a value; returns the index just past it.
inline size_t skip_value(std::string_view t, size_t p) {
    p = skip_ws(t, p);
    if (p >= t.size()) return std::string_view::npos;
    if (t[p] == '"') return skip_string(t, p);
    if (t[p] == '{' || t[p] == '[') {
        int depth = 0;
        while (p < t.size()) {
            const char c = t[p];
            if (c == '"') {
                p = skip_string(t, p);
                if (p == std::string_view::npos) return p;
                continue;
            }
            if (c == '{' || c == '[') ++depth;
            else if (c == '}' || c == ']') {
                if (--depth == 0) return p + 1;
            }
            ++p;
        }
        return std::string_view::npos;
    }
    const size_t b = p;
    while (p < t.size() && t[p] != ',' && t[p] != '}' && t[p] != ']' &&
           t[p] != ' ' && t[p] != '\t' && t[p] != '\n' && t[p] != '\r') ++p;
    return p == b ? std::string_view::npos : p;
}

} // namespace detail

// The raw text of the top-level member `key` of the object `obj`.
inline bool member(std::string_view obj, std::string_view key, std::string_view& raw) {
    size_t p = detail::skip_ws(obj, 0);
    if (p >= obj.size() || obj[p] != '{') return false;
    ++p;
    while (true) {
        p = detail::skip_ws(obj, p);
        if (p >= obj.size()) return false;
        if (obj[p] == '}') return false;
        if (obj[p] == ',') { ++p; continue; }
        const size_t ks = p;
        const size_t ke = detail::skip_string(obj, p);
        if (ke == std::string_view::npos) return false;
        p = detail::skip_ws(obj, ke);
        if (p >= obj.size() || obj[p] != ':') return false;
        const size_t vs = detail::skip_ws(obj, p + 1);
        const size_t ve = detail::skip_value(obj, vs);
        if (ve == std::string_view::npos) return false;
        if (obj.substr(ks + 1, ke - ks - 2) == key) {
            raw = obj.substr(vs, ve - vs);
            return true;
        }
        p = ve;
    }
}

inline bool as_string(std::string_view raw, std::string& out) {
    out.clear();
    if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"') return false;
    for (size_t i = 1; i + 1 < raw.size(); ++i) {
        char c = raw[i];
        if (c == '\\' && i + 2 < raw.size()) {
            c = raw[++i];
            switch (c) {
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                // \u00XX only (what escape() writes); anything wider is kept verbatim.
                if (i + 4 < raw.size()) {
                    const std::string hex(raw.substr(i + 1, 4));
                    char* end = nullptr;
                    const long v = std::strtol(hex.c_str(), &end, 16);
                    if (end && *end == 0 && v >= 0 && v < 0x80) {
                        out += static_cast<char>(v);
                        i += 4;
                        break;
                    }
                }
                out += "\\u";
                break;
            }
            default: out += c; break;
            }
        } else {
            out += c;
        }
    }
    return true;
}

inline bool as_int(std::string_view raw, std::int64_t& out) {
    out = 0;
    if (raw.empty() || raw.size() > 20) return false;
    size_t i = 0;
    bool neg = false;
    if (raw[0] == '-') { neg = true; i = 1; }
    if (i >= raw.size()) return false;
    std::int64_t v = 0;
    for (; i < raw.size(); ++i) {
        if (raw[i] < '0' || raw[i] > '9') return false;
        v = v * 10 + (raw[i] - '0');
    }
    out = neg ? -v : v;
    return true;
}

inline bool as_bool(std::string_view raw, bool& out) {
    if (raw == "true") { out = true; return true; }
    if (raw == "false") { out = false; return true; }
    return false;
}

// The raw text of each element of an array value.
inline bool items(std::string_view raw, std::vector<std::string_view>& out) {
    out.clear();
    size_t p = detail::skip_ws(raw, 0);
    if (p >= raw.size() || raw[p] != '[') return false;
    ++p;
    while (true) {
        p = detail::skip_ws(raw, p);
        if (p >= raw.size()) return false;
        if (raw[p] == ']') return true;
        if (raw[p] == ',') { ++p; continue; }
        const size_t e = detail::skip_value(raw, p);
        if (e == std::string_view::npos) return false;
        out.push_back(raw.substr(p, e - p));
        p = e;
    }
}

inline bool get_string(std::string_view obj, std::string_view key, std::string& out) {
    std::string_view raw;
    out.clear();
    return member(obj, key, raw) && as_string(raw, out);
}

inline bool get_int(std::string_view obj, std::string_view key, std::int64_t& out) {
    std::string_view raw;
    out = 0;
    return member(obj, key, raw) && as_int(raw, out);
}

inline bool get_bool(std::string_view obj, std::string_view key, bool& out) {
    std::string_view raw;
    out = false;
    return member(obj, key, raw) && as_bool(raw, out);
}

// Optional members: absent keeps the default.
inline std::string opt_string(std::string_view obj, std::string_view key) {
    std::string v;
    return get_string(obj, key, v) ? v : std::string();
}

inline std::int64_t opt_int(std::string_view obj, std::string_view key, std::int64_t def = 0) {
    std::int64_t v = 0;
    return get_int(obj, key, v) ? v : def;
}

} // namespace json

// ============================================================ formats ====

struct IdlePeriod {
    std::int64_t start_ms = 0;  // session-elapsed
    std::int64_t end_ms = 0;
};

struct SessionBlock {
    std::int64_t index = 0;             // 1-based, in the assignment
    std::string started_utc, ended_utc;
    std::string end_reason;             // "exit" | "recovered"
    std::int64_t session_ms = 0, idle_ms = 0, effective_ms = 0;
    std::vector<IdlePeriod> idle_periods;
    std::int64_t active_km_seconds = 0;          // keyboard, mouse, touch, pen
    std::int64_t active_controller_seconds = 0;  // XInput and HID gamepads/joysticks
};

struct Totals {
    std::int64_t session_ms = 0, idle_ms = 0, effective_ms = 0, sessions = 0;
};

// One scheduled capture: a frame ("ok") or a recorded gap with its reason.
struct Capture {
    std::int64_t seq = 0;
    std::string file;                 // "<seq>.jpg" inside the package, "" for a gap
    std::string sha256;               // filled at handoff
    std::int64_t bytes = 0;           // filled at handoff
    std::int64_t width = 0, height = 0;
    std::int64_t elapsed_ms = 0;      // in the session
    std::int64_t cumulative_ms = 0;   // across the assignment
    std::string captured_utc;
    std::string status;               // "ok" | "gap"
    std::string reason;               // gap reason, "" when ok
    std::filesystem::path source;     // where the frame waits until handoff (never serialized)
};

struct Package {
    std::string format = kPackageFormat;
    std::string package_id;           // == session_id, 32 hex, stable for every retry
    std::string assignment_id, evaluator_id, game_uuid, build_uuid;
    SessionBlock session;
    Totals totals;                    // after this session
    bool capture_stopped = false;
    std::vector<Capture> captures;
};

// A file the package carries (an "ok" capture), as the Client delivers it.
struct PackageFile {
    std::string file, sha256;
    std::int64_t bytes = 0;
};

inline std::vector<PackageFile> package_files(const Package& p) {
    std::vector<PackageFile> out;
    for (const auto& c : p.captures) {
        if (c.status == "ok" && !c.file.empty()) out.push_back({ c.file, c.sha256, c.bytes });
    }
    return out;
}

inline std::string capture_file_name(std::int64_t seq) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%06lld.jpg", static_cast<long long>(seq));
    return buf;
}

// Only a plain name inside the package directory: nothing a reader could
// turn into a path outside it.
inline bool is_safe_file_name(const std::string& f) {
    if (f.empty() || f.size() > 64 || f == "." || f == ".." || f == kPackageFileName) return false;
    for (const char c : f) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

namespace detail {

inline std::string idle_periods_json(const std::vector<IdlePeriod>& v) {
    std::string out = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += ",";
        out += "[" + std::to_string(v[i].start_ms) + "," + std::to_string(v[i].end_ms) + "]";
    }
    return out + "]";
}

inline bool parse_idle_periods(std::string_view raw, std::vector<IdlePeriod>& out) {
    out.clear();
    std::vector<std::string_view> list;
    if (!json::items(raw, list)) return false;
    for (const auto& pair : list) {
        std::vector<std::string_view> two;
        if (!json::items(pair, two) || two.size() != 2) return false;
        IdlePeriod p;
        if (!json::as_int(two[0], p.start_ms) || !json::as_int(two[1], p.end_ms)) return false;
        if (p.start_ms < 0 || p.end_ms < p.start_ms) return false;
        out.push_back(p);
    }
    return true;
}

} // namespace detail

inline std::string capture_json(const Capture& c) {
    using json::quote;
    return std::string("{\"seq\":") + std::to_string(c.seq) +
        ",\"file\":" + quote(c.file) +
        ",\"sha256\":" + quote(c.sha256) +
        ",\"bytes\":" + std::to_string(c.bytes) +
        ",\"width\":" + std::to_string(c.width) +
        ",\"height\":" + std::to_string(c.height) +
        ",\"elapsed_ms\":" + std::to_string(c.elapsed_ms) +
        ",\"cumulative_ms\":" + std::to_string(c.cumulative_ms) +
        ",\"captured_utc\":" + quote(c.captured_utc) +
        ",\"status\":" + quote(c.status) +
        ",\"reason\":" + quote(c.reason) + "}";
}

inline bool parse_capture(std::string_view obj, Capture& c) {
    c = Capture{};
    if (!json::get_int(obj, "seq", c.seq) || c.seq <= 0) return false;
    if (!json::get_string(obj, "status", c.status)) return false;
    if (c.status != "ok" && c.status != "gap") return false;
    c.file = json::opt_string(obj, "file");
    c.sha256 = json::opt_string(obj, "sha256");
    c.bytes = json::opt_int(obj, "bytes");
    c.width = json::opt_int(obj, "width");
    c.height = json::opt_int(obj, "height");
    c.elapsed_ms = json::opt_int(obj, "elapsed_ms");
    c.cumulative_ms = json::opt_int(obj, "cumulative_ms");
    c.captured_utc = json::opt_string(obj, "captured_utc");
    c.reason = json::opt_string(obj, "reason");
    if (c.status == "ok" && !is_safe_file_name(c.file)) return false;
    return true;
}

inline std::string session_block_json(const SessionBlock& s) {
    using json::quote;
    return std::string("{\"index\":") + std::to_string(s.index) +
        ",\"started_utc\":" + quote(s.started_utc) +
        ",\"ended_utc\":" + quote(s.ended_utc) +
        ",\"end_reason\":" + quote(s.end_reason) +
        ",\"session_ms\":" + std::to_string(s.session_ms) +
        ",\"idle_ms\":" + std::to_string(s.idle_ms) +
        ",\"effective_ms\":" + std::to_string(s.effective_ms) +
        ",\"idle_periods\":" + detail::idle_periods_json(s.idle_periods) +
        ",\"active_seconds\":{\"km\":" + std::to_string(s.active_km_seconds) +
        ",\"controller\":" + std::to_string(s.active_controller_seconds) + "}}";
}

inline bool parse_session_block(std::string_view obj, SessionBlock& s) {
    s = SessionBlock{};
    if (!json::get_int(obj, "index", s.index)) return false;
    s.started_utc = json::opt_string(obj, "started_utc");
    s.ended_utc = json::opt_string(obj, "ended_utc");
    s.end_reason = json::opt_string(obj, "end_reason");
    s.session_ms = json::opt_int(obj, "session_ms");
    s.idle_ms = json::opt_int(obj, "idle_ms");
    s.effective_ms = json::opt_int(obj, "effective_ms");
    std::string_view raw;
    if (json::member(obj, "idle_periods", raw) && !detail::parse_idle_periods(raw, s.idle_periods)) return false;
    if (json::member(obj, "active_seconds", raw)) {
        s.active_km_seconds = json::opt_int(raw, "km");
        s.active_controller_seconds = json::opt_int(raw, "controller");
    }
    return true;
}

inline std::string totals_json(const Totals& t) {
    return std::string("{\"session_ms\":") + std::to_string(t.session_ms) +
        ",\"idle_ms\":" + std::to_string(t.idle_ms) +
        ",\"effective_ms\":" + std::to_string(t.effective_ms) +
        ",\"sessions\":" + std::to_string(t.sessions) + "}";
}

inline void parse_totals(std::string_view obj, Totals& t) {
    t.session_ms = json::opt_int(obj, "session_ms");
    t.idle_ms = json::opt_int(obj, "idle_ms");
    t.effective_ms = json::opt_int(obj, "effective_ms");
    t.sessions = json::opt_int(obj, "sessions");
}

// package.json, one member per line so a person can read it.
inline std::string package_json(const Package& p) {
    using json::quote;
    std::string out = "{\n";
    out += "  \"format\": " + quote(kPackageFormat) + ",\n";
    out += "  \"package_id\": " + quote(p.package_id) + ",\n";
    out += "  \"assignment_id\": " + quote(p.assignment_id) + ",\n";
    out += "  \"evaluator_id\": " + quote(p.evaluator_id) + ",\n";
    out += "  \"game_uuid\": " + quote(p.game_uuid) + ",\n";
    out += "  \"build_uuid\": " + quote(p.build_uuid) + ",\n";
    out += "  \"session\": " + session_block_json(p.session) + ",\n";
    out += "  \"totals\": " + totals_json(p.totals) + ",\n";
    out += std::string("  \"capture_stopped\": ") + (p.capture_stopped ? "true" : "false") + ",\n";
    out += "  \"captures\": [";
    for (size_t i = 0; i < p.captures.size(); ++i) {
        out += i ? ",\n    " : "\n    ";
        out += capture_json(p.captures[i]);
    }
    out += p.captures.empty() ? "]\n" : "\n  ]\n";
    out += "}\n";
    return out;
}

// The tolerant reader the Client uses. True only for a package of this
// format with well-formed ids; unknown members are ignored.
inline bool parse_package(std::string_view text, Package& p) {
    p = Package{};
    std::string format;
    if (!json::get_string(text, "format", format) || format != kPackageFormat) return false;
    if (!json::get_string(text, "package_id", p.package_id) || !is_hex32(p.package_id)) return false;
    if (!json::get_string(text, "assignment_id", p.assignment_id) || !is_hex32(p.assignment_id)) return false;
    p.evaluator_id = json::opt_string(text, "evaluator_id");
    p.game_uuid = json::opt_string(text, "game_uuid");
    p.build_uuid = json::opt_string(text, "build_uuid");
    std::string_view raw;
    if (json::member(text, "session", raw) && !parse_session_block(raw, p.session)) return false;
    if (json::member(text, "totals", raw)) parse_totals(raw, p.totals);
    (void)json::get_bool(text, "capture_stopped", p.capture_stopped);
    if (json::member(text, "captures", raw)) {
        std::vector<std::string_view> list;
        if (!json::items(raw, list)) return false;
        for (const auto& item : list) {
            Capture c;
            if (!parse_capture(item, c)) return false;
            p.captures.push_back(std::move(c));
        }
    }
    return true;
}

// ------------------------------------------------------------ receipt ----

struct Receipt {
    std::string package_id, assignment_id, receipt_id, acknowledged_utc;
    std::vector<PackageFile> files;   // what the service acknowledged (file + sha256)
    bool simulated = false;
};

inline std::string receipt_json(const Receipt& r) {
    using json::quote;
    std::string out = "{\"package_id\":" + quote(r.package_id) +
        ",\"assignment_id\":" + quote(r.assignment_id) +
        ",\"receipt_id\":" + quote(r.receipt_id) +
        ",\"acknowledged_utc\":" + quote(r.acknowledged_utc) + ",\"files\":[";
    for (size_t i = 0; i < r.files.size(); ++i) {
        if (i) out += ",";
        out += "{\"file\":" + quote(r.files[i].file) + ",\"sha256\":" + quote(r.files[i].sha256) + "}";
    }
    out += std::string("],\"simulated\":") + (r.simulated ? "true" : "false") + "}\n";
    return out;
}

// Tolerant: a file entry may be an object {file, sha256} or a bare name.
// An absent `simulated` reads as false; a present but malformed one fails
// the whole receipt, so a damaged file can never pass as a real receipt.
inline bool parse_receipt(std::string_view text, Receipt& r) {
    r = Receipt{};
    if (!json::get_string(text, "package_id", r.package_id) || !is_hex32(r.package_id)) return false;
    if (!json::get_string(text, "assignment_id", r.assignment_id) || !is_hex32(r.assignment_id)) return false;
    if (!json::get_string(text, "receipt_id", r.receipt_id) || r.receipt_id.empty()) return false;
    r.acknowledged_utc = json::opt_string(text, "acknowledged_utc");
    std::string_view raw;
    if (json::member(text, "simulated", raw) && !json::as_bool(raw, r.simulated)) return false;
    if (json::member(text, "files", raw)) {
        std::vector<std::string_view> list;
        if (!json::items(raw, list)) return false;
        for (const auto& item : list) {
            PackageFile f;
            if (!item.empty() && item.front() == '"') {
                if (!json::as_string(item, f.file)) return false;
            } else {
                f.file = json::opt_string(item, "file");
                f.sha256 = json::opt_string(item, "sha256");
            }
            r.files.push_back(std::move(f));
        }
    }
    return true;
}

// ============================================================== paths ====

struct Root {
    std::filesystem::path dir;   // ...\VIRULE\evidence
};

inline Root root_under(const std::filesystem::path& virule_root) {
    return Root{ virule_root.empty() ? std::filesystem::path() : virule_root / L"evidence" };
}

inline std::filesystem::path incoming_dir(const Root& r, const std::string& id) {
    return r.dir / L".incoming" / std::filesystem::path(id);
}
inline std::filesystem::path outbox_dir(const Root& r) { return r.dir / L"outbox"; }
inline std::filesystem::path outbox_dir(const Root& r, const std::string& id) {
    return outbox_dir(r) / std::filesystem::path(id);
}
inline std::filesystem::path receipts_dir(const Root& r) { return r.dir / L"receipts"; }
inline std::filesystem::path receipt_path(const Root& r, const std::string& id) {
    return receipts_dir(r) / std::filesystem::path(id + ".json");
}

inline bool exists_quiet(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec) && !ec;
}

inline std::string read_document(const std::filesystem::path& p) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(p, ec);
    if (ec || size > kMaxDocumentBytes) return {};
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

#if defined(_WIN32)

// %LOCALAPPDATA%\VIRULE (then %USERPROFILE%\AppData\Local\VIRULE), the way
// every VIRULE component resolves its user-data root. Empty when neither
// exists.
inline std::filesystem::path default_virule_root() {
    const auto from_env = [](const wchar_t* name) -> std::filesystem::path {
        wchar_t buf[MAX_PATH * 4];
        const DWORD cap = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
        const DWORD n = GetEnvironmentVariableW(name, buf, cap);
        if (n == 0 || n >= cap) return {};
        return std::filesystem::path(std::wstring(buf, n));
    };
    const auto local = from_env(L"LOCALAPPDATA");
    if (!local.empty()) return local / L"VIRULE";
    const auto profile = from_env(L"USERPROFILE");
    if (!profile.empty()) return profile / L"AppData" / L"Local" / L"VIRULE";
    return {};
}

inline Root default_root() { return root_under(default_virule_root()); }

// ============================================================ storage ====

// Flush one file's data to disk (FlushFileBuffers). True on success.
inline bool flush_file(const std::filesystem::path& p) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    const BOOL ok = FlushFileBuffers(h);
    CloseHandle(h);
    return ok != FALSE;
}

// Write `text` to `p` atomically and durably: a flushed sibling temp file,
// then one MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH). A reader sees the
// old document or the new one, never a torn one.
inline bool write_file_atomic(const std::filesystem::path& p, const std::string& text) {
    if (p.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    const auto tmp = p.parent_path() / (p.filename().wstring() + L".tmp");
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    size_t done = 0;
    while (ok && done < text.size()) {
        DWORD wrote = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(text.size() - done, 1u << 20));
        ok = WriteFile(h, text.data() + done, chunk, &wrote, nullptr) != FALSE && wrote == chunk;
        done += wrote;
    }
    ok = ok && FlushFileBuffers(h) != FALSE;
    CloseHandle(h);
    if (ok) ok = MoveFileExW(tmp.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    if (!ok) DeleteFileW(tmp.c_str());
    return ok;
}

// SHA-256 of a file's bytes as 64 lowercase hex (BCrypt). False on any
// read or provider failure.
inline bool sha256_file(const std::filesystem::path& p, std::string& hex_out, std::int64_t& bytes_out) {
    hex_out.clear();
    bytes_out = 0;
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0;
    std::vector<char> buf(64 * 1024);
    while (ok && f) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = f.gcount();
        if (n <= 0) break;
        ok = BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf.data()), static_cast<ULONG>(n), 0) == 0;
        bytes_out += n;
    }
    if (ok && f.bad()) ok = false;
    unsigned char digest[32];
    if (ok) ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) { bytes_out = 0; return false; }
    static const char* kHex = "0123456789abcdef";
    for (const unsigned char b : digest) {
        hex_out += kHex[b >> 4];
        hex_out += kHex[b & 15];
    }
    return true;
}

// The wake event, shared by both sides with the same parameters so whichever
// opens it first creates it identically: AUTO-RESET, initially clear. A
// signal waits for the Client's next wait even when it is not waiting yet.
// The caller closes the handle. Null on failure.
inline HANDLE open_wake_event() {
    return CreateEventW(nullptr, FALSE, FALSE, kWakeEventName);
}

inline bool signal_wake() {
    HANDLE h = open_wake_event();
    if (!h) return false;
    const BOOL ok = SetEvent(h);
    CloseHandle(h);
    return ok != FALSE;
}

// ============================================================ handoff ====

enum class Handoff {
    HandedOff,            // renamed into the outbox and signalled now
    AlreadyHandedOff,     // outbox\<id> already exists: nothing duplicated
    AlreadyAcknowledged,  // receipts\<id>.json exists: nothing duplicated
    Failed,               // nothing reached the outbox; the next handoff resumes
};

inline const char* handoff_name(Handoff h) {
    switch (h) {
    case Handoff::HandedOff:           return "handed_off";
    case Handoff::AlreadyHandedOff:    return "already_handed_off";
    case Handoff::AlreadyAcknowledged: return "already_acknowledged";
    case Handoff::Failed:              return "failed";
    }
    return "unknown";
}

// STAGE: build .incoming\<id> in place. Re-entrant: a previous attempt that
// died midway already moved some frames in, so each "ok" frame is taken
// from its source when that still exists, else kept where it already is.
// A frame found in neither place is recorded as a gap (capture_failed):
// nothing is ever substituted. Every frame and package.json is flushed and
// hashed. Files the package does not list are removed. `pkg` comes back as
// written (hashes, sizes, any frame turned into a gap).
inline bool stage(const Root& root, Package& pkg) {
    if (root.dir.empty() || !is_hex32(pkg.package_id) || !is_hex32(pkg.assignment_id)) return false;
    const auto dir = incoming_dir(root, pkg.package_id);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;
    std::vector<std::wstring> keep;
    for (auto& c : pkg.captures) {
        if (c.status != "ok") {
            c.file.clear();
            c.sha256.clear();
            c.bytes = 0;
            if (!is_gap_reason(c.reason)) c.reason = "capture_failed";
            continue;
        }
        if (c.file.empty()) c.file = capture_file_name(c.seq);
        const auto target = dir / std::filesystem::path(c.file);
        bool present = false;
        if (is_safe_file_name(c.file)) {
            if (!c.source.empty() && exists_quiet(c.source)) {
                present = MoveFileExW(c.source.c_str(), target.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH) != FALSE;
            } else {
                present = exists_quiet(target);
            }
        }
        if (present) present = flush_file(target) && sha256_file(target, c.sha256, c.bytes);
        if (!present) {
            c.status = "gap";
            c.reason = "capture_failed";
            c.file.clear();
            c.sha256.clear();
            c.bytes = 0;
            c.width = c.height = 0;
            continue;
        }
        c.reason.clear();
        keep.push_back(std::filesystem::path(c.file).wstring());
    }
    for (std::filesystem::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const auto name = it->path().filename().wstring();
        if (std::find(keep.begin(), keep.end(), name) != keep.end()) continue;
        if (name == std::filesystem::path(kPackageFileName).wstring()) continue;
        std::error_code rec;
        std::filesystem::remove_all(it->path(), rec);
    }
    return write_file_atomic(dir / kPackageFileName, package_json(pkg));
}

// PUBLISH: the ONE rename that hands the staged package to the Client.
inline bool publish(const Root& root, const std::string& id) {
    if (root.dir.empty() || !is_hex32(id)) return false;
    std::error_code ec;
    std::filesystem::create_directories(outbox_dir(root), ec);
    if (ec) return false;
    const auto from = incoming_dir(root, id);
    const auto to = outbox_dir(root, id);
    if (!exists_quiet(from / kPackageFileName)) return false;
    return MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE;
}

// The whole handoff: idempotence check, stage, publish, wake.
inline Handoff handoff(const Root& root, Package& pkg) {
    if (root.dir.empty() || !is_hex32(pkg.package_id)) return Handoff::Failed;
    if (exists_quiet(receipt_path(root, pkg.package_id))) return Handoff::AlreadyAcknowledged;
    if (exists_quiet(outbox_dir(root, pkg.package_id))) return Handoff::AlreadyHandedOff;
    if (!stage(root, pkg)) return Handoff::Failed;
    if (!publish(root, pkg.package_id)) return Handoff::Failed;
    (void)signal_wake();
    return Handoff::HandedOff;
}

// ============================================================ receipts ===

inline bool write_receipt(const Root& root, const Receipt& r) {
    if (root.dir.empty() || !is_hex32(r.package_id)) return false;
    return write_file_atomic(receipt_path(root, r.package_id), receipt_json(r));
}

inline bool read_receipt(const Root& root, const std::string& id, Receipt& r) {
    if (!is_hex32(id)) return false;
    const std::string text = read_document(receipt_path(root, id));
    return !text.empty() && parse_receipt(text, r) && r.package_id == id;
}

// The Client's acknowledgment step: the receipt first, durably, then the
// payload goes. A failed receipt write leaves the payload for the next try.
inline bool acknowledge(const Root& root, const Receipt& r) {
    if (!write_receipt(root, r)) return false;
    std::error_code ec;
    std::filesystem::remove_all(outbox_dir(root, r.package_id), ec);
    return true;
}

inline bool read_outbox_package(const Root& root, const std::string& id, Package& p) {
    const std::string text = read_document(outbox_dir(root, id) / kPackageFileName);
    return !text.empty() && parse_package(text, p) && p.package_id == id;
}

#else // !_WIN32

// Portable fallback (tests on other hosts only): temp file, then rename.
inline bool write_file_atomic(const std::filesystem::path& p, const std::string& text) {
    if (p.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    const auto tmp = p.parent_path() / (p.filename().string() + ".tmp");
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(text.data(), static_cast<std::streamsize>(text.size()));
        f.flush();
        if (!f) return false;
    }
    std::filesystem::rename(tmp, p, ec);
    if (ec) { std::filesystem::remove(tmp, ec); return false; }
    return true;
}

#endif // _WIN32

// ===================================================== delivery state ====

struct DeliveryState {
    std::vector<std::string> pending;                 // in the outbox, no receipt
    std::vector<std::string> acknowledged;            // real receipts
    std::vector<std::string> simulated_acknowledged;  // receipts from the test transport
    std::vector<std::string> staging;                 // in .incoming (not handed off)

    bool has_receipt(const std::string& id, bool simulated_counts) const {
        if (std::find(acknowledged.begin(), acknowledged.end(), id) != acknowledged.end()) return true;
        return simulated_counts &&
            std::find(simulated_acknowledged.begin(), simulated_acknowledged.end(), id) != simulated_acknowledged.end();
    }
};

// Everything the evidence root holds for one assignment. A package with
// both an outbox entry and a receipt (acknowledged, payload not yet
// removed) counts as acknowledged: the receipt is the fact.
inline DeliveryState assignment_delivery_state(const Root& root, const std::string& assignment_id) {
    DeliveryState s;
    if (root.dir.empty() || !is_hex32(assignment_id)) return s;
    std::error_code ec;
    for (std::filesystem::directory_iterator it(receipts_dir(root), ec), end; !ec && it != end; it.increment(ec)) {
        const auto name = it->path().filename().string();
        if (name.size() != 37 || name.compare(32, 5, ".json") != 0) continue;
        Receipt r;
        const std::string text = read_document(it->path());
        if (text.empty() || !parse_receipt(text, r)) continue;
        if (r.package_id != name.substr(0, 32) || r.assignment_id != assignment_id) continue;
        (r.simulated ? s.simulated_acknowledged : s.acknowledged).push_back(r.package_id);
    }
    const auto scan = [&](const std::filesystem::path& dir, std::vector<std::string>& into) {
        std::error_code dec;
        for (std::filesystem::directory_iterator it(dir, dec), end; !dec && it != end; it.increment(dec)) {
            const auto id = it->path().filename().string();
            if (!is_hex32(id)) continue;
            Package p;
            const std::string text = read_document(it->path() / kPackageFileName);
            if (text.empty() || !parse_package(text, p)) continue;
            if (p.package_id != id || p.assignment_id != assignment_id) continue;
            if (s.has_receipt(id, true)) continue;
            into.push_back(id);
        }
    };
    scan(outbox_dir(root), s.pending);
    scan(root.dir / L".incoming", s.staging);
    for (auto* v : { &s.pending, &s.acknowledged, &s.simulated_acknowledged, &s.staging }) {
        std::sort(v->begin(), v->end());
    }
    return s;
}

} // namespace virule::core::evaluation_evidence
