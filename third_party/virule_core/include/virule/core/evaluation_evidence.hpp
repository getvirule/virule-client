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
//   delivery\<package_id>.json  the Client's delivery state of it ("package
//                             delivery" below, 2026-10-22)
//   requests\, progress\      the early completion, the report and the
//                             service's progress (2026-10-21; "requests" below)
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

// =========================================== requests (2026-10-21) =======
// THE TWO OTHER THINGS THE CLIENT DELIVERS FOR AN ASSIGNMENT, beside its
// session packages, with the same ownership rule: whoever writes the
// request file hands it over, the Client owns it from then on, and nothing
// is reported done without the service's answer written as a receipt first.
//
//   requests\<assignment>.early.json    the EARLY COMPLETION (the wrapper's
//                                       post-session panel writes it)
//   requests\<assignment>.report.json   the EVALUATION REPORT (the Admin host
//                                       writes it at Submit Evaluation)
//   receipts\<assignment>.early.json    the service recorded the early completion
//   receipts\<assignment>.report.json   the service accepted the report (the
//                                       assignment is completed)
//   delivery\<assignment>.<kind>.json   the Client's delivery state of a request
//   progress\<assignment>.json          the service's own progress of the
//                                       assignment, as its last answer stated it
//
// Every file name is longer than a package's `<32 hex>.json`, so the
// package scans above never read one of these. A request is ONE document,
// replaced atomically (a new report replaces an unsent or refused one), and
// the Client posts its `body` member to the service exactly as written.

inline constexpr const char* kEarlyFormat = "virule-evaluation-early-completion.v1";
inline constexpr const char* kReportFormat = "virule-evaluation-report.v1";

// The owner's two early-completion reasons (owner brief 2026-10-21).
inline constexpr const char* kEarlyReasonCompletedGame = "completed_game";
inline constexpr const char* kEarlyReasonEndOfContent = "end_of_content";
inline bool is_early_reason(const std::string& r) {
    return r == kEarlyReasonCompletedGame || r == kEarlyReasonEndOfContent;
}
inline constexpr size_t kEarlyExplanationMax = 2000;   // the service's EARLY_EXPLANATION_MAX

inline std::filesystem::path requests_dir(const Root& r) { return r.dir / L"requests"; }
inline std::filesystem::path progress_dir(const Root& r) { return r.dir / L"progress"; }
inline std::filesystem::path early_request_path(const Root& r, const std::string& assignment_id) {
    return requests_dir(r) / std::filesystem::path(assignment_id + ".early.json");
}
inline std::filesystem::path report_request_path(const Root& r, const std::string& assignment_id) {
    return requests_dir(r) / std::filesystem::path(assignment_id + ".report.json");
}
inline std::filesystem::path early_receipt_path(const Root& r, const std::string& assignment_id) {
    return receipts_dir(r) / std::filesystem::path(assignment_id + ".early.json");
}
inline std::filesystem::path report_receipt_path(const Root& r, const std::string& assignment_id) {
    return receipts_dir(r) / std::filesystem::path(assignment_id + ".report.json");
}
inline std::filesystem::path request_delivery_path(const Root& r, const std::string& assignment_id, const char* kind) {
    return r.dir / L"delivery" / std::filesystem::path(assignment_id + "." + kind + ".json");
}
inline std::filesystem::path progress_path(const Root& r, const std::string& assignment_id) {
    return progress_dir(r) / std::filesystem::path(assignment_id + ".json");
}

// ---- THE ASSIGNMENT'S RECONCILED PROGRESS (2026-10-22) ----------------------
// Acknowledged gameplay belongs to the evaluator's ASSIGNMENT, not to one
// Windows installation. The service owns what it RECEIVED (the progress
// document the VIRULE Client keeps from every service answer: its sums and,
// per received session, `received:[{session_id, session_ms, idle_ms}]`);
// this computer's ledger owns what it RECORDED, received or still on its
// way. The assignment's progress is their UNION BY SESSION ID: every
// received session once, with the service's own figures, plus every
// session recorded here that the service has not received. A session the
// service received is never counted twice (a package id IS its session
// id), and a session lost with an erased installation before it was
// received is never invented.

// One recorded session, as either side states it.
struct SessionFigure {
    std::string session_id;
    std::int64_t session_ms = 0, idle_ms = 0;
    std::int64_t index = 0;   // the session's number (the service's list carries it)
};

// The service's progress as the progress document holds it. `known` is
// false without a document (nothing received here yet, or an older
// service); `listed` is false when the document carries no `received`
// list (a service older than 2026-10-22), which leaves only its sums.
struct ServiceProgress {
    bool known = false;
    bool listed = false;
    Totals totals;
    std::int64_t receiving = 0;
    bool eligible = false;
    bool writing_unlocked = false;
    bool early = false;
    std::vector<SessionFigure> received;
};

inline std::int64_t nonneg(std::int64_t v) { return v < 0 ? 0 : v; }

inline ServiceProgress parse_service_progress(std::string_view doc) {
    ServiceProgress p;
    if (doc.empty() || doc.front() != '{') return p;
    std::int64_t s = 0, i = 0, n = 0;
    if (!json::get_int(doc, "sessions", n)) return p;
    (void)json::get_int(doc, "session_ms", s);
    (void)json::get_int(doc, "idle_ms", i);
    p.known = true;
    p.totals.session_ms = nonneg(s);
    p.totals.idle_ms = (std::min)(nonneg(i), p.totals.session_ms);
    p.totals.effective_ms = p.totals.session_ms - p.totals.idle_ms;
    p.totals.sessions = nonneg(n);
    (void)json::get_int(doc, "receiving", p.receiving);
    bool b = false;
    p.eligible = json::get_bool(doc, "eligible", b) && b;
    b = false;
    p.writing_unlocked = json::get_bool(doc, "writing_unlocked", b) && b;
    std::string_view early;
    p.early = json::member(doc, "early_completion", early) && !early.empty() && early.front() == '{';
    std::string_view raw;
    std::vector<std::string_view> items;
    if (json::member(doc, "received", raw) && json::items(raw, items)) {
        p.listed = true;
        for (const auto& it : items) {
            SessionFigure f;
            if (!json::get_string(it, "session_id", f.session_id) || !is_hex32(f.session_id)) continue;
            (void)json::get_int(it, "session_ms", f.session_ms);
            (void)json::get_int(it, "idle_ms", f.idle_ms);
            (void)json::get_int(it, "index", f.index);
            if (f.session_ms < 0) f.session_ms = 0;
            f.idle_ms = (std::min)(nonneg(f.idle_ms), f.session_ms);
            p.received.push_back(std::move(f));
        }
    }
    return p;
}

struct Reconciled {
    Totals totals;                        // the assignment's progress
    std::int64_t received_sessions = 0;   // of which the service received
    std::int64_t local_only_sessions = 0; // recorded here, not received yet
    // The last session in time order is not knowable from the service's
    // figures alone; the last LOCAL session is the caller's.
};

// THE UNION. `local` is this computer's ledger (every session it recorded).
// Without a received list the service's sums cannot be told apart from the
// local sessions, so the larger of the two is taken (never their sum, which
// could count a session twice).
inline Reconciled reconcile_progress(const std::vector<SessionFigure>& local, const ServiceProgress& svc) {
    Reconciled r;
    if (svc.known && svc.listed) {
        std::vector<std::string> ids;
        for (const auto& f : svc.received) {
            if (std::find(ids.begin(), ids.end(), f.session_id) != ids.end()) continue;
            ids.push_back(f.session_id);
            r.totals.session_ms += f.session_ms;
            r.totals.idle_ms += f.idle_ms;
            r.received_sessions += 1;
        }
        for (const auto& f : local) {
            if (std::find(ids.begin(), ids.end(), f.session_id) != ids.end()) continue;
            ids.push_back(f.session_id);
            r.totals.session_ms += nonneg(f.session_ms);
            r.totals.idle_ms += (std::min)(nonneg(f.idle_ms), nonneg(f.session_ms));
            r.local_only_sessions += 1;
        }
    } else {
        Totals mine;
        for (const auto& f : local) {
            mine.session_ms += nonneg(f.session_ms);
            mine.idle_ms += (std::min)(nonneg(f.idle_ms), nonneg(f.session_ms));
            mine.sessions += 1;
        }
        if (svc.known && svc.totals.session_ms > mine.session_ms) {
            r.totals = svc.totals;
            r.received_sessions = svc.totals.sessions;
        } else {
            r.totals = mine;
            r.local_only_sessions = mine.sessions;
        }
    }
    r.totals.sessions = r.received_sessions + r.local_only_sessions;
    if (r.totals.idle_ms > r.totals.session_ms) r.totals.idle_ms = r.totals.session_ms;
    r.totals.effective_ms = r.totals.session_ms - r.totals.idle_ms;
    return r;
}

// The Client's write of a service answer's progress: never BACKWARDS. The
// service only ever adds received sessions, so an answer that states fewer
// than the document already holds is an older answer arriving late (a
// relayed read that crossed a receipt) and is not written.
inline bool progress_is_not_older(std::string_view next, std::string_view held) {
    const ServiceProgress n = parse_service_progress(next);
    if (!n.known) return false;
    const ServiceProgress h = parse_service_progress(held);
    if (!h.known) return true;
    return n.totals.sessions >= h.totals.sessions;
}

// The one write of an assignment's progress document (the VIRULE Client's,
// from any service answer that carries it). True when it was written.
inline bool store_progress(const Root& r, const std::string& assignment_id, std::string_view progress) {
    if (r.dir.empty() || !is_hex32(assignment_id)) return false;
    const auto path = progress_path(r, assignment_id);
    if (!progress_is_not_older(progress, read_document(path))) return false;
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    return write_file_atomic(path, std::string(progress) + "\n");
}

// The early completion as the wrapper records it. `body` is what the
// service receives: {request_id, reason, explanation}.
struct EarlyRequest {
    std::string request_id, assignment_id, reason, explanation, created_utc;
};

inline std::string early_body_json(const EarlyRequest& e) {
    using json::quote;
    return "{\"request_id\":" + quote(e.request_id) + ",\"reason\":" + quote(e.reason) +
        ",\"explanation\":" + quote(e.explanation) + "}";
}

inline std::string early_request_json(const EarlyRequest& e) {
    using json::quote;
    return "{\"format\":" + quote(kEarlyFormat) + ",\"assignment_id\":" + quote(e.assignment_id) +
        ",\"created_utc\":" + quote(e.created_utc) + ",\"body\":" + early_body_json(e) + "}\n";
}

inline bool parse_early_request(std::string_view text, EarlyRequest& e) {
    e = EarlyRequest{};
    std::string format;
    if (!json::get_string(text, "format", format) || format != kEarlyFormat) return false;
    if (!json::get_string(text, "assignment_id", e.assignment_id) || !is_hex32(e.assignment_id)) return false;
    e.created_utc = json::opt_string(text, "created_utc");
    std::string_view body;
    if (!json::member(text, "body", body)) return false;
    if (!json::get_string(body, "request_id", e.request_id) || !is_hex32(e.request_id)) return false;
    if (!json::get_string(body, "reason", e.reason) || !is_early_reason(e.reason)) return false;
    if (!json::get_string(body, "explanation", e.explanation) || e.explanation.empty()) return false;
    return true;
}

// The request's raw `body` member (what the Client posts), or "".
inline std::string request_body(std::string_view text) {
    std::string_view body;
    if (!json::member(text, "body", body) || body.empty() || body.front() != '{') return {};
    return std::string(body);
}

// The report as the Admin host records it: {format, assignment_id,
// submission_id, created_utc, packages:[...], body:{...service body...}}.
inline bool report_request_ids(std::string_view text, std::string& assignment_id, std::string& submission_id) {
    std::string format;
    assignment_id.clear();
    submission_id.clear();
    if (!json::get_string(text, "format", format) || format != kReportFormat) return false;
    if (!json::get_string(text, "assignment_id", assignment_id) || !is_hex32(assignment_id)) return false;
    if (!json::get_string(text, "submission_id", submission_id) || !is_hex32(submission_id)) return false;
    return !request_body(text).empty();
}

#if defined(_WIN32)
// THE SESSION'S PRESENCE (2026-10-21). While an evaluation wrapper serves an
// assignment (from its first look at the assignment through its post-session
// panel) it holds this named mutex. The VIRULE Client never replaces that
// assignment's installation while it exists (a mandatory update waits for
// the game and its panels to close), and the Admin reads it as running. The
// system releases it with the process, so a crash never leaves it held.
inline std::wstring running_mutex_name(const std::string& assignment_id) {
    return L"Local\\VIRULE.Evaluation.Running." + std::wstring(assignment_id.begin(), assignment_id.end());
}

inline bool session_running(const std::string& assignment_id) {
    if (!is_hex32(assignment_id)) return false;
    HANDLE h = OpenMutexW(SYNCHRONIZE, FALSE, running_mutex_name(assignment_id).c_str());
    if (h) { CloseHandle(h); return true; }
    return GetLastError() == ERROR_ACCESS_DENIED;   // it exists, held by another integrity level
}

// The wrapper's handoff of an early completion: one atomic write into the
// requests folder (replacing nothing that was acknowledged: a receipt means
// the assignment's one early completion stands), then the wake event.
enum class EarlyHandoff { HandedOff, AlreadyRecorded, Failed };

inline EarlyHandoff hand_off_early(const Root& root, const EarlyRequest& e) {
    if (root.dir.empty() || !is_hex32(e.assignment_id) || !is_hex32(e.request_id) || !is_early_reason(e.reason) ||
        e.explanation.empty() || e.explanation.size() > kEarlyExplanationMax * 4) {
        return EarlyHandoff::Failed;
    }
    if (exists_quiet(early_receipt_path(root, e.assignment_id))) return EarlyHandoff::AlreadyRecorded;
    if (!write_file_atomic(early_request_path(root, e.assignment_id), early_request_json(e))) return EarlyHandoff::Failed;
    (void)signal_wake();
    return EarlyHandoff::HandedOff;
}
#endif

// THE DEVELOPER'S RECEIVED EVIDENCE (2026-10-21), fetched by the developer's
// VIRULE Client from the service in the background and taken into the
// Admin's durable workspace (evaluation_evidence_store import) once the
// evaluation is delivered:
//   received\<evaluation_id>\evaluation.json   {evaluation_id, game_uuid, status,
//                                              delivered_utc, contest_until_utc}
//   received\<evaluation_id>\<package_id>\     package.json + captures, every file
//                                              verified against its SHA-256
//   received\<evaluation_id>\<package_id>.done the package arrived whole: {package_id,
//                                              sha256}; kept after the Admin took the
//                                              files, so nothing is fetched twice
inline std::filesystem::path received_root(const Root& r) { return r.dir / L"received"; }
inline std::filesystem::path received_dir(const Root& r, const std::string& evaluation_id) {
    return received_root(r) / std::filesystem::path(evaluation_id);
}
inline std::filesystem::path received_package_dir(const Root& r, const std::string& evaluation_id, const std::string& package_id) {
    return received_dir(r, evaluation_id) / std::filesystem::path(package_id);
}
inline std::filesystem::path received_marker_path(const Root& r, const std::string& evaluation_id, const std::string& package_id) {
    return received_dir(r, evaluation_id) / std::filesystem::path(package_id + ".done");
}

// An early completion this computer knows of for the assignment: recorded
// by the service (a receipt), or handed over and not yet answered (a
// request). The post-session panel offers the link only while neither exists.
inline bool early_known(const Root& root, const std::string& assignment_id) {
    return exists_quiet(early_receipt_path(root, assignment_id)) || exists_quiet(early_request_path(root, assignment_id));
}

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

// ===================================================== writing unlock ====
// THE ONE UNLOCK PREDICATE (2026-10-22). Writing opens when the order is
// eligible by its whole progress (or the service recorded an early
// completion) AND every finished session's evidence package is
// acknowledged (docs/specs/UIUX.md:1557) AND the service is not still
// receiving a session. A session counts as ACKNOWLEDGED when this computer
// holds its receipt OR the service's progress lists it as received (by id,
// only when the progress document carries a `received` list: a count is
// never matched against ids). A simulated receipt counts only when the
// caller says so (a staging build). `delivery.acknowledged` elsewhere keeps
// meaning real receipt files only; this is the unlock's own reading.
//
// Pure: no file is read here. The Admin host's assignment status and the
// wrapper's post-session live line both call it, so they cannot drift.

inline bool service_received(const ServiceProgress& svc, const std::string& id) {
    if (!svc.known || !svc.listed) return false;
    for (const auto& f : svc.received) {
        if (f.session_id == id) return true;
    }
    return false;
}

// Acknowledged for the unlock: a local receipt, or listed as received.
inline bool session_acknowledged(const std::string& id, const DeliveryState& local, const ServiceProgress& svc,
                                 bool simulated_counts) {
    return local.has_receipt(id, simulated_counts) || service_received(svc, id);
}

struct Unlock {
    bool unlocked = false;
    bool any_session = false;         // a session exists here or at the service
    bool all_acknowledged = false;    // any_session AND nothing below
    bool service_receiving = false;   // the service is still receiving a session
    std::vector<std::string> unacknowledged;   // finalized here, not acknowledged (sorted, unique)
};

// `finalized`: every session this computer finalized (its ledger, plus any
// package the evidence root holds for the assignment).
inline Unlock writing_unlock(bool eligible_or_early, const std::vector<std::string>& finalized,
                             const DeliveryState& local, const ServiceProgress& svc, bool simulated_counts) {
    Unlock u;
    std::vector<std::string> ids = finalized;
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    for (const auto& id : ids) {
        if (!session_acknowledged(id, local, svc, simulated_counts)) u.unacknowledged.push_back(id);
    }
    // The service's history alone is a session too (a reinstall that
    // recorded nothing yet is never locked out of it): its listed ids, or,
    // from a service older than the list, its own count.
    const bool service_has = svc.known && (svc.listed ? !svc.received.empty() : svc.totals.sessions > 0);
    u.any_session = !ids.empty() || service_has;
    u.all_acknowledged = u.any_session && u.unacknowledged.empty();
    u.service_receiving = svc.known && svc.receiving > 0;
    u.unlocked = eligible_or_early && u.all_acknowledged && !u.service_receiving;
    return u;
}

// ====================================================== package delivery ====
// THE CLIENT'S DELIVERY STATE OF ONE PACKAGE (2026-10-22), written by the
// VIRULE Client beside its retry bookkeeping and read by the Admin host to
// say whether a session is on its way:
//   delivery\<package_id>.json  {attempts, failures, last_error,
//     acked: ["package.json", "<seq>.jpg", ...]   (saved after each file),
//     state: "sending" | "waiting",
//     reason: "" | "signed_out" | "other_account" | "offline" | "refused",
//     updated_utc: <unix seconds, the Client's heartbeat while sending>}
// Read leniently: an older Client's file has no state, reason or heartbeat.
inline std::filesystem::path package_delivery_path(const Root& r, const std::string& package_id) {
    return r.dir / L"delivery" / std::filesystem::path(package_id + ".json");
}

struct PackageDelivery {
    bool present = false;
    std::int64_t attempts = 0, failures = 0, updated_unix = 0;
    std::string state, reason, last_error;
    std::vector<std::string> acked;
};

inline PackageDelivery parse_package_delivery(std::string_view text) {
    PackageDelivery d;
    if (text.empty() || text.front() != '{') return d;
    d.present = true;
    d.attempts = json::opt_int(text, "attempts");
    d.failures = json::opt_int(text, "failures");
    d.updated_unix = json::opt_int(text, "updated_utc");
    d.state = json::opt_string(text, "state");
    d.reason = json::opt_string(text, "reason");
    d.last_error = json::opt_string(text, "last_error");
    std::string_view raw;
    std::vector<std::string_view> list;
    if (json::member(text, "acked", raw) && json::items(raw, list)) {
        for (const auto& it : list) {
            std::string f;
            if (!it.empty() && it.front() == '"') {
                if (json::as_string(it, f) && !f.empty()) d.acked.push_back(f);
            } else if (json::get_string(it, "file", f) && !f.empty()) {
                d.acked.push_back(f);
            }
        }
    }
    return d;
}

inline constexpr std::int64_t kSendingHeartbeatSeconds = 30;

// Whether a pending package is MOVING now, and if not, why. No delivery
// file yet: just handed off, the Client has not started (moving). `sending`
// with a heartbeat within 30 s: moving. `sending` but stale: offline. An
// older Client's file (no state): moving before its first attempt, then
// waiting (offline unless it says otherwise). A current Client's held
// package with no named reason is held with none ("").
inline bool package_moving(const PackageDelivery& d, std::int64_t now_unix, std::string& reason) {
    reason.clear();
    if (!d.present) return true;
    if (d.state == "sending") {
        if (d.updated_unix > 0 && now_unix - d.updated_unix <= kSendingHeartbeatSeconds &&
            d.updated_unix - now_unix <= kSendingHeartbeatSeconds) return true;
        reason = "offline";
        return false;
    }
    if (d.state.empty() && d.attempts == 0) return true;
    // A held send states only a reason the Client named: anything else (a
    // partial acknowledgment, a local write failure) is held with no reason
    // of its own, never presented as a connection failure.
    if (d.reason == "signed_out" || d.reason == "other_account" || d.reason == "offline" || d.reason == "refused") {
        reason = d.reason;
    } else if (d.state.empty()) {
        reason = "offline";   // an older Client's file: its failures name no reason
    }
    return false;
}

} // namespace virule::core::evaluation_evidence
