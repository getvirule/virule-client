#pragma once
// THE ZIP ENTRY NAME GUARD (audit 2026-11-11 L-24): the one rule for which
// names inside a zip VIRULE extracts may become a path under the
// destination. Pure, header only, no other VIRULE header; used by VIRULE
// Desktop's own UI payload extraction (src/core/app_data.cpp) and vendored
// byte-identical into virule-client for its extractions (the evaluation
// package's `safe_entry` and the Desktop package's install; Client 0.9.30),
// so every extractor refuses the same names.
//
// A name is SAFE only when all of these hold:
//   - 1 to 1024 bytes of well-formed UTF-8, no control character (below
//     0x20);
//   - it is split on BOTH '/' and '\' (Windows treats them alike), and
//     every segment is non-empty: no leading separator (an absolute path,
//     a UNC or device path such as \\server\share or \\?\C:\), no doubled
//     separator; one trailing separator is allowed and marks a folder entry;
//   - no segment is "." or "..";
//   - no segment contains ':' (a drive letter such as C:, a drive-relative
//     path such as C:x, an alternate data stream such as file:stream) or any
//     other character Windows forbids in a name: < > " | ? *;
//   - no segment ends in '.' or ' ' (Windows strips them, so the name would
//     land on another file than the one it names);
//   - no segment is a device name: CON, PRN, AUX, NUL, COM0 to COM9, LPT0 to
//     LPT9 (also with a superscript 1, 2 or 3), CONIN$, CONOUT$, in any case,
//     alone or before an extension ("nul.txt", "COM1 .log").
// Anything else is refused whole; no name is repaired or shortened.

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace virule::core::zip_entry {

inline constexpr std::size_t kMaxNameBytes = 1024;

struct Name {
    std::vector<std::string> segments;   // the path under the destination, in order (UTF-8 as stored)
    bool folder = false;                 // the name ended in a separator
};

namespace detail {

inline char lower_ascii(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

inline bool equals_ignore_case(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (lower_ascii(a[i]) != lower_ascii(b[i])) return false;
    }
    return true;
}

// Well-formed UTF-8 (RFC 3629): no stray continuation byte, no truncated
// sequence, no overlong form, no surrogate, nothing above U+10FFFF. A path
// built from anything else throws when converted (std::u8string to the wide
// path), so such a name is refused here instead.
inline bool well_formed_utf8(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) { ++i; continue; }
        std::size_t len = 0;
        unsigned char lo = 0x80, hi = 0xBF;   // the allowed range of the SECOND byte
        if (c >= 0xC2 && c <= 0xDF) len = 2;
        else if (c == 0xE0) { len = 3; lo = 0xA0; }
        else if ((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF) len = 3;
        else if (c == 0xED) { len = 3; hi = 0x9F; }
        else if (c == 0xF0) { len = 4; lo = 0x90; }
        else if (c >= 0xF1 && c <= 0xF3) len = 4;
        else if (c == 0xF4) { len = 4; hi = 0x8F; }
        else return false;
        if (i + len > s.size()) return false;
        const unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
        if (c1 < lo || c1 > hi) return false;
        for (std::size_t k = 2; k < len; ++k) {
            const unsigned char ck = static_cast<unsigned char>(s[i + k]);
            if (ck < 0x80 || ck > 0xBF) return false;
        }
        i += len;
    }
    return true;
}

} // namespace detail

/** A Windows device name, alone or before an extension (header). */
inline bool is_device_name(std::string_view segment) {
    std::string_view stem = segment.substr(0, segment.find('.'));
    while (!stem.empty() && stem.back() == ' ') stem.remove_suffix(1);
    for (const char* d : {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}) {
        if (detail::equals_ignore_case(stem, d)) return true;
    }
    for (const char* prefix : {"COM", "LPT"}) {
        if (stem.size() < 4 || !detail::equals_ignore_case(stem.substr(0, 3), prefix)) continue;
        const std::string_view rest = stem.substr(3);
        if (rest.size() == 1 && rest[0] >= '0' && rest[0] <= '9') return true;
        // The superscript digits Windows also reserves (U+00B9, U+00B2, U+00B3).
        if (rest == "\xC2\xB9" || rest == "\xC2\xB2" || rest == "\xC2\xB3") return true;
    }
    return false;
}

/** One path segment Windows will create as exactly that name (header). */
inline bool is_safe_segment(std::string_view s) {
    if (s.empty() || s == "." || s == "..") return false;
    for (const char c : s) {
        if (static_cast<unsigned char>(c) < 0x20) return false;
        switch (c) {
            case ':': case '<': case '>': case '"': case '|': case '?': case '*': case '/': case '\\':
                return false;
            default:
                break;
        }
    }
    if (s.back() == '.' || s.back() == ' ') return false;
    return !is_device_name(s);
}

/** The safe segments of a zip entry name, or false (header). */
inline bool parse(std::string_view name, Name& out) {
    out = Name{};
    if (name.empty() || name.size() > kMaxNameBytes) return false;
    if (!detail::well_formed_utf8(name)) return false;
    if (name.front() == '/' || name.front() == '\\') return false;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= name.size(); ++i) {
        if (i < name.size() && name[i] != '/' && name[i] != '\\') continue;
        const std::string_view seg = name.substr(start, i - start);
        if (i == name.size() && seg.empty()) {
            out.folder = true;    // one trailing separator: a folder entry
            break;
        }
        if (!is_safe_segment(seg)) { out = Name{}; return false; }
        out.segments.emplace_back(seg);
        start = i + 1;
    }
    if (out.segments.empty()) { out = Name{}; return false; }
    return true;
}

/** The entry as a relative path (segments read as UTF-8), or false. */
inline bool relative_path(std::string_view name, std::filesystem::path& rel_out) {
    Name n;
    if (!parse(name, n)) return false;
    std::filesystem::path rel;
    for (const auto& s : n.segments) rel /= std::filesystem::path(std::u8string(s.begin(), s.end()));
    rel_out = rel;
    return true;
}

} // namespace virule::core::zip_entry
