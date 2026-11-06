#pragma once
// THE VERIFIED DIGESTS RECORD of an installed evaluation game (owner brief
// 2026-11-06, the corrective pass after the external malware-analysis
// research, section 3 "Installed verified content"). CLIENT ONLY.
//
// WHAT IT IS. When an install places a scanned build, the Client writes,
// beside the verified content record (<root>\transfers\<job id>\verified.txt,
// virule/core/verified_content.hpp), every DELIVERED package file's SHA-256,
// computed by the extractor from the very bytes it wrote (transfers.hpp
// extract_zip), with the size and write time the file had when the scan of
// the delivered build began, the exact package entry name, and the revision:
//
//   <root>\transfers\<job id>\verified_digests.txt
//   virule-verified-digests.v1
//   <revision id>
//   <hex(key)>\t<size>\t<mtime>\t<sha256>\t<hex(entry name)>     one per file
//
// (`key` is the verified content record's key: the relative path, lower
// case, '/' separators; key and entry are hex-encoded, so no name a package
// can carry breaks a line.) If Defender later flags an installed file that is
// still exactly as recorded (the same size and write time in the walk taken
// before that scan), the Client knows its digest even after the antivirus
// took it, and states it in the incident (finding_identity.hpp).
//
// WHY A SEPARATE FILE. verified.txt is read by every shipped VIRULE wrapper
// (wrapper_launch_check, built into each evaluation game); a new field in it
// would break their parser or silently empty their check. This file is the
// Client's alone; the wrapper never reads it, and verified.txt is unchanged.
//
// WHAT IT IS NOT. Like verified.txt it is the evaluator's own file on their
// own Windows account: a person who rewrites it can only mislabel their own
// computer's report (which they could also simply never send), never anyone
// else's. It is evidence of identity, never an authorization: nothing is
// skipped, scanned less or launched because of it.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <system_error>

#include "virule/core/evaluation_distribution.hpp"
#include "virule/core/evaluation_evidence.hpp"

namespace vclient::verified_digests {

namespace fs = std::filesystem;

inline constexpr const char* kFormat = "virule-verified-digests.v1";
inline constexpr const wchar_t* kFileName = L"verified_digests.txt";
inline constexpr std::uintmax_t kMaxBytes = 512u * 1024u * 1024u;

struct Digest {
    std::uint64_t size = 0;
    std::int64_t mtime = 0;
    std::string sha256;
    std::string entry;   // the exact package entry name
};

struct Record {
    std::string revision_id;
    std::map<std::string, Digest> files;   // verified content key -> digest
};

inline fs::path record_path(const fs::path& virule_root, const std::string& job_id) {
    return virule::core::evaluation_distribution::job_dir(virule_root, job_id) / kFileName;
}

namespace detail {
inline std::string hex_of(const std::string& s) {
    static const char* kHex = "0123456789abcdef";
    std::string o;
    o.reserve(s.size() * 2);
    for (const unsigned char c : s) { o += kHex[c >> 4]; o += kHex[c & 0xF]; }
    return o;
}
inline bool unhex(const std::string& h, std::string& out) {
    if (h.size() % 2) return false;
    out.clear();
    auto v = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
    for (size_t i = 0; i < h.size(); i += 2) {
        const int a = v(h[i]), b = v(h[i + 1]);
        if (a < 0 || b < 0) return false;
        out += static_cast<char>((a << 4) | b);
    }
    return true;
}
inline bool sha256_hex(const std::string& s) {
    if (s.size() != 64) return false;
    for (const char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
} // namespace detail

inline bool write_record(const fs::path& path, const Record& r) {
    std::string o = std::string(kFormat) + "\n" + r.revision_id + "\n";
    for (const auto& [k, d] : r.files) {
        if (!detail::sha256_hex(d.sha256) || k.empty()) continue;
        o += detail::hex_of(k) + "\t" + std::to_string(d.size) + "\t" + std::to_string(d.mtime) + "\t" + d.sha256 + "\t" +
             detail::hex_of(d.entry) + "\n";
    }
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    return virule::core::evaluation_evidence::write_file_atomic(path, o);
}

/** False for a missing, foreign or damaged record (nothing is known). */
inline bool read_record(const fs::path& path, Record& out) {
    out = Record{};
    std::error_code ec;
    const auto bytes = fs::file_size(path, ec);
    if (ec || bytes == 0 || bytes > kMaxBytes) return false;
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (text.size() != bytes) return false;
    size_t at = 0;
    auto line = [&](std::string& l) -> bool {
        if (at >= text.size()) return false;
        const size_t nl = text.find('\n', at);
        if (nl == std::string::npos) return false;
        l = text.substr(at, nl - at);
        at = nl + 1;
        return true;
    };
    std::string l;
    if (!line(l) || l != kFormat) return false;
    if (!line(out.revision_id) || out.revision_id.empty()) return false;
    while (at < text.size()) {
        if (!line(l)) return false;
        std::string part[5];
        size_t from = 0;
        for (int i = 0; i < 5; ++i) {
            const size_t tab = i < 4 ? l.find('\t', from) : std::string::npos;
            if (i < 4 && tab == std::string::npos) return false;
            part[i] = l.substr(from, i < 4 ? tab - from : std::string::npos);
            from = tab + 1;
        }
        std::string key, entry;
        Digest d;
        if (!detail::unhex(part[0], key) || key.empty() || !detail::unhex(part[4], entry) || !detail::sha256_hex(part[3])) return false;
        try {
            d.size = std::stoull(part[1]);
            d.mtime = std::stoll(part[2]);
        } catch (...) { return false; }
        d.sha256 = part[3];
        d.entry = entry;
        out.files[key] = d;
    }
    return true;
}

} // namespace vclient::verified_digests
