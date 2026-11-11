#pragma once
// THE ONE WRAPPER PAYLOAD LOCATOR (audit 2026-11-11 H-2). Header only, pure:
// no Windows, no file API, no wrapper runtime state. Every reader that
// decides what is SCANNED or RUN uses it, so where the payload IS can never
// be answered two ways (app_data.cpp's builder-side readiness check still
// reads the footer at EOF only; it fails closed on a signed output):
//   - the launcher (src/wrapper_runtime/wrapper_runtime.cpp
//     try_read_embedded_payload), which materializes the original game
//     executable and runs it;
//   - the malware scanner (malware_scan.hpp extract_wrapped_originals), which
//     copies that same original out to be scanned before anything is sent,
//     installed or played (Desktop and, vendored byte-identical into
//     virule-client/third_party/virule_core, the VIRULE Client).
// Before this header the scanner read the footer only at EOF-24 while the
// launcher also accepted it before a trailing certificate table, so a wrapped
// executable Authenticode-signed after wrapping (or carrying a fake
// certificate table) ran an original the scanner never saw.
//
// THE ON-DISK FORMAT (src/wrapper_model/wrapper_model.cpp; unchanged, shipped
// games carry it):
//   [stub PE][payload][footer 24][zero pad 0..7][certificate table]
//                                               ^ optional, only when the
//                                                 wrapped file was signed
//   payload  = "VRULPK1\0" u32 file_count, then file_count table entries
//              (u32 path_len, path bytes (UTF-8), u64 offset, u64 size), then
//              the data region (offsets are from the start of the data region)
//   footer   = "VRULEND1" u64 payload_size u64 footer_size (= 24)
//
// WHERE VIRULE'S DATA ENDS. The PE security data directory (index 4) records
// the certificate table, and uniquely among data directories its address is a
// FILE OFFSET. Authenticode requires that table to be the LAST bytes of the
// file; only then does it bound VIRULE's data, and the footer may sit up to 7
// zero bytes before it (the signer's 8-byte alignment). A table that ends
// before EOF is a stale leftover (a wrap made from a signed template): EOF
// stays the end. The check is structural only; the signature is never
// validated here.
//
// A file whose PE headers do not parse is never a payload the launcher runs
// (Location::pe false); the locator still reads its footer at EOF, so the
// scanner examines strictly more than the launcher could ever run.
//
// `read_at(offset, dst, n)` reads exactly n bytes at offset, false otherwise.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace virule::core::wrapper_payload {

inline constexpr char kFooterMagic[8] = {'V', 'R', 'U', 'L', 'E', 'N', 'D', '1'};
inline constexpr char kPayloadMagic[8] = {'V', 'R', 'U', 'L', 'P', 'K', '1', '\0'};
inline constexpr std::uint64_t kFooterBytes = 24;
inline constexpr std::uint64_t kHeadBytes = 12;              // payload magic + file_count
inline constexpr std::uint64_t kMinEntryBytes = 4 + 1 + 16;  // path_len, one path byte, offset, size
inline constexpr std::uint64_t kMaxSigningPad = 7;
inline constexpr std::uint32_t kMaxEntries = 1'000'000;
inline constexpr std::uint32_t kMaxEntryPath = 1024u * 1024u;   // the launcher's limit since the format began

enum class Found {
    none,        // no footer where the format puts one: not a wrapper
    wrapper,     // footer and payload header valid
    malformed,   // a footer is there but the payload it describes is not
};

struct Location {
    Found found = Found::none;
    bool pe = false;            // the PE headers parse (the launcher requires it)
    bool cert_table = false;    // a certificate table is the file's last bytes
    std::uint64_t eof = 0;
    std::uint64_t effective_end = 0;   // where VIRULE's data may end (cert table offset, else EOF)
    std::uint64_t footer_end = 0;
    std::uint64_t payload_start = 0;
    std::uint64_t payload_size = 0;
    std::uint32_t file_count = 0;
};

struct Entry {
    std::string path;           // UTF-8 virtual path, e.g. "__virule__/orig/Game.exe"
    std::uint64_t offset = 0;   // from the start of the data region
    std::uint64_t size = 0;
};

namespace detail {

template <class T>
inline T load_le(const char* p) {
    T v{};
    std::memcpy(&v, p, sizeof v);
    return v;
}

/** Where VIRULE's data ends per the PE security directory. False when the PE
 *  headers do not parse (truncated, not MZ/PE, unknown optional header, a
 *  security directory outside the file). */
template <class ReadAt>
inline bool image_end(std::uint64_t eof, ReadAt& read_at, std::uint64_t& out_end, bool& cert_table) {
    out_end = eof;
    cert_table = false;
    char dos[64]{};
    if (eof < sizeof dos || !read_at(0, dos, sizeof dos)) return false;
    if (dos[0] != 'M' || dos[1] != 'Z') return false;
    const std::uint32_t pe_offset = load_le<std::uint32_t>(dos + 0x3C);
    if (static_cast<std::uint64_t>(pe_offset) + 24 > eof) return false;
    char sig_coff[24]{};
    if (!read_at(pe_offset, sig_coff, sizeof sig_coff)) return false;
    if (sig_coff[0] != 'P' || sig_coff[1] != 'E' || sig_coff[2] != 0 || sig_coff[3] != 0) return false;
    const std::uint16_t opt_size = load_le<std::uint16_t>(sig_coff + 4 + 16);
    if (opt_size < 2) return false;
    if (static_cast<std::uint64_t>(pe_offset) + 24 + opt_size > eof) return false;
    std::vector<char> opt(opt_size);
    if (!read_at(static_cast<std::uint64_t>(pe_offset) + 24, opt.data(), opt.size())) return false;
    const std::uint16_t magic = load_le<std::uint16_t>(opt.data());
    std::size_t num_rva_off = 0, dir_base = 0;
    if (magic == 0x10B) { num_rva_off = 92; dir_base = 96; }          // PE32
    else if (magic == 0x20B) { num_rva_off = 108; dir_base = 112; }   // PE32+
    else return false;
    if (num_rva_off + 4 > opt.size()) return false;
    const std::uint32_t num_rva = load_le<std::uint32_t>(opt.data() + num_rva_off);
    if (num_rva <= 4) return true;                                     // no security entry
    if (dir_base + (4 + 1) * 8 > opt.size()) return false;
    const std::uint32_t sec_off = load_le<std::uint32_t>(opt.data() + dir_base + 4 * 8);
    const std::uint32_t sec_size = load_le<std::uint32_t>(opt.data() + dir_base + 4 * 8 + 4);
    if (sec_off == 0 || sec_size == 0) return true;                    // directory empty
    const std::uint64_t sec_end = static_cast<std::uint64_t>(sec_off) + sec_size;   // u32+u32: no wrap
    if (sec_off >= eof || sec_end > eof) return false;
    if (sec_end != eof) return true;                                   // stale mid-file table
    out_end = sec_off;
    cert_table = true;
    return true;
}

} // namespace detail

/** Find the footer and validate the payload header it describes (above). */
template <class ReadAt>
inline Location locate(std::uint64_t eof, ReadAt&& read_at) {
    Location L;
    L.eof = eof;
    L.effective_end = eof;
    if (eof < kFooterBytes) return L;
    std::uint64_t end = eof;
    bool cert = false;
    L.pe = detail::image_end(eof, read_at, end, cert);
    if (L.pe) { L.effective_end = end; L.cert_table = cert; }
    if (L.effective_end < kFooterBytes) return L;

    // The footer at the effective end, or (only when a certificate table
    // moved the end) up to 7 zero bytes before it. A fixed alignment rule,
    // never a search.
    const std::uint64_t max_pad = L.effective_end < eof ? kMaxSigningPad : 0;
    bool found = false;
    for (std::uint64_t pad = 0; pad <= max_pad && !found; ++pad) {
        if (L.effective_end < pad + kFooterBytes) break;
        const std::uint64_t cand_end = L.effective_end - pad;
        if (pad > 0) {
            char padding[kMaxSigningPad]{};
            if (!read_at(cand_end, padding, static_cast<std::size_t>(pad))) continue;
            bool zero = true;
            for (std::uint64_t i = 0; i < pad; ++i) if (padding[i] != 0) { zero = false; break; }
            if (!zero) continue;
        }
        char magic[8]{};
        if (!read_at(cand_end - kFooterBytes, magic, sizeof magic)) continue;
        if (std::memcmp(magic, kFooterMagic, sizeof magic) != 0) continue;
        L.footer_end = cand_end;
        found = true;
    }
    if (!found) return L;

    L.found = Found::malformed;
    char fields[16]{};
    if (!read_at(L.footer_end - 16, fields, sizeof fields)) return L;
    const std::uint64_t payload_size = detail::load_le<std::uint64_t>(fields);
    const std::uint64_t footer_size = detail::load_le<std::uint64_t>(fields + 8);
    if (footer_size != kFooterBytes) return L;
    // footer_end >= kFooterBytes here, so the subtraction cannot wrap.
    if (payload_size < kHeadBytes || payload_size > L.footer_end - kFooterBytes) return L;
    const std::uint64_t payload_start = L.footer_end - kFooterBytes - payload_size;
    char head[kHeadBytes]{};
    if (!read_at(payload_start, head, sizeof head)) return L;
    if (std::memcmp(head, kPayloadMagic, sizeof kPayloadMagic) != 0) return L;
    const std::uint32_t count = detail::load_le<std::uint32_t>(head + 8);
    // Every entry takes at least kMinEntryBytes of the payload: a count the
    // payload cannot hold is malformed before anything is allocated for it.
    if (count > kMaxEntries || count > (payload_size - kHeadBytes) / kMinEntryBytes) return L;
    L.payload_start = payload_start;
    L.payload_size = payload_size;
    L.file_count = count;
    L.found = Found::wrapper;
    return L;
}

/** The payload's table. False (malformed) when any entry's path is empty or
 *  over kMaxEntryPath, the table runs past the payload, or an entry's bytes
 *  fall outside the data region. `data_start` is the data region's file
 *  offset. */
template <class ReadAt>
inline bool read_table(const Location& L, ReadAt&& read_at, std::vector<Entry>& out, std::uint64_t& data_start) {
    out.clear();
    data_start = 0;
    if (L.found != Found::wrapper) return false;
    const std::uint64_t data_end = L.payload_start + L.payload_size;   // == footer_end - kFooterBytes
    std::uint64_t pos = L.payload_start + kHeadBytes;
    std::vector<Entry> entries;
    entries.reserve(L.file_count < 4096u ? L.file_count : 4096u);
    for (std::uint32_t i = 0; i < L.file_count; ++i) {
        char len_bytes[4]{};
        if (data_end - pos < 4 || !read_at(pos, len_bytes, 4)) return false;
        const std::uint32_t len = detail::load_le<std::uint32_t>(len_bytes);
        if (len == 0 || len > kMaxEntryPath) return false;
        if (data_end - pos - 4 < static_cast<std::uint64_t>(len) + 16) return false;
        Entry e;
        e.path.resize(len);
        char nums[16]{};
        if (!read_at(pos + 4, e.path.data(), len) || !read_at(pos + 4 + len, nums, sizeof nums)) return false;
        e.offset = detail::load_le<std::uint64_t>(nums);
        e.size = detail::load_le<std::uint64_t>(nums + 8);
        pos += 4ull + len + 16ull;
        entries.push_back(std::move(e));
    }
    const std::uint64_t room = data_end - pos;
    for (const auto& e : entries) {
        if (e.offset > room || e.size > room - e.offset) return false;
    }
    data_start = pos;
    out = std::move(entries);
    return true;
}

} // namespace virule::core::wrapper_payload
