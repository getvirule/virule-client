#pragma once
// WHAT THE CLIENT ESTABLISHED OF EACH FLAGGED FILE (owner brief 2026-11-06,
// the corrective pass after the external malware-analysis research, sections
// 3 and 4; VIRULE_BACKEND src/evaluations/security.ts identityOf, migration
// 0029). CLIENT ONLY.
//
// An incident's threats name files as Defender states them (`file:_C:\...`,
// `containerfile:_C:\a.zip; file:_C:\a.zip->inner`) and, for a file the
// antivirus took, as a plain or lower-cased path, a package entry's bare name,
// or a sentence. Before the incident is kept, every entry gets an Identity
// (malware_scan.hpp) from an INDEX of what this Client itself wrote or copied
// at that stage, with the digest it computed WHILE it held the bytes:
//   - a file of the extracted package (extract_zip): origin `package`, the
//     exact entry name, the SHA-256 and size of the bytes the extractor wrote;
//   - an original executable copied out of the wrapper
//     (extract_wrapped_originals): origin `wrapped_original`, the wrapper's
//     entry, the member, the SHA-256 and size of the copy as written;
//   - an installed package file still exactly as recorded at placement
//     (verified_digests.hpp): its recorded digest, even once the antivirus
//     took it;
//   - content inside ANY container, the package zip included, gets NO digest:
//     only the entry's name is stated (the same entry, extracted, is flagged
//     with its own digest; a name in the zip identifies its bytes only if the
//     whole package was read, which a failed extraction does not do).
// Each index digest stands while the file still has the size and write time
// it had when written, or is GONE (real-time protection took the file VIRULE
// had written whole, before or during the scan: what Defender evaluated was
// the bytes VIRULE wrote, so the digest stands, which is the usual quarantine
// path); a file present but changed loses it, and so does a file MORE THAN ONE
// package entry wrote (a duplicate name, a case variant, or a name Windows maps
// onto the same file: which entry's bytes were evaluated cannot be
// established). In VIRULE's own folders a path the index does not know is
// never hashed after the fact. The index is built just before the scan.
//
// A FILE VIRULE DID NOT WRITE (a save, a log, an executable the game wrote, the
// developer's own folder) is hashed AT DETECTION only if it is still on disk
// and the scan did not report it gone or changed (malware_scan.hpp: a file the
// antivirus took, or that changed while it was scanned, is in `missing`):
// origin `local`. Never a digest of a file the antivirus took before VIRULE
// read it, never a container's digest for content inside it, never a guess:
// what cannot be established is stated as absent (`sha256` empty), and the
// service then treats the finding as unidentified (new evidence).
// Nothing here uploads, copies or captures any byte: a digest is all that
// leaves this computer, in the incident.

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include "virule/core/malware_scan.hpp"
#include "virule/core/verified_content.hpp"
#include "client/verified_digests.hpp"

namespace vclient::finding_identity {

namespace fs = std::filesystem;
namespace ms = virule::core::malware_scan;
namespace vc = virule::core::verified_content;

/** One package file the extractor wrote (transfers.hpp extract_zip). */
struct WrittenEntry {
    std::string name;              // the exact entry name in the package
    fs::path target;               // where it was written
    std::uint64_t bytes = 0;
    std::string sha256;            // "" when the write did not complete
    std::uint64_t size_after = 0;  // the file as it stood once closed
    std::int64_t mtime_after = 0;
};

struct Known {
    std::string origin, entry, member, sha256;
    std::uint64_t bytes = 0;
};

struct Index {
    std::map<std::wstring, Known> files;     // normalized lower-case absolute path -> what is known
    std::map<std::string, Known> entries;    // exact package entry names written (recognizing a bare name; never a digest source)
    std::set<std::string> ambiguous;         // entry names the package carries more than once
    std::wstring package;                    // the package zip itself (normalized), "" when none
    /** Folders VIRULE alone wrote at this stage (the extraction, the scan
     *  copies): a file there that the index does not know is NEVER hashed at
     *  detection (only what VIRULE established while writing counts). */
    std::vector<std::wstring> owned;
    /** TEST SEAM for the folder case rule (`detail::CaseCheck`): 1 a
     *  case-sensitive folder, 0 a case-insensitive one, -1 not established.
     *  Empty (always, in the shipped Client): Windows' own answer. */
    std::function<int(const fs::path& dir)> case_probe;
};

/** `idx` treats `dir` as one of its own folders (above). */
inline void own(Index& idx, const fs::path& dir);

/** A path exactly as named: absolute, normalized, native separators, lower
 *  case (nothing folded). */
inline std::wstring exact_key_of(const fs::path& p) {
    std::error_code ec;
    fs::path a = p.is_absolute() ? p : fs::absolute(p, ec);
    std::wstring w = a.lexically_normal().make_preferred().wstring();
    for (auto& c : w) c = static_cast<wchar_t>(towlower(c));
    return w;
}

/** The INDEX key of a path VIRULE wrote: `exact_key_of`, with trailing dots
 *  and spaces dropped from every component. Windows drops them from the names
 *  VIRULE opens (`c.dll.` and `c.dll ` open `c.dll`), so names that reach one
 *  file share a key whatever happened to it in between (a multi-write is then
 *  counted however the writes were timed). Dropping them from an inner folder
 *  too can only merge names, which only ever REMOVES digests. A REPORTED path
 *  that this folding changes names something VIRULE did not write (a file or
 *  folder created with that literal name): `resolve` never gives it an index
 *  digest and never reads it. */
inline std::wstring key_of(const fs::path& p) {
    std::error_code ec;
    fs::path a = p.is_absolute() ? p : fs::absolute(p, ec);
    const std::wstring w = a.lexically_normal().make_preferred().wstring();
    std::wstring out;
    size_t from = 0;
    while (from <= w.size()) {
        const size_t sep = w.find(L'\\', from);
        std::wstring part = w.substr(from, sep == std::wstring::npos ? std::wstring::npos : sep - from);
        const bool drive = part.size() == 2 && part[1] == L':';
        if (!drive) {
            std::wstring folded = part;
            while (!folded.empty() && (folded.back() == L'.' || folded.back() == L' ')) folded.pop_back();
            if (!folded.empty()) part = folded;   // a name of only dots or spaces is left as it is
        }
        out += part;
        if (sep == std::wstring::npos) break;
        out += L'\\';
        from = sep + 1;
    }
    for (auto& c : out) c = static_cast<wchar_t>(towlower(c));
    return out;
}
inline fs::path path_of_utf8(const std::string& s) { return fs::path(std::u8string(s.begin(), s.end())); }

namespace detail {
inline std::int64_t mtime_of(const fs::path& p, bool& ok) {
    std::error_code ec;
    const auto t = fs::last_write_time(p, ec);
    ok = !ec;
    return ok ? static_cast<std::int64_t>(t.time_since_epoch().count()) : 0;
}
/** The file still has exactly the size and write time it had when written. */
inline bool unchanged(const fs::path& p, std::uint64_t size, std::int64_t mtime) {
    std::error_code ec;
    const auto s = fs::file_size(p, ec);
    if (ec || static_cast<std::uint64_t>(s) != size) return false;
    bool ok = false;
    return mtime_of(p, ok) == mtime && ok;
}
/** The digest of the bytes VIRULE wrote still stands for this file: it is
 *  still exactly as written, or it is GONE (real-time protection took it
 *  after VIRULE wrote it whole, before or during the scan: Defender
 *  evaluated the bytes VIRULE wrote; these folders are VIRULE's own, and a
 *  digest is only ever used for a path Defender's record or the scan names).
 *  Present but changed, or a status that cannot be read: it does not. */
inline bool stands(const fs::path& p, std::uint64_t size, std::int64_t mtime) {
    std::error_code ec;
    const bool there = fs::exists(p, ec);
    if (ec) return false;
    return !there || unchanged(p, size, mtime);
}
} // namespace detail

inline void own(Index& idx, const fs::path& dir) {
    std::wstring k = key_of(dir);
    while (!k.empty() && (k.back() == L'\\' || k.back() == L'/')) k.pop_back();
    if (!k.empty()) idx.owned.push_back(k + L"\\");
}

/** The package's own entries, as the extractor wrote them (call this right
 *  before the scan). An entry's digest stands only if its file still stands
 *  as written (`stands`). A FILE MORE THAN ONE ENTRY WROTE (the same name, a
 *  case variant, or a name Windows maps to the same file; the extractor
 *  marks those) has NO digest: which entry's bytes were evaluated cannot be
 *  established. A name carried twice is ambiguous by name too. */
inline void add_package(Index& idx, const std::vector<WrittenEntry>& written) {
    std::map<std::wstring, int> writes;
    for (const auto& w : written) ++writes[key_of(w.target)];
    for (const auto& w : written) {
        Known k;
        k.origin = "package";
        k.entry = w.name;
        const std::wstring key = key_of(w.target);
        if (writes[key] == 1 && ms::detail::is_sha256_hex(w.sha256) && detail::stands(w.target, w.size_after, w.mtime_after)) {
            k.sha256 = w.sha256;
            k.bytes = w.bytes;
        }
        idx.files[key] = k;
        if (idx.ambiguous.count(w.name)) continue;
        if (idx.entries.count(w.name)) { idx.entries.erase(w.name); idx.ambiguous.insert(w.name); continue; }
        idx.entries[w.name] = k;
    }
}

/** The originals copied out of wrappers under `dir` (the extracted or installed
 *  game). The wrapper's entry is its package entry name when the index knows
 *  its file, else its path relative to `dir`. */
inline void add_originals(Index& idx, const std::vector<ms::Original>& originals, const fs::path& dir) {
    for (const auto& o : originals) {
        Known k;
        k.origin = "wrapped_original";
        k.member = o.member;
        const auto wrapper = idx.files.find(key_of(o.wrapper));
        if (wrapper != idx.files.end() && !wrapper->second.entry.empty()) k.entry = wrapper->second.entry;
        else {
            const std::u8string rel = o.wrapper.lexically_relative(dir).generic_u8string();
            k.entry = std::string(rel.begin(), rel.end());
        }
        if (ms::detail::is_sha256_hex(o.sha256) && detail::stands(o.copy, o.size_after, o.mtime_after)) {
            k.sha256 = o.sha256;
            k.bytes = o.bytes;
        }
        idx.files[key_of(o.copy)] = k;
    }
}

/** An installed game's package files still exactly as recorded at placement
 *  (`walk`: the verified content walk taken before this scan, keyed as the
 *  record keys files). Only for the record of THIS revision. */
inline void add_installed(Index& idx, const verified_digests::Record& rec, const std::string& revision_id,
                          const fs::path& dir, const vc::Inventory& walk) {
    if (rec.revision_id != revision_id || revision_id.empty()) return;
    for (const auto& [key, d] : rec.files) {
        const auto now = walk.find(key);
        if (now == walk.end() || now->second.size != d.size || now->second.mtime != d.mtime) continue;
        Known k;
        k.origin = "package";
        k.entry = d.entry;
        k.sha256 = d.sha256;
        k.bytes = d.size;
        idx.files[key_of(dir / path_of_utf8(key))] = k;
        if (!idx.ambiguous.count(d.entry)) {
            if (idx.entries.count(d.entry)) { idx.entries.erase(d.entry); idx.ambiguous.insert(d.entry); }
            else idx.entries[d.entry] = k;
        }
    }
}

namespace detail {
/**
 * A REPORTED PATH, PARSED STRICTLY (nothing trimmed, nothing cut at `;`):
 *   `containerfile:_X; file:_X->inner`  content inside the container X (the
 *                                        two X must be the same text)
 *   `file:_X` or `file:_X->inner`        the file X, or content inside it
 *   `X` (a plain drive path)             the Client's own `missing` entry
 * `;` is legal in a Windows file name, so it is never a separator except in
 * the exact container form, whose `; file:_` cannot occur inside a real path
 * (':' is not allowed in a name). `->` cannot occur in a real path ('>' is not
 * allowed). Anything else does not parse (`ok` false): no file VIRULE can
 * attribute, so no digest.
 */
struct Reported {
    bool ok = false;          // a drive path was named, unambiguously
    bool bare = false;        // no drive path at all (a bare entry name, a sentence)
    std::string path;         // the file (or the container), exactly as named
    bool inside = false;      // the finding is content inside `path`
    std::string inner;        // that content's name, exactly as named
    bool nested = false;      // content inside content (`->` again)
};
inline bool drive_path(const std::string& s) { return s.size() > 2 && s[1] == ':'; }
inline Reported parse_reported(const std::string& r) {
    Reported p;
    static const std::string kContainer = "containerfile:_", kFile = "file:_", kSep = "; file:_", kArrow = "->";
    if (r.rfind(kContainer, 0) == 0) {
        const std::string rest = r.substr(kContainer.size());
        const size_t sep = rest.find(kSep);
        if (sep == std::string::npos) return p;
        const std::string x = rest.substr(0, sep), y = rest.substr(sep + kSep.size());
        const size_t arrow = y.find(kArrow);
        if (arrow == std::string::npos || y.substr(0, arrow) != x || !drive_path(x)) return p;
        p.path = x;
        p.inside = true;
        p.inner = y.substr(arrow + kArrow.size());
        p.nested = p.inner.find(kArrow) != std::string::npos;
        p.ok = true;
        return p;
    }
    std::string x = r.rfind(kFile, 0) == 0 ? r.substr(kFile.size()) : r;
    const size_t arrow = x.find(kArrow);
    if (arrow != std::string::npos) {
        p.inside = true;
        p.inner = x.substr(arrow + kArrow.size());
        p.nested = p.inner.find(kArrow) != std::string::npos;
        x = x.substr(0, arrow);
    }
    if (!drive_path(x)) { p.bare = r.rfind(kFile, 0) != 0 && !p.inside; return p; }
    p.path = x;
    p.ok = true;
    return p;
}
inline ms::Identity of(const Known& k) {
    ms::Identity i;
    i.stated = true;
    i.origin = k.origin;
    i.entry = k.entry;
    i.member = k.member;
    if (ms::detail::is_sha256_hex(k.sha256)) { i.sha256 = k.sha256; i.bytes = k.bytes; }
    return i;
}
inline ms::Identity origin_only(const char* origin, const std::string& entry = std::string()) {
    ms::Identity i;
    i.stated = true;
    i.origin = origin;
    i.entry = entry;
    return i;
}

/** Is `dir` case-sensitive? Windows' per-folder flag, read only (never set):
 *  1 case-sensitive, 0 not, -1 not established. A volume whose file system is
 *  FAT, FAT32 or exFAT is never case-sensitive; any other failure to read the
 *  flag (a network share, an unknown file system, a folder that cannot be
 *  opened) is not established. */
inline int dir_case_sensitivity(const fs::path& dir) {
#if defined(_WIN32)
    const HANDLE h = CreateFileW(dir.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;
    struct { ULONG Flags; } info{ 0 };   // FILE_CASE_SENSITIVE_INFO
    constexpr int kFileCaseSensitiveInfo = 23;   // FILE_INFO_BY_HANDLE_CLASS::FileCaseSensitiveInfo
    constexpr ULONG kCaseSensitiveDir = 0x00000001;   // FILE_CS_FLAG_CASE_SENSITIVE_DIR
    int out = -1;
    if (GetFileInformationByHandleEx(h, static_cast<FILE_INFO_BY_HANDLE_CLASS>(kFileCaseSensitiveInfo), &info, sizeof info)) {
        out = (info.Flags & kCaseSensitiveDir) ? 1 : 0;
    } else {
        wchar_t fsName[MAX_PATH + 1] = {};
        if (GetVolumeInformationByHandleW(h, nullptr, 0, nullptr, nullptr, nullptr, fsName, MAX_PATH)) {
            const std::wstring n = fsName;
            if (n == L"FAT" || n == L"FAT32" || n == L"exFAT") out = 0;
        }
    }
    CloseHandle(h);
    return out;
#else
    (void)dir;
    return -1;
#endif
}

/**
 * THE FOLDER CASE RULE (owner decision 2026-11-06): a fingerprint is trusted
 * for matching only when VIRULE can establish the file's identity without a
 * case alias. Index keys fold case, so a folder whose children may differ
 * only in case (a case-sensitive folder) or whose case behavior cannot be
 * established makes every digest under it untrusted: no index digest is
 * given, nothing is hashed, and the finding stays unidentified (the review
 * reopens). Every folder from the file's parent up to the volume's root is
 * asked once per incident; nothing on the file system is changed.
 */
struct CaseCheck {
    const Index& idx;
    std::map<std::wstring, int> seen;
    bool safe(const fs::path& file) {
        std::error_code ec;
        fs::path d = (file.is_absolute() ? file : fs::absolute(file, ec)).lexically_normal().parent_path();
        for (int guard = 0; !d.empty() && guard < 512; ++guard) {
            const std::wstring k = exact_key_of(d);
            auto it = seen.find(k);
            if (it == seen.end()) it = seen.emplace(k, idx.case_probe ? idx.case_probe(d) : dir_case_sensitivity(d)).first;
            if (it->second != 0) return false;
            const fs::path up = d.parent_path();
            if (up == d) break;
            d = up;
        }
        return true;
    }
};
} // namespace detail

/**
 * THE IDENTITY OF ONE REPORTED PATH (header). `gone`: the scan reported the
 * file taken or changed (or it is a removal entry), so it is never read now.
 * The path is parsed strictly (`detail::parse_reported`); a name that is not
 * exactly a name VIRULE wrote never takes an index digest.
 */
inline ms::Identity resolve(const Index& idx, const std::string& reported, bool gone, const std::function<bool()>& keep_going,
                            detail::CaseCheck& cases) {
    const detail::Reported r = detail::parse_reported(reported);
    if (!r.ok) {
        // A bare package entry name (the antivirus refused the launch file, or
        // a read of it): which bytes were refused is not known, so no digest.
        if (r.bare && (idx.entries.count(reported) || idx.ambiguous.count(reported))) return detail::origin_only("package", reported);
        return detail::origin_only("unknown");
    }
    const fs::path p = path_of_utf8(r.path);
    const std::wstring pk = key_of(p);
    const bool owned = [&]() { for (const auto& o : idx.owned) if (pk.compare(0, o.size(), o) == 0) return true; return false; }();
    // A NAME WITH A LITERAL TRAILING DOT OR SPACE in any component is not a
    // name VIRULE wrote (Windows drops those from the names VIRULE opens): never
    // an index digest (that would be another file's), never read (opened
    // through Windows it would name the folded, other file).
    if (exact_key_of(p) != pk) return detail::origin_only(owned ? "unknown" : "local");
    if (r.inside) {
        // Content INSIDE a container never gets a digest: a container's digest
        // is not the digest of what is inside it, and a name inside the package
        // zip identifies its bytes only if the whole package was read (a failed
        // or partial extraction never lists every entry). The package's entry
        // is named, exactly as reported; the extracted copy of that entry is
        // flagged with its own digest.
        if (pk == idx.package) return detail::origin_only("package", r.nested ? std::string() : r.inner);
        const auto f = idx.files.find(pk);
        if (f != idx.files.end()) return detail::origin_only(f->second.origin.c_str(), f->second.entry);
        return detail::origin_only(owned ? "unknown" : "local");
    }
    const auto f = idx.files.find(pk);
    if (f != idx.files.end()) {
        ms::Identity i = detail::of(f->second);
        // A folder that is case-sensitive, or whose case behavior cannot be
        // established, makes the digest untrusted (the folder case rule).
        if (!i.sha256.empty() && !cases.safe(p)) { i.sha256.clear(); i.bytes = 0; }
        return i;
    }
    if (!idx.package.empty() && pk == idx.package) return detail::origin_only("package");
    // In a folder VIRULE alone wrote, only what it established while writing
    // counts: a path the index does not know is never hashed now.
    if (owned) return detail::origin_only("unknown");
    // A file VIRULE did not write: hashed now only if still there, unchanged.
    ms::Identity i = detail::origin_only("local");
    std::error_code ec;
    if (!gone && fs::is_regular_file(p, ec) && !ec && cases.safe(p)) {
        std::string hex;
        std::uint64_t bytes = 0;
        if (ms::detail::sha256_file(p, hex, bytes, keep_going)) { i.sha256 = hex; i.bytes = bytes; }
    }
    return i;
}

/**
 * Give every entry of an incident result its Identity (header): each threat
 * and each `missing` entry (the removal, or the file the antivirus refused).
 * A threat whose file the scan reported in `missing` is never read again (the
 * comparison folds names, which only ever prevents a read).
 */
inline void attach(ms::Result& r, const Index& idx, const std::function<bool()>& keep_going = {}) {
    detail::CaseCheck cases{ idx, {} };
    std::set<std::wstring> gone;
    for (const auto& m : r.missing) {
        const detail::Reported d = detail::parse_reported(m);
        if (d.ok) gone.insert(key_of(path_of_utf8(d.path)));
    }
    for (auto& t : r.threats) {
        const detail::Reported d = detail::parse_reported(t.path);
        const bool taken = d.ok && gone.count(key_of(path_of_utf8(d.path))) > 0;
        t.identity = resolve(idx, t.path, taken, keep_going, cases);
    }
    r.missing_identity.clear();
    for (const auto& m : r.missing) r.missing_identity.push_back(resolve(idx, m, true, keep_going, cases));
}

} // namespace vclient::finding_identity
