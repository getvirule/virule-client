#pragma once
// THE ONE FOLDER WALK (audit 2026-11-11 L-21). Every walk VIRULE makes over
// a game's files to account for them goes through here: the malware scan's
// inventory and its search for wrapped originals (malware_scan.hpp
// inventory, extract_wrapped_originals), the AMSI path's file list
// (amsi_scan.hpp),
// the verified content record (verified_content.hpp) and the evaluation
// build's measure and package collection (evaluation_delivery.hpp). Header
// only, no other VIRULE header. Vendored byte-identical into virule-client
// beside malware_scan.hpp, amsi_scan.hpp and verified_content.hpp, which
// include it (Client 0.9.30; an older Client walks with the old rule, so the
// Desktop and the Client ship this together, and this Desktop's minimum
// Client is 0.9.30).
//
// THE RULE, the same for every caller:
//   - every regular file under the folder is reported, with its path
//     relative to the folder, its size and its last write time;
//   - every folder is entered;
//   - a LINK is never followed and is never skipped: the walk FAILS. A link
//     is any reparse point whose tag is a name surrogate (it names another
//     file or folder): a symbolic link (IO_REPARSE_TAG_SYMLINK), a junction
//     or mount point (IO_REPARSE_TAG_MOUNT_POINT), a WSL link, and any other
//     surrogate Windows defines. Content reached through a link is not the
//     folder's, and content behind a link is content nobody accounted for;
//   - EVERY OTHER REPARSE POINT IS AN ORDINARY FILE OR FOLDER. That is the
//     cloud placeholder of Dropbox, OneDrive and every Cloud Files provider
//     (IO_REPARSE_TAG_CLOUD*: in a Dropbox folder EVERY file and folder
//     carries one, hydrated or not), deduplication, compression (WOF) and
//     the like: their bytes are the file's own. The walk reads metadata
//     only, which never hydrates a placeholder; a scan or copy that then
//     reads the file hydrates it as Windows does for any reader;
//   - NOTHING IS SKIPPED: a folder that cannot be listed, an entry whose
//     metadata cannot be read, or anything else that is not a plain file or
//     folder makes the walk fail, and each caller fails with its own
//     existing sentence (it never reports over content it did not see).
// The folder the caller names is opened as Windows opens it (a configured
// game folder may itself be reached through a link); the rule applies to
// everything under it.
//
// METADATA. Listing: the size and write time Windows returns with the
// directory listing, and, for a reparse point, from the file itself (the
// listing describes the placeholder, not the file); exactly what a
// std::filesystem directory_entry reports on MSVC, so a record written
// before this walk (verified_content's verified.txt) compares equal.
// PerFile: always from the file itself (std::filesystem::file_size and
// last_write_time), what the malware scan's inventory has always read.
// The write time is std::filesystem::file_time_type ticks (on Windows the
// FILETIME value).

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace virule::core::folder_walk {

namespace fs = std::filesystem;

struct File {
    fs::path path;        // the folder / relative
    fs::path relative;    // relative to the folder, as listed
    std::uint64_t size = 0;
    std::int64_t mtime = 0;
};

enum class Failure {
    none,
    unreadable_folder,   // the folder, or a folder under it, could not be listed whole
    unreadable_file,     // an entry's metadata could not be read
    link,                // a link (header): never followed, never skipped
    stopped,             // the caller's visit returned false
};

struct Walk {
    Failure failure = Failure::none;
    fs::path at;          // the entry the walk stopped at
    bool ok() const { return failure == Failure::none; }
};

enum class Metadata { listing, per_file };

// The Windows constants the rule is written in (winnt.h values), so the
// rule itself is pure and testable anywhere.
inline constexpr std::uint32_t kAttributeDirectory = 0x00000010u;     // FILE_ATTRIBUTE_DIRECTORY
inline constexpr std::uint32_t kAttributeReparsePoint = 0x00000400u;  // FILE_ATTRIBUTE_REPARSE_POINT
inline constexpr std::uint32_t kTagNameSurrogate = 0x20000000u;       // IsReparseTagNameSurrogate
inline constexpr std::uint32_t kTagMountPoint = 0xA0000003u;          // IO_REPARSE_TAG_MOUNT_POINT
inline constexpr std::uint32_t kTagSymlink = 0xA000000Cu;             // IO_REPARSE_TAG_SYMLINK

enum class Kind { file, folder, link };

/** One listed entry by its attributes and reparse tag (header). */
inline Kind classify(std::uint32_t attributes, std::uint32_t reparse_tag) {
    if ((attributes & kAttributeReparsePoint) != 0 &&
        ((reparse_tag & kTagNameSurrogate) != 0 || reparse_tag == kTagSymlink || reparse_tag == kTagMountPoint)) {
        return Kind::link;
    }
    return (attributes & kAttributeDirectory) != 0 ? Kind::folder : Kind::file;
}

namespace detail {

inline bool from_file(const fs::path& p, File& f) {
    std::error_code ec;
    const auto size = fs::file_size(p, ec);
    if (ec) return false;
    const auto when = fs::last_write_time(p, ec);
    if (ec) return false;
    f.size = static_cast<std::uint64_t>(size);
    f.mtime = static_cast<std::int64_t>(when.time_since_epoch().count());
    return true;
}

} // namespace detail

/** Every regular file under `folder`, depth first, in listing order, by the
 *  rule above. `visit` returning false stops the walk (`stopped`). */
inline Walk walk(const fs::path& folder, const std::function<bool(const File&)>& visit,
                 Metadata metadata = Metadata::listing) {
    Walk w;
    const auto fail = [&w](Failure f, const fs::path& at) { w.failure = f; w.at = at; return w; };
#if defined(_WIN32)
    struct Frame {
        HANDLE h = INVALID_HANDLE_VALUE;
        fs::path dir, rel;
        WIN32_FIND_DATAW data{};
        bool pending = false;   // `data` holds an entry not yet taken
    };
    std::vector<Frame> stack;
    struct Closer {
        std::vector<Frame>& s;
        ~Closer() { for (auto& f : s) if (f.h != INVALID_HANDLE_VALUE) FindClose(f.h); }
    } closer{stack};
    const auto open = [&stack](const fs::path& dir, const fs::path& rel) -> bool {
        Frame f;
        f.dir = dir;
        f.rel = rel;
        f.h = FindFirstFileExW((dir / L"*").c_str(), FindExInfoBasic, &f.data, FindExSearchNameMatch, nullptr,
                               FIND_FIRST_EX_LARGE_FETCH);
        if (f.h == INVALID_HANDLE_VALUE) {
            // A folder with no entry at all (a volume root) lists nothing;
            // a folder that is not there (any more) is not an empty one.
            if (GetLastError() != ERROR_FILE_NOT_FOUND) return false;
            const DWORD a = GetFileAttributesW(dir.c_str());
            if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY) == 0) return false;
        } else {
            f.pending = true;
        }
        stack.push_back(std::move(f));
        return true;
    };
    if (folder.empty() || !open(folder, fs::path())) return fail(Failure::unreadable_folder, folder);
    while (!stack.empty()) {
        Frame& top = stack.back();
        if (top.h == INVALID_HANDLE_VALUE) { stack.pop_back(); continue; }
        if (!top.pending) {
            if (!FindNextFileW(top.h, &top.data)) {
                if (GetLastError() != ERROR_NO_MORE_FILES) return fail(Failure::unreadable_folder, top.dir);
                FindClose(top.h);
                top.h = INVALID_HANDLE_VALUE;
                stack.pop_back();
                continue;
            }
        }
        top.pending = false;
        const std::wstring name = top.data.cFileName;
        if (name == L"." || name == L"..") continue;
        const std::uint32_t attrs = top.data.dwFileAttributes;
        const std::uint32_t tag = (attrs & kAttributeReparsePoint) != 0 ? top.data.dwReserved0 : 0u;
        File f;
        f.path = top.dir / name;
        f.relative = top.rel / name;
        switch (classify(attrs, tag)) {
            case Kind::link:
                return fail(Failure::link, f.path);
            case Kind::folder:
                // `top` is not used after this: the push may move it.
                if (!open(f.path, f.relative)) return fail(Failure::unreadable_folder, f.path);
                continue;
            case Kind::file:
                break;
        }
        if (metadata == Metadata::listing && (attrs & kAttributeReparsePoint) == 0) {
            f.size = (static_cast<std::uint64_t>(top.data.nFileSizeHigh) << 32) | top.data.nFileSizeLow;
            f.mtime = static_cast<std::int64_t>((static_cast<std::uint64_t>(top.data.ftLastWriteTime.dwHighDateTime) << 32) |
                                                top.data.ftLastWriteTime.dwLowDateTime);
        } else if (!detail::from_file(f.path, f)) {
            return fail(Failure::unreadable_file, f.path);
        }
        if (visit && !visit(f)) return fail(Failure::stopped, f.path);
    }
    return w;
#else
    (void)metadata;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(folder, fs::directory_options::none, ec);
         !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        std::error_code fec;
        const auto st = it->symlink_status(fec);
        if (fec) return fail(Failure::unreadable_file, it->path());
        if (fs::is_symlink(st)) return fail(Failure::link, it->path());
        if (fs::is_directory(st)) continue;
        if (!fs::is_regular_file(st)) return fail(Failure::unreadable_file, it->path());
        File f;
        f.path = it->path();
        f.relative = it->path().lexically_relative(folder);
        if (!detail::from_file(f.path, f)) return fail(Failure::unreadable_file, f.path);
        if (visit && !visit(f)) return fail(Failure::stopped, f.path);
    }
    if (ec) return fail(Failure::unreadable_folder, folder);
    return w;
#endif
}

} // namespace virule::core::folder_walk
