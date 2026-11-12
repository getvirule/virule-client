// THE ZIP ENTRY NAME GUARD in the Client's two extractors (audit L-24,
// 2026-11-12; virule/core/zip_entry.hpp, vendored from v2_mvp). Built and
// run by tests\zip_guard\run_tests.bat.
//
//   A. Every entry name of a REAL VIRULE Desktop package passes the guard
//      (the names file given as argv[1], one stored name per line, listed
//      from the staging alpha.77 package by the .bat; skipped with a note
//      when no names file is given).
//   B. Hostile names are refused by BOTH real extractors, each with its own
//      existing failure: the Desktop package install
//      (admin_install::extract_package, "zip entry escapes the destination:
//      <name>") and the evaluation package (transfers::detail::extract_zip,
//      "The package holds an unsafe file name."). Nothing is written. The
//      drive used for the drive-relative names is one this computer does not
//      have, so even the rule this replaced could write nothing there.
//   C. A benign package (both separators, nested folders, a folder entry)
//      still extracts to the same files through both extractors.
//
// Starts no client and touches no port; everything is under %TEMP%.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "client/admin_install.hpp"
#include "client/transfers.hpp"
#include "virule/core/zip_entry.hpp"

namespace fs = std::filesystem;
namespace ze = virule::core::zip_entry;
namespace ai = vclient::admin_install;
namespace tr = vclient::transfers;

static int g_pass = 0, g_fail = 0;
static void check(const std::string& what, bool ok) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what.c_str());
    (ok ? g_pass : g_fail)++;
}

static void write_zip(const fs::path& zp, const std::vector<std::pair<std::string, std::string>>& files) {
    mz_zip_archive zip{};
    FILE* zf = nullptr;
    _wfopen_s(&zf, zp.wstring().c_str(), L"wb");
    mz_zip_writer_init_cfile(&zip, zf, 0);
    for (const auto& f : files) {
        mz_zip_writer_add_mem(&zip, f.first.c_str(), f.second.data(), f.second.size(), MZ_NO_COMPRESSION);
    }
    mz_zip_writer_finalize_archive(&zip);
    mz_zip_writer_end(&zip);
    fclose(zf);
}

static size_t files_under(const fs::path& dir) {
    std::error_code ec;
    size_t n = 0;
    for (auto it = fs::recursive_directory_iterator(dir, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (it->is_regular_file(ec)) ++n;
    }
    return n;
}

// A drive letter this computer does not have.
static char absent_drive() {
    const DWORD mask = GetLogicalDrives();
    for (char c = 'Q'; c <= 'Z'; ++c) {
        if (!(mask & (1u << (c - 'A')))) return c;
    }
    return 0;
}

static std::string printable(const std::string& s) {
    std::string out;
    for (const unsigned char c : s) {
        if (c < 0x20 || c >= 0x7f) { char b[8]; std::snprintf(b, sizeof b, "\\x%02X", c); out += b; }
        else out += static_cast<char>(c);
    }
    return out;
}

int main(int argc, char** argv) {
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    const fs::path root = fs::path(tmp) / L"virule-zip-guard-test";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);

    // ---- A. the real Desktop package's names ----
    // The package is only LISTED (miniz's central directory, the names exactly
    // as the extractor receives them); nothing in it is extracted or run.
    if (argc > 1) {
        std::printf("real package: %s\n", argv[1]);
        mz_zip_archive zip{};
        size_t names = 0, refused = 0, folders = 0;
        const bool opened = mz_zip_reader_init_file(&zip, argv[1], 0) != 0;
        check("the real Desktop package opens as a zip", opened);
        if (opened) {
            const mz_uint n = mz_zip_reader_get_num_files(&zip);
            for (mz_uint i = 0; i < n; ++i) {
                mz_zip_archive_file_stat st{};
                if (!mz_zip_reader_file_stat(&zip, i, &st)) { ++refused; continue; }
                const std::string name = st.m_filename;
                ++names;
                ze::Name parsed;
                fs::path rel;
                if (!ze::parse(name, parsed) || !tr::detail::safe_entry(name, rel)) {
                    ++refused;
                    std::printf("  refused: %s\n", printable(name).c_str());
                }
                if (parsed.folder) ++folders;
            }
            mz_zip_reader_end(&zip);
        }
        std::printf("real package entries: %zu (%zu folder entries)\n", names, folders);
        check("the real Desktop package lists entries", names > 0);
        check("every entry name of the real Desktop package passes the guard", names > 0 && refused == 0);
    } else {
        std::printf("NOTE: no Desktop package given; section A skipped\n");
    }

    // ---- B. hostile names, through both real extractors ----
    const char drive = absent_drive();
    check("(setup) a drive letter this computer does not have", drive != 0);
    const std::string d(1, drive);
    const std::vector<std::string> hostile = {
        "a/" + d + ":x",          // drive-relative after a first segment (escaped the Desktop guard)
        "a\\" + d + ":x",
        d + ":x",                 // drive-relative
        d + ":/x",                // absolute
        "/abs", "\\abs", "\\\\server\\share\\x", "\\\\?\\C:\\x",
        "../x", "a/../../x", "a\\..\\x", "./x", "a/./b",
        "a//b",                   // doubled separator
        "file:stream", "a/b:stream",   // alternate data stream (never a one-letter name: that is a drive)
        "nul", "NUL.txt", "a/CON", "a/com1.log", "LPT9", "aux .txt", "conin$", "CONOUT$.x",
        "lpt\xC2\xB9", "COM\xC2\xB3.txt",   // superscript digits
        "x.", "a/x ", "a./b", "a /b",       // trailing dot or space (Windows strips them)
        "a/b<c", "a/b>c", "a/b\"c", "a/b|c", "a/b?c", "a/b*c",
        std::string("a/b\x01" "c"),
        std::string(1100, 'a'),
        // not well-formed UTF-8 (the path conversion throws; the Client must
        // refuse, never end): invalid bytes, a truncated sequence, an overlong form
        std::string("\xFF\xFE.txt"), std::string("a\xC3"), std::string("\xC0\xAF"),
    };
    for (const std::string& name : hostile) {
        const fs::path zp = root / "hostile.zip";
        write_zip(zp, { { name, "payload" } });
        const std::string label = printable(name.size() > 60 ? name.substr(0, 12) + "...(" + std::to_string(name.size()) + " bytes)" : name);
        // The Client's guard: zip_entry plus the UTF-8 refusal (safe_entry).
        // zip_entry::parse alone does not check UTF-8 (reported upstream).
        fs::path guard_rel;
        check("the Client's guard refuses \"" + label + "\"", !tr::detail::safe_entry(name, guard_rel));
        // miniz's own writer refuses a few names outright (a leading '/', an
        // oversized name), so such a package cannot be built here: the
        // guard's refusal above is the whole check for those.
        {
            mz_zip_archive probe{};
            bool stored = false;
            if (mz_zip_reader_init_file(&probe, zp.string().c_str(), 0)) {
                mz_zip_archive_file_stat st{};
                stored = mz_zip_reader_get_num_files(&probe) == 1 && mz_zip_reader_file_stat(&probe, 0, &st) &&
                         name == st.m_filename;
                mz_zip_reader_end(&probe);
            }
            if (!stored) { std::printf("  note: miniz cannot store \"%s\"; guard-level check only\n", label.c_str()); continue; }
        }
        const fs::path dst_a = root / "desktop";
        const fs::path dst_t = root / "game";
        fs::remove_all(dst_a, ec);
        fs::remove_all(dst_t, ec);
        fs::create_directories(dst_a, ec);
        fs::create_directories(dst_t, ec);
        std::string why_a, why_t;
        const bool ok_a = ai::extract_package(zp, dst_a, why_a);
        const bool ok_t = tr::detail::extract_zip(zp, dst_t, why_t, {});
        check("Desktop package refuses \"" + label + "\" as an escape",
              !ok_a && why_a.rfind("zip entry escapes the destination: ", 0) == 0 && files_under(dst_a) == 0);
        check("evaluation package refuses \"" + label + "\" as unsafe",
              !ok_t && why_t == "The package holds an unsafe file name." && files_under(dst_t) == 0);
    }
    std::error_code dec;
    check("nothing was written on the absent drive", !fs::exists(fs::path(d + ":\\x"), dec));

    // ---- C. a benign package still extracts the same through both ----
    {
        const fs::path zp = root / "benign.zip";
        write_zip(zp, { { "virule.exe", "exe" }, { ".resources\\bin\\x64\\libcef.dll", "dll" },
                        { "admin_ui/assets/index-abc.js", "js" }, { "docs/", "" },
                        { "a.b.c/file.name.txt", "dots" }, { "spaces in name/x y.txt", "sp" } });
        for (int which = 0; which < 2; ++which) {
            const fs::path dst = root / (which == 0 ? "benign-desktop" : "benign-game");
            fs::remove_all(dst, ec);
            fs::create_directories(dst, ec);
            std::string why;
            const bool ok = which == 0 ? ai::extract_package(zp, dst, why) : tr::detail::extract_zip(zp, dst, why, {});
            const char* who = which == 0 ? "Desktop package" : "evaluation package";
            check(std::string(who) + ": a benign package extracts", ok);
            check(std::string(who) + ": both separators place the same nested files",
                  fs::is_regular_file(dst / "virule.exe", ec) &&
                      fs::is_regular_file(dst / ".resources" / "bin" / "x64" / "libcef.dll", ec) &&
                      fs::is_regular_file(dst / "admin_ui" / "assets" / "index-abc.js", ec) &&
                      fs::is_regular_file(dst / "a.b.c" / "file.name.txt", ec) &&
                      fs::is_regular_file(dst / "spaces in name" / "x y.txt", ec));
            check(std::string(who) + ": a folder entry makes a folder", fs::is_directory(dst / "docs", ec));
            check(std::string(who) + ": exactly the package's files", files_under(dst) == 5);
        }
    }

    fs::remove_all(root, ec);
    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
