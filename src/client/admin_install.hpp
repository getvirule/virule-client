#pragma once
// The managed VIRULE Admin installation (Phase 2).
//
// The client owns exactly ONE Admin install location:
// %LOCALAPPDATA%\Programs\VIRULE\Admin\. A development tree or a manually
// extracted copy anywhere else is never reported as installed, never
// updated, and never launched. The whole surface is three closed
// operations, driven by the browser over the bridge:
//
//   - status: installed yes/no, installed version, running yes/no
//   - install/update: the verified staged pipeline below
//   - open: launch the installed virule.exe, and nothing else
//
// THE VERIFIED STAGED PIPELINE (install and update are the same path; an
// update never touches the live install file-by-file):
//   1. fetch the approved Admin manifest from virule.app;
//   2. validate it structurally (version grammar, an HTTPS
//      github.com/getvirule/virule-overlay-releases/releases/download/ url,
//      64-hex sha256, bounded size, minimumClientVersion);
//   3. download the package to staging, streamed, capped at the manifest's
//      declared size, hashed while downloading;
//   4. exact size, then exact SHA-256 (the gate that never has a waiver);
//   5. extract into a staging directory beside the target; every entry is
//      zip-slip guarded (no "..", no absolute paths, no drive letters);
//   6. verify Authenticode + the VIRULE signer identity on every
//      VIRULE-owned executable/component in the staged tree;
//   7. place atomically: fresh install is ONE directory rename; update is
//      live -> Admin.previous, staging -> Admin, and a failed swap renames
//      the previous install straight back, so a known-good install always
//      survives;
//   8. record the manifest's version in client-owned state (the Admin
//      binaries are never probed for a version);
//   9. desktop shortcut if the browser's pending intent asked for one;
//  10. on a FRESH install, launch the installed Admin automatically.
//
// A running Admin is never killed: an update that finds the Admin running
// (or its files locked) reports admin_running and changes nothing.
//
// BROWSER STATE IS INTENT, NOT AUTHORIZATION - and this operation needs no
// browser-side authorization because everything installed is gated by the
// approved manifest hash plus the VIRULE Authenticode identity, exactly the
// Virule-Setup trust decision. If the browser closes after handing the
// install over, the client finishes on its own and the Admin still opens.

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>

#include "client/bridge.hpp"
#include "shared/client_state.hpp"
#include "shared/http_client.hpp"
#include "shared/json_scan.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"
#include "shared/verify_binary.hpp"
#include "shared/version.h"

#include "miniz/miniz.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <objbase.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#endif

namespace vclient::admin_install {

// The approved Admin manifest: virule.app decides which release is
// approved; GitHub only stores the bytes.
constexpr wchar_t kManifestHost[] = L"virule.app";
constexpr wchar_t kManifestPath[] = L"/client/admin-manifest.json";
constexpr size_t kMaxManifestBytes = 16 * 1024;

// The prefix every manifest package url must carry: a DIRECT versioned
// release-asset URL of the Admin release repository, nothing else.
constexpr char kPackageUrlPrefix[] =
    "https://github.com/getvirule/virule-overlay-releases/releases/download/";

// Hard ceiling on the declared package size (the manifest's own size is the
// operative cap; this bounds the manifest itself).
constexpr unsigned long long kMaxPackageBytes = 2ull * 1024ull * 1024ull * 1024ull;

// The identity every VIRULE-owned staged binary must be signed with.
constexpr wchar_t kExpectedSigner[] = L"CN=Heath Michaels";

// Every VIRULE-owned binary the package must carry, verified in the staged
// tree before placement (stock CEF runtime files are third-party and carry
// no VIRULE signature). Paths are relative to the package root.
inline const wchar_t* kRequiredSigned[] = {
    L"virule.exe",
    L".resources\\admin\\ViruleAdminHost.exe",
    L".resources\\bin\\Win32\\SidecarK32.dll",
    L".resources\\bin\\Win32\\SidecarKHost.exe",
    L".resources\\bin\\x64\\SidecarK64.dll",
    L".resources\\bin\\x64\\SidecarKHost.exe",
};

// ONE install/update at a time; the flag also keeps the idle-exit policy
// from ending the process mid-operation after the browser closes.
inline std::atomic<bool> g_busy{ false };

// ---- status ----

inline bool admin_installed() {
    std::error_code ec;
    return std::filesystem::exists(paths::installed_admin_exe(), ec) && !ec;
}

// Is any process running out of the managed Admin directory (virule.exe,
// ViruleAdminHost.exe, the CEF subprocesses)? Image-path prefix match, so a
// development copy or a D:\Virule deployment never reads as "running".
inline bool admin_running() {
    const auto dir = paths::admin_install_dir();
    if (dir.empty()) return false;
    std::wstring prefix = dir.wstring();
    if (prefix.empty()) return false;
    if (prefix.back() != L'\\') prefix += L'\\';
    for (wchar_t& c : prefix) c = (wchar_t)towlower(c);

    bool found = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                      entry.th32ProcessID);
            if (!proc) continue;
            wchar_t image[MAX_PATH * 2] = {};
            DWORD n = (DWORD)(sizeof(image) / sizeof(image[0]));
            if (QueryFullProcessImageNameW(proc, 0, image, &n)) {
                std::wstring path(image, n);
                for (wchar_t& c : path) c = (wchar_t)towlower(c);
                if (path.rfind(prefix, 0) == 0) found = true;
            }
            CloseHandle(proc);
        } while (!found && Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}

// The status block the bridge's status answer embeds. Version comes from
// client-owned state and is reported only while the install actually exists.
inline std::string status_json() {
    const bool installed = admin_installed();
    std::string version;
    if (installed) version = state::load().admin_version;
    std::string out = "{\"installed\":";
    out += installed ? "true" : "false";
    out += ",\"version\":\"" + json_scan::json_escape(version) + "\"";
    out += ",\"running\":";
    out += (installed && admin_running()) ? "true" : "false";
    out += "}";
    return out;
}

// ---- open ----

// Bring the running managed Admin's window to the front (best effort). The
// Admin's main window is a CEF Views window (Chromium's own class), so the
// stable match is: a visible, unowned top-level window whose owning process
// runs out of the managed Admin directory.
inline void focus_running_admin() {
    const auto dir = paths::admin_install_dir();
    if (dir.empty()) return;
    std::wstring prefix = dir.wstring();
    if (prefix.back() != L'\\') prefix += L'\\';
    for (wchar_t& c : prefix) c = (wchar_t)towlower(c);

    struct Ctx { const std::wstring* prefix; HWND found; };
    Ctx ctx{ &prefix, nullptr };
    EnumWindows(
        [](HWND hwnd, LPARAM lp) -> BOOL {
            auto* ctx = (Ctx*)lp;
            if (!IsWindowVisible(hwnd)) return TRUE;
            if (GetWindow(hwnd, GW_OWNER) != nullptr) return TRUE;
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == 0) return TRUE;
            HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                      FALSE, pid);
            if (!proc) return TRUE;
            wchar_t image[MAX_PATH * 2] = {};
            DWORD n = (DWORD)(sizeof(image) / sizeof(image[0]));
            const bool got = QueryFullProcessImageNameW(proc, 0, image, &n) != 0;
            CloseHandle(proc);
            if (!got) return TRUE;
            std::wstring path(image, n);
            for (wchar_t& c : path) c = (wchar_t)towlower(c);
            if (path.rfind(*ctx->prefix, 0) != 0) return TRUE;
            ctx->found = hwnd;
            return FALSE;
        },
        (LPARAM)&ctx);
    if (ctx.found == nullptr) return;
    if (IsIconic(ctx.found)) ShowWindow(ctx.found, SW_RESTORE);
    SetForegroundWindow(ctx.found);
}

// Launch the INSTALLED Admin, and only it. Not a process-launch surface:
// the path is derived, never received. IDEMPOTENT BY DESIGN: the Admin also
// enforces single instance itself, but this side never knowingly launches a
// second copy - a running Admin is focused instead, and a launch already in
// flight (process not yet visible) is not repeated. "Open VIRULE" clicked
// twenty times still means one Admin.
inline std::atomic<unsigned long long> g_last_admin_launch_tick{ 0 };

inline bool open_installed_admin() {
    if (!admin_installed()) return false;
    if (admin_running()) {
        focus_running_admin();
        log::client("admin: already running; focused existing window");
        return true;
    }
    // A just-launched Admin takes a moment to show up in the process scan;
    // treat a repeat inside that window as the same open, not a new one.
    const unsigned long long last = g_last_admin_launch_tick.load();
    const unsigned long long now = GetTickCount64();
    if (last != 0 && now - last < 10000) {
        log::client("admin: launch already in flight; not launching again");
        return true;
    }
    g_last_admin_launch_tick.store(now);
    const auto exe = paths::installed_admin_exe();
    const auto dir = paths::admin_install_dir();
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + exe.wstring() + L"\"";
    if (!CreateProcessW(exe.wstring().c_str(), cmd.data(), nullptr, nullptr,
                        FALSE, 0, nullptr, dir.wstring().c_str(), &si, &pi)) {
        log::client("admin: launch failed");
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    log::client("admin: launched installed virule.exe");
    return true;
}

// ---- the manifest ----

struct Manifest {
    std::string version;
    std::string url;
    std::string sha256;
    long long size = 0;
};

inline bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (const char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

inline bool is_version_grammar(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    for (const char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

// "x.y.z..." -> the leading numeric triple (pre-release suffixes ignored).
inline bool parse_version_triple(const std::string& s, long long out[3]) {
    size_t p = 0;
    for (int i = 0; i < 3; ++i) {
        bool any = false;
        long long v = 0;
        while (p < s.size() && s[p] >= '0' && s[p] <= '9') {
            v = v * 10 + (s[p] - '0');
            ++p;
            any = true;
        }
        if (!any) return false;
        out[i] = v;
        if (i < 2) {
            if (p >= s.size() || s[p] != '.') return false;
            ++p;
        }
    }
    return true;
}

inline bool fetch_manifest(Manifest& out, std::string& why) {
    unsigned long status = 0;
    std::string body;
    if (!http::https_get(kManifestHost, kManifestPath, kMaxManifestBytes,
                         status, body) ||
        status != 200) {
        why = "manifest fetch failed, status=" + std::to_string(status);
        return false;
    }
    if (!json_scan::find_string_in(body, 0, body.size(), "version", out.version) ||
        !is_version_grammar(out.version)) {
        why = "manifest version missing or malformed";
        return false;
    }
    if (!json_scan::find_string_in(body, 0, body.size(), "url", out.url) ||
        out.url.empty() || out.url.size() > 512 ||
        out.url.rfind(kPackageUrlPrefix, 0) != 0) {
        why = std::string("manifest url missing or not under ") + kPackageUrlPrefix;
        return false;
    }
    if (!json_scan::find_string_in(body, 0, body.size(), "sha256", out.sha256)) {
        why = "manifest sha256 missing";
        return false;
    }
    for (auto& c : out.sha256) {
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
    }
    if (!is_hex64(out.sha256)) {
        why = "manifest sha256 is not 64 hex digits";
        return false;
    }
    if (!json_scan::find_number_in(body, 0, body.size(), "size", out.size) ||
        out.size <= 0 || (unsigned long long)out.size > kMaxPackageBytes) {
        why = "manifest size missing or out of bounds";
        return false;
    }
    std::string minimum;
    if (json_scan::find_string_in(body, 0, body.size(), "minimumClientVersion",
                                  minimum)) {
        long long need[3] = {};
        if (parse_version_triple(minimum, need)) {
            const long long have[3] = { VIRULE_CLIENT_VERSION_MAJOR,
                                        VIRULE_CLIENT_VERSION_MINOR,
                                        VIRULE_CLIENT_VERSION_PATCH };
            for (int i = 0; i < 3; ++i) {
                if (have[i] > need[i]) break;
                if (have[i] < need[i]) {
                    why = "this client is older than the manifest's minimumClientVersion " + minimum;
                    return false;
                }
            }
        }
    }
    return true;
}

// ---- extraction (miniz over a file-backed reader; nothing buffers the
// whole package in memory) ----

struct ZipFileReader {
    std::ifstream in;
};

inline size_t zip_read_callback(void* opaque, mz_uint64 file_ofs, void* buf,
                                size_t n) {
    auto* r = static_cast<ZipFileReader*>(opaque);
    r->in.clear();
    r->in.seekg((std::streamoff)file_ofs, std::ios::beg);
    if (!r->in) return 0;
    r->in.read(static_cast<char*>(buf), (std::streamsize)n);
    return (size_t)r->in.gcount();
}

struct ZipWriteSink {
    std::ofstream out;
    bool ok = true;
};

inline size_t zip_write_callback(void* opaque, mz_uint64, const void* buf,
                                 size_t n) {
    auto* sink = static_cast<ZipWriteSink*>(opaque);
    if (!sink->out.write(static_cast<const char*>(buf), (std::streamsize)n).good()) {
        sink->ok = false;
        return 0;
    }
    return n;
}

// Extract the verified package into `dst_dir`. Every entry name is guarded
// against escaping the destination (the Admin's own zip-slip guard): no
// "..", no absolute paths, no drive letters. Component-wise path
// reassembly, wide-path file IO throughout.
inline bool extract_package(const std::filesystem::path& zip_path,
                            const std::filesystem::path& dst_dir,
                            std::string& why) {
    std::error_code ec;
    const auto zip_size = std::filesystem::file_size(zip_path, ec);
    if (ec) {
        why = "package unreadable";
        return false;
    }
    ZipFileReader reader;
    reader.in.open(zip_path, std::ios::binary);
    if (!reader.in) {
        why = "package open failed";
        return false;
    }
    mz_zip_archive zip{};
    zip.m_pRead = zip_read_callback;
    zip.m_pIO_opaque = &reader;
    if (!mz_zip_reader_init(&zip, zip_size, 0)) {
        why = "zip open failed";
        return false;
    }
    bool ok = true;
    const mz_uint n = mz_zip_reader_get_num_files(&zip);
    for (mz_uint i = 0; i < n && ok; ++i) {
        mz_zip_archive_file_stat st{};
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            why = "zip stat failed";
            ok = false;
            break;
        }
        const std::string name = st.m_filename;
        // Reject entries that escape the destination (zip-slip guard).
        if (name.find("..") != std::string::npos || name.empty() ||
            name.front() == '/' || name.front() == '\\' ||
            (name.size() > 1 && name[1] == ':')) {
            why = "zip entry escapes the destination: " + name;
            ok = false;
            break;
        }
        std::filesystem::path out = dst_dir;
        for (const auto& part : std::filesystem::path(name)) out /= part;
        ec.clear();
        if (mz_zip_reader_is_file_a_directory(&zip, i)) {
            std::filesystem::create_directories(out, ec);
            continue;
        }
        std::filesystem::create_directories(out.parent_path(), ec);
        ZipWriteSink sink;
        sink.out.open(out, std::ios::binary | std::ios::trunc);
        if (!sink.out) {
            why = "zip extract open failed: " + name;
            ok = false;
            break;
        }
        if (!mz_zip_reader_extract_to_callback(&zip, i, zip_write_callback,
                                               &sink, 0) ||
            !sink.ok) {
            why = "zip extract failed: " + name;
            ok = false;
            break;
        }
        sink.out.close();
        if (!sink.out.good()) {
            why = "zip extract close failed: " + name;
            ok = false;
        }
    }
    mz_zip_reader_end(&zip);
    return ok;
}

// ---- desktop shortcut ----

// A normal Windows desktop shortcut to the installed Admin. Overwrites an
// existing VIRULE.lnk (idempotent). Never a shortcut to the client, Setup,
// or a development copy: the target is derived from the managed install.
inline bool create_desktop_shortcut() {
    const auto lnk = paths::desktop_shortcut();
    if (lnk.empty()) return false;
    const auto exe = paths::installed_admin_exe();
    const auto dir = paths::admin_install_dir();
    const HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(init);
    bool ok = false;
    IShellLinkW* link = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_IShellLinkW, (void**)&link))) {
        link->SetPath(exe.wstring().c_str());
        link->SetWorkingDirectory(dir.wstring().c_str());
        link->SetIconLocation(exe.wstring().c_str(), 0);
        link->SetDescription(L"VIRULE");
        IPersistFile* file = nullptr;
        if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, (void**)&file))) {
            ok = SUCCEEDED(file->Save(lnk.wstring().c_str(), TRUE));
            file->Release();
        }
        link->Release();
    }
    if (uninit) CoUninitialize();
    return ok;
}

// ---- the install/update operation ----

// Wire states pushed to pages as {"type":"admin_result","state":...}.
//   installed      fresh install completed; the Admin was launched
//   updated        update completed
//   admin_running  the Admin is running; nothing was changed (close it and retry)
//   failed         any other failure; the technical reason is in the log
inline void broadcast_result(const std::string& state,
                             const std::string& version) {
    const std::string payload = "{\"type\":\"admin_result\",\"state\":\"" + state +
        "\",\"version\":\"" + json_scan::json_escape(version) + "\"}";
    bridge::broadcast_to_pages(payload);
}

inline void cleanup_staging() {
    std::error_code ec;
    std::filesystem::remove(paths::admin_download_zip(), ec);
    ec.clear();
    std::filesystem::remove_all(paths::admin_staging_dir(), ec);
}

inline bool rename_with_retries(const std::filesystem::path& from,
                                const std::filesystem::path& to) {
    for (int i = 0; i < 10; ++i) {
        std::error_code ec;
        std::filesystem::rename(from, to, ec);
        if (!ec) return true;
        Sleep(300);
    }
    return false;
}

// The whole verified staged pipeline. Runs on a worker thread; pushes its
// result to every connected page and finishes even when none is left.
inline void run(bool shortcut) {
    if (g_busy.exchange(true)) {
        // An operation is already in flight; its own result push covers
        // every connected page.
        return;
    }
    struct BusyGuard {
        ~BusyGuard() { g_busy.store(false); }
    } busy_guard;

    const bool was_installed = admin_installed();
    log::client(std::string("admin: ") + (was_installed ? "update" : "install") +
                " requested" + (shortcut ? " (desktop shortcut)" : ""));

    // An update of a running Admin never proceeds; check before any work.
    if (was_installed && admin_running()) {
        log::client("admin: update refused; the Admin is running");
        broadcast_result("admin_running", "");
        return;
    }

    // 1-2. The approved manifest.
    Manifest manifest;
    std::string why;
    if (!fetch_manifest(manifest, why)) {
        log::client("admin: manifest rejected: " + why);
        broadcast_result("failed", "");
        return;
    }
    log::client("admin: manifest version=" + manifest.version +
                " size=" + std::to_string(manifest.size) +
                " sha256=" + manifest.sha256);

    // Parse the package url (an https github.com asset; WinHTTP follows the
    // CDN redirect).
    std::wstring whost, wpath;
    {
        const std::string prefix = "https://";
        std::string rest = manifest.url.substr(prefix.size());
        const size_t slash = rest.find('/');
        if (slash == std::string::npos) {
            log::client("admin: manifest url unparseable");
            broadcast_result("failed", "");
            return;
        }
        const std::string host = rest.substr(0, slash);
        const std::string path = rest.substr(slash);
        whost.assign(host.begin(), host.end());
        wpath.assign(path.begin(), path.end());
    }

    cleanup_staging();
    const auto zip_path = paths::admin_download_zip();
    const auto staging = paths::admin_staging_dir();
    const auto admin_dir = paths::admin_install_dir();
    const auto previous = paths::admin_previous_dir();
    std::error_code ec;
    std::filesystem::create_directories(paths::install_dir(), ec);

    // 3. Streamed download, hashed on the way through, capped at the
    // manifest's declared size.
    unsigned long status = 0;
    unsigned long long got_size = 0;
    std::string got_sha;
    if (!http::https_get_to_file(whost.c_str(), wpath.c_str(),
                                 (unsigned long long)manifest.size, zip_path,
                                 status, got_size, got_sha,
                                 []() { bridge::touch_activity(); })) {
        log::client("admin: package download failed, status=" + std::to_string(status));
        cleanup_staging();
        broadcast_result("failed", "");
        return;
    }

    // 4. Exact size, then exact SHA-256. Never waived.
    if (got_size != (unsigned long long)manifest.size) {
        log::client("admin: package size mismatch: got " + std::to_string(got_size));
        cleanup_staging();
        broadcast_result("failed", "");
        return;
    }
    if (got_sha != manifest.sha256) {
        log::client("admin: package sha256 mismatch: " + got_sha);
        cleanup_staging();
        broadcast_result("failed", "");
        return;
    }
    log::client("admin: package verified (" + std::to_string(got_size) + " bytes)");

    // 5. Safe extraction into staging.
    std::filesystem::create_directories(staging, ec);
    if (!extract_package(zip_path, staging, why)) {
        log::client("admin: " + why);
        cleanup_staging();
        broadcast_result("failed", "");
        return;
    }

    // 6. The staged tree must carry every required VIRULE-signed component,
    // validly signed by the VIRULE identity.
    for (const wchar_t* rel : kRequiredSigned) {
        const auto p = staging / rel;
        ec.clear();
        if (!std::filesystem::exists(p, ec) || ec) {
            log::client("admin: required signed file missing in package");
            cleanup_staging();
            broadcast_result("failed", "");
            return;
        }
        if (!verify_binary::authenticode_valid(p) ||
            !verify_binary::signed_by(p, kExpectedSigner)) {
            log::client("admin: staged binary failed signature verification: " +
                        p.filename().string());
            cleanup_staging();
            broadcast_result("failed", "");
            return;
        }
    }
    log::client("admin: staged tree verified (Authenticode + signer identity)");

    // 7. Atomic placement. The previous install survives any failed swap.
    ec.clear();
    std::filesystem::remove_all(previous, ec);
    if (was_installed) {
        if (!rename_with_retries(admin_dir, previous)) {
            // Locked files: the Admin (or something in it) is running.
            log::client("admin: live install is locked; not updated");
            cleanup_staging();
            broadcast_result("admin_running", "");
            return;
        }
        if (!rename_with_retries(staging, admin_dir)) {
            // Put the known-good install straight back.
            (void)rename_with_retries(previous, admin_dir);
            log::client("admin: staging swap failed; previous install restored");
            cleanup_staging();
            broadcast_result("failed", "");
            return;
        }
        ec.clear();
        std::filesystem::remove_all(previous, ec);
    } else {
        if (!rename_with_retries(staging, admin_dir)) {
            log::client("admin: install placement failed");
            cleanup_staging();
            broadcast_result("failed", "");
            return;
        }
    }
    ec.clear();
    std::filesystem::remove(zip_path, ec);

    // 8. Record the installed version (the manifest's).
    {
        auto s = state::load();
        s.admin_version = manifest.version;
        if (shortcut) s.created_desktop_shortcut = true;
        (void)state::save(s);
    }

    // 9. The desktop shortcut, when the browser's intent asked for one.
    if (shortcut) {
        if (create_desktop_shortcut()) {
            log::client("admin: desktop shortcut created");
        } else {
            // A missing shortcut is a cosmetic loss, never an install failure.
            log::client("admin: desktop shortcut could not be created");
        }
    }

    // 10. A FRESH install opens the Admin automatically; an update leaves
    // the user where they are.
    if (!was_installed) {
        (void)open_installed_admin();
    }

    log::client("admin: " + std::string(was_installed ? "updated" : "installed") +
                " version " + manifest.version);
    broadcast_result(was_installed ? "updated" : "installed", manifest.version);
}

} // namespace vclient::admin_install
