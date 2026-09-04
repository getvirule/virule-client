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
// THE CLIENT OWNS THE UPDATE LIFECYCLE (owner spec 2026-09-03): an update
// that finds the Admin running tells no one to close anything by hand.
// After a short grace (the surfaces that initiated the update show the
// approved "Shutting down VIRULE" messaging during it), the client closes
// the Admin GRACEFULLY (WM_CLOSE, the same path as the user's own close
// button; never TerminateProcess), waits for it to exit, performs the
// verified staged update, and relaunches the Admin it closed. An Admin
// that refuses to close changes nothing: admin_running is still the
// answer, and the known-good install survives untouched.
//
// THE SILENT UPDATE CHECK: the client caches the approved manifest's
// version (startup, a periodic recheck while serving, and on the Admin
// Settings query) so the Admin can show "Update available" without owning
// any manifest logic itself. Checking is automatic; INSTALLING is always
// user-initiated.
//
// BROWSER STATE IS INTENT, NOT AUTHORIZATION - and this operation needs no
// browser-side authorization because everything installed is gated by the
// approved manifest hash plus the VIRULE Authenticode identity, exactly the
// Virule-Setup trust decision. If the browser closes after handing the
// install over, the client finishes on its own and the Admin still opens.

#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

#include "client/bridge.hpp"
#include "client/result_card.hpp"
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

// ---- the authoritative installed-version record ----
// THE FALSE "UP TO DATE" FIX (2026-09-03): the installed Admin's version
// used to live ONLY in client state.json, which a client reinstall/reset
// removes and recreates while the managed Admin survives, so the browser
// could compare the approved manifest against stale or empty knowledge.
// The version now travels WITH the payload: the staged pipeline writes
// `installed-release.json` into the staging tree BEFORE the atomic
// placement, so the file and the binaries can never disagree, and it is
// recovered from there whenever client state was lost. state.json keeps a
// mirror (it also covers pre-metadata installs).

inline std::filesystem::path installed_release_file() {
    const auto d = paths::admin_install_dir();
    return d.empty() ? d : d / L"installed-release.json";
}

inline bool is_version_grammar(const std::string& s); // defined below

// The version recorded inside the managed install itself; "" when the
// file is missing (a pre-metadata install) or malformed.
inline std::string installed_release_version() {
    const auto file = installed_release_file();
    if (file.empty()) return "";
    std::ifstream in(file, std::ios::binary);
    if (!in) return "";
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    if (text.size() > 4096) return "";
    std::string version;
    if (!json_scan::find_string_in(text, 0, text.size(), "version", version) ||
        !is_version_grammar(version)) {
        return "";
    }
    return version;
}

// The one answer everything reports: in-install metadata first, the
// state.json mirror second. "" = genuinely unknown (a pre-metadata install
// whose client state was lost); callers must never turn unknown into a
// currency claim.
inline std::string authoritative_admin_version() {
    if (!admin_installed()) return "";
    const std::string from_install = installed_release_version();
    if (!from_install.empty()) return from_install;
    return state::load().admin_version;
}

// Startup reconciliation: heal whichever record is missing or stale. The
// in-install metadata is the authority when present; a pre-metadata
// install with surviving state gets the metadata file written so the
// version becomes recoverable from then on.
inline void reconcile_installed_version() {
    if (!admin_installed()) return;
    const std::string from_install = installed_release_version();
    auto s = state::load();
    if (!from_install.empty()) {
        if (s.admin_version != from_install) {
            log::client("admin: recovered installed version " + from_install +
                        " from install metadata (state said '" +
                        s.admin_version + "')");
            s.admin_version = from_install;
            (void)state::save(s);
        }
        return;
    }
    if (!s.admin_version.empty()) {
        std::ofstream out(installed_release_file(),
                          std::ios::binary | std::ios::trunc);
        if (out) {
            const std::string body = "{\"version\":\"" +
                json_scan::json_escape(s.admin_version) + "\"}";
            out.write(body.data(), (std::streamsize)body.size());
            log::client("admin: wrote install metadata from state (" +
                        s.admin_version + ")");
        }
    }
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
// the authoritative install metadata (state.json is only its mirror) and
// is reported only while the install actually exists. An empty version
// with installed:true means GENUINELY UNKNOWN, and the browser renders it
// as installed-with-no-currency-claim, never as "up to date".
inline std::string status_json() {
    const bool installed = admin_installed();
    std::string version;
    if (installed) version = authoritative_admin_version();
    std::string out = "{\"installed\":";
    out += installed ? "true" : "false";
    out += ",\"version\":\"" + json_scan::json_escape(version) + "\"";
    out += ",\"running\":";
    out += (installed && admin_running()) ? "true" : "false";
    out += "}";
    return out;
}

// ---- open ----

// The running managed Admin's top-level window, or nullptr. The Admin's
// main window is a CEF Views window (Chromium's own class), so the stable
// match is: a visible, unowned top-level window whose owning process runs
// out of the managed Admin directory.
inline HWND find_running_admin_window() {
    const auto dir = paths::admin_install_dir();
    if (dir.empty()) return nullptr;
    std::wstring prefix = dir.wstring();
    if (prefix.empty()) return nullptr;
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
    return ctx.found;
}

// Bring the running managed Admin's window to the front (best effort).
inline void focus_running_admin() {
    HWND hwnd = find_running_admin_window();
    if (hwnd == nullptr) return;
    if (IsIconic(hwnd)) ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
}

// GRACEFUL shutdown of the running managed Admin for an update: WM_CLOSE
// to its top-level window (exactly the user's own close button; never
// TerminateProcess, never any unrelated process), then wait for every
// managed-directory process to exit. One repeat close request midway
// covers a message that was swallowed while the window was busy. False =
// the Admin refused or timed out; NOTHING was changed and the caller
// answers admin_running.
inline bool close_running_admin(unsigned long long wait_ms) {
    HWND hwnd = find_running_admin_window();
    if (hwnd != nullptr) PostMessageW(hwnd, WM_CLOSE, 0, 0);
    const ULONGLONG deadline = GetTickCount64() + wait_ms;
    bool reposted = false;
    for (;;) {
        if (!admin_running()) return true;
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) return false;
        if (!reposted && deadline - now < wait_ms / 2) {
            if (HWND again = find_running_admin_window()) {
                PostMessageW(again, WM_CLOSE, 0, 0);
            }
            reposted = true;
        }
        Sleep(500);
    }
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

// ---- the silent Admin update check ----
// AUTOMATIC CHECKING, USER-INITIATED INSTALLING (owner spec 2026-09-03).
// The client is the one component that reads the approved manifest, so it
// caches the approved version here; the Admin's Settings page asks over a
// local control connection and owns no manifest logic. No check ever runs
// while no managed Admin install exists (nothing to update = no traffic).

// A fresh explicit ask (Settings opening) tolerates a cache this old;
// beyond it the manifest is refetched.
constexpr unsigned long long kUpdateCheckFreshMs = 15ull * 60ull * 1000ull;
// The quiet periodic recheck while the client happens to be serving.
constexpr unsigned long long kUpdateCheckPeriodMs = 6ull * 60ull * 60ull * 1000ull;

inline std::mutex g_update_mutex;
inline std::string g_approved_version;             // "" = no answer yet
inline unsigned long long g_update_check_tick = 0; // 0 = never attempted

// Refresh the cached approved version when the cache is older than
// `fresh_ms`. The attempt instant is stamped up front so a failing network
// can never turn the quiet check into a hammer.
inline void refresh_update_check(unsigned long long fresh_ms) {
    if (!admin_installed()) return;
    {
        std::lock_guard<std::mutex> lock(g_update_mutex);
        const unsigned long long now = GetTickCount64();
        if (g_update_check_tick != 0 && now - g_update_check_tick < fresh_ms) {
            return;
        }
        g_update_check_tick = now;
    }
    Manifest manifest;
    std::string why;
    if (!fetch_manifest(manifest, why)) {
        log::client("admin: update check failed: " + why);
        return;
    }
    std::lock_guard<std::mutex> lock(g_update_mutex);
    if (g_approved_version != manifest.version) {
        log::client("admin: update check: approved version " + manifest.version);
    }
    g_approved_version = manifest.version;
}

// The admin_update_status answer for the bridge's local
// admin_update_check message.
inline std::string update_status_json() {
    const bool installed = admin_installed();
    std::string admin_version;
    if (installed) admin_version = authoritative_admin_version();
    if (installed) refresh_update_check(kUpdateCheckFreshMs);
    std::string approved;
    {
        std::lock_guard<std::mutex> lock(g_update_mutex);
        approved = g_approved_version;
    }
    // "update" is a CLAIM and requires a real comparison: both the
    // installed version and the approved version must be known. Unknown
    // installed version = no claim in either direction.
    const bool update = installed && !approved.empty() &&
                        !admin_version.empty() && approved != admin_version;
    std::string out = "{\"type\":\"admin_update_status\",\"installed\":";
    out += installed ? "true" : "false";
    out += ",\"admin_version\":\"" + json_scan::json_escape(admin_version) + "\"";
    out += ",\"approved_version\":\"" + json_scan::json_escape(approved) + "\"";
    out += ",\"update\":";
    out += update ? "true" : "false";
    out += "}";
    return out;
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

// The verified staged pipeline body (manifest through placement). Runs on
// a worker thread; pushes its result to every connected page and finishes
// even when none is left. Returns the wire state ("installed" / "updated" /
// "admin_running" / "failed"). Callers own launching the Admin and any
// native lifecycle card (see run()).
inline std::string run_pipeline(bool shortcut, bool was_installed) {
    // 1-2. The approved manifest.
    Manifest manifest;
    std::string why;
    if (!fetch_manifest(manifest, why)) {
        log::client("admin: manifest rejected: " + why);
        broadcast_result("failed", "");
        return "failed";
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
            return "failed";
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
        return "failed";
    }

    // 4. Exact size, then exact SHA-256. Never waived.
    if (got_size != (unsigned long long)manifest.size) {
        log::client("admin: package size mismatch: got " + std::to_string(got_size));
        cleanup_staging();
        broadcast_result("failed", "");
        return "failed";
    }
    if (got_sha != manifest.sha256) {
        log::client("admin: package sha256 mismatch: " + got_sha);
        cleanup_staging();
        broadcast_result("failed", "");
        return "failed";
    }
    log::client("admin: package verified (" + std::to_string(got_size) + " bytes)");

    // 5. Safe extraction into staging.
    std::filesystem::create_directories(staging, ec);
    if (!extract_package(zip_path, staging, why)) {
        log::client("admin: " + why);
        cleanup_staging();
        broadcast_result("failed", "");
        return "failed";
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
            return "failed";
        }
        if (!verify_binary::authenticode_valid(p) ||
            !verify_binary::signed_by(p, kExpectedSigner)) {
            log::client("admin: staged binary failed signature verification: " +
                        p.filename().string());
            cleanup_staging();
            broadcast_result("failed", "");
            return "failed";
        }
    }
    log::client("admin: staged tree verified (Authenticode + signer identity)");

    // 6b. The installed-version metadata rides the staging tree, so the
    // atomic placement below makes version and binaries inseparable (the
    // authoritative record the false-"up to date" fix reads back).
    {
        std::ofstream meta(staging / L"installed-release.json",
                           std::ios::binary | std::ios::trunc);
        const std::string body = "{\"version\":\"" +
            json_scan::json_escape(manifest.version) + "\"}";
        if (!meta || !meta.write(body.data(), (std::streamsize)body.size()).good()) {
            log::client("admin: could not write install metadata");
            cleanup_staging();
            broadcast_result("failed", "");
            return "failed";
        }
    }

    // 7. Atomic placement. The previous install survives any failed swap.
    ec.clear();
    std::filesystem::remove_all(previous, ec);
    if (was_installed) {
        if (!rename_with_retries(admin_dir, previous)) {
            // Locked files: the Admin (or something in it) is running.
            log::client("admin: live install is locked; not updated");
            cleanup_staging();
            broadcast_result("admin_running", "");
            return "admin_running";
        }
        if (!rename_with_retries(staging, admin_dir)) {
            // Put the known-good install straight back.
            (void)rename_with_retries(previous, admin_dir);
            log::client("admin: staging swap failed; previous install restored");
            cleanup_staging();
            broadcast_result("failed", "");
            return "failed";
        }
        ec.clear();
        std::filesystem::remove_all(previous, ec);
    } else {
        if (!rename_with_retries(staging, admin_dir)) {
            log::client("admin: install placement failed");
            cleanup_staging();
            broadcast_result("failed", "");
            return "failed";
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

    log::client("admin: " + std::string(was_installed ? "updated" : "installed") +
                " version " + manifest.version);
    const std::string result = was_installed ? "updated" : "installed";
    broadcast_result(result, manifest.version);
    return result;
}

// The whole install/update operation, with the lifecycle rules around the
// pipeline. Returns the wire state (or "busy" when another operation
// already runs).
//
// `native_feedback` = the client owns the visible feedback for this
// operation (a LOCAL caller: the Admin's Settings Update, the launch
// handoff). THE DEAD-AIR FIX (owner spec 2026-09-03): the moment the
// Admin has closed for an update, the client immediately shows the
// branded native "Updating…" card, keeps it up through download / verify /
// stage / replace, relaunches the updated Admin, and closes the card -
// the user never stares at nothing and never reopens VIRULE by hand.
// Page-driven operations (native_feedback = false) leave the visible flow
// to the page, exactly as before.
inline std::string run(bool shortcut, bool native_feedback = false) {
    if (g_busy.exchange(true)) {
        // An operation is already in flight; its own result push covers
        // every connected page.
        return "busy";
    }
    struct BusyGuard {
        ~BusyGuard() { g_busy.store(false); }
    } busy_guard;

    const bool was_installed = admin_installed();
    log::client(std::string("admin: ") + (was_installed ? "update" : "install") +
                " requested" + (shortcut ? " (desktop shortcut)" : ""));

    // THE CLIENT OWNS THE SHUTDOWN (owner spec 2026-09-03). A running
    // Admin is closed GRACEFULLY for the update: the initiating surface
    // (Admin Settings, virule.app) has already shown the approved
    // "Shutting down VIRULE" messaging, so a short grace lets it be seen,
    // then WM_CLOSE and a bounded wait. A refusal changes nothing and
    // still answers admin_running (the safe fallback, no longer the
    // normal path). An already-closed Admin skips all of this.
    bool closed_admin_for_update = false;
    if (was_installed && admin_running()) {
        log::client("admin: update requested while running; closing the Admin gracefully");
        Sleep(4000); // the approved shutdown-message grace
        if (!close_running_admin(25000)) {
            log::client("admin: the Admin did not close; nothing changed");
            broadcast_result("admin_running", "");
            return "admin_running";
        }
        closed_admin_for_update = true;
        log::client("admin: the Admin closed; continuing the update");
    }

    // The Admin surface is gone; the client's own surface takes over NOW
    // (never a dead-air download). Idempotent when the launch handoff
    // already put the card up.
    if (native_feedback && closed_admin_for_update &&
        !result_card::is_working_visible()) {
        result_card::show_working("Updating\xE2\x80\xA6", "");
    }

    const std::string state = run_pipeline(shortcut, was_installed);

    if (state == "installed") {
        // A fresh install opens the Admin automatically; the Admin window
        // is the next feedback surface.
        (void)open_installed_admin();
        if (native_feedback) result_card::close();
    } else if (state == "updated") {
        if (closed_admin_for_update) {
            // Relaunch the Admin the client closed (the user never reopens
            // VIRULE by hand), then retire the card: next owner first.
            (void)open_installed_admin();
            if (native_feedback) result_card::close();
        }
        // An update of an Admin that was already closed leaves the user
        // where they are (the caller may still choose to launch: the
        // launch handoff does).
    } else if (closed_admin_for_update) {
        // The update failed AFTER the Admin was closed for it. The
        // known-good install is untouched (atomic placement), so bring
        // VIRULE back rather than leaving the user with nothing; Settings
        // will still offer the update.
        log::client("admin: update failed after shutdown; relaunching the previous Admin");
        if (native_feedback) result_card::update("Something went wrong.", "");
        (void)open_installed_admin();
    }
    return state;
}

// UPDATE ON VIRULE LAUNCH (owner spec 2026-09-03): a user-initiated VIRULE
// launch comes up CURRENT. The launching virule.exe (or admin_open) asks
// this client whether an approved update exists; when one does, the launch
// is handed here: the client shows the branded native "Updating…" card
// immediately (the launcher's splash may still be closing - a brief
// overlap beats a gap), waits for the handing-off Admin process to exit,
// performs the verified staged update, and launches ONLY the new Admin. A
// failed update never blocks the launch: the current known-good Admin
// opens instead (Settings still offers the update).
inline void launch_after_update_handoff() {
    if (!admin_installed()) return;
    result_card::show_working("Updating\xE2\x80\xA6", "");
    // The virule.exe that handed off exits within moments; a bounded wait
    // covers it. Anything still running past it is a REAL Admin session
    // (which is never interrupted): focus it and stand down.
    for (int i = 0; i < 40 && admin_running(); ++i) Sleep(250);
    if (admin_running()) {
        result_card::close();
        focus_running_admin();
        return;
    }
    // Re-verify against the approved manifest (fresh cache after the
    // handoff's own check, so this is instant; a genuinely stale cache
    // refetches, bounded by the HTTP timeouts).
    refresh_update_check(kUpdateCheckFreshMs);
    std::string approved;
    {
        std::lock_guard<std::mutex> lock(g_update_mutex);
        approved = g_approved_version;
    }
    const std::string installed = authoritative_admin_version();
    const bool update = !approved.empty() && !installed.empty() &&
                        approved != installed;
    if (!update) {
        result_card::close();
        (void)open_installed_admin();
        return;
    }
    const std::string state = run(false, /*native_feedback=*/true);
    if (state == "updated") {
        // The Admin was not running, so run() left the launch to us.
        (void)open_installed_admin();
        result_card::close();
    } else if (state == "busy") {
        // Another operation owns the lifecycle; its own feedback covers it.
        result_card::close();
    } else if (state != "installed") {
        // Never block a launch on a failed update: open the current Admin.
        log::client("admin: launch-time update did not complete; launching current Admin");
        result_card::close();
        (void)open_installed_admin();
    }
}

} // namespace vclient::admin_install
