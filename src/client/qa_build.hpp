#pragma once
// QA GAME DELIVERY (Phase 4): the machine-local half of "a QA tester can
// install, play, update and remove the exact build they are authorized for".
//
// WHAT THE BROWSER MAY SAY. The QA page supplies a game_uuid and nothing
// else. It cannot name a URL, a path, an executable or an archive. Every
// piece of trusted metadata (which build is authorized, what it must hash
// to, how large it is, which executable inside it may be launched, and a
// short-lived place to fetch the bytes) is resolved by THIS client from the
// VIRULE backend, authenticated with the tester credential the existing QA
// verification flow already wrote. Browser state is intent; the server is
// authorization.
//
// THE ARTIFACT IS PRIVATE. QA builds live in a private GitHub repository and
// are never publicly downloadable. The client never holds a GitHub
// credential: the backend authorizes the tester and returns GitHub's
// short-lived, path-scoped, credential-free delegated URL, which this client
// streams directly. No game bytes pass through the VIRULE Worker.
//
// THE VERIFIED STAGED PIPELINE (install and update are ONE path):
//   1. resolve the authorized build for this game (backend, credentialed);
//   2. ask for a delegated download location for THAT build_uuid;
//   3. stream to staging, hashed in flight, capped at the declared size;
//   4. exact size, then exact SHA-256. Never waived;
//   5. extract with the zip-slip guard (no "..", no absolute, no drive);
//   6. confirm the package actually contains its declared executable;
//   7. place atomically: install is one rename; update is
//      live -> .previous, staging -> live, and a failed swap puts the
//      known-good install straight back;
//   8. write the managed-install record.
//
// GAME BINARIES ARE NOT SIGNATURE-GATED. A QA build is a developer's own
// unreleased game; requiring Authenticode on it would reject every
// legitimate build. The trust boundary is the server-authorized artifact
// record plus the exact package SHA-256, which is why step 4 has no waiver.
//
// WHAT THE CLIENT OWNS. Inside the tester's chosen library root it owns
// exactly `<root>/VIRULE QA/<game_uuid>/` per game and the transient staging
// siblings. Remove deletes that ONE directory. The library root itself is
// the tester's and is never deleted, never emptied, and never treated as
// disposable. This is not, and never becomes, a full VIRULE uninstall.

#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#include "client/admin_install.hpp"
#include "client/bridge.hpp"
#include "shared/client_state.hpp"
#include "shared/http_client.hpp"
#include "shared/json_scan.hpp"
#include "shared/logging.hpp"
#include "shared/machine_identity.hpp"
#include "shared/paths.hpp"
#include "shared/qa_credential.hpp"
#include "virule/core/launch_policy.hpp"
#include "virule/core/time.hpp"

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

namespace vclient::qa_build {

namespace fs = std::filesystem;
namespace js = vclient::json_scan;
namespace lp = virule::core::launch_policy;

// The backend surface. Same host and proof posture as every other VIRULE
// service call this client makes.
inline constexpr const wchar_t* kCurrentPathW  = L"/v1/qa/build/current";
inline constexpr const wchar_t* kDownloadPathW = L"/v1/qa/build/download";

inline constexpr const char* kCurrentPrefix  = "virule-qa-build-current.v1";
inline constexpr const char* kDownloadPrefix = "virule-qa-build-download.v1";

// The one folder the client creates inside the tester's chosen root. Named,
// not hidden: a tester should be able to see where their QA games went.
inline constexpr const wchar_t* kLibraryFolder = L"VIRULE QA";

// Hard ceiling mirroring the publisher's and the backend's.
inline constexpr unsigned long long kMaxPackageBytes =
    2ull * 1024ull * 1024ull * 1024ull;

// ONE build operation at a time, process-wide. Also holds off the idle-exit
// policy so a download survives every page closing.
inline std::atomic<bool> g_busy{ false };
// The game currently being installed/updated, for the status answer.
inline std::mutex g_busy_mutex;
inline std::string g_busy_game;
inline std::string g_busy_kind; // "installing" | "updating"

inline bool is_uuid(const std::string& s) {
    if (s.size() != 32) return false;
    for (const char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

inline bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (const char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

// ------------------------------------------------- managed install record --

// One installed QA game, exactly as the client owns it. IDs are the
// identity; the game's display title is never part of a path or a decision.
struct Install {
    std::string game_uuid;
    std::string build_uuid;
    std::string root;          // the tester's library root, generic form
    std::string dir;           // the managed game directory, generic form
    std::string exe_rel_path;  // relative, inside dir
    std::string sha256;        // the package this install came from
    long long size = 0;
    std::string installed_utc;
};

inline fs::path installs_file() {
    const auto d = paths::client_state_dir();
    return d.empty() ? d : d / L"qa_installs.json";
}

inline std::string to_generic(const fs::path& p) {
    return p.generic_string();
}

inline std::vector<Install> load_installs() {
    std::vector<Install> out;
    const auto file = installs_file();
    if (file.empty()) return out;
    std::ifstream in(file, std::ios::binary);
    if (!in) return out;
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    size_t p = text.find('[');
    const size_t end = text.rfind(']');
    while (p != std::string::npos && end != std::string::npos && p < end) {
        const size_t ob = text.find('{', p);
        if (ob == std::string::npos || ob >= end) break;
        const size_t oe = text.find('}', ob);
        if (oe == std::string::npos || oe > end) break;
        Install r;
        if (js::find_string_in(text, ob, oe, "game_uuid", r.game_uuid) &&
            js::find_string_in(text, ob, oe, "build_uuid", r.build_uuid) &&
            is_uuid(r.game_uuid) && is_uuid(r.build_uuid)) {
            (void)js::find_string_in(text, ob, oe, "root", r.root);
            (void)js::find_string_in(text, ob, oe, "dir", r.dir);
            (void)js::find_string_in(text, ob, oe, "exe_rel_path", r.exe_rel_path);
            (void)js::find_string_in(text, ob, oe, "sha256", r.sha256);
            (void)js::find_number_in(text, ob, oe, "size", r.size);
            (void)js::find_string_in(text, ob, oe, "installed_utc", r.installed_utc);
            out.push_back(std::move(r));
        }
        p = oe + 1;
    }
    return out;
}

inline bool save_installs(const std::vector<Install>& list) {
    const auto file = installs_file();
    if (file.empty()) return false;
    std::error_code ec;
    fs::create_directories(file.parent_path(), ec);
    std::string body = "{\"version\":1,\"installs\":[";
    bool first = true;
    for (const auto& r : list) {
        if (!first) body += ",";
        first = false;
        body += "{\"game_uuid\":\"" + r.game_uuid +
            "\",\"build_uuid\":\"" + r.build_uuid +
            "\",\"root\":\"" + js::json_escape(r.root) +
            "\",\"dir\":\"" + js::json_escape(r.dir) +
            "\",\"exe_rel_path\":\"" + js::json_escape(r.exe_rel_path) +
            "\",\"sha256\":\"" + r.sha256 +
            "\",\"size\":" + std::to_string(r.size) +
            ",\"installed_utc\":\"" + js::json_escape(r.installed_utc) + "\"}";
    }
    body += "]}";
    const fs::path tmp = file.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(body.data(), (std::streamsize)body.size());
        if (!out.good()) return false;
    }
    ec.clear();
    fs::rename(tmp, file, ec);
    if (ec) {
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(body.data(), (std::streamsize)body.size());
        fs::remove(tmp, ec);
        return out.good();
    }
    return true;
}

// The recorded install for a game, only when its directory and executable
// still exist. A record whose files were deleted behind the client's back is
// not an install.
inline bool find_install(const std::string& game_uuid, Install& out) {
    for (const auto& r : load_installs()) {
        if (r.game_uuid != game_uuid) continue;
        std::error_code ec;
        const fs::path dir = fs::path(r.dir);
        const fs::path exe = dir / fs::path(r.exe_rel_path);
        if (!fs::exists(exe, ec) || ec) return false;
        out = r;
        return true;
    }
    return false;
}

inline void put_install(const Install& rec) {
    auto list = load_installs();
    for (auto& r : list) {
        if (r.game_uuid == rec.game_uuid) {
            r = rec;
            (void)save_installs(list);
            return;
        }
    }
    list.push_back(rec);
    (void)save_installs(list);
}

inline void drop_install(const std::string& game_uuid) {
    auto list = load_installs();
    std::vector<Install> kept;
    for (auto& r : list) {
        if (r.game_uuid != game_uuid) kept.push_back(std::move(r));
    }
    (void)save_installs(kept);
}

// ---------------------------------------------------------- library root --

// Is this a root the client may create a game library inside? Rejects the
// obviously wrong (a nonexistent or unwritable place) and the actively
// dangerous (anywhere inside the VIRULE program installation, which the full
// uninstall inventory owns).
inline bool root_usable(const fs::path& root, std::string& why) {
    std::error_code ec;
    if (root.empty()) { why = "empty"; return false; }
    if (!fs::exists(root, ec) || ec || !fs::is_directory(root, ec)) {
        why = "not an existing directory";
        return false;
    }
    // Never inside the managed program installation: a QA game library there
    // would be swept by a full VIRULE uninstall.
    const auto install = paths::install_dir();
    if (!install.empty()) {
        auto a = fs::weakly_canonical(root, ec).wstring();
        auto b = fs::weakly_canonical(install, ec).wstring();
        for (auto& c : a) c = (wchar_t)towlower(c);
        for (auto& c : b) c = (wchar_t)towlower(c);
        if (!b.empty() && a.rfind(b, 0) == 0) {
            why = "inside the VIRULE program folder";
            return false;
        }
    }
    // Writable in practice, not in theory.
    const fs::path probe = root / L".virule-qa-write-probe";
    {
        std::ofstream out(probe, std::ios::binary | std::ios::trunc);
        if (!out) { why = "not writable"; return false; }
    }
    ec.clear();
    fs::remove(probe, ec);
    return true;
}

inline std::string current_root() {
    return state::load().qa_games_root;
}

inline bool have_usable_root() {
    const std::string r = current_root();
    if (r.empty()) return false;
    std::string why;
    return root_usable(fs::path(r), why);
}

// The managed library folder and this game's directory inside it.
inline fs::path library_dir(const std::string& root) {
    return fs::path(root) / kLibraryFolder;
}

inline fs::path game_dir(const std::string& root, const std::string& game_uuid) {
    return library_dir(root) / fs::path(game_uuid);
}

inline fs::path staging_dir(const std::string& root, const std::string& game_uuid) {
    return library_dir(root) / fs::path(".staging-" + game_uuid);
}

inline fs::path previous_dir(const std::string& root, const std::string& game_uuid) {
    return library_dir(root) / fs::path(".previous-" + game_uuid);
}

inline fs::path download_zip(const std::string& root, const std::string& game_uuid) {
    return library_dir(root) / fs::path(".download-" + game_uuid + ".zip");
}

// The native folder picker. Deliberately minimal: one standard Windows
// "pick a folder" dialog, no VIRULE chrome, no options, no second question.
// Runs on its own STA thread because this process has no UI thread of its
// own, and is brought to the foreground the same way the QA result card is.
struct PickerResult {
    bool chosen = false;
    std::string path;
};

inline DWORD WINAPI picker_thread_main(LPVOID param) {
    auto* out = static_cast<PickerResult*>(param);
    const HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(init);
    IFileOpenDialog* dialog = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr,
                                   CLSCTX_INPROC_SERVER, IID_IFileOpenDialog,
                                   (void**)&dialog))) {
        DWORD options = 0;
        if (SUCCEEDED(dialog->GetOptions(&options))) {
            dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM |
                               FOS_PATHMUSTEXIST);
        }
        dialog->SetTitle(L"Choose where to install VIRULE QA games");
        dialog->SetOkButtonLabel(L"Use this folder");
        if (SUCCEEDED(dialog->Show(nullptr))) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dialog->GetResult(&item)) && item) {
                PWSTR raw = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &raw)) && raw) {
                    out->path = to_generic(fs::path(raw));
                    out->chosen = true;
                    CoTaskMemFree(raw);
                }
                item->Release();
            }
        }
        dialog->Release();
    }
    if (uninit) CoUninitialize();
    return 0;
}

// Ask the tester where QA games should live. Returns false when they
// cancelled or the choice is unusable; the caller reports that plainly and
// changes nothing.
inline bool choose_root(std::string& chosen_out, std::string& why) {
    PickerResult result;
    HANDLE th = CreateThread(nullptr, 0, picker_thread_main, &result, 0, nullptr);
    if (!th) { why = "the folder picker could not be opened"; return false; }
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    if (!result.chosen) { why = "cancelled"; return false; }
    if (!root_usable(fs::path(result.path), why)) return false;
    auto s = state::load();
    s.qa_games_root = result.path;
    if (!state::save(s)) { why = "the choice could not be saved"; return false; }
    chosen_out = result.path;
    log::client("qa build: library root set");
    return true;
}

// ------------------------------------------------------- backend calls ----

// The build the backend says this tester may currently have.
struct AuthorizedBuild {
    bool authorized = false;
    std::string build_uuid;
    std::string sha256;
    long long size = 0;
    std::string exe_rel_path;
    // Filled only by resolve_download().
    std::string download_url;
};

// Sign a QA build call with the tester credential plus a fresh proof that
// this machine holds the credentialed key. Identical posture to the runtime
// policy call: the credential proves WHO, the proof proves HERE AND NOW.
inline bool post_signed(const wchar_t* path, const std::string& prefix,
                        const qa_credential::Entry& cred,
                        const std::string& game_uuid,
                        const std::string& extra_msg,
                        const std::string& extra_json,
                        unsigned long& status_out, std::string& response) {
    const std::string timestamp = virule::core::utc_timestamp_rfc3339();
    const std::string message = prefix + "|" + game_uuid + "|" + cred.tester_id +
        "|" + extra_msg + timestamp;
    const std::string public_key = machine_identity::public_key_hex();
    if (!lp::is_public_key_hex(public_key)) return false;
    const std::string signature = machine_identity::sign_hex(message);
    if (!lp::is_signature_hex(signature)) return false;

    std::string body = "{\"game_uuid\":\"" + game_uuid +
        "\",\"organization_id\":\"" + cred.organization_id +
        "\",\"tester_id\":\"" + cred.tester_id +
        "\",\"machine_key\":\"" + cred.machine_key +
        "\",\"bound_utc\":\"" + cred.bound_utc +
        "\",\"credential_signature\":\"" + cred.signature + "\"" +
        extra_json +
        ",\"timestamp\":\"" + timestamp +
        "\",\"developer_public_key\":\"" + public_key +
        "\",\"developer_signature\":\"" + signature + "\"}";
    return http::https_post_json(lp::kEmbargoApiHostW, path, body, status_out, response);
}

inline bool parse_build_fields(const std::string& response, AuthorizedBuild& out) {
    if (!js::find_string_in(response, 0, response.size(), "build_uuid", out.build_uuid) ||
        !is_uuid(out.build_uuid)) {
        return false;
    }
    if (!js::find_string_in(response, 0, response.size(), "sha256", out.sha256) ||
        !is_hex64(out.sha256)) {
        return false;
    }
    if (!js::find_number_in(response, 0, response.size(), "size", out.size) ||
        out.size <= 0 || (unsigned long long)out.size > kMaxPackageBytes) {
        return false;
    }
    if (!js::find_string_in(response, 0, response.size(), "exe_rel_path", out.exe_rel_path) ||
        out.exe_rel_path.empty()) {
        return false;
    }
    return true;
}

// Which credential speaks for this game? A machine may hold several (one per
// Organization the tester works with). Production credentials first, then the
// isolated QA TEST MODE store, so test mode never shadows a real one.
inline std::vector<qa_credential::Entry> candidate_credentials() {
    auto out = qa_credential::load_all(paths::security_dir(),
                                       qa_credential::kFileName);
    std::error_code ec;
    if (fs::exists(paths::qa_test_mode_flag(), ec) && !ec) {
        for (auto& e : qa_credential::load_all(paths::security_dir(),
                                               qa_credential::kTestFileName)) {
            out.push_back(std::move(e));
        }
    }
    return out;
}

// A short memo of the last answer per game. The page polls status while a
// game is running or installing, and without this every poll would spend a
// request against the service's per-IP rate limit for an answer that cannot
// meaningfully have changed. Operations always resolve FRESH (they pass
// through resolve_current_uncached), so the cache can only ever make an idle
// view slightly stale, never an install.
struct CurrentCache {
    std::string game_uuid;
    AuthorizedBuild build;
    qa_credential::Entry cred;
    std::string why;
    bool ok = false;
    unsigned long long tick = 0;
};
inline std::mutex g_cache_mutex;
inline CurrentCache g_cache;
inline constexpr unsigned long long kCurrentCacheMs = 15000;

inline void invalidate_current_cache() {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    g_cache = CurrentCache{};
}

inline bool resolve_current_uncached(const std::string& game_uuid, AuthorizedBuild& out,
                                     qa_credential::Entry& used, std::string& why);

// The cached form the status answer uses.
inline bool resolve_current_cached(const std::string& game_uuid, AuthorizedBuild& out,
                                   qa_credential::Entry& used, std::string& why) {
    {
        std::lock_guard<std::mutex> lock(g_cache_mutex);
        if (g_cache.game_uuid == game_uuid && g_cache.tick != 0 &&
            GetTickCount64() - g_cache.tick < kCurrentCacheMs) {
            out = g_cache.build;
            used = g_cache.cred;
            why = g_cache.why;
            return g_cache.ok;
        }
    }
    const bool ok = resolve_current_uncached(game_uuid, out, used, why);
    {
        std::lock_guard<std::mutex> lock(g_cache_mutex);
        g_cache.game_uuid = game_uuid;
        g_cache.build = out;
        g_cache.cred = used;
        g_cache.why = why;
        g_cache.ok = ok;
        g_cache.tick = GetTickCount64();
    }
    return ok;
}

// Resolve the authorized build for a game, trying each held credential. A
// 403 means "not this one"; anything else stops the search, so a server
// fault is never mistaken for "unauthorized".
inline bool resolve_current_uncached(const std::string& game_uuid, AuthorizedBuild& out,
                                     qa_credential::Entry& used, std::string& why) {
    const auto creds = candidate_credentials();
    if (creds.empty()) { why = "no QA credential on this machine"; return false; }
    for (const auto& cred : creds) {
        unsigned long status = 0;
        std::string response;
        if (!post_signed(kCurrentPathW, kCurrentPrefix, cred, game_uuid, "", "",
                         status, response)) {
            why = "the VIRULE service could not be reached";
            return false;
        }
        if (status == 403) continue;               // a different tester slot
        if (status == 404) { why = "no build"; return false; }
        if (status != 200) {
            why = "service status " + std::to_string(status);
            return false;
        }
        if (!parse_build_fields(response, out)) {
            why = "the build answer could not be read";
            return false;
        }
        out.authorized = true;
        used = cred;
        return true;
    }
    why = "not authorized";
    return false;
}

// Mint a delegated download location for one specific build. build_uuid rides
// inside the signed message, so a grant cannot be replayed onto another
// build.
inline bool resolve_download(const qa_credential::Entry& cred,
                             const std::string& game_uuid,
                             const std::string& build_uuid,
                             AuthorizedBuild& out, std::string& why) {
    unsigned long status = 0;
    std::string response;
    const std::string extra_json = ",\"build_uuid\":\"" + build_uuid + "\"";
    if (!post_signed(kDownloadPathW, kDownloadPrefix, cred, game_uuid,
                     build_uuid + "|", extra_json, status, response)) {
        why = "the VIRULE service could not be reached";
        return false;
    }
    if (status != 200) { why = "download not authorized (status " +
                               std::to_string(status) + ")"; return false; }
    if (!parse_build_fields(response, out)) {
        why = "the build answer could not be read";
        return false;
    }
    if (!js::find_string_in(response, 0, response.size(), "download_url",
                            out.download_url) ||
        out.download_url.rfind("https://", 0) != 0 ||
        out.download_url.size() > 4096) {
        why = "no usable download location";
        return false;
    }
    out.authorized = true;
    return true;
}

// ------------------------------------------------------- running state ----

// Is anything running out of this game's managed directory? Image-path
// prefix match, exactly the Admin's rule, so another copy of the same game
// somewhere else never reads as running.
inline bool game_running(const fs::path& dir) {
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

// ------------------------------------------------------------- status ----

// The page's whole view of one game. States:
//   unauthorized     no credential here speaks for this game
//   no_build         authorized, but nothing is published yet
//   not_installed    a build is authorized and not installed
//   installing       this client is installing it now
//   updating         this client is updating it now
//   installed        installed and current
//   update_available installed, but a newer build is authorized
//   running          installed and its process is alive
//   error            the service could not be consulted
inline std::string status_json(const std::string& game_uuid) {
    std::string state = "error";
    std::string installed_build, authorized_build;
    bool root_ok = have_usable_root();

    Install rec;
    const bool installed = find_install(game_uuid, rec);
    if (installed) installed_build = rec.build_uuid;

    {
        std::lock_guard<std::mutex> lock(g_busy_mutex);
        if (g_busy.load() && g_busy_game == game_uuid) {
            state = g_busy_kind;
        }
    }

    if (state == "error") {
        AuthorizedBuild build;
        qa_credential::Entry cred;
        std::string why;
        if (resolve_current_cached(game_uuid, build, cred, why)) {
            authorized_build = build.build_uuid;
            if (!installed) {
                state = "not_installed";
            } else if (installed && game_running(fs::path(rec.dir))) {
                state = "running";
            } else if (rec.build_uuid != build.build_uuid) {
                state = "update_available";
            } else {
                state = "installed";
            }
        } else if (why == "no build") {
            state = installed ? "installed" : "no_build";
        } else if (why == "not authorized" || why == "no QA credential on this machine") {
            state = "unauthorized";
        }
        // Anything else stays "error": a transport or service problem must
        // never read as "you are not authorized".
    }

    std::string out = "{\"type\":\"qa_build_status\",\"v\":1,\"game_uuid\":\"" +
        js::json_escape(game_uuid) + "\",\"state\":\"" + state +
        "\",\"installed_build_uuid\":\"" + installed_build +
        "\",\"authorized_build_uuid\":\"" + authorized_build +
        "\",\"have_root\":" + (root_ok ? "true" : "false") +
        ",\"busy\":" + (g_busy.load() ? "true" : "false") + "}";
    return out;
}

inline void broadcast_result(const std::string& game_uuid,
                             const std::string& state) {
    bridge::broadcast_to_pages(
        "{\"type\":\"qa_build_result\",\"game_uuid\":\"" +
        js::json_escape(game_uuid) + "\",\"state\":\"" + state + "\"}");
}

// ---------------------------------------------------------- the install ----

inline void cleanup_staging(const std::string& root, const std::string& game_uuid) {
    std::error_code ec;
    fs::remove(download_zip(root, game_uuid), ec);
    ec.clear();
    fs::remove_all(staging_dir(root, game_uuid), ec);
}

// Split "https://host/path?query" into the WinHTTP pair. The delegated URL
// carries a long signed query; it belongs in the path component.
inline bool split_https_url(const std::string& url, std::wstring& host,
                            std::wstring& path) {
    const std::string prefix = "https://";
    if (url.rfind(prefix, 0) != 0) return false;
    const std::string rest = url.substr(prefix.size());
    const size_t slash = rest.find('/');
    if (slash == std::string::npos) return false;
    const std::string h = rest.substr(0, slash);
    const std::string p = rest.substr(slash);
    if (h.empty() || p.empty()) return false;
    host.assign(h.begin(), h.end());
    path.assign(p.begin(), p.end());
    return true;
}

// Install or update ONE game. Runs on a worker thread; finishes even when
// every page has closed, and pushes its result to whatever is connected.
inline void run_install(const std::string& game_uuid) {
    if (!is_uuid(game_uuid)) return;
    if (g_busy.exchange(true)) {
        // Another build operation owns the client; its own result push
        // covers every page.
        return;
    }
    struct BusyGuard {
        ~BusyGuard() {
            {
                std::lock_guard<std::mutex> lock(g_busy_mutex);
                g_busy_game.clear();
                g_busy_kind.clear();
            }
            g_busy.store(false);
        }
    } busy_guard;

    Install existing;
    const bool was_installed = find_install(game_uuid, existing);
    {
        std::lock_guard<std::mutex> lock(g_busy_mutex);
        g_busy_game = game_uuid;
        g_busy_kind = was_installed ? "updating" : "installing";
    }
    log::client(std::string("qa build: ") + (was_installed ? "update" : "install") +
                " requested");

    // A running game is never killed. The tester closes it and retries.
    if (was_installed && game_running(fs::path(existing.dir))) {
        log::client("qa build: refused; the game is running");
        broadcast_result(game_uuid, "game_running");
        return;
    }

    const std::string root = current_root();
    std::string why;
    if (root.empty() || !root_usable(fs::path(root), why)) {
        log::client("qa build: no usable library root (" + why + ")");
        broadcast_result(game_uuid, "need_root");
        return;
    }

    // 1. What may this tester have? FRESH, never the status cache: an
    // operation must act on the authorization as it is right now.
    invalidate_current_cache();
    AuthorizedBuild build;
    qa_credential::Entry cred;
    if (!resolve_current_uncached(game_uuid, build, cred, why)) {
        log::client("qa build: not authorized: " + why);
        broadcast_result(game_uuid, why == "no build" ? "no_build" : "not_authorized");
        return;
    }
    if (was_installed && existing.build_uuid == build.build_uuid) {
        log::client("qa build: already current");
        broadcast_result(game_uuid, was_installed ? "updated" : "installed");
        return;
    }

    // 2. A short-lived delegated location for exactly that build.
    AuthorizedBuild grant;
    if (!resolve_download(cred, game_uuid, build.build_uuid, grant, why)) {
        log::client("qa build: download not authorized: " + why);
        broadcast_result(game_uuid, "failed");
        return;
    }
    if (grant.build_uuid != build.build_uuid || grant.sha256 != build.sha256 ||
        grant.size != build.size) {
        log::client("qa build: grant disagrees with the authorized build");
        broadcast_result(game_uuid, "failed");
        return;
    }

    std::wstring host, path;
    if (!split_https_url(grant.download_url, host, path)) {
        log::client("qa build: download location unparseable");
        broadcast_result(game_uuid, "failed");
        return;
    }

    std::error_code ec;
    fs::create_directories(library_dir(root), ec);
    cleanup_staging(root, game_uuid);
    const auto zip_path = download_zip(root, game_uuid);
    const auto staging = staging_dir(root, game_uuid);
    const auto target = game_dir(root, game_uuid);
    const auto previous = previous_dir(root, game_uuid);

    // 3. Streamed download, hashed in flight, capped at the declared size.
    unsigned long status = 0;
    unsigned long long got_size = 0;
    std::string got_sha;
    if (!http::https_get_to_file(host.c_str(), path.c_str(),
                                 (unsigned long long)grant.size, zip_path,
                                 status, got_size, got_sha,
                                 []() { bridge::touch_activity(); })) {
        log::client("qa build: download failed, status=" + std::to_string(status));
        cleanup_staging(root, game_uuid);
        broadcast_result(game_uuid, "failed");
        return;
    }

    // 4. Exact size, then exact SHA-256. THE trust boundary; never waived.
    if (got_size != (unsigned long long)grant.size) {
        log::client("qa build: size mismatch: got " + std::to_string(got_size));
        cleanup_staging(root, game_uuid);
        broadcast_result(game_uuid, "failed");
        return;
    }
    if (got_sha != grant.sha256) {
        log::client("qa build: sha256 mismatch");
        cleanup_staging(root, game_uuid);
        broadcast_result(game_uuid, "failed");
        return;
    }
    log::client("qa build: package verified (" + std::to_string(got_size) + " bytes)");

    // 5. Safe extraction. Same zip-slip guard the Admin package uses.
    fs::create_directories(staging, ec);
    std::string extract_why;
    if (!admin_install::extract_package(zip_path, staging, extract_why)) {
        log::client("qa build: " + extract_why);
        cleanup_staging(root, game_uuid);
        broadcast_result(game_uuid, "failed");
        return;
    }

    // 6. The package must actually contain the executable the record claims,
    // or the tester installs something that cannot be played. Game binaries
    // are deliberately NOT signature-gated: a QA build is unreleased
    // developer software and the authorized package hash is the trust
    // boundary.
    const fs::path staged_exe = staging / fs::path(grant.exe_rel_path);
    ec.clear();
    if (!fs::exists(staged_exe, ec) || ec) {
        log::client("qa build: package does not contain its declared executable");
        cleanup_staging(root, game_uuid);
        broadcast_result(game_uuid, "failed");
        return;
    }

    // 7. Atomic placement. A known-good install always survives.
    ec.clear();
    fs::remove_all(previous, ec);
    if (was_installed) {
        if (!admin_install::rename_with_retries(target, previous)) {
            log::client("qa build: the installed game is locked; not updated");
            cleanup_staging(root, game_uuid);
            broadcast_result(game_uuid, "game_running");
            return;
        }
        if (!admin_install::rename_with_retries(staging, target)) {
            (void)admin_install::rename_with_retries(previous, target);
            log::client("qa build: swap failed; previous install restored");
            cleanup_staging(root, game_uuid);
            broadcast_result(game_uuid, "failed");
            return;
        }
        ec.clear();
        fs::remove_all(previous, ec);
    } else {
        // Not a known install, but the directory can still be there: a
        // record whose files were deleted behind the client's back reads as
        // "not installed", and the rename would then fail against the
        // leftover. Clear it first so a broken install can always be
        // repaired by installing again.
        ec.clear();
        if (fs::exists(target, ec) && !ec) {
            ec.clear();
            fs::remove_all(target, ec);
            if (ec) {
                log::client("qa build: a leftover install directory could not be cleared");
                cleanup_staging(root, game_uuid);
                broadcast_result(game_uuid, "failed");
                return;
            }
        }
        if (!admin_install::rename_with_retries(staging, target)) {
            log::client("qa build: placement failed");
            cleanup_staging(root, game_uuid);
            broadcast_result(game_uuid, "failed");
            return;
        }
    }
    ec.clear();
    fs::remove(zip_path, ec);

    // 8. The managed-install record.
    Install rec;
    rec.game_uuid = game_uuid;
    rec.build_uuid = grant.build_uuid;
    rec.root = root;
    rec.dir = to_generic(target);
    rec.exe_rel_path = grant.exe_rel_path;
    rec.sha256 = grant.sha256;
    rec.size = grant.size;
    rec.installed_utc = virule::core::utc_timestamp_rfc3339();
    put_install(rec);

    log::client(std::string("qa build: ") + (was_installed ? "updated" : "installed"));
    // NEVER auto-launch. An install finishing is not a request to play.
    broadcast_result(game_uuid, was_installed ? "updated" : "installed");
}

// --------------------------------------------------------------- play ----

// Launch the recorded executable of a managed install, and only that. Not a
// process-launch surface: the path is read from the client's own record, and
// the record is only ever written by a verified install.
inline bool play(const std::string& game_uuid) {
    if (!is_uuid(game_uuid)) return false;
    Install rec;
    if (!find_install(game_uuid, rec)) return false;
    const fs::path dir = fs::path(rec.dir);
    const fs::path exe = dir / fs::path(rec.exe_rel_path);
    // The recorded executable must still be INSIDE the managed directory: a
    // record edited by hand can never point the launcher elsewhere.
    std::error_code ec;
    const auto exe_canon = fs::weakly_canonical(exe, ec);
    const auto dir_canon = fs::weakly_canonical(dir, ec);
    if (ec) return false;
    auto a = exe_canon.wstring();
    auto b = dir_canon.wstring();
    if (!b.empty() && b.back() != L'\\') b += L'\\';
    for (auto& c : a) c = (wchar_t)towlower(c);
    for (auto& c : b) c = (wchar_t)towlower(c);
    if (a.rfind(b, 0) != 0) return false;
    if (!fs::exists(exe_canon, ec) || ec) return false;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + exe_canon.wstring() + L"\"";
    if (!CreateProcessW(exe_canon.wstring().c_str(), cmd.data(), nullptr, nullptr,
                        FALSE, 0, nullptr, dir_canon.wstring().c_str(), &si, &pi)) {
        log::client("qa build: launch failed");
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    log::client("qa build: launched the managed game");
    return true;
}

// ------------------------------------------------------------- remove ----

// Remove THIS managed QA game installation. Deletes exactly the directory
// the client created for this game, then forgets the record. The tester's
// library root, everything else inside it, and VIRULE itself are untouched:
// this is not an uninstall and never becomes one.
inline bool remove(const std::string& game_uuid) {
    if (!is_uuid(game_uuid)) return false;
    Install rec;
    if (!find_install(game_uuid, rec)) {
        // Nothing installed: forget any stale record and report success, so
        // the page lands on the Install state either way.
        drop_install(game_uuid);
        return true;
    }
    if (game_running(fs::path(rec.dir))) {
        log::client("qa build: remove refused; the game is running");
        return false;
    }
    // The directory must be the one THIS client would have created for this
    // game inside the recorded root. A record naming anything else is not
    // acted on, so a tampered record can never aim the delete somewhere.
    const auto expected = game_dir(rec.root, game_uuid);
    std::error_code ec;
    const auto a = fs::weakly_canonical(fs::path(rec.dir), ec);
    const auto b = fs::weakly_canonical(expected, ec);
    if (ec || a != b || a.empty()) {
        log::client("qa build: remove refused; the record does not name a managed directory");
        return false;
    }
    ec.clear();
    fs::remove_all(a, ec);
    if (ec) {
        log::client("qa build: remove failed");
        return false;
    }
    drop_install(game_uuid);
    // Transient siblings only; the library folder and the root stay.
    cleanup_staging(rec.root, game_uuid);
    log::client("qa build: removed the managed game installation");
    return true;
}

} // namespace vclient::qa_build
