#pragma once
// VIRULE SERVICE DISTRIBUTION (2026-10-06). ViruleService.exe is a first-class
// artifact of the CLIENT release: it is published beside virule-client.exe on
// the same GitHub Release and described by the same manifest.json, in three
// ADDITIVE fields an older Setup or client never reads:
//
//   {"version","url","sha256","size",                     <- unchanged
//    "service_url","service_sha256","service_size"}       <- new
//
// (The marker scanner every component uses matches "url"/"sha256"/"size" only
// with a leading quote, so the new names can never be mistaken for the old
// ones; publish.ps1 also writes them after the old fields.)
//
// ONE TRUST MODEL, REUSED: exactly the client's own (self_update.hpp,
// Virule-Setup): the url pinned to this environment's client release
// repository, exact declared size, exact SHA-256 (never waived), Authenticode
// validity and the VIRULE signer identity (staging builds skip only the two
// signature gates, as everywhere). No second update system: the client's
// ordinary update check carries the service fields and calls reconcile().
//
// WHO PLACES IT:
//   - a new Virule-Setup, at install/repair, beside the client;
//   - the client, whenever the installed service is MISSING (the migration
//     path for machines whose client arrived through an older Setup or the
//     client self-update) or differs from the release this client IS (the
//     service update: a client release always ships its own service).
//
// REPLACEMENT IS A MAINTENANCE TRANSACTION (residency.hpp): the maintenance
// lock is taken, the running service is asked to stop, live -> .old,
// staged -> live, the new service is started and must become resident; any
// failure puts the known-good binary back and starts it, and that exact
// artifact is not retried for kFailedRetryHoldS.
//
// MANAGED INSTALLS ONLY, the uninstall latch wins, and a sandboxed client
// (redirected %LOCALAPPDATA%) never downloads without an explicit manifest
// seam, exactly like the check-in (admin_install::checkin_suppressed).

#include <atomic>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

#include "shared/environment.hpp"
#include "shared/http_client.hpp"
#include "shared/json_scan.hpp"
#include "shared/lifecycle_intent.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"
#include "shared/residency.hpp"
#include "shared/verify_binary.hpp"
#include "shared/version.h"

namespace vclient::service_install {

namespace rs = residency;

constexpr long long kMaxServiceBytes = 16ll * 1024ll * 1024ll;
constexpr long long kFailedRetryHoldS = 6ll * 60ll * 60ll;

// How long a new service gets to become resident before a replacement is
// judged failed and rolled back.
constexpr unsigned long long kResidentWaitMs = 10000;

struct Artifact {
    bool present = false;
    std::string url;
    std::string sha256; // lowercase 64 hex
    long long size = 0;
};

inline bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

// The additive service fields of a client release manifest. All three absent
// = an older release that ships no service (not an error). Any one present
// means all three must be well formed. `pin` is the production rule (the url
// is a direct asset of this environment's client release repository); a
// development manifest seam relaxes only that pin.
inline bool parse_artifact(const std::string& body, bool pin, Artifact& out,
                           std::string& why) {
    out = Artifact{};
    std::string url, sha;
    long long size = 0;
    const bool has_url = json_scan::find_string_in(body, 0, body.size(), "service_url", url);
    const bool has_sha = json_scan::find_string_in(body, 0, body.size(), "service_sha256", sha);
    const bool has_size = json_scan::find_number_in(body, 0, body.size(), "service_size", size);
    if (!has_url && !has_sha && !has_size) return true; // no service in this release
    if (!has_url || url.empty() || url.size() > 512) {
        why = "manifest service_url missing or malformed";
        return false;
    }
    if (pin && url.rfind(env::kClientUrlPrefix, 0) != 0) {
        why = std::string("manifest service_url is not under ") + env::kClientUrlPrefix;
        return false;
    }
    for (auto& c : sha) {
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
    }
    if (!has_sha || !is_hex64(sha)) {
        why = "manifest service_sha256 is not 64 hex digits";
        return false;
    }
    if (!has_size || size <= 0 || size > kMaxServiceBytes) {
        why = "manifest service_size missing or out of bounds";
        return false;
    }
    out.present = true;
    out.url = url;
    out.sha256 = sha;
    out.size = size;
    return true;
}

inline std::string file_sha256(const std::filesystem::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return "";
    std::string bytes((std::istreambuf_iterator<char>(in)),
                      std::istreambuf_iterator<char>());
    if (!in.good() && !in.eof()) return "";
    return verify_binary::sha256_hex(
        reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
}

// The full gate on a staged file: exact size, exact SHA-256 (never waived),
// then Authenticode + the VIRULE signer (production; `allow_unsigned` is the
// --dev-unsigned seam and waives only these two).
inline bool verify_staged(const std::filesystem::path& file, const Artifact& a,
                          bool allow_unsigned, std::string& why) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(file, ec);
    if (ec || (long long)size != a.size) {
        why = "service size mismatch";
        return false;
    }
    if (file_sha256(file) != a.sha256) {
        why = "service sha256 mismatch";
        return false;
    }
    if (env::kRequireAuthenticode && !allow_unsigned) {
        if (!verify_binary::authenticode_valid(file)) {
            why = "service Authenticode verification failed";
            return false;
        }
        if (!verify_binary::signed_by(file, env::kExpectedSigner)) {
            why = "service signer is not the VIRULE identity";
            return false;
        }
    }
    return true;
}

// Download the artifact to `target` (capped at the declared size), then the
// full gate. The target is removed on any failure.
inline bool download_verified(const Artifact& a, const std::filesystem::path& target,
                              bool allow_unsigned, std::string& why) {
    http::Url u;
    if (!http::parse_url(std::wstring(a.url.begin(), a.url.end()), u)) {
        why = "service url unparseable";
        return false;
    }
    std::error_code ec;
    std::filesystem::remove(target, ec);
    unsigned long status = 0;
    bool ok = false;
    if (u.secure && u.port == 443) {
        unsigned long long got = 0;
        std::string sha;
        ok = http::https_get_to_file(u.host.c_str(), u.path.c_str(),
                                     (unsigned long long)a.size, target, status,
                                     got, sha,
                                     []() { return !lifecycle::uninstall_intent_active(); });
    } else {
        // Development seam only (a local manifest server).
        std::string payload;
        if (http::http_get(u.host.c_str(), u.port, u.secure, u.path.c_str(),
                           (size_t)a.size, status, payload) &&
            status == 200) {
            std::ofstream out(target, std::ios::binary | std::ios::trunc);
            ok = out && out.write(payload.data(), (std::streamsize)payload.size()).good();
        }
    }
    if (!ok) {
        ec.clear();
        std::filesystem::remove(target, ec);
        why = "service download failed, status=" + std::to_string(status);
        return false;
    }
    if (!verify_staged(target, a, allow_unsigned, why)) {
        ec.clear();
        std::filesystem::remove(target, ec);
        return false;
    }
    return true;
}

inline bool rename_with_retries(const std::filesystem::path& from,
                                const std::filesystem::path& to) {
    for (int i = 0; i < 15; ++i) {
        std::error_code ec;
        std::filesystem::rename(from, to, ec);
        if (!ec) return true;
        Sleep(300);
    }
    return false;
}

// Wait (bounded) for a just-started service to become resident: its
// singleton exists while the process is alive.
inline bool wait_resident(HANDLE process, unsigned long long wait_ms) {
    const ULONGLONG deadline = GetTickCount64() + wait_ms;
    for (;;) {
        if (rs::mutex_exists(rs::kServiceSingleton)) {
            // A singleton that belongs to a process that already died is
            // not residency.
            return process == nullptr ||
                   WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
        }
        if (process && WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return false;
        if (GetTickCount64() >= deadline) return false;
        Sleep(100);
    }
}

// Place the verified `staged` binary as the live service. The CALLER holds
// the maintenance lock. `seams` are forwarded to the started service.
inline bool place_staged(const std::filesystem::path& staged,
                         const std::wstring& seams, std::string& why) {
    const auto live = paths::installed_service_exe();
    const auto old_exe = paths::service_old_exe();
    std::error_code ec;
    if (!rs::stop_service_and_wait(10000)) {
        why = "the running VIRULE Service did not stop";
        return false;
    }
    std::filesystem::remove(old_exe, ec);
    ec.clear();
    const bool had_live = std::filesystem::exists(live, ec) && !ec;
    if (had_live && !rename_with_retries(live, old_exe)) {
        why = "the live service binary is locked";
        if (HANDLE h = rs::launch_managed(live, L"", seams)) CloseHandle(h);
        return false;
    }
    if (!rename_with_retries(staged, live)) {
        if (had_live) (void)rename_with_retries(old_exe, live);
        why = "the staged service could not be placed";
        if (had_live) {
            if (HANDLE h = rs::launch_managed(live, L"", seams)) CloseHandle(h);
        }
        return false;
    }
    HANDLE h = rs::launch_managed(live, L"", seams);
    const bool resident = h != nullptr && wait_resident(h, kResidentWaitMs);
    if (resident) {
        CloseHandle(h);
        ec.clear();
        std::filesystem::remove(old_exe, ec);
        return true;
    }
    // Roll back. The new process is this transaction's own broken child.
    if (h) {
        if (WaitForSingleObject(h, 0) == WAIT_TIMEOUT) {
            TerminateProcess(h, 1);
            WaitForSingleObject(h, 5000);
        }
        CloseHandle(h);
    }
    ec.clear();
    std::filesystem::remove(live, ec);
    if (had_live && rename_with_retries(old_exe, live)) {
        if (HANDLE back = rs::launch_managed(live, L"", seams)) CloseHandle(back);
    }
    why = "the new VIRULE Service did not become resident; known-good restored";
    return false;
}

// ---- the client's side (run configuration set once by main.cpp) ----

inline std::atomic<bool> g_enabled{ false }; // running AS the managed install
inline bool g_dev_unsigned = false;          // signature gates only
inline bool g_manifest_seam = false;         // a dev manifest url is in use
inline std::wstring g_seams;                 // forwarded to the started service

inline std::mutex g_mutex;
inline std::string g_failed_sha;             // the artifact that last failed
inline long long g_failed_utc = 0;
inline std::atomic<bool> g_busy{ false };
inline bool g_said_absent = false;

// Startup residue: an interrupted replacement must not strand the managed
// service. A missing live binary with a surviving .old is restored; stale
// staging is debris. Runs once, before the watcher starts.
inline void reconcile_startup_residue() {
    if (!g_enabled.load()) return;
    if (rs::maintenance_held()) return; // a live transaction owns these files
    std::error_code ec;
    const auto live = paths::installed_service_exe();
    const auto old_exe = paths::service_old_exe();
    if (!std::filesystem::exists(live, ec) && std::filesystem::exists(old_exe, ec)) {
        if (rename_with_retries(old_exe, live)) {
            log::client("service: interrupted replacement reconciled (known-good restored)");
        }
    }
    ec.clear();
    std::filesystem::remove(old_exe, ec);
    ec.clear();
    std::filesystem::remove(paths::service_update_staged_exe(), ec);
}

// Bring the installed service in line with the release manifest the client
// just read. `release_version` is that manifest's client version.
inline void reconcile(const std::string& release_version, const Artifact& a) {
    if (!g_enabled.load()) return;
    if (lifecycle::uninstall_intent_active()) return;
    if (!a.present) {
        if (!g_said_absent) {
            log::client("service: the release manifest describes no VIRULE Service");
            g_said_absent = true;
        }
        return;
    }
    g_said_absent = false;
    if (g_busy.exchange(true)) return;
    struct Clear { ~Clear() { g_busy.store(false); } } clear_on_exit;

    const auto live = paths::installed_service_exe();
    std::error_code ec;
    const bool installed = std::filesystem::exists(live, ec) && !ec;
    if (installed) {
        // Converge only with the release this client IS: a newer manifest
        // means a client self-update is coming, and that new client brings
        // its own service along; an older one is never a downgrade target.
        if (release_version != VIRULE_CLIENT_VERSION_STRING) return;
        if (file_sha256(live) == a.sha256) return; // current
    }
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_failed_sha == a.sha256 &&
            (long long)time(nullptr) - g_failed_utc < kFailedRetryHoldS) {
            return; // this exact artifact failed recently; no retry loop
        }
    }
    if (paths::environment_redirected() && !g_manifest_seam) {
        log::client("service: sandboxed environment without a manifest seam; not downloading");
        return;
    }

    log::client(std::string("service: ") + (installed ? "updating" : "installing") +
                " VIRULE Service (" + std::to_string(a.size) + " bytes)");
    const auto staged = paths::service_update_staged_exe();
    std::string why;
    bool ok = download_verified(a, staged, g_dev_unsigned, why);
    if (ok) {
        rs::MaintenanceLock lock;
        if (!lock.acquire(30000)) {
            why = "another VIRULE maintenance operation is running";
            ok = false;
        } else if (lifecycle::uninstall_intent_active()) {
            why = "uninstall in progress";
            ok = false;
        } else {
            ok = place_staged(staged, g_seams, why);
        }
    }
    ec.clear();
    std::filesystem::remove(staged, ec);
    if (ok) {
        log::client("service: VIRULE Service is resident (" + a.sha256.substr(0, 12) + ")");
        std::lock_guard<std::mutex> lock(g_mutex);
        g_failed_sha.clear();
        return;
    }
    log::client("service: " + why);
    std::lock_guard<std::mutex> lock(g_mutex);
    g_failed_sha = a.sha256;
    g_failed_utc = (long long)time(nullptr);
}

} // namespace vclient::service_install
