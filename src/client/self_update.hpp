#pragma once
// CLIENT SELF-UPDATE (owner spec 2026-09-04). virule-client.exe is the
// persistent machine manager and manages ITS OWN updates: a Client-only
// release must reach already-installed machines without Virule-Setup.exe
// ever being run again. Setup remains bootstrap/repair infrastructure.
//
// ONE TRUST MODEL, REUSED: the approved client release is discovered and
// verified through exactly the machinery Virule-Setup.exe uses - the
// getvirule/virule-client LATEST release's manifest.json, the url pinned
// to that repository's releases/download/ prefix, exact declared size,
// exact SHA-256 (never waived), Authenticode validity and the VIRULE
// signer identity (CN=Heath Michaels). GitHub is transport, not trust.
//
// LIFECYCLE (download first, swap only when safe):
//
//   serving client
//     -> quiet check (startup + a 6-hour recheck; SemVer UPGRADE only,
//        never an automatic downgrade, equal = nothing)
//     -> streamed download to virule-client.exe.update, hashed in flight
//     -> exact size / exact sha256 / Authenticode / signer identity
//     -> transaction recorded as "verified" (self_update.json)
//     -> WAIT for a safe takeover point (main.cpp owns that decision: no
//        Admin install/update, no uninstall, no QA redemption, no Setup
//        takeover, no native lifecycle card, no launch handoff in flight)
//     -> stop accepting new lifecycle operations, spawn the %TEMP% helper
//        (a copy of THIS signed exe running --finish-self-update), exit
//     -> helper: wait parent gone -> re-verify the staged binary in full
//        -> rename live exe to .old -> rename .update into place -> start
//        the new client -> confirm the bridge answers with the NEW version
//        -> clean residue. Any failure puts the known-good binary straight
//        back and restarts it; the failed version is not retried before
//        kFailedRetryHoldS.
//
// The swap is designed to fit inside the browser's existing 5s disconnect
// hysteresis: open virule.app pages reconnect to the new client naturally
// and never fall into the install flow. Routine self-update is QUIET: no
// card, no toast, no Admin surface of any kind.
//
// EXPLICIT UNINSTALL ALWAYS WINS: while the durable uninstall-intent latch
// is set (or the in-process teardown has begun) nothing here checks,
// downloads, swaps, spawns, or resurrects anything; staged residue is
// discarded. The helper re-checks the latch at every stage and never
// starts a client under it.
//
// The whole surface is MANAGED-INSTALL ONLY: a client running from
// anywhere but %LOCALAPPDATA%\Programs\VIRULE\virule-client.exe (a
// development tree) never self-updates.
//
// TRANSACTION (client\self_update.json - never "file exists therefore
// maybe update"): {"state":"verified"|"swapping"|"failed",
// "target_version","sha256","size","failed_utc"}. Removed on success and
// by discard; reconciled deterministically at every client startup.
//
// Development seams (tests only; production runs take neither):
//   --self-manifest-url=   fetch the release manifest elsewhere; relaxes
//                          ONLY the repository url pin, never the grammar
//                          and never the hash gate
//   --dev-unsigned         waives ONLY the signature gates (the exact
//                          seam Virule-Setup has)

#include <atomic>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

#include "client/admin_install.hpp" // version_is_upgrade, grammar helpers
#include "client/bridge.hpp"
#include "shared/client_state.hpp"
#include "shared/http_client.hpp"
#include "shared/json_scan.hpp"
#include "shared/lifecycle_intent.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"
#include "shared/uninstall.hpp" // kUninstallKey (DisplayVersion refresh)
#include "shared/verify_binary.hpp"
#include "shared/version.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace vclient::self_update {

// The client release manifest: identical source and pin to Virule-Setup.
constexpr wchar_t kManifestHost[] = L"github.com";
constexpr wchar_t kManifestPath[] =
    L"/getvirule/virule-client/releases/latest/download/manifest.json";
constexpr char kClientUrlPrefix[] =
    "https://github.com/getvirule/virule-client/releases/download/";
constexpr size_t kMaxManifestBytes = 16 * 1024;
constexpr size_t kMaxClientBytes = 64 * 1024 * 1024;

// Cadence: one asynchronous check shortly after startup, then a quiet
// 6-hour recheck while the process happens to be serving. The freshness
// stamp is set before the network attempt so a failing network can never
// turn the quiet check into a hammer.
constexpr unsigned long long kCheckFreshMs = 15ull * 60ull * 1000ull;
constexpr unsigned long long kCheckPeriodMs = 6ull * 60ull * 60ull * 1000ull;

// A version whose swap failed is not automatically retried before this
// (the next periodic check after the hold earns exactly one fresh
// attempt; never a respawn loop).
constexpr long long kFailedRetryHoldS = 6ll * 60ll * 60ll;

// ---- run configuration (set once by main.cpp before serving) ----

inline std::atomic<bool> g_enabled{ false };   // running AS the managed install
inline bool g_dev_unsigned = false;            // signature gates only
inline std::wstring g_manifest_override;       // dev seam; empty = production
inline bool g_no_register = false;             // forwarded to the new client

// The staged update is verified and waiting for a safe takeover point.
inline std::atomic<bool> g_swap_ready{ false };

inline std::mutex g_mutex;
inline std::string g_approved_version;         // "" = no answer yet
inline unsigned long long g_check_tick = 0;    // 0 = never attempted

// ---- the transaction record ----

struct Txn {
    std::string state;          // "" | "verified" | "swapping" | "failed"
    std::string target_version;
    std::string sha256;
    long long size = 0;
    long long failed_utc = 0;
    long long swap_utc = 0;     // when "swapping" was entered
};

// A "swapping" transaction belongs to the HELPER until this much time has
// passed since it was entered; only then may a starting client treat it
// as abandoned. The helper's entire lifetime is bounded well under this
// (parent wait 30s + health 20s + rollback), so a fresh "swapping" record
// seen by a just-started client means a LIVE helper - reinterpreting it
// early is how a rolled-back update could re-stage itself mid-rollback
// and loop (the Admin update-loop failure pattern; never reproduced).
constexpr long long kSwapStaleS = 10ll * 60ll;

inline Txn load_txn() {
    Txn t;
    const auto file = paths::self_update_state_file();
    if (file.empty()) return t;
    std::ifstream in(file, std::ios::binary);
    if (!in) return t;
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    if (text.size() > 4096) return t;
    (void)json_scan::find_string_in(text, 0, text.size(), "state", t.state);
    (void)json_scan::find_string_in(text, 0, text.size(), "target_version",
                                    t.target_version);
    (void)json_scan::find_string_in(text, 0, text.size(), "sha256", t.sha256);
    (void)json_scan::find_number_in(text, 0, text.size(), "size", t.size);
    (void)json_scan::find_number_in(text, 0, text.size(), "failed_utc",
                                    t.failed_utc);
    (void)json_scan::find_number_in(text, 0, text.size(), "swap_utc",
                                    t.swap_utc);
    if (t.state != "verified" && t.state != "swapping" && t.state != "failed") {
        return Txn{};
    }
    if (!admin_install::is_version_grammar(t.target_version) ||
        !admin_install::is_hex64(t.sha256) || t.size <= 0) {
        return Txn{};
    }
    return t;
}

inline bool save_txn(const Txn& t) {
    const auto file = paths::self_update_state_file();
    if (file.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    std::string body = "{\"version\":1,\"state\":\"" + t.state + "\"";
    body += ",\"target_version\":\"" + json_scan::json_escape(t.target_version) + "\"";
    body += ",\"sha256\":\"" + t.sha256 + "\"";
    body += ",\"size\":" + std::to_string(t.size);
    body += ",\"failed_utc\":" + std::to_string(t.failed_utc);
    body += ",\"swap_utc\":" + std::to_string(t.swap_utc);
    body += "}";
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(body.data(), (std::streamsize)body.size());
    return out.good();
}

inline void clear_txn() {
    std::error_code ec;
    std::filesystem::remove(paths::self_update_state_file(), ec);
}

// Discard any not-yet-committed self-update (staged binary + transaction).
// Used when the approved release stops being an upgrade, and whenever the
// uninstall intent outranks a pending update.
inline void discard_pending() {
    std::error_code ec;
    std::filesystem::remove(paths::client_update_staged_exe(), ec);
    clear_txn();
    g_swap_ready.store(false);
}

inline void mark_failed(const std::string& version) {
    Txn t;
    t.state = "failed";
    t.target_version = version;
    t.sha256 = std::string(64, '0'); // grammar filler; failed records carry no payload
    t.size = 1;
    t.failed_utc = (long long)time(nullptr);
    (void)save_txn(t);
    std::error_code ec;
    std::filesystem::remove(paths::client_update_staged_exe(), ec);
    g_swap_ready.store(false);
}

// ---- verification ----

inline std::string sha256_of_file(const std::filesystem::path& file) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return "";
    }
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return "";
    }
    std::string out;
    std::ifstream in(file, std::ios::binary);
    if (in) {
        std::string chunk(64 * 1024, '\0');
        bool ok = true;
        for (;;) {
            in.read(chunk.data(), (std::streamsize)chunk.size());
            const std::streamsize got = in.gcount();
            if (got <= 0) break;
            if (BCryptHashData(hash, (PUCHAR)chunk.data(), (ULONG)got, 0) != 0) {
                ok = false;
                break;
            }
        }
        unsigned char digest[32];
        if (ok && !in.bad() &&
            BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
            static const char* kHex = "0123456789abcdef";
            out.resize(64);
            for (size_t i = 0; i < 32; ++i) {
                out[i * 2 + 0] = kHex[(digest[i] >> 4) & 0xF];
                out[i * 2 + 1] = kHex[digest[i] & 0xF];
            }
        }
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

// The full staged-binary gate: exact recorded size, exact recorded
// SHA-256 (never waived), Authenticode + the VIRULE signer identity
// (--dev-unsigned waives only the signature checks).
inline bool staged_binary_valid(const Txn& t, std::string& why) {
    const auto staged = paths::client_update_staged_exe();
    std::error_code ec;
    if (staged.empty() || !std::filesystem::exists(staged, ec) || ec) {
        why = "staged binary missing";
        return false;
    }
    ec.clear();
    const auto size = std::filesystem::file_size(staged, ec);
    if (ec || (long long)size != t.size) {
        why = "staged size mismatch";
        return false;
    }
    const std::string sha = sha256_of_file(staged);
    if (sha.empty() || sha != t.sha256) {
        why = "staged sha256 mismatch";
        return false;
    }
    if (!g_dev_unsigned) {
        if (!verify_binary::authenticode_valid(staged)) {
            why = "staged Authenticode verification failed";
            return false;
        }
        if (!verify_binary::signed_by(staged, admin_install::kExpectedSigner)) {
            why = "staged signer is not the VIRULE identity";
            return false;
        }
    }
    return true;
}

// ---- the release manifest ----

// Url/parse_url moved to shared/http_client.hpp (the admin-manifest dev
// seam uses the same parser); these aliases keep this file's call sites.
using Url = http::Url;
using http::parse_url;

struct Manifest {
    std::string version;
    std::string url;
    std::string sha256;
    long long size = 0;
};

inline bool fetch_manifest(Manifest& out, std::string& why) {
    const bool dev = !g_manifest_override.empty();
    unsigned long status = 0;
    std::string body;
    if (dev) {
        Url u;
        if (!parse_url(g_manifest_override, u)) {
            why = "unparseable --self-manifest-url";
            return false;
        }
        if (!http::http_get(u.host.c_str(), u.port, u.secure, u.path.c_str(),
                            kMaxManifestBytes, status, body) ||
            status != 200) {
            why = "manifest fetch failed, status=" + std::to_string(status);
            return false;
        }
    } else if (!http::https_get(kManifestHost, kManifestPath, kMaxManifestBytes,
                                status, body) ||
               status != 200) {
        why = "manifest fetch failed, status=" + std::to_string(status);
        return false;
    }
    if (!json_scan::find_string_in(body, 0, body.size(), "version", out.version) ||
        !admin_install::is_version_grammar(out.version)) {
        why = "manifest version missing or malformed";
        return false;
    }
    if (!json_scan::find_string_in(body, 0, body.size(), "url", out.url) ||
        out.url.empty() || out.url.size() > 512) {
        why = "manifest url missing or malformed";
        return false;
    }
    // The dev seam relaxes ONLY the repository pin; grammar and the hash
    // gate hold exactly as in production.
    if (!dev && out.url.rfind(kClientUrlPrefix, 0) != 0) {
        why = std::string("manifest url is not under ") + kClientUrlPrefix;
        return false;
    }
    if (!json_scan::find_string_in(body, 0, body.size(), "sha256", out.sha256)) {
        why = "manifest sha256 missing";
        return false;
    }
    for (auto& c : out.sha256) {
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
    }
    if (!admin_install::is_hex64(out.sha256)) {
        why = "manifest sha256 is not 64 hex digits";
        return false;
    }
    if (!json_scan::find_number_in(body, 0, body.size(), "size", out.size) ||
        out.size <= 0 || out.size > (long long)kMaxClientBytes) {
        why = "manifest size missing or out of bounds";
        return false;
    }
    return true;
}

// ---- staging (download + verify; swap comes later, when safe) ----

inline bool stage_update(const Manifest& m) {
    Url u;
    {
        std::wstring wurl(m.url.begin(), m.url.end());
        if (!parse_url(wurl, u)) {
            log::client("self-update: manifest url unparseable");
            return false;
        }
    }
    const auto staged = paths::client_update_staged_exe();
    std::error_code ec;
    std::filesystem::create_directories(paths::install_dir(), ec);
    ec.clear();
    std::filesystem::remove(staged, ec);

    log::client("self-update: staging client " + m.version +
                " (" + std::to_string(m.size) + " bytes)");
    bool downloaded = false;
    unsigned long status = 0;
    if (u.secure && u.port == 443) {
        // Production: streamed to the staging file, hashed in flight, the
        // manifest's declared size as the hard cap. An uninstall beginning
        // mid-transfer aborts it (uninstall wins).
        unsigned long long got_size = 0;
        std::string got_sha;
        downloaded = http::https_get_to_file(
            u.host.c_str(), u.path.c_str(), (unsigned long long)m.size, staged,
            status, got_size, got_sha,
            []() {
                bridge::touch_activity();
                return !bridge::g_uninstalling.load();
            });
        if (downloaded &&
            (got_size != (unsigned long long)m.size || got_sha != m.sha256)) {
            log::client("self-update: download size/sha256 mismatch");
            downloaded = false;
        }
    } else {
        // Dev seam only (--self-manifest-url against a local server): the
        // client binary is small enough to buffer; the same exact-size and
        // exact-hash gates apply.
        std::string payload;
        if (http::http_get(u.host.c_str(), u.port, u.secure, u.path.c_str(),
                           (size_t)m.size, status, payload) &&
            status == 200 && (long long)payload.size() == m.size &&
            verify_binary::sha256_hex(
                reinterpret_cast<const unsigned char*>(payload.data()),
                payload.size()) == m.sha256) {
            std::ofstream out(staged, std::ios::binary | std::ios::trunc);
            downloaded = out &&
                out.write(payload.data(), (std::streamsize)payload.size()).good();
        }
    }
    if (!downloaded) {
        if (bridge::g_uninstalling.load()) {
            log::client("self-update: download aborted (uninstall in progress)");
        } else {
            log::client("self-update: download failed, status=" +
                        std::to_string(status));
        }
        ec.clear();
        std::filesystem::remove(staged, ec);
        return false;
    }

    Txn t;
    t.state = "verified";
    t.target_version = m.version;
    t.sha256 = m.sha256;
    t.size = m.size;
    std::string why;
    if (!staged_binary_valid(t, why)) {
        log::client("self-update: " + why + "; staged binary rejected");
        ec.clear();
        std::filesystem::remove(staged, ec);
        return false;
    }
    if (!save_txn(t)) {
        log::client("self-update: could not record the transaction; discarded");
        ec.clear();
        std::filesystem::remove(staged, ec);
        return false;
    }
    g_swap_ready.store(true);
    log::client("self-update: client " + m.version +
                " staged and verified; waiting for a safe takeover point");
    return true;
}

// ---- the quiet check ----

// Refresh the approved-client knowledge when the cache is older than
// `fresh_ms`, and stage a genuine UPGRADE (SemVer ordering; equal does
// nothing, an approved version LOWER than this build never downgrades).
inline void refresh_check(unsigned long long fresh_ms) {
    if (!g_enabled.load()) return;
    if (bridge::g_uninstalling.load()) return;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        const unsigned long long now = GetTickCount64();
        if (g_check_tick != 0 && now - g_check_tick < fresh_ms) return;
        g_check_tick = now;
    }
    if (lifecycle::uninstall_intent_active()) return;

    Manifest m;
    std::string why;
    if (!fetch_manifest(m, why)) {
        log::client("self-update: check failed: " + why);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_approved_version != m.version) {
            log::client("self-update: approved client version " + m.version);
        }
        g_approved_version = m.version;
    }

    if (!admin_install::version_is_upgrade(m.version,
                                           VIRULE_CLIENT_VERSION_STRING)) {
        // Current (or the approved release is older: rollback stays an
        // explicit operation, never automatic). Stale staging for some
        // other version is debris.
        const Txn t = load_txn();
        if (!t.state.empty() && t.state != "swapping") discard_pending();
        return;
    }

    const Txn t = load_txn();
    if (t.state == "swapping") return; // startup reconciliation owns it
    if (t.state == "failed" && t.target_version == m.version &&
        (long long)time(nullptr) - t.failed_utc < kFailedRetryHoldS) {
        return; // this exact version failed recently; no retry loop
    }
    if (t.state == "verified" && t.target_version == m.version) {
        g_swap_ready.store(true); // already staged and recorded
        return;
    }
    (void)stage_update(m);
}

// ---- the swap handoff (serving client side) ----

// Copy this signed exe to %TEMP% and run it as the narrow replacement
// helper. The caller (main.cpp) has already drained the bridge and is
// about to exit; the helper waits for that exit before touching anything.
inline bool begin_swap() {
    Txn t = load_txn();
    if (t.state != "verified") return false;
    std::string why;
    if (!staged_binary_valid(t, why)) {
        log::client("self-update: " + why + " at swap time; discarded");
        discard_pending();
        return false;
    }
    wchar_t self[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH)) return false;
    wchar_t temp_dir[MAX_PATH] = {};
    const DWORD n = GetTempPathW(MAX_PATH, temp_dir);
    if (n == 0 || n >= MAX_PATH) return false;
    const std::wstring helper = std::wstring(temp_dir) + L"virule-selfupdate-" +
        std::to_wstring(GetTickCount64()) + L".exe";
    if (!CopyFileW(self, helper.c_str(), FALSE)) return false;

    t.state = "swapping";
    t.swap_utc = (long long)time(nullptr);
    if (!save_txn(t)) {
        DeleteFileW(helper.c_str());
        return false;
    }
    std::wstring cmd = L"\"" + helper + L"\" --finish-self-update " +
        std::to_wstring(GetCurrentProcessId());
    if (g_dev_unsigned) cmd += L" --dev-unsigned";
    if (g_no_register) cmd += L" --no-register";
    if (!g_manifest_override.empty()) {
        cmd += L" --self-manifest-url=" + g_manifest_override;
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring mutable_cmd = cmd;
    if (!CreateProcessW(helper.c_str(), mutable_cmd.data(), nullptr, nullptr,
                        FALSE, 0, nullptr, nullptr, &si, &pi)) {
        DeleteFileW(helper.c_str());
        t.state = "verified";
        (void)save_txn(t);
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    log::client("self-update: replacement helper started for " +
                t.target_version + "; exiting for the swap");
    return true;
}

// ---- startup reconciliation ----

// Bring any interrupted self-update to ONE deterministic state before
// serving: a completed-but-uncleaned swap is finished, a swap that never
// happened re-arms only if the staged binary still verifies, and every
// other combination prefers the healthy running client over residue.
// `listening` = this process holds the bridge (a freshly swapped-in client
// only clears the helper's rollback material once it is demonstrably
// serving; before that the helper still owns the transaction).
inline void reconcile_startup_residue(bool listening) {
    if (!g_enabled.load()) return;
    std::error_code ec;
    const Txn t = load_txn();
    if (t.state == "swapping") {
        if (t.target_version == VIRULE_CLIENT_VERSION_STRING) {
            // We ARE the new client. Once the bridge is up the helper's
            // health check succeeds; cleaning here only covers a helper
            // that died between the swap and its own cleanup.
            if (!listening) return;
            std::filesystem::remove(paths::client_old_exe(), ec);
            ec.clear();
            std::filesystem::remove(paths::client_update_staged_exe(), ec);
            clear_txn();
            log::client("self-update: completed swap reconciled at startup");
        } else {
            // Not the target version, so either the helper died before
            // replacing anything, or a LIVE helper is mid-rollback and
            // just restarted this known-good build. A fresh "swapping"
            // record still belongs to the helper: leave it entirely alone
            // (refresh_check holds off while it stands, so nothing can
            // re-stage or double-swap underneath the rollback). Only a
            // record older than the helper's whole bounded lifetime is
            // abandoned - then re-arm a payload that still verifies.
            if (t.swap_utc != 0 &&
                (long long)time(nullptr) - t.swap_utc < kSwapStaleS) {
                return;
            }
            Txn back = t;
            back.state = "verified";
            std::string why;
            if (staged_binary_valid(back, why) && save_txn(back)) {
                g_swap_ready.store(true);
                log::client("self-update: interrupted swap re-armed (" +
                            back.target_version + ")");
            } else {
                discard_pending();
                log::client("self-update: interrupted swap discarded (" + why + ")");
            }
        }
        return;
    }
    if (t.state == "verified") {
        std::string why;
        if (t.target_version == VIRULE_CLIENT_VERSION_STRING) {
            discard_pending(); // already this version; staging is debris
        } else if (staged_binary_valid(t, why)) {
            g_swap_ready.store(true);
        } else {
            discard_pending();
            log::client("self-update: stale staging discarded (" + why + ")");
        }
        return;
    }
    if (t.state == "failed") {
        ec.clear();
        std::filesystem::remove(paths::client_update_staged_exe(), ec);
        return; // the failure record (and its retry hold) stays
    }
    // No transaction: any stray files are residue of an old, completed or
    // abandoned world.
    ec.clear();
    std::filesystem::remove(paths::client_update_staged_exe(), ec);
    ec.clear();
    std::filesystem::remove(paths::client_old_exe(), ec);
}

// ---- installed-identity refresh (the authoritative version, outward) ----

// The running executable's compiled version constant is the authority.
// At startup a managed client heals what mirrors it: state.json's
// installed_version and the Apps & Features DisplayVersion (only when the
// ViruleClient entry already exists; creating registrations is Setup's
// job). virule:// self-heal already runs in serve().
inline void refresh_installed_identity() {
    if (!g_enabled.load()) return;
    auto s = state::load();
    if (s.installed_version != VIRULE_CLIENT_VERSION_STRING) {
        s.installed_version = VIRULE_CLIENT_VERSION_STRING;
        (void)state::save(s);
    }
    // A redirected (test-sandbox) world heals only its own filesystem
    // mirror above; the registry is the real machine's and stays untouched.
    // The "ours" check below is no defense there: a contaminated entry's
    // UninstallString names the SANDBOX exe, which IS the sandboxed
    // client's own installed_client_exe, so it once "healed" DisplayVersion
    // on the real entry (the P3 contamination incident's second writer).
    if (paths::environment_redirected()) return;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, uninstall::kUninstallKey, 0,
                      KEY_SET_VALUE | KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
        // Refresh only an entry that is genuinely THIS installation's: its
        // UninstallString must name this executable (a redirected test
        // sandbox, or some other world's entry, is never rewritten).
        wchar_t existing[1024] = {};
        DWORD size = sizeof(existing) - sizeof(wchar_t);
        DWORD type = 0;
        bool ours = false;
        if (RegQueryValueExW(key, L"UninstallString", nullptr, &type,
                             reinterpret_cast<BYTE*>(existing),
                             &size) == ERROR_SUCCESS && type == REG_SZ) {
            std::wstring command(existing);
            std::wstring exe = paths::installed_client_exe().wstring();
            for (wchar_t& c : command) c = (wchar_t)towlower(c);
            for (wchar_t& c : exe) c = (wchar_t)towlower(c);
            ours = !exe.empty() && command.find(exe) != std::wstring::npos;
        }
        if (ours) {
            const std::wstring version = VIRULE_CLIENT_VERSION_WSTRING;
            RegSetValueExW(key, L"DisplayVersion", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(version.c_str()),
                           (DWORD)((version.size() + 1) * sizeof(wchar_t)));
        }
        RegCloseKey(key);
    }
}

// ---- the %TEMP% replacement helper (--finish-self-update <pid>) ----

// EXTREMELY NARROW BY DESIGN: it replaces exactly the managed client
// binary with the recorded staged file (after re-verifying it in full),
// starts exactly the managed client, and cleans exactly the self-update
// residue. No path, url, or executable arrives from anywhere: everything
// is derived from paths.hpp and the transaction record. It never runs
// under the uninstall latch and never resurrects a client the user is
// removing.

inline bool helper_start_client(const std::filesystem::path& exe,
                                PROCESS_INFORMATION* pi_out) {
    const auto dir = paths::install_dir();
    std::wstring cmd = L"\"" + exe.wstring() + L"\"";
    if (g_no_register) cmd += L" --no-register";
    if (g_dev_unsigned) cmd += L" --dev-unsigned";
    if (!g_manifest_override.empty()) {
        cmd += L" --self-manifest-url=" + g_manifest_override;
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // Explicit lpCurrentDirectory (the 2026-09-04 CWD lesson); the client
    // additionally sets its own CWD at startup.
    if (!CreateProcessW(exe.wstring().c_str(), cmd.data(), nullptr, nullptr,
                        FALSE, 0, nullptr, dir.wstring().c_str(), &si, &pi)) {
        return false;
    }
    if (pi_out) {
        *pi_out = pi;
    } else {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    return true;
}

// Poll the bridge until a client answers status with `version`. True =
// healthy takeover confirmed.
inline bool helper_wait_healthy(const std::string& version,
                                unsigned long long wait_ms) {
    const ULONGLONG deadline = GetTickCount64() + wait_ms;
    const std::string needle = "\"version\":\"" + version + "\"";
    for (;;) {
        std::string response;
        if (bridge::loopback_roundtrip(bridge::kPort, nullptr,
                                       "\"virule_client\"",
                                       "{\"type\":\"status\"}", response) &&
            response.find(needle) != std::string::npos) {
            return true;
        }
        if (GetTickCount64() >= deadline) return false;
        Sleep(500);
    }
}

inline bool helper_rename_retries(const std::filesystem::path& from,
                                  const std::filesystem::path& to) {
    for (int i = 0; i < 15; ++i) {
        std::error_code ec;
        std::filesystem::rename(from, to, ec);
        if (!ec) return true;
        Sleep(300);
    }
    return false;
}

inline int run_finish_self_update(unsigned long parent_pid) {
    log::client("self-update helper: starting");
    // The parent client announced its exit before spawning this helper;
    // waiting on it is verification. A parent that will not die means the
    // swap is off: revert to "verified" and leave (no forced kill, ever).
    if (parent_pid != 0) {
        if (HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, parent_pid)) {
            const DWORD waited = WaitForSingleObject(h, 30000);
            CloseHandle(h);
            if (waited != WAIT_OBJECT_0) {
                log::client("self-update helper: parent did not exit; swap abandoned");
                Txn t = load_txn();
                if (t.state == "swapping") {
                    t.state = "verified";
                    (void)save_txn(t);
                }
                uninstall::schedule_self_delete();
                return 1;
            }
        }
    }

    // EXPLICIT UNINSTALL WINS: never swap, never start, never resurrect.
    if (lifecycle::uninstall_intent_active()) {
        log::client("self-update helper: uninstall intent active; update discarded");
        discard_pending();
        uninstall::schedule_self_delete();
        return 0;
    }

    Txn t = load_txn();
    if (t.state != "swapping") {
        log::client("self-update helper: no swapping transaction; nothing to do");
        uninstall::schedule_self_delete();
        return 1;
    }

    const auto target = paths::installed_client_exe();
    const auto staged = paths::client_update_staged_exe();
    const auto old_exe = paths::client_old_exe();
    std::error_code ec;

    // FULL re-verification against the recorded transaction, immediately
    // before the swap: exact size, exact sha256, Authenticode, signer.
    std::string why;
    if (!staged_binary_valid(t, why)) {
        log::client("self-update helper: " + why + "; known-good client kept");
        mark_failed(t.target_version);
        (void)helper_start_client(target, nullptr);
        uninstall::schedule_self_delete();
        return 1;
    }

    // The two-rename swap. The known-good binary survives every failure.
    std::filesystem::remove(old_exe, ec);
    if (!helper_rename_retries(target, old_exe)) {
        log::client("self-update helper: live exe is locked; swap failed");
        mark_failed(t.target_version);
        (void)helper_start_client(target, nullptr);
        uninstall::schedule_self_delete();
        return 1;
    }
    if (!helper_rename_retries(staged, target)) {
        (void)helper_rename_retries(old_exe, target);
        log::client("self-update helper: staging swap failed; known-good client restored");
        mark_failed(t.target_version);
        (void)helper_start_client(target, nullptr);
        uninstall::schedule_self_delete();
        return 1;
    }

    // Start the new client and confirm the takeover: the bridge must
    // answer with the NEW version. Failure rolls straight back.
    PROCESS_INFORMATION pi{};
    bool healthy = false;
    if (helper_start_client(target, &pi)) {
        healthy = helper_wait_healthy(t.target_version, 20000);
        if (!healthy) {
            // The fresh process never became a serving client. It is this
            // helper's own child, mid-bootstrap, holding the binary we
            // must roll back: end it. (The graceful-close doctrine
            // protects the Admin and running user sessions, not a broken
            // just-spawned replacement.)
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT) {
                TerminateProcess(pi.hProcess, 1);
                WaitForSingleObject(pi.hProcess, 5000);
            }
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    if (healthy) {
        ec.clear();
        std::filesystem::remove(old_exe, ec);
        clear_txn();
        log::client("self-update helper: client " + t.target_version +
                    " is serving; update complete");
        uninstall::schedule_self_delete();
        return 0;
    }

    if (lifecycle::uninstall_intent_active()) {
        // An uninstall began mid-swap: stand down completely; its helper
        // owns the tree from here.
        log::client("self-update helper: uninstall intent appeared; standing down");
        uninstall::schedule_self_delete();
        return 0;
    }

    // Deterministic rollback: the new binary goes back to staging (then
    // away), the known-good binary returns, and it is started once. The
    // failed version is held against automatic retry; no loop.
    log::client("self-update helper: new client failed to become healthy; rolling back");
    (void)helper_rename_retries(target, staged);
    (void)helper_rename_retries(old_exe, target);
    mark_failed(t.target_version);
    if (helper_start_client(target, nullptr)) {
        (void)helper_wait_healthy(VIRULE_CLIENT_VERSION_STRING, 15000);
    }
    log::client("self-update helper: known-good client restored");
    uninstall::schedule_self_delete();
    return 1;
}

} // namespace vclient::self_update
