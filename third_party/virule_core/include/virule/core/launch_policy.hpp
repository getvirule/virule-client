#pragma once
// Launch policy: the small, shared vocabulary for the two launch-gate tools
// (Steam Launch Validation and Embargo) that BOTH the Admin build system and
// the wrapper runtime must agree on.
//
// WHY ONE HEADER
//   The Admin validates a game's tool configuration and packages the runtime
//   policy into the wrapped build's .virule/manifest.json (the existing
//   runtime manifest, "game" object). The wrapper reads that policy back and
//   enforces it. Key names, the Steam App ID grammar and the embargo
//   timestamp grammar therefore live in exactly one place, so the two sides
//   cannot drift.
//
// WHAT THIS IS NOT
//   Not a manifest writer or reader. Each side keeps its own emitter/reader
//   (the Admin's prepare_wrapper_manifest, the wrapper's manifest helpers);
//   this header only supplies the names and the parsers they share.
//
// Header-only and dependency-free on purpose: the wrapper runtime links
// virule_core but deliberately pulls nothing database-shaped out of it.

#include <cstdint>
#include <string>

namespace virule::core::launch_policy {

// ---------------------------------------------------------------- keys ----
// Runtime manifest keys inside the "game" object. Emitted by the Admin ONLY
// when the corresponding tool is ON (absent == OFF), exactly like the
// existing save_import_enabled / save_awards_* gates, so every build that
// predates these tools is byte-identical to before and behaves as "both
// tools OFF".
inline constexpr const char* kKeySteamLaunchEnabled   = "steam_launch_enabled";
inline constexpr const char* kKeySteamLaunchDevMode   = "steam_launch_dev_mode";
inline constexpr const char* kKeyEmbargoEnabled       = "embargo_enabled";
inline constexpr const char* kKeyEmbargoUnlockUtc     = "embargo_unlock_utc";
// PRESS ACCESS: the optional earlier unlock instant for authorized press
// Steam keys. Emitted ONLY when it is set and strictly earlier than the
// public release; absent == no press window, which keeps every same-day
// build byte-identical to the one-date grammar.
inline constexpr const char* kKeyEmbargoPressAccessUtc = "embargo_press_access_utc";
inline constexpr const char* kKeyEmbargoDevMode       = "embargo_dev_mode";
// The developer machine PUBLIC key (64 lowercase hex, raw Ed25519). Emitted
// only when at least one tool has Developer Mode ON. Never anything private.
inline constexpr const char* kKeyDevMachinePublicKey  = "dev_machine_public_key";
// The shared Steam App ID already ships as game.steam_app_id; there is ONE
// stored value and ONE manifest field for Overlay, save awards and Steam
// Launch Validation alike.
inline constexpr const char* kKeySteamAppId           = "steam_app_id";

// -------------------------------------------------------- Steam App ID ----
// AppId_t is uint32 in the Steamworks SDK and k_uAppIdInvalid == 0, so a
// valid ID is 1..4294967295 written as 1..10 ASCII digits (no sign, no
// separators, surrounding whitespace tolerated). Returns true and the
// numeric value when valid. Same rule the wrapper has always applied to
// game.steam_app_id.
inline bool parse_steam_app_id(const std::string& raw, std::uint32_t& out) {
    out = 0;
    size_t b = 0, e = raw.size();
    while (b < e && (raw[b] == ' ' || raw[b] == '\t' || raw[b] == '\r' || raw[b] == '\n')) ++b;
    while (e > b && (raw[e - 1] == ' ' || raw[e - 1] == '\t' || raw[e - 1] == '\r' || raw[e - 1] == '\n')) --e;
    const size_t n = e - b;
    if (n == 0 || n > 10) return false;
    unsigned long long v = 0;
    for (size_t i = b; i < e; ++i) {
        const char c = raw[i];
        if (c < '0' || c > '9') return false;
        v = v * 10ull + static_cast<unsigned long long>(c - '0');
    }
    if (v < 1ull || v > 4294967295ull) return false;
    out = static_cast<std::uint32_t>(v);
    return true;
}

// ------------------------------------------------- canonical UTC instant ----
// THE stored shape of an embargo instant: exactly "YYYY-MM-DDTHH:MM:SSZ",
// calendar-correct (Feb 30 and month 13 are rejected), UTC only. Returns the
// instant as Unix seconds (proleptic Gregorian, days-from-civil). Mirrors the
// Admin host's is_canonical_utc_timestamp() and adds the numeric value the
// wrapper compares against trusted external time.
inline bool parse_canonical_utc_timestamp(const std::string& s, std::int64_t& unix_seconds_out) {
    unix_seconds_out = 0;
    if (s.size() != 20) return false;
    auto digits = [&](size_t pos, int count, int& v) {
        v = 0;
        for (int k = 0; k < count; ++k) {
            const char c = s[pos + static_cast<size_t>(k)];
            if (c < '0' || c > '9') return false;
            v = v * 10 + (c - '0');
        }
        return true;
    };
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T'
        || s[13] != ':' || s[16] != ':' || s[19] != 'Z') {
        return false;
    }
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, sec = 0;
    if (!digits(0, 4, y) || !digits(5, 2, mo) || !digits(8, 2, d)
        || !digits(11, 2, h) || !digits(14, 2, mi) || !digits(17, 2, sec)) {
        return false;
    }
    if (y < 1970 || y > 9999) return false;
    if (mo < 1 || mo > 12) return false;
    if (h > 23 || mi > 59 || sec > 59) return false;
    static const int kDays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    int dim = kDays[mo - 1];
    const bool leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
    if (mo == 2 && leap) dim = 29;
    if (d < 1 || d > dim) return false;

    // days_from_civil (Howard Hinnant), valid for the proleptic Gregorian
    // calendar; y >= 1970 here so the result is non-negative.
    const std::int64_t yy = (mo <= 2) ? (y - 1) : y;
    const std::int64_t era = yy / 400;
    const std::int64_t yoe = yy - era * 400;
    const std::int64_t mp  = (mo + 9) % 12;             // March = 0
    const std::int64_t doy = (153 * mp + 2) / 5 + d - 1;
    const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days = era * 146097 + doe - 719468;
    unix_seconds_out = days * 86400 + h * 3600 + mi * 60 + sec;
    return true;
}

// Convenience: true iff the text is a canonical UTC instant.
inline bool is_canonical_utc_timestamp(const std::string& s) {
    std::int64_t unused = 0;
    return parse_canonical_utc_timestamp(s, unused);
}

// 64 lowercase hex characters (a raw 32-byte Ed25519 public key).
inline bool is_public_key_hex(const std::string& s) {
    if (s.size() != 64) return false;
    for (const char c : s) {
        const bool digit = c >= '0' && c <= '9';
        const bool lower = c >= 'a' && c <= 'f';
        if (!digit && !lower) return false;
    }
    return true;
}

// ------------------------------------------------------- Press Embargo ----
// The hosted Press Embargo service, spoken through the versioned VIRULE API
// only; nothing here names infrastructure.
//
// Build time: the Admin registers the immutable build tuple
// (game_uuid, build_uuid, embargo_unlock_utc) and embeds the returned
// CERTIFICATE (a detached Ed25519 signature, hex) in the manifest.
// Runtime: the wrapper presents that certificate; at or after the unlock
// instant the service answers with a PERMANENT RELEASE AUTHORIZATION signed
// over the same tuple plus the release instant. The wrapper verifies both
// against kViruleEmbargoPublicKeyHex, persists the authorization, and never
// needs the service again for that build. The service going away later can
// never lock a released game.

// Manifest key beside the other embargo keys (present iff embargo is ON in
// a build made after registration existed).
inline constexpr const char* kKeyEmbargoCertificate = "embargo_certificate";

// Versioned API surface. Wide variants for the WinHTTP callers.
inline constexpr const char*    kEmbargoApiHost       = "api.virule.app";
inline constexpr const wchar_t* kEmbargoApiHostW      = L"api.virule.app";
inline constexpr const wchar_t* kEmbargoRegisterPathW = L"/v1/embargo/register";
inline constexpr const wchar_t* kEmbargoStatusPathW   = L"/v1/embargo/status";
inline constexpr const wchar_t* kEmbargoReleasePathW  = L"/v1/embargo/release";
inline constexpr const wchar_t* kEmbargoPressPathW    = L"/v1/embargo/press";
inline constexpr const wchar_t* kEmbargoKeyRegisterPathW = L"/v1/embargo/keys/register";
inline constexpr const wchar_t* kEmbargoPressRevokePathW  = L"/v1/embargo/press/revoke";
inline constexpr const wchar_t* kEmbargoPressRestorePathW = L"/v1/embargo/press/restore";
inline constexpr const wchar_t* kEmbargoSchedulePathW     = L"/v1/embargo/schedule";

// VIRULE's Press Embargo PUBLIC verification key (raw Ed25519, hex).
// Public by design; the private half exists only inside the hosted service.
inline constexpr const char* kViruleEmbargoPublicKeyHex =
    "6e7b1142a6913f202667430c3af50a76ba460f3a784558577cbe4eef3fa4df0b";

// 32 lowercase hex characters: the shape of game_uuid / build_uuid.
inline bool is_uuid_hex32(const std::string& s) {
    if (s.size() != 32) return false;
    for (const char c : s) {
        const bool digit = c >= '0' && c <= '9';
        const bool lower = c >= 'a' && c <= 'f';
        if (!digit && !lower) return false;
    }
    return true;
}

// ONE Steam key normalization, shared by the Admin (registration) and the
// wrapper (player entry) and mirrored by the service before it digests:
// uppercase, alphanumeric only, so "aaaaa-bbbbb-ccccc" and
// "AAAAA BBBBB CCCCC" are the same key. Never logged anywhere.
inline std::string normalize_steam_key(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (const char c : raw) {
        if (c >= '0' && c <= '9') out += c;
        else if (c >= 'A' && c <= 'Z') out += c;
        else if (c >= 'a' && c <= 'z') out += static_cast<char>(c - 'a' + 'A');
    }
    return out;
}

// Real Steam keys normalize to 15 (5-5-5) or 25 (5x5) characters; the bounds
// are generous so an unusual batch format still passes. Mirrors the service.
inline bool is_plausible_steam_key(const std::string& normalized) {
    return normalized.size() >= 12 && normalized.size() <= 32;
}

// 128 lowercase hex characters: a detached Ed25519 signature.
inline bool is_signature_hex(const std::string& s) {
    if (s.size() != 128) return false;
    for (const char c : s) {
        const bool digit = c >= '0' && c <= '9';
        const bool lower = c >= 'a' && c <= 'f';
        if (!digit && !lower) return false;
    }
    return true;
}

// The exact ASCII strings the service signs. Every field is grammar-checked
// before it can appear in one, so the encoding is unambiguous on both sides.
//
// SIGNED DOCUMENT VERSIONS. cert.v1 is the original one-date certificate and
// keeps verifying forever for already-shipped builds. cert.v2 is the
// two-date certificate (public release + press access) every press-enabled
// build uses; a build WITHOUT a press window still registers cert.v1, so
// same-day builds stay byte-identical to the original grammar. The permanent
// release authorization (release.v1) is UNCHANGED for both certificate
// versions. press.v1 is the installation-bound press authorization.
inline std::string embargo_certificate_message(const std::string& game_uuid,
                                               const std::string& build_uuid,
                                               const std::string& unlock_utc) {
    return "virule-embargo-cert.v1|" + game_uuid + "|" + build_uuid + "|" + unlock_utc;
}

inline std::string embargo_certificate_message_v2(const std::string& game_uuid,
                                                  const std::string& build_uuid,
                                                  const std::string& unlock_utc,
                                                  const std::string& press_access_utc) {
    return "virule-embargo-cert.v2|" + game_uuid + "|" + build_uuid + "|" + unlock_utc
         + "|" + press_access_utc;
}

inline std::string embargo_release_message(const std::string& game_uuid,
                                           const std::string& build_uuid,
                                           const std::string& unlock_utc,
                                           const std::string& released_utc) {
    return "virule-embargo-release.v1|" + game_uuid + "|" + build_uuid + "|" + unlock_utc + "|" + released_utc;
}

// Developer proof messages for press-key management, signed with the
// DEVELOPER MACHINE credential (dev_machine_license.hpp), the existing
// per-installation Ed25519 signing identity. Authority is anchored to the
// FRESH IMMUTABLE BUILD, never to game_uuid alone: registering a build
// pins the signing key to that build_uuid (random, undistributed at that
// moment), and only that key may later register press keys under it. A
// game_uuid that leaked from an older or non-embargo build is therefore
// worthless for claiming anything. The timestamp bounds replay; both sides
// use the canonical UTC grammar.
inline std::string press_claim_message(const std::string& game_uuid,
                                       const std::string& build_uuid,
                                       const std::string& timestamp_utc) {
    return "virule-press-claim.v2|" + game_uuid + "|" + build_uuid + "|" + timestamp_utc;
}

inline std::string press_keys_register_message(const std::string& game_uuid,
                                               const std::string& build_uuid,
                                               const std::string& normalized_key,
                                               const std::string& timestamp_utc) {
    return "virule-press-keys.v2|" + game_uuid + "|" + build_uuid + "|" + normalized_key
         + "|" + timestamp_utc;
}

// Developer proof for revoking/restoring ONE recipient's EARLY press
// access, named by the game-scoped opaque key reference. `action` is
// exactly "revoke" or "restore". Same trust anchor as the other developer
// proofs: the key pinned to a registered build of the game.
inline std::string press_revoke_message(const std::string& build_uuid,
                                        const std::string& press_key_ref,
                                        const std::string& action,
                                        const std::string& timestamp_utc) {
    return "virule-press-revoke.v1|" + build_uuid + "|" + press_key_ref + "|" + action
         + "|" + timestamp_utc;
}

// LIVE EMBARGO SCHEDULE (2026-08-27). Two distinct signed grammars:
//
// 1. The DEVELOPER PROOF the Admin signs to set (or clear, with empty
//    unlock) the game-scoped online schedule. Fixed field count, so empty
//    instants stay unambiguous. Same trust anchor as the other developer
//    proofs: the key pinned to a registered build of the game.
inline std::string press_schedule_message(const std::string& build_uuid,
                                          const std::string& unlock_utc,
                                          const std::string& press_access_utc,
                                          const std::string& timestamp_utc) {
    return "virule-press-schedule.v1|" + build_uuid + "|" + unlock_utc + "|" + press_access_utc
         + "|" + timestamp_utc;
}

// 2. The SERVICE-SIGNED schedule document runtimes verify against
//    kViruleEmbargoPublicKeyHex before caching or using it, so a forged or
//    edited local cache can never move a date. GAME-scoped: every build of
//    the game shares one schedule. press_access_utc may be empty (no press
//    window in the override).
inline std::string embargo_schedule_message(const std::string& game_uuid,
                                            const std::string& unlock_utc,
                                            const std::string& press_access_utc,
                                            const std::string& updated_utc) {
    return "virule-embargo-schedule.v1|" + game_uuid + "|" + unlock_utc + "|" + press_access_utc
         + "|" + updated_utc;
}

// The right certificate message for a build: v2 when it carries a press
// window, v1 otherwise. The verifier must use the version the build
// actually registered, so a stripped or added press date cannot verify.
inline std::string embargo_certificate_message_for(const std::string& game_uuid,
                                                  const std::string& build_uuid,
                                                  const std::string& unlock_utc,
                                                  const std::string& press_access_utc) {
    return press_access_utc.empty()
        ? embargo_certificate_message(game_uuid, build_uuid, unlock_utc)
        : embargo_certificate_message_v2(game_uuid, build_uuid, unlock_utc, press_access_utc);
}

// The press LAUNCH authorization message: grants launch at/after press
// access. Bound to the build tuple AND the local installation identity, so
// the persisted document is deliberately NOT portable the way the public
// release authorization is.
inline std::string embargo_press_message(const std::string& game_uuid,
                                         const std::string& build_uuid,
                                         const std::string& unlock_utc,
                                         const std::string& press_access_utc,
                                         const std::string& installation_id,
                                         const std::string& issued_utc) {
    return "virule-embargo-press.v1|" + game_uuid + "|" + build_uuid + "|" + unlock_utc
         + "|" + press_access_utc + "|" + installation_id + "|" + issued_utc;
}

// The press ENTITLEMENT message: authorized-press IDENTITY, installation
// bound, issued BEFORE press access. It never grants launch; it lets a
// journalist's installation be recognized so later launches show the
// press-access countdown without re-entering the Steam key. Distinct
// prefix from the launch authorization on purpose, so one can never be
// mistaken for the other.
inline std::string embargo_press_entitlement_message(const std::string& game_uuid,
                                                     const std::string& build_uuid,
                                                     const std::string& unlock_utc,
                                                     const std::string& press_access_utc,
                                                     const std::string& installation_id,
                                                     const std::string& issued_utc) {
    return "virule-press-entitlement.v1|" + game_uuid + "|" + build_uuid + "|" + unlock_utc
         + "|" + press_access_utc + "|" + installation_id + "|" + issued_utc;
}

// VERSION 2 press documents (2026-08-27). The opaque press key reference is
// part of the SIGNED message, so a presented credential names the exact
// press entitlement it derives from and the service's revocation check can
// never be stripped off a request. v1 stays verifying forever for
// already-shipped builds; every build produced from this wrapper on writes,
// presents and accepts v2 documents only (a fresh build_uuid never has v1
// documents on disk). The two versions carry distinct prefixes and field
// counts, so neither can be replayed as the other.
inline std::string embargo_press_message_v2(const std::string& game_uuid,
                                            const std::string& build_uuid,
                                            const std::string& unlock_utc,
                                            const std::string& press_access_utc,
                                            const std::string& installation_id,
                                            const std::string& press_key_ref,
                                            const std::string& issued_utc) {
    return "virule-embargo-press.v2|" + game_uuid + "|" + build_uuid + "|" + unlock_utc
         + "|" + press_access_utc + "|" + installation_id + "|" + press_key_ref
         + "|" + issued_utc;
}

inline std::string embargo_press_entitlement_message_v2(const std::string& game_uuid,
                                                        const std::string& build_uuid,
                                                        const std::string& unlock_utc,
                                                        const std::string& press_access_utc,
                                                        const std::string& installation_id,
                                                        const std::string& press_key_ref,
                                                        const std::string& issued_utc) {
    return "virule-press-entitlement.v2|" + game_uuid + "|" + build_uuid + "|" + unlock_utc
         + "|" + press_access_utc + "|" + installation_id + "|" + press_key_ref
         + "|" + issued_utc;
}

} // namespace virule::core::launch_policy
