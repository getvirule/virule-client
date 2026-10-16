#pragma once
// THE CLIENT'S ACCOUNT STATE ON DISK (VIRULE_BACKEND/docs/ACCOUNTS.md,
// "Desktop"). The VIRULE Client is the ONE owner of persistent desktop
// authentication; the Admin presents it and never holds a credential.
//
// Two files, both protected with Windows DPAPI (user scope, own entropy
// label), so they decrypt only for this Windows user on this computer:
//
//   security\account_device.cred      the DEVICE KEY: an Ed25519 keypair
//                                     made for account authorization only.
//                                     Every token request and API call
//                                     carries a DPoP proof signed by it
//                                     (RFC 9449); the service binds the
//                                     authorization to its thumbprint.
//   client\account.dat                the SESSION: the rotating refresh
//                                     token and the last account snapshot
//                                     (email, status, capabilities, the
//                                     account's explicit appearance and a
//                                     not-yet-delivered appearance change).
//
// THE DEVICE KEY BELONGS TO ONE AUTHORIZATION (2026-10-15). Sign-out (by
// the person or by the service) deletes it, and the next sign-in makes a
// new one. So two people who sign in on this computer one after the other
// never share a key, the service can never correlate their authorizations
// through it, and an authorization a sign-out could not revoke (offline) is
// left bound to a key that no longer exists anywhere.
//
// Staging builds use `.staging` names, so a staging client can never read
// or overwrite a production sign-in (and the services would refuse it
// anyway: different databases, different relying party).
//
// WHY A KEY OF ITS OWN and not dev_machine.cred: the machine identity can
// legitimately be replaced (the Admin issues its own when it finds a
// client-created one), which would silently break every authorization
// bound to it. The installation identity is still reported to the service
// at sign-in, as information, never as proof.
//
// Nothing here logs a token, a key or a seed.

#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#include "shared/environment.hpp"
#include "shared/json_scan.hpp"
#include "shared/logging.hpp"
#include "shared/machine_identity.hpp"
#include "shared/paths.hpp"
#include "virule/core/dev_machine_proof.hpp"

#if defined(_WIN32)
#include <wincrypt.h>
#include <dpapi.h>
#pragma comment(lib, "crypt32.lib")
#endif

namespace vclient::account_store {

namespace dmp = virule::core::dev_machine::proof;

inline constexpr const char* kDeviceEntropy = "virule-account-device.v1";
inline constexpr const char* kSessionEntropy = "virule-account-session.v1";

inline std::filesystem::path device_file() {
    const auto d = paths::security_dir();
    if (d.empty()) return d;
    return d / (env::kStaging ? L"account_device.staging.cred" : L"account_device.cred");
}

inline std::filesystem::path session_file() {
    const auto d = paths::client_state_dir();
    if (d.empty()) return d;
    return d / (env::kStaging ? L"account.staging.dat" : L"account.dat");
}

inline bool protect(const std::string& plain, const char* entropy, std::vector<unsigned char>& out) {
    out.clear();
    if (plain.empty()) return false;
    DATA_BLOB in{ static_cast<DWORD>(plain.size()), reinterpret_cast<BYTE*>(const_cast<char*>(plain.data())) };
    DATA_BLOB ent{ static_cast<DWORD>(std::strlen(entropy)), reinterpret_cast<BYTE*>(const_cast<char*>(entropy)) };
    DATA_BLOB enc{};
    if (!CryptProtectData(&in, L"virule-account", &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &enc)) {
        return false;
    }
    out.assign(enc.pbData, enc.pbData + enc.cbData);
    LocalFree(enc.pbData);
    return true;
}

inline bool unprotect(const std::vector<unsigned char>& blob, const char* entropy, std::string& out) {
    out.clear();
    std::vector<unsigned char> plain;
    if (!dmp::dpapi_unprotect_win(blob, entropy, plain)) return false;
    out.assign(plain.begin(), plain.end());
    if (!plain.empty()) dmp::detail::secure_zero(plain.data(), plain.size());
    return true;
}

inline std::string read_all(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

// ------------------------------------------------------------ device key --

struct DeviceKey {
    unsigned char seed[32]{};
    unsigned char pk[32]{};
    ~DeviceKey() { dmp::detail::secure_zero(seed, sizeof(seed)); }
};

inline std::mutex& device_mutex() {
    static std::mutex m;
    return m;
}

inline bool load_device_locked(DeviceKey& key) {
    const std::string text = read_all(device_file());
    if (text.empty()) return false;
    std::string pub, blob_b64;
    if (!json_scan::find_string_in(text, 0, text.size(), "public_key", pub) ||
        !json_scan::find_string_in(text, 0, text.size(), "private_blob", blob_b64)) {
        return false;
    }
    std::vector<unsigned char> blob;
    if (!dmp::nacl::b64_decode_strict(blob_b64, blob)) return false;
    std::string seed;
    if (!unprotect(blob, kDeviceEntropy, seed) || seed.size() != 32) {
        if (!seed.empty()) dmp::detail::secure_zero(seed.data(), seed.size());
        return false;
    }
    std::memcpy(key.seed, seed.data(), 32);
    dmp::detail::secure_zero(seed.data(), seed.size());
    dmp::detail::public_from_seed(key.seed, key.pk);
    return dmp::detail::to_hex(key.pk, 32) == pub;
}

/** Load the device key, creating it on first use. */
inline bool device_key(DeviceKey& key) {
    std::lock_guard<std::mutex> lock(device_mutex());
    if (load_device_locked(key)) return true;
    if (!dmp::random_bytes_win(key.seed, sizeof(key.seed))) return false;
    std::string plain(reinterpret_cast<const char*>(key.seed), 32);
    std::vector<unsigned char> blob;
    const bool ok = protect(plain, kDeviceEntropy, blob);
    dmp::detail::secure_zero(plain.data(), plain.size());
    if (!ok) return false;
    dmp::detail::public_from_seed(key.seed, key.pk);
    // Compact JSON: the flat field scanner reads "name":"value" exactly.
    const std::string body = std::string("{\"version\":1,\"public_key\":\"") +
        dmp::detail::to_hex(key.pk, 32) + "\",\"private_blob\":\"" +
        machine_identity::b64_encode(blob.data(), blob.size()) + "\"}\n";
    if (!machine_identity::write_file_atomic(device_file(), body)) return false;
    log::client("account: device key created");
    DeviceKey check;
    return load_device_locked(check);
}

/** Remove the device key: every sign-out, and uninstall with data removal. */
inline void remove_device_key() {
    std::lock_guard<std::mutex> lock(device_mutex());
    std::error_code ec;
    std::filesystem::remove(device_file(), ec);
}

// ------------------------------------------------- escape-aware reading --

/** Read one JSON string member, decoding \" \\ \/ \b \f \n \r \t \uXXXX
 *  (BMP and surrogate pairs) into UTF-8. The first occurrence of the key
 *  wins; callers only read flat, service-defined objects. */
inline bool read_json_string(const std::string& text, const char* name, std::string& out) {
    out.clear();
    const std::string marker = std::string("\"") + name + "\":\"";
    size_t p = text.find(marker);
    if (p == std::string::npos) return false;
    p += marker.size();
    auto hex4 = [&](size_t at, unsigned& v) {
        if (at + 4 > text.size()) return false;
        v = 0;
        for (size_t i = 0; i < 4; ++i) {
            const char c = text[at + i];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else return false;
        }
        return true;
    };
    auto put = [&](unsigned cp) {
        if (cp < 0x80) out += (char)cp;
        else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
        else { out += (char)(0xF0 | (cp >> 18)); out += (char)(0x80 | ((cp >> 12) & 0x3F)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
    };
    while (p < text.size()) {
        const char c = text[p++];
        if (c == '"') return true;
        if (c != '\\') { out += c; continue; }
        if (p >= text.size()) return false;
        const char e = text[p++];
        switch (e) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                unsigned v = 0;
                if (!hex4(p, v)) return false;
                p += 4;
                if (v >= 0xD800 && v <= 0xDBFF && p + 6 <= text.size() && text[p] == '\\' && text[p + 1] == 'u') {
                    unsigned lo = 0;
                    if (hex4(p + 2, lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                        v = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00);
                        p += 6;
                    }
                }
                put(v);
                break;
            }
            default: return false;
        }
    }
    return false;
}

// --------------------------------------------------------------- session --

struct Session {
    std::string refresh_token;   // the bearer secret, DPoP-bound
    std::string email;
    std::string display_name;
    std::string status;          // active | restricted | ...
    std::string cap_developer;   // none | pending | active | revoked
    std::string cap_evaluator;
    std::string cap_qa;
    std::string device_id;
    long long checked_epoch = 0; // when the snapshot was last confirmed by the service
    // The ACCOUNT's explicit appearance as the service last stated it
    // ("light" | "dark"; empty = never chosen) and its version.
    std::string appearance;
    long long appearance_version = 0;
    // An explicit choice made here that the service has not confirmed yet
    // (offline): delivered on the next successful contact against
    // pending_base, so it never overwrites a newer choice made elsewhere.
    std::string pending_appearance;
    long long pending_base = -1;  // -1 = a live choice (no base)
    // The service's opaque account hint (32 hex): the website account page
    // is opened with it so a browser signed in to ANOTHER account says so.
    std::string account_hint;
};

inline std::string session_json(const Session& s) {
    namespace js = json_scan;
    return std::string("{\"v\":1,\"refresh_token\":\"") + s.refresh_token +
        "\",\"email\":\"" + js::json_escape(s.email) +
        "\",\"display_name\":\"" + js::json_escape(s.display_name) +
        "\",\"status\":\"" + s.status +
        "\",\"developer\":\"" + s.cap_developer +
        "\",\"evaluator\":\"" + s.cap_evaluator +
        "\",\"qa_tester\":\"" + s.cap_qa +
        "\",\"device_id\":\"" + s.device_id +
        "\",\"appearance\":\"" + s.appearance +
        "\",\"pending_appearance\":\"" + s.pending_appearance +
        "\",\"account_hint\":\"" + s.account_hint +
        "\",\"checked\":" + std::to_string(s.checked_epoch) +
        ",\"appearance_version\":" + std::to_string(s.appearance_version) +
        ",\"pending_base\":" + std::to_string(s.pending_base) + "}";
}

inline std::mutex& session_mutex() {
    static std::mutex m;
    return m;
}

inline bool save_session(const Session& s) {
    std::lock_guard<std::mutex> lock(session_mutex());
    std::string plain = session_json(s);
    std::vector<unsigned char> blob;
    const bool ok = protect(plain, kSessionEntropy, blob);
    dmp::detail::secure_zero(plain.data(), plain.size());
    if (!ok) return false;
    return machine_identity::write_file_atomic(session_file(),
        machine_identity::b64_encode(blob.data(), blob.size()));
}

inline bool load_session(Session& s) {
    std::lock_guard<std::mutex> lock(session_mutex());
    const std::string b64 = read_all(session_file());
    if (b64.empty()) return false;
    std::vector<unsigned char> blob;
    if (!dmp::nacl::b64_decode_strict(b64, blob)) return false;
    std::string text;
    if (!unprotect(blob, kSessionEntropy, text)) return false;
    Session out;
    long long checked = 0;
    const bool ok = json_scan::find_string_in(text, 0, text.size(), "refresh_token", out.refresh_token) &&
        read_json_string(text, "email", out.email);
    (void)read_json_string(text, "display_name", out.display_name);
    (void)json_scan::find_string_in(text, 0, text.size(), "status", out.status);
    (void)json_scan::find_string_in(text, 0, text.size(), "developer", out.cap_developer);
    (void)json_scan::find_string_in(text, 0, text.size(), "evaluator", out.cap_evaluator);
    (void)json_scan::find_string_in(text, 0, text.size(), "qa_tester", out.cap_qa);
    (void)json_scan::find_string_in(text, 0, text.size(), "device_id", out.device_id);
    (void)json_scan::find_number_in(text, 0, text.size(), "checked", checked);
    out.checked_epoch = checked;
    // Older session files carry none of these: no explicit appearance.
    (void)json_scan::find_string_in(text, 0, text.size(), "appearance", out.appearance);
    (void)json_scan::find_string_in(text, 0, text.size(), "pending_appearance", out.pending_appearance);
    long long av = 0, pb = -1;
    if (json_scan::find_number_in(text, 0, text.size(), "appearance_version", av)) out.appearance_version = av;
    if (json_scan::find_number_in(text, 0, text.size(), "pending_base", pb)) out.pending_base = pb;
    if (out.appearance != "light" && out.appearance != "dark") out.appearance.clear();
    if (out.pending_appearance != "light" && out.pending_appearance != "dark") out.pending_appearance.clear();
    (void)json_scan::find_string_in(text, 0, text.size(), "account_hint", out.account_hint);
    dmp::detail::secure_zero(text.data(), text.size());
    if (!ok || out.refresh_token.empty()) return false;
    s = std::move(out);
    return true;
}

inline void clear_session() {
    std::lock_guard<std::mutex> lock(session_mutex());
    std::error_code ec;
    std::filesystem::remove(session_file(), ec);
}

} // namespace vclient::account_store
