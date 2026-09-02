#pragma once
// This machine's VIRULE identity, as the VIRULE Client uses it.
//
// THE FILE IS THE EXISTING PRODUCT CONTRACT, not a new system:
// %LOCALAPPDATA%\VIRULE\security\dev_machine.cred, exactly as the VIRULE
// Admin creates it (dev_machine_license.cpp) and exactly as the wrapper
// runtime consumes it (dev_machine_proof.hpp / qa_runtime_client.hpp):
//
//   { "version": 1,
//     "install_id": "<32 hex>",
//     "public_key": "<64 hex>",          // raw Ed25519 public key
//     "private_blob": "<base64 DPAPI>" } // protected 32-byte seed,
//                                        // entropy = install_id
//
// RULES (deliberately different from the Admin's ensure_credential in ONE
// respect):
//   - An existing credential that is well-formed AND decryptable on this
//     machine AND whose seed reproduces its recorded public key is used
//     AS-IS and never rewritten. This is the wrapper's validation model
//     (the credential's own install_id is the DPAPI entropy); the client
//     has no database, so the Admin's workspace-id equality check does not
//     apply here. On a machine with the VIRULE Admin installed the
//     Admin-created credential passes this validation and is simply
//     reused, so both products present ONE machine identity.
//   - Only when nothing usable exists does the client create a credential,
//     with a freshly generated random 32-hex install id. state.json
//     records that the client created it, which is what allows a full
//     VIRULE uninstall to remove it (an Admin-created identity is never
//     removed: it is the developer's press/QA signing identity).
//
// The QA machine proof and the redeemed tester credential both key off
// this file, which is why a credential redeemed by the client verifies at
// game launch (qa_runtime_client.hpp reproduces the bound key from this
// same file).

#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#include "shared/logging.hpp"
#include "virule/core/dev_machine_proof.hpp"

#if defined(_WIN32)
#include <wincrypt.h>
#include <dpapi.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

namespace vclient::machine_identity {

namespace dmp = virule::core::dev_machine::proof;

inline std::mutex& mutex() {
    static std::mutex m;
    return m;
}

// Padded standard-alphabet base64 (the dev_machine_license.cpp encoder), so
// b64_decode_strict reads back exactly what this writes.
inline std::string b64_encode(const unsigned char* data, size_t n) {
    static const char* kAlpha =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((n + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        const unsigned u = (unsigned(data[i]) << 16) |
                           (unsigned(data[i + 1]) << 8) | unsigned(data[i + 2]);
        out += kAlpha[(u >> 18) & 63];
        out += kAlpha[(u >> 12) & 63];
        out += kAlpha[(u >> 6) & 63];
        out += kAlpha[u & 63];
    }
    if (i < n) {
        const size_t rem = n - i;
        unsigned u = unsigned(data[i]) << 16;
        if (rem == 2) u |= unsigned(data[i + 1]) << 8;
        out += kAlpha[(u >> 18) & 63];
        out += kAlpha[(u >> 12) & 63];
        out += (rem == 2) ? kAlpha[(u >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

inline bool dpapi_protect(const std::vector<unsigned char>& plain,
                          const std::string& entropy,
                          std::vector<unsigned char>& out) {
    out.clear();
    if (plain.empty()) return false;
    DATA_BLOB in{ static_cast<DWORD>(plain.size()),
                  const_cast<BYTE*>(plain.data()) };
    DATA_BLOB ent{ static_cast<DWORD>(entropy.size()),
                   reinterpret_cast<BYTE*>(const_cast<char*>(entropy.data())) };
    DATA_BLOB enc{};
    // The description string matches the Admin's protect call exactly.
    if (!CryptProtectData(&in, L"virule-dev-machine", &ent, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &enc)) {
        return false;
    }
    out.assign(enc.pbData, enc.pbData + enc.cbData);
    dmp::detail::secure_zero(enc.pbData, enc.cbData);
    LocalFree(enc.pbData);
    return true;
}

inline std::string json_escape_min(const std::string& s) {
    std::string out = "\"";
    for (const char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                static const char* kHex = "0123456789abcdef";
                out += "\\u00";
                out += kHex[(c >> 4) & 0xF];
                out += kHex[c & 0xF];
            } else {
                out += c;
            }
        }
    }
    out += "\"";
    return out;
}

inline bool write_file_atomic(const std::filesystem::path& p, const std::string& body) {
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    if (ec) return false;
    const auto tmp = p.parent_path() / (p.filename().string() + ".tmp");
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f << body;
        if (!f) return false;
    }
    ec.clear();
    std::filesystem::rename(tmp, p, ec);
    if (ec) {
        ec.clear();
        std::filesystem::remove(p, ec);
        ec.clear();
        std::filesystem::rename(tmp, p, ec);
    }
    if (ec) {
        std::error_code ec2;
        std::filesystem::remove(tmp, ec2);
        return false;
    }
    return true;
}

// Load the credential and recover its seed if it is usable ON THIS MACHINE
// (well-formed, DPAPI-decryptable with its own install id, seed reproduces
// the recorded public key). seed_out may be null when only the public half
// is wanted (the private material is then never decrypted... it still must
// be, to prove usability, so it is decrypted and wiped).
inline bool load_usable(dmp::CredentialFields& out, unsigned char* seed_out) {
    const std::string text = dmp::read_credential_text(dmp::local_credential_path());
    if (text.empty()) return false;
    dmp::CredentialFields c{};
    if (!dmp::parse_credential_text(text, c)) return false;
    if (!dmp::credential_well_formed(c)) return false;
    std::vector<unsigned char> blob;
    if (!dmp::nacl::b64_decode_strict(c.private_blob_b64, blob)) return false;
    std::vector<unsigned char> plain;
    if (!dmp::dpapi_unprotect_win(blob, c.install_id, plain) || plain.size() != 32) {
        if (!plain.empty()) dmp::detail::secure_zero(plain.data(), plain.size());
        return false;
    }
    unsigned char seed[32];
    std::memcpy(seed, plain.data(), 32);
    dmp::detail::secure_zero(plain.data(), plain.size());
    unsigned char pk[32];
    dmp::detail::public_from_seed(seed, pk);
    if (dmp::detail::to_hex(pk, 32) != c.public_key_hex) {
        dmp::detail::secure_zero(seed, sizeof(seed));
        return false;
    }
    if (seed_out) std::memcpy(seed_out, seed, 32);
    dmp::detail::secure_zero(seed, sizeof(seed));
    out = c;
    return true;
}

// Create a fresh identity (random install id, random seed) in the exact
// Admin file format. Only called when nothing usable exists.
inline bool create_credential() {
    unsigned char id_bytes[16];
    unsigned char seed[32];
    if (!dmp::random_bytes_win(id_bytes, sizeof(id_bytes)) ||
        !dmp::random_bytes_win(seed, sizeof(seed))) {
        log::client("identity create: no entropy source");
        return false;
    }
    const std::string install_id = dmp::detail::to_hex(id_bytes, sizeof(id_bytes));
    unsigned char pk[32];
    dmp::detail::public_from_seed(seed, pk);

    std::vector<unsigned char> plain(seed, seed + 32);
    std::vector<unsigned char> blob;
    const bool protect_ok = dpapi_protect(plain, install_id, blob);
    dmp::detail::secure_zero(plain.data(), plain.size());
    dmp::detail::secure_zero(seed, sizeof(seed));
    if (!protect_ok) {
        log::client("identity create: DPAPI protect failed");
        return false;
    }

    std::string body;
    body += "{\n";
    body += "  \"version\": " + std::to_string(dmp::kCredentialVersion) + ",\n";
    body += "  \"install_id\": " + json_escape_min(install_id) + ",\n";
    body += "  \"public_key\": " + json_escape_min(dmp::detail::to_hex(pk, 32)) + ",\n";
    body += "  \"private_blob\": " + json_escape_min(b64_encode(blob.data(), blob.size())) + "\n";
    body += "}\n";

    if (!write_file_atomic(dmp::local_credential_path(), body)) {
        log::client("identity create: could not write credential file");
        return false;
    }
    log::client("identity create: new machine identity created");
    return true;
}

// Ensure a usable machine identity exists. Returns false only when one can
// neither be validated nor created. `created_out` reports whether THIS call
// created the file (uninstall provenance).
inline bool ensure(bool& created_out) {
    created_out = false;
    std::lock_guard<std::mutex> lock(mutex());
    dmp::CredentialFields c{};
    if (load_usable(c, nullptr)) return true;
    if (!create_credential()) return false;
    created_out = true;
    return load_usable(c, nullptr);
}

// The 64-hex public key, or "" when no usable identity exists.
inline std::string public_key_hex() {
    std::lock_guard<std::mutex> lock(mutex());
    dmp::CredentialFields c{};
    if (!load_usable(c, nullptr)) return "";
    return c.public_key_hex;
}

// Detached Ed25519 signature over `message`, 128 lowercase hex (the wire
// form the VIRULE API's signature grammar uses). "" on failure.
inline std::string sign_hex(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex());
    dmp::CredentialFields c{};
    unsigned char seed[32];
    if (!load_usable(c, seed)) return "";
    unsigned char pk[32];
    if (!dmp::detail::hex_to_bytes(c.public_key_hex, pk, 32)) {
        dmp::detail::secure_zero(seed, sizeof(seed));
        return "";
    }
    unsigned char sig[64];
    dmp::detail::sign_detached(seed, pk,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(), sig);
    dmp::detail::secure_zero(seed, sizeof(seed));
    return dmp::detail::to_hex(sig, sizeof(sig));
}

// EPHEMERAL test identity (Super Admin QA TEST MODE): one throwaway
// Ed25519 keypair for one signature, exactly like the Admin's
// append_ephemeral_test_proof. Nothing about the real machine identity is
// read, written or replaced.
inline bool ephemeral_sign_hex(const std::string& message,
                               std::string& public_hex_out,
                               std::string& signature_hex_out) {
    unsigned char seed[32];
    if (!dmp::random_bytes_win(seed, sizeof(seed))) return false;
    unsigned char pk[32];
    dmp::detail::public_from_seed(seed, pk);
    unsigned char sig[64];
    dmp::detail::sign_detached(seed, pk,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(), sig);
    dmp::detail::secure_zero(seed, sizeof(seed));
    public_hex_out = dmp::detail::to_hex(pk, sizeof(pk));
    signature_hex_out = dmp::detail::to_hex(sig, sizeof(sig));
    return true;
}

} // namespace vclient::machine_identity
