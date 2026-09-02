#pragma once
// Developer Machine proof: the WRAPPER-SIDE half of the hidden Developer
// Machine credential (see dev_machine_license.hpp for the Admin-side
// contract: creation, self-repair, public identity retrieval).
//
// WHAT THIS DOES
//   A wrapped build whose Steam Launch Validation and/or Embargo tool had
//   Developer Mode ON carries the developer machine's PUBLIC key. At launch
//   the wrapper asks: "is this the machine that built me?" The answer is a
//   proof of possession, never a flag:
//     1. find the local credential file (%LOCALAPPDATA%\VIRULE\security\
//        dev_machine.cred); 2. validate structure + version; 3. recover the
//     private seed through DPAPI (entropy = the credential's own install id,
//     exactly as the Admin protected it); 4. check the seed reproduces the
//     credential's recorded public key; 5. draw a fresh random challenge;
//     6. sign it with the recovered identity; 7. verify the signature against
//     the public key EMBEDDED IN THIS BUILD.
//   Only a complete success bypasses a tool. Every other outcome (missing,
//   malformed, undecryptable here, inconsistent, different key, bad
//   signature) is silent: the tool simply enforces normally.
//
// WHAT THIS NEVER DOES
//   Create, repair or rewrite a credential (Admin-only), read a database,
//   log or return private material. The private seed lives on the stack for
//   the duration of one proof and is wiped.
//
// SHARED PRIMITIVES
//   expand_seed / public_from_seed / sign_detached are the Ed25519 signing
//   routines the Admin credential module uses to create and sign; they live
//   here (header-only, byte-identical to the RFC 8032-verified originals) so
//   the wrapper and the Admin run the SAME code and cannot disagree.
//   Verification reuses crypto_sign_open from the vendored TweetNaCl subset.
//
// TESTABILITY
//   prove_developer_machine() takes the credential TEXT plus DPAPI and RNG
//   seams, so a harness can exercise every branch deterministically; the
//   Windows wrappers at the bottom bind the real DPAPI/BCrypt calls.

#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "virule/core/super_admin_license.hpp"

namespace virule::core::dev_machine::proof {

namespace nacl = virule::core::super_admin::detail;

// ------------------------------------------------------------ utilities ----
namespace detail {

inline void secure_zero(void* p, size_t n) {
    volatile unsigned char* q = static_cast<volatile unsigned char*>(p);
    while (n--) *q++ = 0;
}

inline std::string to_hex(const unsigned char* b, size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out[i * 2 + 0] = kHex[(b[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[b[i] & 0xF];
    }
    return out;
}

inline bool is_lower_hex(const std::string& s, size_t expected_len) {
    if (s.size() != expected_len) return false;
    for (const char c : s) {
        const bool digit = c >= '0' && c <= '9';
        const bool lower = c >= 'a' && c <= 'f';
        if (!digit && !lower) return false;
    }
    return true;
}

inline bool hex_to_bytes(const std::string& hex, unsigned char* out, size_t n) {
    if (!is_lower_hex(hex, n * 2)) return false;
    for (size_t i = 0; i < n; ++i) {
        auto nib = [](char c) -> unsigned {
            return (c >= '0' && c <= '9') ? static_cast<unsigned>(c - '0')
                                          : static_cast<unsigned>(c - 'a' + 10);
        };
        out[i] = static_cast<unsigned char>((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    }
    return true;
}

// ---- Ed25519 signing (TweetNaCl 20140427 crypto_sign, seed form) --------
// The seed IS the protected private material; the expanded 64-byte secret
// key is re-derived per use and never stored.
inline void expand_seed(const unsigned char seed[32], unsigned char d[64]) {
    nacl::crypto_hash(d, seed, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
}

inline void public_from_seed(const unsigned char seed[32], unsigned char pk[32]) {
    unsigned char d[64];
    nacl::gf p[4];
    expand_seed(seed, d);
    nacl::scalarbase(p, d);
    nacl::pack(pk, p);
    secure_zero(d, sizeof(d));
}

// Detached 64-byte Ed25519 signature over m.
inline void sign_detached(const unsigned char seed[32], const unsigned char pk[32],
                          const unsigned char* m, size_t n, unsigned char sig[64]) {
    unsigned char d[64], h[64], r[64];
    nacl::gf p[4];
    long long x[64];

    expand_seed(seed, d);

    // r = H(prefix || m), where prefix is the upper half of the expansion.
    {
        std::vector<unsigned char> buf(32 + n);
        std::memcpy(buf.data(), d + 32, 32);
        if (n) std::memcpy(buf.data() + 32, m, n);
        nacl::crypto_hash(r, buf.data(), static_cast<unsigned long long>(buf.size()));
        secure_zero(buf.data(), buf.size());
    }
    nacl::reduce(r);
    nacl::scalarbase(p, r);
    nacl::pack(sig, p);           // R

    // h = H(R || A || m)
    {
        std::vector<unsigned char> buf(64 + n);
        std::memcpy(buf.data(), sig, 32);
        std::memcpy(buf.data() + 32, pk, 32);
        if (n) std::memcpy(buf.data() + 64, m, n);
        nacl::crypto_hash(h, buf.data(), static_cast<unsigned long long>(buf.size()));
    }
    nacl::reduce(h);

    // S = r + h*a mod L
    for (int i = 0; i < 64; ++i) x[i] = 0;
    for (int i = 0; i < 32; ++i) x[i] = static_cast<long long>(r[i]);
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 32; ++j) {
            x[i + j] += static_cast<long long>(h[i]) * static_cast<long long>(d[j]);
        }
    }
    nacl::modL(sig + 32, x);

    secure_zero(d, sizeof(d));
    secure_zero(h, sizeof(h));
    secure_zero(r, sizeof(r));
    secure_zero(x, sizeof(x));
}

// Detached verification through the vendored crypto_sign_open: rebuilds the
// attached form (sig || m) and lets the reference routine decide.
inline bool verify_detached(const unsigned char pk[32], const unsigned char* m, size_t n,
                            const unsigned char sig[64]) {
    std::vector<unsigned char> sm(64 + n);
    std::memcpy(sm.data(), sig, 64);
    if (n) std::memcpy(sm.data() + 64, m, n);
    std::vector<unsigned char> out(64 + n);
    unsigned long long mlen = 0;
    return nacl::crypto_sign_open(out.data(), &mlen, sm.data(),
                                  static_cast<unsigned long long>(sm.size()), pk) == 0;
}

} // namespace detail

// --------------------------------------------------------- credential ----
// Current credential file format (dev_machine_license.hpp kCredentialVersion).
inline constexpr int kCredentialVersion = 1;

struct CredentialFields {
    int version{0};
    std::string install_id;
    std::string public_key_hex;
    std::string private_blob_b64;
};

// Structural parse ONLY: JSON object with the four fields of the right types.
// Whether the blob decrypts here is answered by the proof itself.
inline bool parse_credential_text(const std::string& text, CredentialFields& out) {
    size_t i = 0;
    nacl::JsonValue root;
    if (!nacl::json_parse_value(text, i, root, 0)) return false;
    nacl::json_skip_ws(text, i);
    if (i != text.size()) return false;
    if (root.type != nacl::JsonValue::Type::Object) return false;

    const auto* ver = root.find("version");
    const auto* iid = root.find("install_id");
    const auto* pub = root.find("public_key");
    const auto* prv = root.find("private_blob");
    if (!ver || ver->type != nacl::JsonValue::Type::Number) return false;
    if (!iid || iid->type != nacl::JsonValue::Type::String) return false;
    if (!pub || pub->type != nacl::JsonValue::Type::String) return false;
    if (!prv || prv->type != nacl::JsonValue::Type::String) return false;

    try {
        out.version = std::stoi(ver->number_raw);
    } catch (...) {
        return false;
    }
    out.install_id = iid->str;
    out.public_key_hex = pub->str;
    out.private_blob_b64 = prv->str;
    return true;
}

// Everything a credential must satisfy structurally to be CONSIDERED.
inline bool credential_well_formed(const CredentialFields& c) {
    if (c.version != kCredentialVersion) return false;
    if (!detail::is_lower_hex(c.install_id, 32)) return false;
    if (!detail::is_lower_hex(c.public_key_hex, 64)) return false;
    if (c.private_blob_b64.empty()) return false;
    return true;
}

// ---------------------------------------------------------------- proof ----
enum class ProofResult {
    Proven,             // this machine holds the identity that built the wrapper
    BuildKeyInvalid,    // the build carries no usable public key
    CredentialMissing,  // no credential text at all
    Malformed,          // unparsable / wrong shape / wrong version
    UnprotectFailed,    // DPAPI refused here (other machine, other user, tampered)
    SeedMismatch,       // decrypted seed does not reproduce the recorded key
    KeyMismatch,        // valid local identity, but not the one that built this
    SignatureInvalid,   // challenge signature did not verify
    NoEntropy,          // no random challenge available
};

inline const char* proof_result_name(ProofResult r) {
    switch (r) {
    case ProofResult::Proven:            return "proven";
    case ProofResult::BuildKeyInvalid:   return "build key invalid";
    case ProofResult::CredentialMissing: return "credential missing";
    case ProofResult::Malformed:         return "credential malformed";
    case ProofResult::UnprotectFailed:   return "credential not decryptable here";
    case ProofResult::SeedMismatch:      return "credential inconsistent";
    case ProofResult::KeyMismatch:       return "different developer identity";
    case ProofResult::SignatureInvalid:  return "signature invalid";
    case ProofResult::NoEntropy:         return "no entropy";
    }
    return "unknown";
}

// DPAPI seam: decrypt `blob` with `entropy`, producing `plain`.
using UnprotectFn = std::function<bool(const std::vector<unsigned char>& blob,
                                       const std::string& entropy,
                                       std::vector<unsigned char>& plain)>;
// RNG seam: fill n random bytes.
using RandomFn = std::function<bool(unsigned char* out, size_t n)>;

// THE proof. Pure over its inputs; see the header comment for the sequence.
inline ProofResult prove_developer_machine(const std::string& credential_text,
                                           const std::string& build_public_key_hex,
                                           const UnprotectFn& unprotect,
                                           const RandomFn& random_bytes) {
    unsigned char build_pk[32];
    if (!detail::hex_to_bytes(build_public_key_hex, build_pk, 32)) return ProofResult::BuildKeyInvalid;
    if (credential_text.empty()) return ProofResult::CredentialMissing;

    CredentialFields c{};
    if (!parse_credential_text(credential_text, c)) return ProofResult::Malformed;
    if (!credential_well_formed(c)) return ProofResult::Malformed;

    std::vector<unsigned char> blob;
    if (!nacl::b64_decode_strict(c.private_blob_b64, blob)) return ProofResult::Malformed;

    std::vector<unsigned char> plain;
    if (!unprotect || !unprotect(blob, c.install_id, plain)) {
        if (!plain.empty()) detail::secure_zero(plain.data(), plain.size());
        return ProofResult::UnprotectFailed;
    }
    if (plain.size() != 32) {
        if (!plain.empty()) detail::secure_zero(plain.data(), plain.size());
        return ProofResult::UnprotectFailed;
    }

    unsigned char seed[32];
    std::memcpy(seed, plain.data(), 32);
    detail::secure_zero(plain.data(), plain.size());

    unsigned char local_pk[32];
    detail::public_from_seed(seed, local_pk);
    if (detail::to_hex(local_pk, 32) != c.public_key_hex) {
        detail::secure_zero(seed, sizeof(seed));
        return ProofResult::SeedMismatch;
    }
    if (std::memcmp(local_pk, build_pk, 32) != 0) {
        detail::secure_zero(seed, sizeof(seed));
        return ProofResult::KeyMismatch;
    }

    unsigned char challenge[32];
    if (!random_bytes || !random_bytes(challenge, sizeof(challenge))) {
        detail::secure_zero(seed, sizeof(seed));
        return ProofResult::NoEntropy;
    }

    unsigned char sig[64];
    detail::sign_detached(seed, local_pk, challenge, sizeof(challenge), sig);
    detail::secure_zero(seed, sizeof(seed));

    // The build's key is the verifier, never the credential's own.
    const bool ok = detail::verify_detached(build_pk, challenge, sizeof(challenge), sig);
    detail::secure_zero(sig, sizeof(sig));
    return ok ? ProofResult::Proven : ProofResult::SignatureInvalid;
}

} // namespace virule::core::dev_machine::proof

// ============================================================ Windows ====
// Real DPAPI / BCrypt bindings and the on-disk credential location. Only the
// wrapper uses these; the Admin keeps its own (identical) DPAPI calls inside
// dev_machine_license.cpp because it also PROTECTS.
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace virule::core::dev_machine::proof {

inline bool dpapi_unprotect_win(const std::vector<unsigned char>& blob,
                                const std::string& entropy,
                                std::vector<unsigned char>& out) {
    out.clear();
    if (blob.empty()) return false;
    DATA_BLOB in{ static_cast<DWORD>(blob.size()),
                  const_cast<BYTE*>(blob.data()) };
    DATA_BLOB ent{ static_cast<DWORD>(entropy.size()),
                   reinterpret_cast<BYTE*>(const_cast<char*>(entropy.data())) };
    DATA_BLOB dec{};
    if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &dec)) {
        return false;
    }
    out.assign(dec.pbData, dec.pbData + dec.cbData);
    SecureZeroMemory(dec.pbData, dec.cbData);
    LocalFree(dec.pbData);
    return true;
}

inline bool random_bytes_win(unsigned char* out, size_t n) {
    return BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

// %LOCALAPPDATA%\VIRULE\security\dev_machine.cred, resolved the way the
// Admin resolves its user-data root (LOCALAPPDATA, then USERPROFILE). Empty
// when neither is available.
inline std::filesystem::path local_credential_path() {
    const auto from_env = [](const wchar_t* name) -> std::filesystem::path {
        wchar_t buf[MAX_PATH * 4];
        const DWORD cap = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
        const DWORD n = GetEnvironmentVariableW(name, buf, cap);
        if (n == 0 || n >= cap) return {};
        return std::filesystem::path(std::wstring(buf, n));
    };
    std::filesystem::path root;
    const auto local = from_env(L"LOCALAPPDATA");
    if (!local.empty()) root = local / L"VIRULE";
    else {
        const auto profile = from_env(L"USERPROFILE");
        if (!profile.empty()) root = profile / L"AppData" / L"Local" / L"VIRULE";
    }
    if (root.empty()) return {};
    return root / L"security" / L"dev_machine.cred";
}

inline std::string read_credential_text(const std::filesystem::path& p) {
    if (p.empty()) return "";
    std::error_code ec;
    if (!std::filesystem::exists(p, ec) || ec) return "";
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

// The wrapper's one-call entry point: real file, real DPAPI, real RNG.
inline ProofResult prove_local_developer_machine(const std::string& build_public_key_hex) {
    const std::string text = read_credential_text(local_credential_path());
    return prove_developer_machine(text, build_public_key_hex,
                                   &dpapi_unprotect_win, &random_bytes_win);
}

} // namespace virule::core::dev_machine::proof
#endif // _WIN32
