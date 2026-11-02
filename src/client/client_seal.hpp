#pragma once
// THE CLIENT'S LOCAL SEAL (owner brief 2026-11-02, "Client Security
// Authority Phase 2" sections 4, 6, 7 and 11; docs/ARCHITECTURE.md
// "Developer verification and the upload gate").
//
// The VIRULE Client keeps a few records that decide security-sensitive work:
// the verification of the exact package it may upload, and the security
// incidents it reports. They live in Client-owned storage
// (%LOCALAPPDATA%\VIRULE\client\...), never in the shared transfer job that
// the Admin host writes, and every one is SEALED: an HMAC-SHA256 under a
// random 32-byte key that only this Client creates and reads, kept under
// Windows DPAPI (user scope, entropy below) in client\seal.key. A record
// whose seal does not verify is not this Client's and is ignored, so a
// `scanned`/`clean` value written by another program, the Admin included,
// authorizes nothing.
//
// BOUNDARY (accepted for the MVP, brief section 16): DPAPI user scope means
// a program running as the same Windows user could in principle unprotect
// the key. Hardware-backed isolation is future work.

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "virule/core/dev_machine_proof.hpp"
#include "virule/core/evaluation_evidence.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

namespace vclient::client_seal {

namespace fs = std::filesystem;
namespace ee = virule::core::evaluation_evidence;

inline constexpr const char* kEntropy = "VIRULE.Client.Seal.v1";
inline constexpr const char* kSealMember = "seal";

inline fs::path client_dir(const fs::path& virule_root) { return virule_root / L"client"; }
inline fs::path key_path(const fs::path& virule_root) { return client_dir(virule_root) / L"seal.key"; }

namespace detail {

inline std::string hex(const unsigned char* d, size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; ++i) { out[i * 2] = kHex[(d[i] >> 4) & 0xF]; out[i * 2 + 1] = kHex[d[i] & 0xF]; }
    return out;
}

inline bool protect(const std::vector<unsigned char>& plain, std::vector<unsigned char>& out) {
    DATA_BLOB in{ static_cast<DWORD>(plain.size()), const_cast<BYTE*>(plain.data()) };
    DATA_BLOB ent{ static_cast<DWORD>(std::strlen(kEntropy)), reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy)) };
    DATA_BLOB enc{};
    if (!CryptProtectData(&in, L"virule-client-seal", &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &enc)) return false;
    out.assign(enc.pbData, enc.pbData + enc.cbData);
    LocalFree(enc.pbData);
    return true;
}

// The key, created once per data root (the Client's; a sandbox in tests).
inline bool load_key(const fs::path& virule_root, std::vector<unsigned char>& key) {
    static std::mutex m;
    static std::map<std::wstring, std::vector<unsigned char>> cache;   // per data root, this process
    std::lock_guard<std::mutex> lock(m);
    key.clear();
    const fs::path p = key_path(virule_root);
    if (const auto it = cache.find(p.wstring()); it != cache.end()) { key = it->second; return true; }
    std::error_code ec;
    if (fs::exists(p, ec)) {
        FILE* f = nullptr;
        if (_wfopen_s(&f, p.wstring().c_str(), L"rb") != 0 || !f) return false;
        std::vector<unsigned char> blob;
        unsigned char buf[4096];
        for (size_t n; (n = fread(buf, 1, sizeof(buf), f)) > 0;) blob.insert(blob.end(), buf, buf + n);
        fclose(f);
        if (virule::core::dev_machine::proof::dpapi_unprotect_win(blob, kEntropy, key) && key.size() == 32) {
            cache[p.wstring()] = key;
            return true;
        }
        // Unreadable (another Windows user's, damaged): a new key replaces
        // it. Every record sealed under the old one stops verifying, which
        // only means the Client verifies again (fail closed).
        key.clear();
    }
    std::vector<unsigned char> fresh(32);
    if (!virule::core::dev_machine::proof::random_bytes_win(fresh.data(), fresh.size())) return false;
    std::vector<unsigned char> blob;
    if (!protect(fresh, blob)) return false;
    fs::create_directories(p.parent_path(), ec);
    if (!ee::write_file_atomic(p, std::string(blob.begin(), blob.end()))) return false;
    key = std::move(fresh);
    cache[p.wstring()] = key;
    return true;
}

inline std::string hmac_hex(const std::vector<unsigned char>& key, const std::string& text) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return "";
    BCRYPT_HASH_HANDLE h = nullptr;
    unsigned char mac[32];
    bool okd = BCryptCreateHash(alg, &h, nullptr, 0, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0) == 0 &&
               BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())), static_cast<ULONG>(text.size()), 0) == 0 &&
               BCryptFinishHash(h, mac, sizeof(mac), 0) == 0;
    if (h) BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return okd ? hex(mac, sizeof(mac)) : std::string();
}

inline bool same(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char d = 0;
    for (size_t i = 0; i < a.size(); ++i) d |= static_cast<unsigned char>(a[i] ^ b[i]);
    return d == 0;
}

} // namespace detail

/** Write `body` (a JSON object's members, WITHOUT braces) sealed: the
 *  document is `{<body>,"seal":"<hmac of body>"}`. */
inline bool write_sealed(const fs::path& virule_root, const fs::path& p, const std::string& body) {
    std::vector<unsigned char> key;
    if (!detail::load_key(virule_root, key)) return false;
    const std::string mac = detail::hmac_hex(key, body);
    if (mac.empty()) return false;
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    return ee::write_file_atomic(p, "{" + body + ",\"" + kSealMember + "\":\"" + mac + "\"}\n");
}

/** The sealed document's body when its seal verifies under this Client's
 *  key; false for anything else (absent, malformed, another writer's). */
inline bool read_sealed(const fs::path& virule_root, const fs::path& p, std::string& body_out) {
    body_out.clear();
    const std::string text = ee::read_document(p);
    const std::string tail = std::string(",\"") + kSealMember + "\":\"";
    const size_t at = text.rfind(tail);
    if (text.size() < 2 || text.front() != '{' || at == std::string::npos) return false;
    const size_t mac_at = at + tail.size();
    if (text.size() < mac_at + 64 + 2) return false;
    const std::string mac = text.substr(mac_at, 64);
    std::string rest = text.substr(mac_at + 64);
    while (!rest.empty() && (rest.back() == '\n' || rest.back() == '\r' || rest.back() == ' ')) rest.pop_back();
    if (rest != "\"}") return false;
    const std::string body = text.substr(1, at - 1);
    std::vector<unsigned char> key;
    if (!detail::load_key(virule_root, key)) return false;
    const std::string want = detail::hmac_hex(key, body);
    if (want.empty() || !detail::same(want, mac)) return false;
    body_out = "{" + body + "}";
    return true;
}

} // namespace vclient::client_seal
