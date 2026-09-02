#pragma once
// Binary verification primitives: SHA-256 (BCrypt) and Authenticode
// (WinVerifyTrust). Verification is a first-class concept here by design:
// Virule-Setup verifies its embedded client payload before installing it,
// and any future downloaded package will go through the same two checks
// (hash pinned by a trusted channel + a valid Authenticode signature).

#include <filesystem>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#endif

namespace vclient::verify_binary {

// SHA-256 of a byte buffer as 64 lowercase hex, or "" on failure.
inline std::string sha256_hex(const unsigned char* data, size_t n) {
    std::string out;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return out;
    }
    BCRYPT_HASH_HANDLE h = nullptr;
    unsigned char digest[32];
    if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(h, const_cast<PUCHAR>(data), (ULONG)n, 0) == 0 &&
            BCryptFinishHash(h, digest, sizeof(digest), 0) == 0) {
            static const char* kHex = "0123456789abcdef";
            out.resize(64);
            for (size_t i = 0; i < 32; ++i) {
                out[i * 2 + 0] = kHex[(digest[i] >> 4) & 0xF];
                out[i * 2 + 1] = kHex[digest[i] & 0xF];
            }
        }
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

// Authenticode: does this file carry a valid, trusted signature?
// (WinVerifyTrust with the generic action verify policy; revocation checks
// follow system policy.)
inline bool authenticode_valid(const std::filesystem::path& file) {
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    const std::wstring w = file.wstring();
    file_info.pcwszFilePath = w.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file_info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;

    const LONG status = WinVerifyTrust(nullptr, &action, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);

    return status == ERROR_SUCCESS;
}

} // namespace vclient::verify_binary
