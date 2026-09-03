#pragma once
// Binary verification primitives: SHA-256 (BCrypt), Authenticode
// (WinVerifyTrust) and the signer-identity check. Verification is a
// first-class concept here by design: Virule-Setup verifies every
// downloaded binary through the same three checks before installing it
// (hash pinned by the release manifest + a valid Authenticode signature +
// the expected VIRULE signing identity), and any future downloaded package
// goes through exactly the same gate.

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
#include <wincrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
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

// The X.500 subject string of the file's Authenticode SIGNER certificate
// (e.g. "CN=Heath Michaels, O=Heath Michaels, ..."), or L"" when the file
// carries no readable embedded signature. Identity only; authenticode_valid
// remains the trust decision.
inline std::wstring signer_subject(const std::filesystem::path& file) {
    std::wstring out;
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    const std::wstring w = file.wstring();
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, w.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr,
                          nullptr, &store, &msg, nullptr)) {
        return out;
    }
    DWORD info_size = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &info_size) &&
        info_size > 0) {
        std::vector<unsigned char> buf(info_size);
        auto* info = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
        if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, info, &info_size)) {
            CERT_INFO want{};
            want.Issuer = info->Issuer;
            want.SerialNumber = info->SerialNumber;
            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, &want, nullptr);
            if (cert) {
                const DWORD n = CertNameToStrW(X509_ASN_ENCODING,
                    const_cast<CERT_NAME_BLOB*>(&cert->pCertInfo->Subject),
                    CERT_X500_NAME_STR, nullptr, 0);
                if (n > 1) {
                    out.resize(n);
                    CertNameToStrW(X509_ASN_ENCODING,
                        const_cast<CERT_NAME_BLOB*>(&cert->pCertInfo->Subject),
                        CERT_X500_NAME_STR, out.data(), n);
                    out.resize(n - 1); // drop the terminator
                }
                CertFreeCertificateContext(cert);
            }
        }
    }
    if (msg) CryptMsgClose(msg);
    if (store) CertCloseStore(store, 0);
    return out;
}

// Does the file's signer subject contain the expected identity fragment?
// Case-sensitive on purpose: the fragment is a literal from our own
// certificate ("CN=Heath Michaels"), not user input.
inline bool signed_by(const std::filesystem::path& file,
                      const wchar_t* expected_subject_fragment) {
    const std::wstring subject = signer_subject(file);
    if (subject.empty()) return false;
    return subject.find(expected_subject_fragment) != std::wstring::npos;
}

} // namespace vclient::verify_binary
