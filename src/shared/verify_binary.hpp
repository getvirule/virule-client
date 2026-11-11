#pragma once
// Binary verification primitives: SHA-256 (BCrypt), Authenticode
// (WinVerifyTrust) and the signer-identity check. Verification is a
// first-class concept here by design: Virule-Setup verifies every
// downloaded binary through the same three checks before installing it
// (hash pinned by the release manifest + a valid Authenticode signature +
// the expected VIRULE signing identity), and any future downloaded package
// goes through exactly the same gate.

#include <cstring>
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

// What one WinVerifyTrust answer means for the trust decision (audit M-7,
// 2026-11-11). Pure, so it is unit tested: tests\verify_binary.
enum class TrustOutcome {
    trusted,             // ERROR_SUCCESS
    revoked,             // a certificate in the chain is KNOWN revoked
    revocation_unknown,  // otherwise valid, but revocation could not be checked
    untrusted,           // anything else: no signature, bad signature, bad chain
};

inline TrustOutcome classify_trust_status(LONG status) {
    switch ((HRESULT)status) {
        case (HRESULT)ERROR_SUCCESS:
            return TrustOutcome::trusted;
        case CERT_E_REVOKED:
        case CRYPT_E_REVOKED:
            return TrustOutcome::revoked;
        case CERT_E_REVOCATION_FAILURE:
        case CRYPT_E_REVOCATION_OFFLINE:
        case CRYPT_E_NO_REVOCATION_CHECK:
            return TrustOutcome::revocation_unknown;
        default:
            return TrustOutcome::untrusted;
    }
}

// One WinVerifyTrust pass (generic verify action, no UI).
inline LONG winverifytrust_status(const std::filesystem::path& file,
                                  DWORD revocation_checks, DWORD provider_flags) {
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    const std::wstring w = file.wstring();
    file_info.pcwszFilePath = w.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = revocation_checks;
    data.dwProvFlags = provider_flags;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file_info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;

    const LONG status = WinVerifyTrust(nullptr, &action, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    return status;
}

// Authenticode: does this file carry a valid, trusted signature whose chain
// is not revoked?
//
// REVOCATION (audit M-7): the whole chain except the root is checked
// (WTD_REVOKE_WHOLECHAIN + WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT), online,
// with Windows' own revocation cache. A certificate KNOWN to be revoked
// fails. A revocation status that cannot be determined (offline, a
// responder down, nothing cached) does NOT by itself fail: the signature is
// then verified again without revocation and must still be fully valid. An
// offline computer therefore verifies exactly as before, a revoked VIRULE
// certificate is refused wherever its revocation is known, and the
// manifest's exact SHA-256 pin applies either way. Callers verify a file
// they have just downloaded, so the network is normally there.
inline bool authenticode_valid(const std::filesystem::path& file) {
    const LONG strict = winverifytrust_status(
        file, WTD_REVOKE_WHOLECHAIN, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT);
    switch (classify_trust_status(strict)) {
        case TrustOutcome::trusted:
            return true;
        case TrustOutcome::revocation_unknown:
            return winverifytrust_status(file, WTD_REVOKE_NONE, 0) == ERROR_SUCCESS;
        case TrustOutcome::revoked:
        case TrustOutcome::untrusted:
        default:
            return false;
    }
}

namespace detail {

// The file's Authenticode SIGNER certificate handed to `use`, or false when
// the file carries no readable embedded signature.
template <class Use>
inline bool with_signer_cert(const std::filesystem::path& file, Use&& use) {
    bool found = false;
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    const std::wstring w = file.wstring();
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, w.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr,
                          nullptr, &store, &msg, nullptr)) {
        return false;
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
                use(cert);
                found = true;
                CertFreeCertificateContext(cert);
            }
        }
    }
    if (msg) CryptMsgClose(msg);
    if (store) CertCloseStore(store, 0);
    return found;
}

} // namespace detail

// The X.500 subject string of the file's Authenticode SIGNER certificate
// (e.g. "CN=Heath Michaels, O=Heath Michaels, ..."), or L"" when the file
// carries no readable embedded signature. For logs; the identity decision
// is signed_by.
inline std::wstring signer_subject(const std::filesystem::path& file) {
    std::wstring out;
    detail::with_signer_cert(file, [&](PCCERT_CONTEXT cert) {
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
    });
    return out;
}

// Every Common Name (CN) attribute value in a certificate name, in order.
inline std::vector<std::wstring> common_names(const CERT_NAME_BLOB& name) {
    std::vector<std::wstring> out;
    CERT_NAME_INFO* info = nullptr;
    DWORD size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_NAME, name.pbData, name.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &info, &size) || !info) {
        return out;
    }
    for (DWORD i = 0; i < info->cRDN; ++i) {
        const CERT_RDN& rdn = info->rgRDN[i];
        for (DWORD j = 0; j < rdn.cRDNAttr; ++j) {
            const CERT_RDN_ATTR& attr = rdn.rgRDNAttr[j];
            if (!attr.pszObjId || std::strcmp(attr.pszObjId, szOID_COMMON_NAME) != 0) continue;
            const DWORD n = CertRDNValueToStrW(attr.dwValueType,
                const_cast<CERT_RDN_VALUE_BLOB*>(&attr.Value), nullptr, 0);
            std::wstring value;
            if (n > 1) {
                value.resize(n);
                CertRDNValueToStrW(attr.dwValueType,
                    const_cast<CERT_RDN_VALUE_BLOB*>(&attr.Value), value.data(), n);
                value.resize(n - 1); // drop the terminator
            }
            out.push_back(value);
        }
    }
    LocalFree(info);
    return out;
}

// The identity rule (audit M-7), pure so it is unit tested: the subject
// carries EXACTLY ONE Common Name and it equals the expected one, whole
// value, case-sensitive. `expected` is the seam's literal (launch_policy
// kExpectedSignerW, "CN=Heath Michaels"); its "CN=" prefix is optional
// here. A subject that merely CONTAINS the text (another CN, an O or OU
// carrying it, a longer CN) is not the VIRULE signer.
inline bool common_name_matches(const std::vector<std::wstring>& names,
                                const wchar_t* expected) {
    if (!expected) return false;
    std::wstring want = expected;
    if (want.rfind(L"CN=", 0) == 0) want.erase(0, 3);
    if (want.empty()) return false;
    return names.size() == 1 && names[0] == want;
}

// Is the file's Authenticode signer certificate the expected identity
// (common_name_matches over its subject)? Identity only; authenticode_valid
// remains the trust decision, and every caller requires both.
inline bool signed_by(const std::filesystem::path& file, const wchar_t* expected_signer) {
    bool match = false;
    detail::with_signer_cert(file, [&](PCCERT_CONTEXT cert) {
        match = common_name_matches(common_names(cert->pCertInfo->Subject), expected_signer);
    });
    return match;
}

} // namespace vclient::verify_binary
