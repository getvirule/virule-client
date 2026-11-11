// Binary verification (shared/verify_binary.hpp; audit M-7, 2026-11-11).
// Built and run by tests\verify_binary\run_tests.bat. Starts NO client and
// writes nothing: the signed files are only READ.
//
//   1. The pure identity rule (common_name_matches): exactly one CN, equal
//      whole-value; a CN that merely contains or extends the name, a second
//      CN, an empty or absent name all fail.
//   2. The pure revocation decision (classify_trust_status): revoked fails,
//      "could not check" is its own outcome, anything else untrusted.
//   3. Real files: every signed VIRULE executable named on the command line
//      passes authenticode_valid AND signed_by(L"CN=Heath Michaels"), and
//      fails signed_by for a fragment of that name (the substring match this
//      replaced would have passed "CN=Heath"); this unsigned test executable
//      fails both.

#include <cstdio>
#include <string>
#include <vector>

#include "shared/verify_binary.hpp"

namespace vb = vclient::verify_binary;

static int g_pass = 0, g_fail = 0;
static void check(const char* what, bool ok) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    (ok ? g_pass : g_fail)++;
}

int main(int argc, char** argv) {
    // 1. The identity rule.
    const wchar_t* kSigner = L"CN=Heath Michaels";
    check("cn: the exact name matches", vb::common_name_matches({ L"Heath Michaels" }, kSigner));
    check("cn: the prefix-less expected form matches too", vb::common_name_matches({ L"Heath Michaels" }, L"Heath Michaels"));
    check("cn: a longer CN containing the name fails", !vb::common_name_matches({ L"Heath Michaels Evil" }, kSigner));
    check("cn: a CN that ends with the name fails", !vb::common_name_matches({ L"Not Heath Michaels" }, kSigner));
    check("cn: a fragment of the name fails", !vb::common_name_matches({ L"Heath" }, kSigner));
    check("cn: case differs, fails", !vb::common_name_matches({ L"heath michaels" }, kSigner));
    check("cn: two CNs (one of them right) fail", !vb::common_name_matches({ L"Someone Else", L"Heath Michaels" }, kSigner));
    check("cn: no CN fails", !vb::common_name_matches({}, kSigner));
    check("cn: an empty expected name never matches", !vb::common_name_matches({ L"" }, L"CN="));
    check("cn: a null expected name never matches", !vb::common_name_matches({ L"Heath Michaels" }, nullptr));

    // 2. The revocation decision.
    using TO = vb::TrustOutcome;
    check("trust: success is trusted", vb::classify_trust_status(ERROR_SUCCESS) == TO::trusted);
    check("trust: CERT_E_REVOKED is revoked", vb::classify_trust_status(CERT_E_REVOKED) == TO::revoked);
    check("trust: CRYPT_E_REVOKED is revoked", vb::classify_trust_status(CRYPT_E_REVOKED) == TO::revoked);
    check("trust: CERT_E_REVOCATION_FAILURE is unknown", vb::classify_trust_status(CERT_E_REVOCATION_FAILURE) == TO::revocation_unknown);
    check("trust: CRYPT_E_REVOCATION_OFFLINE is unknown", vb::classify_trust_status(CRYPT_E_REVOCATION_OFFLINE) == TO::revocation_unknown);
    check("trust: CRYPT_E_NO_REVOCATION_CHECK is unknown", vb::classify_trust_status(CRYPT_E_NO_REVOCATION_CHECK) == TO::revocation_unknown);
    check("trust: TRUST_E_NOSIGNATURE is untrusted", vb::classify_trust_status(TRUST_E_NOSIGNATURE) == TO::untrusted);
    check("trust: TRUST_E_BAD_DIGEST is untrusted", vb::classify_trust_status(TRUST_E_BAD_DIGEST) == TO::untrusted);
    check("trust: CERT_E_UNTRUSTEDROOT is untrusted", vb::classify_trust_status(CERT_E_UNTRUSTEDROOT) == TO::untrusted);

    // 3. Real files (read only).
    for (int i = 1; i < argc; ++i) {
        const std::filesystem::path p = argv[i];
        std::printf("file: %s\n", argv[i]);
        if (!std::filesystem::exists(p)) { check("  the signed file exists", false); continue; }
        const LONG strict = vb::winverifytrust_status(p, WTD_REVOKE_WHOLECHAIN, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT);
        std::printf("  whole-chain revocation pass: 0x%08lX\n", (unsigned long)strict);
        std::printf("  subject: %ls\n", vb::signer_subject(p).c_str());
        check("  authenticode_valid", vb::authenticode_valid(p));
        check("  signed_by CN=Heath Michaels", vb::signed_by(p, L"CN=Heath Michaels"));
        check("  NOT signed_by CN=Heath (a fragment)", !vb::signed_by(p, L"CN=Heath"));
        check("  NOT signed_by CN=Michaels (a fragment)", !vb::signed_by(p, L"CN=Michaels"));
    }
    if (argc < 2) std::printf("note: no signed file given; the real-file checks did not run\n");

    wchar_t self[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, self, (DWORD)(sizeof(self) / sizeof(self[0])));
    check("this unsigned executable is not authenticode_valid", !vb::authenticode_valid(self));
    check("this unsigned executable is not signed_by the VIRULE identity", !vb::signed_by(self, L"CN=Heath Michaels"));

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
