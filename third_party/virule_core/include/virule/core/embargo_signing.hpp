#pragma once
// Press Embargo signature verification: ONE shared, pure helper over the
// vendored Ed25519 (dev_machine_proof.hpp) and the launch-policy vocabulary,
// used by BOTH sides:
//   - the Admin, to sanity-check the certificate the service returns at
//     registration before embedding it in a build;
//   - the wrapper runtime, to verify certificates and permanent release
//     authorizations offline against the embedded VIRULE public key.
// Pure function of its inputs; no OS calls, so the test harness drives it
// directly with RFC 8032-style vectors.

#include <string>

#include "virule/core/dev_machine_proof.hpp"
#include "virule/core/launch_policy.hpp"

namespace virule::core::embargo_signing {

// True iff signature_hex (128 lowercase hex) is a valid detached Ed25519
// signature over the exact ASCII message under public_key_hex (64 lowercase
// hex). Any malformed input verifies false.
inline bool verify_hex_signature(const std::string& message,
                                 const std::string& signature_hex,
                                 const std::string& public_key_hex) {
    namespace pf = virule::core::dev_machine::proof;
    unsigned char pk[32];
    unsigned char sig[64];
    if (!pf::detail::hex_to_bytes(public_key_hex, pk, 32)) return false;
    if (!pf::detail::hex_to_bytes(signature_hex, sig, 64)) return false;
    return pf::detail::verify_detached(pk,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(), sig);
}

// The common case: verify against VIRULE's embedded Press Embargo key.
inline bool verify_virule_signature(const std::string& message, const std::string& signature_hex) {
    return verify_hex_signature(message, signature_hex,
        virule::core::launch_policy::kViruleEmbargoPublicKeyHex);
}

} // namespace virule::core::embargo_signing
