#pragma once
// Native QA invitation redemption: the tester machine's half of the
// browser/native handshake, ported from the VIRULE product's
// qa_access_service::redeem_invite. The wire contract is the published
// /v1/qa/redeem contract (VIRULE_BACKEND docs/API_CONTRACT_V1.md):
//
//   message  virule-qa-redeem.v2|<token>|<timestamp>
//   body     { token, timestamp, developer_public_key, developer_signature }
//
// The proof presents THIS machine's identity (machine_identity.hpp over
// dev_machine.cred); the service performs the authoritative issuer check,
// binding/re-binding and sibling invalidation, and answers one state:
//   verified | issuer | claimed | expired | invalid
// On `verified` the response carries the service-signed native tester
// credential, which the caller verifies (qa_credential::signature_valid)
// before writing qa_tester.cred.

#include <string>

#include "shared/client_state.hpp"
#include "shared/http_client.hpp"
#include "shared/json_scan.hpp"
#include "shared/machine_identity.hpp"
#include "shared/protocol_reg.hpp"
#include "virule/core/launch_policy.hpp"
#include "virule/core/time.hpp"

namespace vclient::qa_service {

namespace lp = virule::core::launch_policy;

inline constexpr const wchar_t* kQaRedeemPathW = L"/v1/qa/redeem";

struct RedeemOutcome {
    std::string state;
    std::string organization_name;  // display label, may be empty
    std::string game_name;          // display label, may be empty
    // Filled when state == "verified":
    std::string organization_id;
    std::string tester_id;
    std::string machine_key;        // this machine's bound public key
    std::string bound_utc;          // the binding instant (service clock)
    std::string credential_signature; // service signature over the credential
};

// Redeem an invitation token AS THIS MACHINE. `test_identity` (Super Admin
// QA TEST MODE) presents an ephemeral throwaway key instead, so the
// authoring machine can exercise the full flow without the issuer answer
// and without touching its real identity. Returns false with plain product
// copy in error_out only for local/transport failures; service answers land
// in outcome.state.
inline bool redeem_invite(const std::string& token,
                          RedeemOutcome& outcome,
                          std::string& error_out,
                          bool test_identity = false) {
    namespace js = vclient::json_scan;
    outcome = RedeemOutcome{};
    error_out.clear();
    // 32-character Base64URL (current mint) or 64 lowercase hex (legacy).
    if (!protocol_reg::is_invite_token(token)) {
        outcome.state = "invalid";
        return true;
    }
    const std::string timestamp = virule::core::utc_timestamp_rfc3339();
    const std::string message = std::string("virule-qa-redeem.v2|") +
        token + "|" + timestamp;

    std::string public_key, signature;
    if (test_identity) {
        if (!machine_identity::ephemeral_sign_hex(message, public_key, signature)) {
            error_out = "A QA test identity could not be created.";
            return false;
        }
    } else {
        bool created = false;
        (void)machine_identity::ensure(created);
        // Uninstall provenance: only an identity THIS product created may
        // ever be removed by a full VIRULE uninstall.
        if (created) state::mark_created_dev_machine_cred();
        public_key = machine_identity::public_key_hex();
        if (!lp::is_public_key_hex(public_key)) {
            error_out = "This computer's VIRULE identity could not be created.";
            return false;
        }
        signature = machine_identity::sign_hex(message);
        if (!lp::is_signature_hex(signature)) {
            error_out = "This computer's VIRULE identity could not sign the request.";
            return false;
        }
    }

    const std::string body = std::string("{\"token\":\"") + token +
        "\",\"timestamp\":\"" + timestamp +
        "\",\"developer_public_key\":\"" + public_key +
        "\",\"developer_signature\":\"" + signature + "\"}";

    unsigned long status = 0;
    std::string response;
    if (!http::https_post_json(lp::kEmbargoApiHostW, kQaRedeemPathW, body, status, response)) {
        error_out = "QA verification couldn't be completed. Check your internet connection.";
        return false;
    }
    if (status != 200) {
        error_out = "QA verification couldn't be completed right now (status " +
            std::to_string(status) + ").";
        return false;
    }
    if (!js::find_string_in(response, 0, response.size(), "state", outcome.state) ||
        outcome.state.empty()) {
        error_out = "The QA verification answer couldn't be read.";
        return false;
    }
    (void)js::find_string_in(response, 0, response.size(), "organization_name", outcome.organization_name);
    (void)js::find_string_in(response, 0, response.size(), "game_name", outcome.game_name);
    if (outcome.state == "verified") {
        // The flat scanner finds the nested credential fields by key name;
        // every one of them is grammar-checked opaque hex / canonical UTC.
        if (!js::find_string_in(response, 0, response.size(), "organization_id", outcome.organization_id) ||
            !js::find_string_in(response, 0, response.size(), "tester_id", outcome.tester_id) ||
            !js::find_string_in(response, 0, response.size(), "machine_key", outcome.machine_key) ||
            !js::find_string_in(response, 0, response.size(), "bound_utc", outcome.bound_utc) ||
            !js::find_string_in(response, 0, response.size(), "credential_signature", outcome.credential_signature)) {
            error_out = "The QA credential couldn't be read.";
            return false;
        }
    }
    return true;
}

} // namespace vclient::qa_service
