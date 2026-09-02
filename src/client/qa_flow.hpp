#pragma once
// The QA verification flow, as the VIRULE Client runs it. This is the
// Admin's run_qa_verify_mode ported onto the client: validate the token,
// redeem AS THIS MACHINE against /v1/qa/redeem, verify the service's
// signature over the returned credential, write qa_tester.cred, and hand
// the outcome to whoever owns the visible UX.
//
// BROWSER/NATIVE OWNERSHIP (the locked owner rule): while an invitation
// page is open the browser owns ALL visible verification UX and this runs
// silently. The final state is pushed to any page connected to this
// client's own bridge; if none is there, a running VIRULE Admin GUI
// session's bridge (port 47611) is asked to deliver it to its pages. Only
// when no page anywhere was open does the native result card appear.
//
// SUPER ADMIN QA TEST MODE (the Admin's machine-local flag file) is
// honored identically here: redeem with an ephemeral throwaway identity
// and write the isolated qa_tester_test.cred, so the authoring machine
// can exercise the client end to end without touching its real identity
// or the real credential store.

#include <mutex>
#include <string>

#include "client/bridge.hpp"
#include "client/result_card.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"
#include "shared/qa_credential.hpp"
#include "shared/qa_service.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace vclient::qa_flow {

// A duplicate ACCEPT for the same token inside a short window (a double
// click, a page retry, bridge + protocol racing) must not redeem twice.
inline bool debounce(const std::string& token) {
    static std::mutex mutex;
    static std::string last_token;
    static ULONGLONG last_tick = 0;
    std::lock_guard<std::mutex> lock(mutex);
    const ULONGLONG now = GetTickCount64();
    if (token == last_token && now - last_tick < 10000) return false;
    last_token = token;
    last_tick = now;
    return true;
}

inline bool qa_test_mode_enabled() {
    std::error_code ec;
    return std::filesystem::exists(paths::qa_test_mode_flag(), ec);
}

struct Outcome {
    bool success = false;
    std::string wire_state = "error"; // pushed to pages
    std::string primary;              // native card copy
    std::string secondary;
};

// Redeem and write. Pure worker: no UI, no sockets.
inline Outcome redeem_and_store(const std::string& token) {
    Outcome out;
    const bool test_mode = qa_test_mode_enabled();

    qa_service::RedeemOutcome outcome;
    std::string error;
    if (!qa_service::redeem_invite(token, outcome, error, test_mode)) {
        out.primary = "Something went wrong.";
        out.secondary = error.empty() ? "Try again." : error;
        out.wire_state = "error";
        log::client("qa: redemption failed: " + (error.empty() ? "unknown" : error));
        return out;
    }
    if (outcome.state == "verified") {
        qa_credential::Entry entry;
        entry.organization_id = outcome.organization_id;
        entry.tester_id = outcome.tester_id;
        entry.machine_key = outcome.machine_key;
        entry.bound_utc = outcome.bound_utc;
        entry.signature = outcome.credential_signature;
        entry.organization_name = outcome.organization_name;
        // Verify before writing: the credential must carry the VIRULE
        // service's signature (the wrapper re-checks this at launch, so a
        // credential failing here could never work anyway).
        if (!qa_credential::signature_valid(entry)) {
            out.primary = "Something went wrong.";
            out.secondary = "Try again.";
            out.wire_state = "error";
            log::client("qa: credential signature did not verify; nothing written");
            return out;
        }
        if (qa_credential::save(paths::security_dir(), entry,
                                test_mode ? qa_credential::kTestFileName
                                          : qa_credential::kFileName)) {
            out.success = true;
            out.primary = "You're all set.";
            out.wire_state = "verified";
            log::client(std::string("qa: credential written (") +
                        (test_mode ? "test mode" : "production") + ")");
        } else {
            out.primary = "Something went wrong.";
            out.secondary = "Try again.";
            out.wire_state = "error";
            log::client("qa: credential write failed");
        }
    } else if (outcome.state == "issuer") {
        out.primary = "This invite is for your QA tester.";
        out.secondary = "To test the QA panel yourself, turn on Developer Mode in this game's QA tool.";
        out.wire_state = "issuer";
    } else if (outcome.state == "claimed") {
        out.primary = "This invite is no longer active.";
        out.secondary = "Ask your contact for a new invite.";
        out.wire_state = "claimed";
    } else if (outcome.state == "expired") {
        out.primary = "This invite has expired.";
        out.secondary = "Ask your contact for a new invite.";
        out.wire_state = "expired";
    } else {
        out.primary = "This invite is no longer active.";
        out.secondary = "Ask your contact for a new invite.";
        out.wire_state = "invalid";
    }
    return out;
}

// Ask a running VIRULE Admin GUI session (its qa_bridge on 47611) to
// deliver the result to its pages. Returns whether a page was open there.
inline bool report_via_admin_bridge(const std::string& token, const std::string& state) {
    std::string response;
    const std::string request = "{\"type\":\"qa_result\",\"token\":\"" + token +
        "\",\"state\":\"" + state + "\"}";
    if (!bridge::loopback_roundtrip(47611, nullptr, "\"virule\"", request, response)) {
        return false;
    }
    if (response.find("\"qa_page_state\"") == std::string::npos) return false;
    return response.find("\"open\":true") != std::string::npos;
}

// The whole flow for one accepted token, including the ownership decision.
// `wait_grace_ms` gives a just-launched browser handoff a moment to
// (re)connect to this client's bridge before deciding no page is watching.
inline void run(const std::string& token, unsigned wait_grace_ms = 3000) {
    if (!debounce(token)) return;
    const Outcome out = redeem_and_store(token);

    bool page_open = false;
    const ULONGLONG deadline = GetTickCount64() + wait_grace_ms;
    for (;;) {
        if (bridge::any_page_open()) {
            page_open = bridge::broadcast_qa_result(token, out.wire_state);
            if (page_open) break;
        }
        if (GetTickCount64() >= deadline) break;
        Sleep(150);
    }
    if (!page_open) {
        page_open = report_via_admin_bridge(token, out.wire_state);
    }
    if (!page_open) {
        result_card::show(out.primary, out.success ? std::string() : out.secondary);
        result_card::wait_closed();
    }
}

} // namespace vclient::qa_flow
