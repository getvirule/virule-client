#pragma once
// THE CLIENT'S MACHINE PROOFS (owner brief 2026-11-02, "Client Security
// Authority Phase 2" sections 10 to 15; the service's half is
// VIRULE_BACKEND src/evaluations/machine_proof.ts, docs/EVALUATIONS.md
// "Machine proofs"; docs/ARCHITECTURE.md "Machine proofs").
//
// The routes only this Client's own drivers make (they are never relayed:
// shared/account_relay.hpp) carry a proof from this computer's Ed25519
// identity (dev_machine.cred), by a key the account PROVED it holds:
//
//   binding    evaluator  POST /v1/assignments/credential
//              developer  POST /v1/evaluations/machine
//              {machine_key, timestamp, machine_signature} over
//              virule-evaluator-bind.v1 | virule-developer-machine.v1
//                 |<API host>|<device id>|<machine key>|<timestamp>
//   request    x-virule-machine-key / -timestamp / -signature over
//              virule-evaluation-request.v1|<API host>|<device id>|<role>|<METHOD>|<path>|<sha256 hex of the body>|<timestamp>
//
// The API host and the device id are the existing QA-link convention
// (client/account.hpp account_link_qa): the host the request goes to (a
// staging proof is never a production one) and this installation's device
// authorization (one device of one account). Pure: no I/O; the signing and the
// sending are main.cpp AccountTransferService.

#include <string>

namespace vclient::machine_proof {

inline bool is_hex_id(const std::string& s) {
    if (s.size() != 32) return false;
    for (const char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

namespace detail {
// The path split into its segments after the family prefix; false if the
// path is not under `family`.
inline bool segments(const std::string& path, const std::string& family, std::string out[6], int& n) {
    n = 0;
    if (path.compare(0, family.size(), family) != 0) return false;
    size_t i = family.size();
    if (i == path.size()) return true;
    if (path[i] != '/') return false;
    while (i < path.size()) {
        if (path[i] != '/' || n == 6) return false;
        const size_t j = path.find('/', i + 1);
        const std::string seg = path.substr(i + 1, (j == std::string::npos ? path.size() : j) - i - 1);
        if (seg.empty()) return false;
        out[n++] = seg;
        if (j == std::string::npos) break;
        i = j;
    }
    return true;
}
} // namespace detail

/** The role whose machine proof a request needs: "evaluator", "developer",
 *  or "" for every other request. Mirrors the service's provenRoute. */
inline std::string role_of(const std::string& method, const std::string& path) {
    if (method != "POST") return "";
    std::string s[6];
    int n = 0;
    if (detail::segments(path, "/v1/assignments", s, n)) {
        if (n == 3 && is_hex_id(s[0]) && s[1] == "security" && s[2] == "incident") return "evaluator";
        if (n == 4 && is_hex_id(s[0]) && s[1] == "download" && is_hex_id(s[2]) && (s[3] == "complete" || s[3] == "failed")) return "evaluator";
        if (n == 2 && is_hex_id(s[0]) && (s[1] == "report" || s[1] == "early-completion")) return "evaluator";
        if (n == 3 && is_hex_id(s[0]) && s[1] == "evidence" && is_hex_id(s[2])) return "evaluator";
        return "";
    }
    if (detail::segments(path, "/v1/evaluations", s, n)) {
        if (n == 4 && s[0] == "games" && is_hex_id(s[1]) && s[2] == "security" && s[3] == "incident") return "developer";
        if (n == 3 && s[0] == "games" && is_hex_id(s[1]) && s[2] == "uploads") return "developer";
        if (n == 3 && s[0] == "uploads" && is_hex_id(s[1]) && s[2] == "complete") return "developer";
    }
    return "";
}

/** The role a `machine_not_bound` answer asks this Client to prove its key
 *  for: a proven route's, and the evaluator's runtime report (its existing
 *  proof needs a proved key too since 2026-11-02). */
inline std::string rebind_role(const std::string& method, const std::string& path) {
    const std::string role = role_of(method, path);
    if (!role.empty() || method != "POST") return role;
    std::string s[6];
    int n = 0;
    if (detail::segments(path, "/v1/assignments", s, n) && n == 2 && is_hex_id(s[0]) && s[1] == "runtime") return "evaluator";
    return "";
}

inline std::string bind_route(const std::string& role) {
    return role == "evaluator" ? "/v1/assignments/credential" : "/v1/evaluations/machine";
}

inline std::string bind_message(const std::string& role, const std::string& host, const std::string& device_id,
                                const std::string& machine_key, const std::string& timestamp) {
    return std::string(role == "evaluator" ? "virule-evaluator-bind.v1" : "virule-developer-machine.v1") + "|" + host + "|" +
           device_id + "|" + machine_key + "|" + timestamp;
}

inline std::string bind_body(const std::string& machine_key, const std::string& timestamp, const std::string& signature) {
    return "{\"machine_key\":\"" + machine_key + "\",\"timestamp\":\"" + timestamp + "\",\"machine_signature\":\"" + signature + "\"}";
}

inline std::string request_message(const std::string& host, const std::string& device_id, const std::string& role,
                                   const std::string& method, const std::string& path, const std::string& body_sha256,
                                   const std::string& timestamp) {
    return "virule-evaluation-request.v1|" + host + "|" + device_id + "|" + role + "|" + method + "|" + path + "|" + body_sha256 + "|" + timestamp;
}

/** The service's answer that the key is not one this account proved: the
 *  Client proves it (bind_route) and asks once more. */
inline bool not_bound(unsigned long status, const std::string& body) {
    return status == 401 && body.find("\"machine_not_bound\"") != std::string::npos;
}

} // namespace vclient::machine_proof
