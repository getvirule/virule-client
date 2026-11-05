#pragma once
// THE EVALUATION RELAY'S GRAMMAR (client/account.hpp api_call): what the
// Admin may ask this installation to call on its behalf, and how the
// service's answer is handed back. Pure string work with no dependencies,
// so it is unit-tested on its own (tests/account_relay).
//
// The relay reaches EXACTLY the Admin's own requests of the two path
// families of the VIRULE API, /v1/evaluations and /v1/assignments
// (VIRULE_BACKEND docs/EVALUATIONS.md), with GET or POST (admin_route_ok).
// Everything else is refused before a token is touched.
//
// THE CLIENT'S OWN DRIVERS' ROUTES ARE NEVER RELAYED (owner decision
// 2026-11-02, "no lower-level bypass"): the evaluator credential for THIS
// machine's key, the signed runtime report, the security incidents, the
// download and its verified receipt, the upload sessions, the evidence
// packages, early completion and the report are made only by the Client's
// own code (client/transfers.hpp, runtime_report.hpp, evidence delivery),
// which is where their scan, verification and machine binding happen. A
// local program reaching this bridge cannot make them with the account's
// authorization instead.

#include <string>
#include <vector>

#include "shared/json_scan.hpp"

namespace vclient::account_relay {

/** /v1/evaluations or /v1/assignments, then at most four "/segment" parts
 *  of [A-Za-z0-9_-]. No query, no fragment, no dot segment, no other family. */
inline bool path_ok(const std::string& path) {
    static const std::string kFamilies[] = { "/v1/evaluations", "/v1/assignments" };
    const std::string* family = nullptr;
    for (const auto& f : kFamilies) {
        if (path.compare(0, f.size(), f) == 0) family = &f;
    }
    if (!family) return false;
    const std::string rest = path.substr(family->size());
    int segments = 0;
    size_t i = 0;
    while (i < rest.size()) {
        if (rest[i] != '/') return false;
        size_t j = i + 1;
        while (j < rest.size() && rest[j] != '/') {
            const char c = rest[j];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
                return false;
            }
            ++j;
        }
        if (j == i + 1 || ++segments > 4) return false;
        i = j;
    }
    return true;
}

/** The request body: the message's LAST field, `"body":{...}`, taken as raw
 *  JSON up to the message's own closing brace (the service validates it).
 *  "{}" when absent or not an object. */
inline std::string body_of(const std::string& message) {
    const size_t at = message.find("\"body\":");
    if (at == std::string::npos) return "{}";
    const size_t vb = at + 7;
    if (message.size() < vb + 3 || message[vb] != '{' || message.back() != '}' ||
        message[message.size() - 2] != '}') {
        return "{}";
    }
    return message.substr(vb, message.size() - 1 - vb);
}

/** THE ADMIN'S REQUESTS, AND ONLY THEM (owner decision 2026-11-02): the
 *  exact set the Admin UI makes (admin_ui src/ui/evaluations/evaluationState.ts,
 *  src/ui/assignments/assignmentState.ts, EvaluatorSupport.tsx). `path` has
 *  already passed path_ok. An id is 32 lowercase hex, as the service routes
 *  it (VIRULE_BACKEND src/evaluations/developer.ts, evaluator.ts). */
inline bool is_id(const std::string& s) {
    if (s.size() != 32) return false;
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

inline bool admin_route_ok(const std::string& method, const std::string& path) {
    std::vector<std::string> seg;
    for (size_t i = 1; i <= path.size();) {
        const size_t j = path.find('/', i);
        seg.push_back(path.substr(i, (j == std::string::npos ? path.size() : j) - i));
        if (j == std::string::npos) break;
        i = j + 1;
    }
    // seg[0] == "v1", seg[1] == the family.
    if (seg.size() < 2 || seg[0] != "v1") return false;
    const bool dev = seg[1] == "evaluations";
    const size_t n = seg.size() - 2;
    const auto at = [&](size_t k) -> const std::string& { return seg[k + 2]; };
    if (method == "GET") return n == 0;   // the developer view, the evaluator workspace
    if (method != "POST") return false;
    if (dev) {
        if (n == 1) return at(0) == "purchases" || at(0) == "seen";
        if (n == 2) return (at(0) == "games" && is_id(at(1))) || (is_id(at(0)) && at(1) == "rating");   // the profile; a rating
        if (n == 3) return at(0) == "games" && is_id(at(1)) && at(2) == "build";                       // the build record
        return false;
    }
    if (n == 1) return at(0) == "preferences" || at(0) == "support";
    // The evaluator's explicit Resume of an assignment ready to resume (owner
    // brief 2026-11-05): relayed only after this computer's own check
    // (client/account.hpp `api_call`, is_resume).
    if (n == 2) return (at(0) == "offers" && at(1) == "open") || (is_id(at(0)) && at(1) == "resume");
    if (n == 3) {
        return at(0) == "offers" && is_id(at(1)) &&
               (at(2) == "close" || at(2) == "accept" || at(2) == "reject" || at(2) == "decline");
    }
    return false;
}

/** One relay request as the Client reads it: the method, the path and (for
 *  a POST) the raw body. `ok` false = refused before a token is touched. */
struct Request {
    bool ok = false;
    std::string method;
    std::string path;
    std::string body;
};

inline Request parse(const std::string& message) {
    Request r;
    if (!json_scan::find_string_in(message, 0, message.size(), "method", r.method) ||
        !json_scan::find_string_in(message, 0, message.size(), "path", r.path) ||
        (r.method != "GET" && r.method != "POST") || !path_ok(r.path) || !admin_route_ok(r.method, r.path)) {
        return Request{};
    }
    if (r.method == "POST") r.body = body_of(message);
    r.ok = true;
    return r;
}

/** THE PURCHASE (owner decision 2026-11-02): the one request that buys
 *  evaluations, exactly as the service routes it (VIRULE_BACKEND
 *  src/evaluations/developer.ts, `rest === "/purchases"`, POST). Decided on
 *  the PARSED request, which is exactly what api_call would send, so no
 *  spelling of the message reaches the purchase without being recognized. */
inline bool is_purchase(const Request& r) {
    return r.ok && r.method == "POST" && r.path == "/v1/evaluations/purchases";
}

/** POST /v1/assignments/<id>/resume: the assignment id, else "". */
inline std::string resume_assignment(const Request& r) {
    static const std::string kPrefix = "/v1/assignments/";
    static const std::string kSuffix = "/resume";
    if (!r.ok || r.method != "POST" || r.path.size() != kPrefix.size() + 32 + kSuffix.size()) return "";
    if (r.path.compare(0, kPrefix.size(), kPrefix) != 0 || r.path.compare(kPrefix.size() + 32, kSuffix.size(), kSuffix) != 0) return "";
    const std::string id = r.path.substr(kPrefix.size(), 32);
    return is_id(id) ? id : "";
}

/** The service's body trimmed of surrounding whitespace when it is a JSON
 *  object, otherwise "null": nothing but an object is passed on. */
inline std::string object_or_null(const std::string& body) {
    const auto blank = [](char c) { return c == ' ' || c == '\n' || c == '\r' || c == '\t'; };
    size_t b = 0, e = body.size();
    while (b < e && blank(body[b])) ++b;
    while (e > b && blank(body[e - 1])) --e;
    if (e > b && body[b] == '{' && body[e - 1] == '}') return body.substr(b, e - b);
    return "null";
}

/** The relay's answer for an HTTP status and the service's body. */
inline std::string answer(unsigned long status, const std::string& body) {
    return "{\"type\":\"account_api\",\"status\":" + std::to_string(status) + ",\"body\":" + object_or_null(body) + "}";
}

/** The relay's answer when there was no HTTP answer at all. */
inline std::string failure(const char* error) {
    return std::string("{\"type\":\"account_api\",\"status\":0,\"error\":\"") + error + "\"}";
}

/** The relay's answer when THIS COMPUTER cannot buy an evaluation
 *  (shared/evaluation_purchase_readiness.hpp): nothing was sent, so there
 *  is no HTTP status; `reason` is the readiness code and `message` the
 *  sentence for the person. `message` is the owner's fixed copy, never
 *  caller input, and is quoted as JSON. */
inline std::string not_ready(const std::string& reason_json, const std::string& message_json) {
    return "{\"type\":\"account_api\",\"status\":0,\"error\":\"not_ready\",\"reason\":" + reason_json +
           ",\"message\":" + message_json + "}";
}

/** The relay's answer when THIS COMPUTER refuses to resume (its own scan
 *  refused the build a person cleared; client/account.hpp): `status` is the
 *  service's answer to the Client's own refusal report (0 when it could not
 *  be sent), `message` fixed copy, never caller input. */
inline std::string refused_here(unsigned long status, const std::string& message_json) {
    return "{\"type\":\"account_api\",\"status\":0,\"error\":\"refused_here\",\"reported\":" +
           std::string(status == 200 ? "true" : "false") + ",\"message\":" + message_json + "}";
}

/** The largest answer handed back (inside the bridge's local frame bound). */
inline constexpr size_t kMaxAnswerBytes = 59000;

} // namespace vclient::account_relay
