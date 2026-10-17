#pragma once
// THE EVALUATION RELAY'S GRAMMAR (client/account.hpp api_call): what the
// Admin may ask this installation to call on its behalf, and how the
// service's answer is handed back. Pure string work with no dependencies,
// so it is unit-tested on its own (tests/account_relay).
//
// The relay reaches EXACTLY two path families of the VIRULE API,
// /v1/evaluations and /v1/assignments (VIRULE_BACKEND docs/EVALUATIONS.md),
// with GET or POST. Everything else is refused before a token is touched.

#include <string>

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
        (r.method != "GET" && r.method != "POST") || !path_ok(r.path)) {
        return Request{};
    }
    if (r.method == "POST") r.body = body_of(message);
    r.ok = true;
    return r;
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

/** The largest answer handed back (inside the bridge's local frame bound). */
inline constexpr size_t kMaxAnswerBytes = 59000;

} // namespace vclient::account_relay
