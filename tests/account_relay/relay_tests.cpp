// The evaluation relay's grammar (shared/account_relay.hpp): which paths
// the Admin may have this installation call, how the request body is taken
// from the message, and what is handed back. Pure string work; no client,
// no network, no bridge port.

#include <cstdio>
#include <string>

#include "shared/account_relay.hpp"

namespace relay = vclient::account_relay;

static int g_pass = 0, g_fail = 0;
static void check(const char* name, bool ok) {
    if (ok) { ++g_pass; std::printf("ok   %s\n", name); }
    else { ++g_fail; std::printf("FAIL %s\n", name); }
}

int main() {
    // ---- paths: the two families and nothing else ----
    check("the developer view", relay::path_ok("/v1/evaluations"));
    check("a purchase", relay::path_ok("/v1/evaluations/purchases"));
    check("a game's build record", relay::path_ok("/v1/evaluations/games/0123456789abcdef0123456789abcdef/build"));
    check("the evaluator workspace", relay::path_ok("/v1/assignments"));
    check("an offer decision", relay::path_ok("/v1/assignments/offers/0123456789abcdef0123456789abcdef/accept"));
    check("account routes are refused", !relay::path_ok("/v1/account/me"));
    check("token routes are refused", !relay::path_ok("/v1/oauth/token"));
    check("another family sharing the prefix is refused", !relay::path_ok("/v1/evaluationsx"));
    check("a trailing slash is refused", !relay::path_ok("/v1/evaluations/"));
    check("an empty segment is refused", !relay::path_ok("/v1/evaluations//purchases"));
    check("a dot segment is refused", !relay::path_ok("/v1/evaluations/../account/me"));
    check("a query is refused", !relay::path_ok("/v1/evaluations?x=1"));
    check("a fragment is refused", !relay::path_ok("/v1/assignments#x"));
    check("an absolute URL is refused", !relay::path_ok("https://evil.example/v1/evaluations"));
    check("an encoded character is refused", !relay::path_ok("/v1/evaluations/%2e%2e"));
    check("five segments are refused", !relay::path_ok("/v1/assignments/a/b/c/d/e"));
    check("four segments are allowed", relay::path_ok("/v1/assignments/a/b/c/d"));
    check("the bare version is refused", !relay::path_ok("/v1"));

    // ---- the body: the message's last field, raw ----
    const std::string m1 = R"({"type":"account_api","method":"POST","path":"/v1/evaluations/purchases","body":{"quantity":2,"game":{"title":"A \"quoted\" } title","genres":["action"]}}})";
    check("the body is the raw JSON object", relay::body_of(m1) == R"({"quantity":2,"game":{"title":"A \"quoted\" } title","genres":["action"]}})");
    check("no body is an empty object", relay::body_of(R"({"type":"account_api","method":"POST","path":"/v1/assignments/offers/open"})") == "{}");
    check("a non-object body is an empty object", relay::body_of(R"({"type":"account_api","body":"x"})") == "{}");
    check("an empty body object passes", relay::body_of(R"({"type":"account_api","body":{}})") == "{}");

    // ---- answers ----
    check("an object body is handed back", relay::answer(200, " {\"a\":1}\r\n") == R"({"type":"account_api","status":200,"body":{"a":1}})");
    check("anything else is null", relay::answer(502, "<html>bad gateway</html>") == R"({"type":"account_api","status":502,"body":null})");
    check("an empty body is null", relay::answer(204, "") == R"({"type":"account_api","status":204,"body":null})");
    check("a failure names its reason", relay::failure("offline") == R"({"type":"account_api","status":0,"error":"offline"})");

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
