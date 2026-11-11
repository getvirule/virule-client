// The evaluation relay's grammar (shared/account_relay.hpp): which paths
// the Admin may have this installation call, how the request body is taken
// from the message, and what is handed back. Pure string work; no client,
// no network, no bridge port.

#include <cstdio>
#include <string>

#include "shared/account_relay.hpp"
#include "shared/machine_proof.hpp"

namespace relay = vclient::account_relay;

static int g_pass = 0, g_fail = 0;
static void check(const std::string& name, bool ok) {
    if (ok) { ++g_pass; std::printf("ok   %s\n", name.c_str()); }
    else { ++g_fail; std::printf("FAIL %s\n", name.c_str()); }
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

    // ---- THE ADMIN'S REQUESTS AND ONLY THEM (owner decision 2026-11-02):
    // every request the Admin UI makes passes; every route of the Client's
    // own drivers (machine-bound credential, signed runtime report, security
    // incidents, download and receipt, upload sessions, evidence, report) is
    // refused before a token is touched ----
    {
        const std::string id = "0123456789abcdef0123456789abcdef", id2 = "fedcba9876543210fedcba9876543210";
        const auto ok = [](const char* method, const std::string& path) {
            return relay::parse(std::string("{\"type\":\"account_api\",\"method\":\"") + method + "\",\"path\":\"" + path + "\",\"body\":{}}").ok;
        };
        // The Admin's own (admin_ui evaluationState.ts, assignmentState.ts, EvaluatorSupport.tsx).
        check("admin: GET the developer view", ok("GET", "/v1/evaluations"));
        check("admin: GET the evaluator workspace", ok("GET", "/v1/assignments"));
        check("admin: a purchase", ok("POST", "/v1/evaluations/purchases"));
        check("admin: seen", ok("POST", "/v1/evaluations/seen"));
        check("admin: a game's profile", ok("POST", "/v1/evaluations/games/" + id));
        check("admin: a game's build record", ok("POST", "/v1/evaluations/games/" + id + "/build"));
        check("admin: a rating", ok("POST", "/v1/evaluations/" + id + "/rating"));
        check("admin: preferences", ok("POST", "/v1/assignments/preferences"));
        check("admin: support", ok("POST", "/v1/assignments/support"));
        check("admin: open offers", ok("POST", "/v1/assignments/offers/open"));
        for (const char* d : { "close", "accept", "reject", "decline" }) {
            check(std::string("admin: an offer ") + d, ok("POST", "/v1/assignments/offers/" + id + "/" + d));
        }
        // The Client's own drivers: never through the relay.
        check("driver: the machine-bound evaluator credential is refused", !ok("POST", "/v1/assignments/credential"));
        check("driver: the signed runtime report is refused", !ok("POST", "/v1/assignments/" + id + "/runtime"));
        check("driver: an evaluator security incident is refused", !ok("POST", "/v1/assignments/" + id + "/security/incident"));
        check("driver: a developer security incident is refused", !ok("POST", "/v1/evaluations/games/" + id + "/security/incident"));
        check("driver: a download authorization is refused", !ok("POST", "/v1/assignments/" + id + "/download"));
        check("driver: a download receipt is refused", !ok("POST", "/v1/assignments/" + id + "/download/" + id2 + "/complete"));
        check("driver: a download failure is refused", !ok("POST", "/v1/assignments/" + id + "/download/" + id2 + "/failed"));
        check("driver: a download read is refused", !ok("GET", "/v1/assignments/" + id + "/download/" + id2));
        check("driver: a launch ticket is refused", !ok("POST", "/v1/assignments/" + id + "/ticket"));
        check("driver: an upload session is refused", !ok("POST", "/v1/evaluations/games/" + id + "/uploads"));
        for (const char* u : { "renew", "complete", "abort" }) {
            check(std::string("driver: upload ") + u + " is refused", !ok("POST", "/v1/evaluations/uploads/" + id + "/" + u));
        }
        check("driver: an upload read is refused", !ok("GET", "/v1/evaluations/uploads/" + id));
        check("driver: an evidence package is refused", !ok("POST", "/v1/assignments/" + id + "/evidence/" + id2));
        check("driver: progress is refused", !ok("GET", "/v1/assignments/" + id + "/progress"));
        check("driver: early completion is refused", !ok("POST", "/v1/assignments/" + id + "/early-completion"));
        check("driver: the report is refused", !ok("POST", "/v1/assignments/" + id + "/report"));
        check("driver: game art is refused", !ok("GET", "/v1/evaluations/games/" + id + "/art"));
        // Shape: ids are the service's ids; GETs only of the two views.
        check("an id that is not 32 lowercase hex is refused", !ok("POST", "/v1/evaluations/games/ABCDEF") &&
              !ok("POST", "/v1/assignments/offers/open/accept"));
        check("a POST of a view is refused", !ok("POST", "/v1/assignments"));
        check("a GET of a decision is refused", !ok("GET", "/v1/evaluations/purchases"));
    }

    // ---- the purchase (owner decision 2026-11-02): recognized on the
    // PARSED request, exactly what api_call would send ----
    {
        const auto purchase = [](const std::string& m) { return relay::is_purchase(relay::parse(m)); };
        check("the purchase is the purchase", purchase(m1));
        check("a purchase with no body is the purchase",
              purchase(R"({"type":"account_api","method":"POST","path":"/v1/evaluations/purchases"})"));
        check("fields in another order are still the purchase",
              purchase(R"({"path":"/v1/evaluations/purchases","type":"account_api","method":"POST","body":{}})"));
        check("a GET of the same path is not (the service answers 405)",
              !purchase(R"({"type":"account_api","method":"GET","path":"/v1/evaluations/purchases"})"));
        check("another developer POST is not",
              !purchase(R"({"type":"account_api","method":"POST","path":"/v1/evaluations/seen","body":{}})"));
        check("an evaluator decision is not",
              !purchase(R"({"type":"account_api","method":"POST","path":"/v1/assignments/offers/0123456789abcdef0123456789abcdef/accept"})"));
        check("a refused path is never sent, so it is no purchase to miss",
              !relay::parse(R"({"type":"account_api","method":"POST","path":"/v1/evaluations/purchases/"})").ok &&
              !relay::parse(R"({"type":"account_api","method":"POST","path":"/v1/evaluations/purchases?x=1"})").ok &&
              !relay::parse(R"({"type":"account_api","method":"post","path":"/v1/evaluations/purchases"})").ok);
        // A "method" inside the body is read first only when the envelope has
        // none; whatever is read is what is sent, and is_purchase decides on it.
        const relay::Request odd = relay::parse(R"({"type":"account_api","path":"/v1/evaluations/purchases","body":{"method":"POST"}})");
        check("whatever method is read is the one sent and the one judged", odd.ok == relay::is_purchase(odd) || !odd.ok);
        check("a refusal names the reason and the sentence and is no HTTP status",
              relay::not_ready("\"defender_off\"", "\"x\"") ==
                  R"({"type":"account_api","status":0,"error":"not_ready","reason":"defender_off","message":"x"})");
    }

    // ---- THE MACHINE PROOF'S ROUTES (owner brief 2026-11-02; shared/machine_proof.hpp,
    // the service's machine_proof.ts provenRoute): exactly the Client's own
    // drivers' state changes are signed, and none of them is ever relayed.
    {
        namespace mp = vclient::machine_proof;
        const std::string A = "0123456789abcdef0123456789abcdef", D = "fedcba9876543210fedcba9876543210";
        const std::pair<std::string, std::string> proven[] = {
            { "/v1/assignments/" + A + "/security/incident", "evaluator" },
            { "/v1/assignments/" + A + "/security/refusal", "evaluator" },
            { "/v1/assignments/" + A + "/download/" + D + "/complete", "evaluator" },
            { "/v1/assignments/" + A + "/download/" + D + "/failed", "evaluator" },
            { "/v1/assignments/" + A + "/report", "evaluator" },
            { "/v1/assignments/" + A + "/early-completion", "evaluator" },
            { "/v1/assignments/" + A + "/evidence/" + D, "evaluator" },
            { "/v1/evaluations/games/" + A + "/security/incident", "developer" },
            { "/v1/evaluations/games/" + A + "/uploads", "developer" },
            { "/v1/evaluations/uploads/" + A + "/complete", "developer" },
        };
        for (const auto& [path, role] : proven) {
            check("proven as " + role + ": POST " + path.substr(0, 40) + "...", mp::role_of("POST", path) == role);
            check("never relayed: POST " + path.substr(0, 40) + "...", !relay::admin_route_ok("POST", path));
        }
        const std::string plain[] = {
            "/v1/evaluations/purchases", "/v1/evaluations/seen", "/v1/evaluations/games/" + A, "/v1/evaluations/games/" + A + "/build",
            "/v1/assignments/preferences", "/v1/assignments/offers/open", "/v1/assignments/" + A + "/download",
            "/v1/assignments/credential", "/v1/assignments/" + A + "/runtime", "/v1/evaluations/uploads/" + A + "/renew",
            "/v1/assignments/" + A + "/evidence/" + D + "/files/1.jpg",
        };
        for (const auto& path : plain) check("no request proof: POST " + path.substr(0, 44), mp::role_of("POST", path).empty());
        check("only POST is proven", mp::role_of("GET", "/v1/assignments/" + A + "/report").empty() &&
                                      mp::role_of("PUT", "/v1/assignments/" + A + "/evidence/" + D).empty());
        check("a malformed id is not a proven route", mp::role_of("POST", "/v1/assignments/xyz/report").empty() &&
                                                     mp::role_of("POST", "/v1/assignments/" + A + "/report/extra").empty());
        check("the request message is the service's", mp::request_message("h", "d", "evaluator", "POST", "/p", "s", "t") ==
                                                      "virule-evaluation-request.v1|h|d|evaluator|POST|/p|s|t");
        check("the bind messages are the service's",
              mp::bind_message("evaluator", "h", "d", "k", "t") == "virule-evaluator-bind.v1|h|d|k|t" &&
              mp::bind_message("developer", "h", "d", "k", "t") == "virule-developer-machine.v1|h|d|k|t");
        check("the runtime report re-proves its key as the evaluator; other plain routes never bind",
              mp::rebind_role("POST", "/v1/assignments/" + A + "/runtime") == "evaluator" &&
              mp::rebind_role("POST", "/v1/assignments/" + A + "/report") == "evaluator" &&
              mp::rebind_role("POST", "/v1/evaluations/purchases").empty() &&
              mp::rebind_role("GET", "/v1/assignments/" + A + "/runtime").empty());
        check("the refusal that asks for a binding is recognized",
              mp::not_bound(401, R"({"error":{"code":"machine_not_bound","message":"x"}})") &&
              !mp::not_bound(401, R"({"error":{"code":"not_authorized","message":"x"}})") && !mp::not_bound(400, "machine_not_bound"));
    }

    // ---- THE RESUME (owner brief 2026-11-05): relayed for the Admin; on its
    // success the Client verifies the cleared build again (client/account.hpp
    // on_resumed; owner decision 2026-11-05: no historical veto).
    {
        const std::string A = "0123456789abcdef0123456789abcdef";
        check("the Resume is an Admin route (POST only)", relay::admin_route_ok("POST", "/v1/assignments/" + A + "/resume") &&
              !relay::admin_route_ok("GET", "/v1/assignments/" + A + "/resume"));
        check("a malformed assignment id is not a Resume", !relay::admin_route_ok("POST", "/v1/assignments/xyz/resume"));
        const relay::Request q = relay::parse("{\"type\":\"account_api\",\"method\":\"POST\",\"path\":\"/v1/assignments/" + A + "/resume\",\"body\":{\"revision_id\":\"" + A + "\"}}");
        check("the Resume is recognized with its assignment (the gate runs on it)", q.ok && relay::resume_assignment(q) == A);
        const relay::Request other = relay::parse("{\"type\":\"account_api\",\"method\":\"POST\",\"path\":\"/v1/assignments/offers/open\"}");
        check("no other request is a Resume", other.ok && relay::resume_assignment(other).empty());
        check("the 0.9.24 local refusal's documented answer shape is unchanged (no longer produced)",
              relay::refused_here(200, "\"x\"") == R"({"type":"account_api","status":0,"error":"refused_here","reported":true,"message":"x"})");
        // THE ONE-TIME SECURITY END NOTICE (2026-11-05): the evaluator's OK.
        check("the security end acknowledgment is an Admin route (POST only, an assignment id)",
              relay::admin_route_ok("POST", "/v1/assignments/" + A + "/security/seen") &&
              !relay::admin_route_ok("GET", "/v1/assignments/" + A + "/security/seen") &&
              !relay::admin_route_ok("POST", "/v1/assignments/xyz/security/seen"));
        check("...and nothing else under security: the incident and the refusal stay the Client's own calls",
              !relay::admin_route_ok("POST", "/v1/assignments/" + A + "/security/incident") &&
              !relay::admin_route_ok("POST", "/v1/assignments/" + A + "/security/refusal"));
    }

    // ---- the evaluator's contractor payments (owner brief 2026-11-06) ----
    {
        const std::string I = "0123456789abcdef0123456789abcdef";
        const std::string F = "/v1/assignments/payments";
        check("payments: the view, older invoices, one invoice, its line pages and its document are GETs the Admin makes",
              relay::admin_route_ok("GET", F) && relay::admin_route_ok("GET", F + "/older/" + I) &&
              relay::admin_route_ok("GET", F + "/invoices/" + I) && relay::admin_route_ok("GET", F + "/invoices/" + I + "/document") &&
              relay::admin_route_ok("GET", F + "/invoices/" + I + "/1") && relay::admin_route_ok("GET", F + "/invoices/" + I + "/9999"));
        check("payments: the submission is the one POST", relay::admin_route_ok("POST", F + "/invoices/" + I + "/submit") &&
              !relay::admin_route_ok("GET", F + "/invoices/" + I + "/submit"));
        check("payments: nothing else is relayed (no write of an amount, no other GET)",
              !relay::admin_route_ok("POST", F) && !relay::admin_route_ok("POST", F + "/invoices/" + I) &&
              !relay::admin_route_ok("POST", F + "/invoices/" + I + "/document") && !relay::admin_route_ok("GET", F + "/entries") &&
              !relay::admin_route_ok("POST", F + "/entries") && !relay::admin_route_ok("GET", F + "/invoices") &&
              !relay::admin_route_ok("GET", F + "/older") && !relay::admin_route_ok("PUT", F));
        check("payments: malformed ids and pages are refused",
              !relay::admin_route_ok("GET", F + "/invoices/xyz") && !relay::admin_route_ok("GET", F + "/invoices/" + I + "/0") &&
              !relay::admin_route_ok("GET", F + "/invoices/" + I + "/10000") && !relay::admin_route_ok("GET", F + "/invoices/" + I + "/01") &&
              !relay::admin_route_ok("GET", F + "/older/ABCDEF0123456789abcdef0123456789") &&
              !relay::admin_route_ok("POST", F + "/invoices/" + I.substr(1) + "/submit"));
        check("payments: the paths pass the family grammar (four segments at most)",
              relay::path_ok(F + "/invoices/" + I + "/document") && !relay::path_ok(F + "/invoices/" + I + "/document/x"));
        check("payments: the developer family has no payments routes",
              !relay::admin_route_ok("GET", "/v1/evaluations/payments") && !relay::admin_route_ok("POST", "/v1/evaluations/payments/invoices/" + I + "/submit"));
        check("payments: the evaluator workspace GET is unchanged and other GETs stay refused",
              relay::admin_route_ok("GET", "/v1/assignments") && !relay::admin_route_ok("GET", "/v1/assignments/offers") &&
              !relay::admin_route_ok("GET", "/v1/assignments/" + I + "/ticket"));
        const relay::Request q = relay::parse("{\"type\":\"account_api\",\"method\":\"POST\",\"path\":\"" + F + "/invoices/" + I +
                                              "/submit\",\"body\":{\"version\":2,\"snapshot_sha256\":\"" + std::string(64, 'a') + "\"}}");
        check("payments: a submission parses with its body, and is neither a purchase nor a Resume",
              q.ok && q.body.find("\"version\":2") != std::string::npos && !relay::is_purchase(q) && relay::resume_assignment(q).empty());
    }

    // ---- STRIPE CHECKOUT AND THE FINANCIAL HOLD (owner brief 2026-11-10) ----
    {
        const std::string C = "0123456789abcdef0123456789abcdef";
        const std::string K = "/v1/evaluations/checkouts";
        check("checkout: creating one is a developer POST, read is a GET of one, cancel a POST of one",
              relay::admin_route_ok("POST", K) && relay::admin_route_ok("GET", K + "/" + C) && relay::admin_route_ok("POST", K + "/" + C + "/cancel"));
        check("checkout: nothing else of it is relayed",
              !relay::admin_route_ok("GET", K) && !relay::admin_route_ok("POST", K + "/" + C) && !relay::admin_route_ok("GET", K + "/" + C + "/cancel") &&
              !relay::admin_route_ok("POST", K + "/" + C + "/settle") && !relay::admin_route_ok("POST", K + "/" + C + "/paid") &&
              !relay::admin_route_ok("GET", K + "/xyz") && !relay::admin_route_ok("GET", K + "/" + C + "/x"));
        check("checkout: the evaluator family has no checkout routes",
              !relay::admin_route_ok("POST", "/v1/assignments/checkouts") && !relay::admin_route_ok("GET", "/v1/assignments/checkouts/" + C));
        check("checkout: the webhook and the return page are never relayed",
              !relay::path_ok("/v1/stripe/webhook") && !relay::path_ok("/v1/checkout/return"));
        const auto purchase = [](const std::string& m) { return relay::is_purchase(relay::parse(m)); };
        check("checkout: creating one is a PURCHASE (the readiness gate decides it first); reading or cancelling one is not",
              purchase(R"({"type":"account_api","method":"POST","path":"/v1/evaluations/checkouts","body":{}})") &&
              !purchase("{\"type\":\"account_api\",\"method\":\"GET\",\"path\":\"" + K + "/" + C + "\"}") &&
              !purchase("{\"type\":\"account_api\",\"method\":\"POST\",\"path\":\"" + K + "/" + C + "/cancel\",\"body\":{}}"));
        check("the OK of an evaluation a financial hold ended is relayed, nothing else of it",
              relay::admin_route_ok("POST", "/v1/assignments/" + C + "/ended/seen") && !relay::admin_route_ok("GET", "/v1/assignments/" + C + "/ended/seen") &&
              !relay::admin_route_ok("POST", "/v1/assignments/xyz/ended/seen") && !relay::admin_route_ok("POST", "/v1/assignments/" + C + "/ended"));
    }

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
