#pragma once
// DESKTOP SIGN-IN: the VIRULE Client is the one owner of persistent
// desktop authentication (VIRULE_BACKEND/docs/ACCOUNTS.md, "Desktop").
//
// THE FLOW (OAuth 2.0 authorization code + PKCE S256 + PAR + DPoP, per
// RFC 9700 / RFC 8252 / RFC 9126 / RFC 9449):
//   1. The Admin (through its host's local control connection) asks the
//      Client to sign in: {"type":"account_sign_in"}.
//   2. The Client makes a PKCE verifier, a state value and a one-shot
//      LOOPBACK listener on 127.0.0.1:<ephemeral port>, and pushes the
//      authorization request to the service (PAR) under a DPoP proof from
//      its device key. Only an opaque request_uri comes back.
//   3. The person's normal browser opens <site>/authorize?client_id=...
//      &request_uri=... . They sign in there (passkey or password) and
//      click Continue.
//   4. The service redirects the browser to the loopback listener with a
//      120-second single-use code, the state and the issuer. The listener
//      answers only GET /callback, only once, only with the state it made
//      (constant-time comparison), and then closes.
//   5. The Client redeems the code with the PKCE verifier and a DPoP proof
//      from the SAME device key, stores the rotating refresh token under
//      DPAPI (shared/account_store.hpp), and fetches the account and its
//      server-decided capabilities.
//   6. The Admin polls {"type":"account_status"} and reflects the account.
//
// ONE PENDING SIGN-IN, REOPENABLE (2026-10-19). While a sign-in waits on
// the browser, another account_sign_in starts NOTHING new: it opens the
// SAME pending sign-in page again (the same request_uri, the same loopback
// listener, the same PKCE pair), so a person who closed the tab, or whose
// browser opened behind VIRULE, can always get back to it, and two clicks
// can never make two competing authorizations. The page stays usable for
// the request's ten minutes (PAR); after that the flow ends ("timeout")
// and the next account_sign_in starts a fresh one. A sign-in that is
// exchanging its code reopens nothing. The authorize URL carries only the
// opaque request_uri, never a token or the verifier.
//
// WHAT NEVER LEAVES THIS PROCESS: the refresh token, the access token, the
// PKCE verifier and the device key. No bridge message returns any of them,
// and nothing here logs one. account_* messages are LOCAL-ONLY (no Origin):
// a web page can neither start a sign-in nor read the account.
//
// SESSIONS: the access token (10 minutes) lives in memory only; the refresh
// token rotates on every use and is persisted at once; a refresh the
// service refuses (revoked, reused, expired) signs this installation out.
// Network failure is NOT a sign-out: the last snapshot is kept, marked
// offline, and capabilities are re-confirmed on the next successful call.

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "shared/account_relay.hpp"
#include "shared/account_roles.hpp"
#include "shared/account_store.hpp"
#include "shared/environment.hpp"
#include "shared/http_client.hpp"
#include "shared/installed_capabilities.hpp"
#include "shared/json_scan.hpp"
#include "shared/logging.hpp"
#include "shared/machine_identity.hpp"
#include "shared/paths.hpp"
#include "shared/qa_credential.hpp"
#include "virule/core/dev_machine_proof.hpp"
#include "virule/core/launch_policy.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <bcrypt.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#endif

namespace vclient::account {

namespace dmp = virule::core::dev_machine::proof;
namespace store = vclient::account_store;

inline constexpr const char* kClientId = "virule-desktop";
inline constexpr unsigned long long kFlowTimeoutMs = 10ull * 60 * 1000;
inline constexpr long long kSnapshotFreshSeconds = 5 * 60;

// ------------------------------------------------------------ endpoints --
// Production and staging come from the environment seam: the API host
// (launch_policy kEmbargoApiHostW) and the site (kSiteUrlW). The ONE
// development seam, --account-endpoint=<http(s)://host:port>, points both at
// a local test service; it is how tools/account_flow_test.mjs drives this
// exact code against the real Worker.
struct Endpoint {
    std::wstring host;
    unsigned short port = 443;
    bool secure = true;
    std::string origin; // scheme://host[:port], for DPoP htu and the authorize URL
};

/** ASCII narrowing for hosts and URLs (every one here is ASCII by grammar). */
inline std::string narrow(const std::wstring& w) {
    std::string o;
    o.reserve(w.size());
    for (const wchar_t c : w) o += (c < 0x80) ? (char)c : '?';
    return o;
}
inline std::wstring widen(const std::string& s) {
    std::wstring o;
    o.reserve(s.size());
    for (const unsigned char c : s) o += (wchar_t)c;
    return o;
}

/** STAGING-BUILD-ONLY test seam (--account-browser=capture): sign-in talks
 *  to the REAL staging service but, instead of opening the default browser,
 *  surfaces the authorize URL in the status so a harness can play the
 *  browser (tools/account_live_staging_test.mjs). Ignored in production. */
inline bool& capture_browser() {
    static bool v = false;
    return v;
}
inline Endpoint& endpoint_override() {
    static Endpoint e;
    return e;
}
inline bool test_seam_active() {
    return !endpoint_override().host.empty() || (env::kStaging && capture_browser());
}

inline Endpoint api_endpoint() {
    if (!endpoint_override().host.empty()) return endpoint_override();
    namespace lp = virule::core::launch_policy;
    Endpoint e;
    e.host = lp::kEmbargoApiHostW;
    e.origin = std::string("https://") + lp::kEmbargoApiHost;
    return e;
}

/** The website origin the person signs in on (no trailing slash). */
inline std::string site_origin() {
    if (!endpoint_override().host.empty()) return endpoint_override().origin;
    std::wstring w = virule::core::launch_policy::kSiteUrlW;
    while (!w.empty() && w.back() == L'/') w.pop_back();
    return narrow(w);
}

inline bool set_endpoint_override(const std::wstring& url) {
    http::Url u;
    if (!http::parse_url(url, u)) return false;
    Endpoint e;
    e.host = u.host;
    e.port = u.port;
    e.secure = u.secure;
    const std::string host = narrow(u.host);
    e.origin = std::string(u.secure ? "https://" : "http://") + host +
        ((u.secure && u.port == 443) || (!u.secure && u.port == 80) ? "" : ":" + std::to_string(u.port));
    endpoint_override() = e;
    return true;
}

// --------------------------------------------------------------- crypto --

inline std::string b64url(const unsigned char* d, size_t n) {
    std::string s = machine_identity::b64_encode(d, n);
    for (char& c : s) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}
inline std::string b64url(const std::string& s) {
    return b64url(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

inline bool sha256(const std::string& in, unsigned char out[32]) {
    return BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(in.data())), (ULONG)in.size(), out, 32) == 0;
}

inline std::string random_b64url(size_t n) {
    std::vector<unsigned char> b(n);
    if (!dmp::random_bytes_win(b.data(), n)) return "";
    return b64url(b.data(), n);
}

/** Constant-time equality for the state value. */
inline bool same(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char d = 0;
    for (size_t i = 0; i < a.size(); ++i) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

/** RFC 9449 DPoP proof, EdDSA over the device key. `ath` = b64url(SHA-256(access token)). */
inline std::string dpop_proof(const store::DeviceKey& key, const char* method, const std::string& url,
                              const std::string& access_token = "") {
    const std::string x = b64url(key.pk, 32);
    const std::string header = std::string("{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"") + x + "\"}}";
    std::string payload = std::string("{\"jti\":\"") + random_b64url(16) + "\",\"htm\":\"" + method +
        "\",\"htu\":\"" + url + "\",\"iat\":" + std::to_string((long long)time(nullptr));
    if (!access_token.empty()) {
        unsigned char h[32];
        if (!sha256(access_token, h)) return "";
        payload += ",\"ath\":\"" + b64url(h, 32) + "\"";
    }
    payload += "}";
    const std::string signing_input = b64url(header) + "." + b64url(payload);
    unsigned char sig[64];
    dmp::detail::sign_detached(key.seed, key.pk,
        reinterpret_cast<const unsigned char*>(signing_input.data()), signing_input.size(), sig);
    return signing_input + "." + b64url(sig, 64);
}

inline std::string form_escape(const std::string& v) {
    static const char* kHex = "0123456789ABCDEF";
    std::string o;
    for (const unsigned char c : v) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') o += (char)c;
        else { o += '%'; o += kHex[c >> 4]; o += kHex[c & 15]; }
    }
    return o;
}

inline std::string url_decode(const std::string& v) {
    std::string o;
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i] == '+') o += ' ';
        else if (v[i] == '%' && i + 2 < v.size() && isxdigit((unsigned char)v[i + 1]) && isxdigit((unsigned char)v[i + 2])) {
            o += (char)std::stoi(v.substr(i + 1, 2), nullptr, 16);
            i += 2;
        } else o += v[i];
    }
    return o;
}

// ----------------------------------------------------------- the service --

struct Reply {
    unsigned long status = 0; // 0 = no HTTP answer (offline)
    std::string body;
};

inline Reply call(const wchar_t* method, const char* method_a, const std::string& path, const std::string& form_body,
                  const store::DeviceKey& key, const std::string& access_token = "", bool quick = false) {
    const Endpoint e = api_endpoint();
    const std::string url = e.origin + path;
    std::wstring headers;
    const std::string proof = dpop_proof(key, method_a, url, access_token);
    headers += L"DPoP: " + widen(proof) + L"\r\n";
    if (!access_token.empty()) headers += L"Authorization: DPoP " + widen(access_token) + L"\r\n";
    if (!form_body.empty()) {
        headers += (form_body[0] == '{') ? L"Content-Type: application/json\r\n" : L"Content-Type: application/x-www-form-urlencoded\r\n";
    }
    Reply r;
    http::Timeouts t;
    t.receive_ms = 20000;
    if (quick) t = http::Timeouts{ 3000, 3000, 3000, 5000 };
    (void)http::request(method, e.host.c_str(), e.port, e.secure, widen(path),
                        headers, form_body, 64 * 1024, r.status, r.body, t);
    return r;
}

// ---------------------------------------------------------------- state --

enum class Phase { idle, browser, exchanging };

struct State {
    std::mutex m;
    Phase phase = Phase::idle;
    bool loaded = false;
    bool signed_in = false;
    store::Session session;
    std::string access_token;
    unsigned long long access_expiry_tick = 0;
    bool offline = false;
    std::string last_error;          // short machine code, never a secret
    unsigned long long flow_id = 0;  // increments per sign-in attempt
    // The pending sign-in's authorize page while it waits on the browser
    // (opaque request_uri only), so account_sign_in can open it again.
    std::string authorize_url;
    // DEVELOPMENT SEAM ONLY: how many times the pending page was opened
    // again (reported only while a test seam is active).
    unsigned reopened = 0;
    // DEVELOPMENT SEAM ONLY (--account-endpoint): the authorize URL the
    // browser would have opened, surfaced so a harness can play the
    // browser. Never set, never reported, in a normal run.
    std::string test_authorize_url;
    // DEVELOPMENT SEAM ONLY: the account-settings URL the browser would have
    // opened (it carries a single-use link token, so it is reported only
    // while a test seam is active, never in a normal run).
    std::string test_settings_url;
};

inline State& st() {
    static State s;
    return s;
}

/** Serializes every token operation: two refreshes racing would present
 *  one refresh token twice, which the service treats as theft. */
inline std::mutex& token_mutex() {
    static std::mutex m;
    return m;
}

inline std::atomic<bool> g_cancel{ false };
inline std::atomic<bool> g_refreshing{ false };

inline void ensure_loaded_locked(State& s) {
    if (s.loaded) return;
    s.loaded = true;
    store::Session saved;
    if (store::load_session(saved)) {
        s.session = saved;
        s.signed_in = true;
    }
}

/** Forget the account on this installation: the session (refresh token,
 *  snapshot, any undelivered appearance change) AND the device key, so the
 *  next sign-in, whoever makes it, starts a new key and a new authorization
 *  (shared/account_store.hpp). Local game files and every other local
 *  record are untouched. */
inline void sign_out_locally(State& s, const char* reason) {
    s.signed_in = false;
    s.session = store::Session{};
    s.access_token.clear();
    s.access_expiry_tick = 0;
    s.offline = false;
    s.last_error = reason;
    store::clear_session();
    store::remove_device_key();
}

/** Apply a token response: persist the rotated refresh token FIRST. */
inline bool apply_tokens(State& s, const std::string& body) {
    std::string at, rt;
    long long expires = 0;
    if (!json_scan::find_string_in(body, 0, body.size(), "access_token", at) ||
        !json_scan::find_string_in(body, 0, body.size(), "refresh_token", rt)) {
        return false;
    }
    (void)json_scan::find_number_in(body, 0, body.size(), "expires_in", expires);
    s.session.refresh_token = rt;
    if (!store::save_session(s.session)) log::client("account: could not persist the rotated session");
    s.access_token = at;
    s.access_expiry_tick = GetTickCount64() + (unsigned long long)std::max<long long>(0, expires - 30) * 1000ull;
    return true;
}

/** Read the service's {"preferences":{"appearance":...,"version":N}} into
 *  the snapshot. `appearance` null = the account never chose one. */
inline bool apply_preferences(store::Session& x, const std::string& body) {
    const size_t at = body.find("\"preferences\":{");
    if (at == std::string::npos) return false;
    const size_t end = body.find('}', at);
    if (end == std::string::npos) return false;
    std::string a;
    long long v = 0;
    if (!json_scan::find_string_in(body, at, end, "appearance", a) || (a != "light" && a != "dark")) a.clear();
    (void)json_scan::find_number_in(body, at, end, "version", v);
    x.appearance = a;
    x.appearance_version = v;
    return true;
}

/** Read /v1/account/me into the snapshot. */
inline bool apply_me(State& s, const std::string& body) {
    store::Session& x = s.session;
    std::string email;
    if (!store::read_json_string(body, "email", email)) return false;
    x.email = email;
    (void)store::read_json_string(body, "display_name", x.display_name);
    (void)json_scan::find_string_in(body, 0, body.size(), "status", x.status);
    const size_t caps = body.find("\"capabilities\":{");
    if (caps != std::string::npos) {
        const size_t end = body.find('}', caps);
        (void)json_scan::find_string_in(body, caps, end, "developer", x.cap_developer);
        (void)json_scan::find_string_in(body, caps, end, "evaluator", x.cap_evaluator);
        (void)json_scan::find_string_in(body, caps, end, "qa_tester", x.cap_qa);
    }
    (void)json_scan::find_string_in(body, 0, body.size(), "device_id", x.device_id);
    (void)json_scan::find_string_in(body, 0, body.size(), "account_hint", x.account_hint);
    (void)apply_preferences(x, body);
    // The tester identities linked to this account: every 32-hex id in the
    // `qa_linked_testers` array (each tester identity is its own link).
    const size_t ql = body.find("\"qa_linked_testers\":[");
    if (ql != std::string::npos) {
        const size_t qe = body.find(']', ql);
        std::string ids;
        for (size_t i = body.find('"', ql + 20); qe != std::string::npos && i != std::string::npos && i < qe;
             i = body.find('"', i + 1)) {
            const size_t j = body.find('"', i + 1);
            if (j == std::string::npos || j > qe) break;
            const std::string id = body.substr(i + 1, j - i - 1);
            if (id.size() == 32 && id.find_first_not_of("0123456789abcdef") == std::string::npos)
                ids += (ids.empty() ? "" : ",") + id;
            i = j;
        }
        x.qa_linked = ids;
        x.qa_linked_known = true;
    }
    x.checked_epoch = (long long)time(nullptr);
    s.offline = false;
    s.last_error.clear();
    // THE ROLES THIS VIRULE KEEPS THROUGH SIGN-OUT (account_roles.hpp): what
    // the service just confirmed this account may exercise.
    const bool active = x.status == "active";
    roles::remember(active && x.cap_developer == "active", active && x.cap_evaluator == "active");
    return store::save_session(x);
}

/** Refresh the access token (caller holds token_mutex). */
inline bool refresh_locked(const store::DeviceKey& key) {
    std::string rt;
    {
        std::lock_guard<std::mutex> lock(st().m);
        if (!st().signed_in) return false;
        rt = st().session.refresh_token;
    }
    const Reply r = call(L"POST", "POST", "/v1/oauth/token",
        "grant_type=refresh_token&client_id=" + std::string(kClientId) + "&refresh_token=" + form_escape(rt), key);
    std::lock_guard<std::mutex> lock(st().m);
    if (r.status == 0 || r.status >= 500 || r.status == 429) {
        st().offline = true;
        return false;
    }
    if (r.status != 200 || !apply_tokens(st(), r.body)) {
        // The service refused the device authorization (revoked, reused,
        // expired, account recovered): this installation is signed out.
        log::client("account: the service ended this sign-in");
        sign_out_locally(st(), "signed_out_by_service");
        return false;
    }
    return true;
}

/** A usable access token (caller holds token_mutex), refreshing when needed. */
inline bool access_token_locked(const store::DeviceKey& key, std::string& at) {
    unsigned long long expiry = 0;
    {
        std::lock_guard<std::mutex> lock(st().m);
        if (!st().signed_in) return false;
        at = st().access_token;
        expiry = st().access_expiry_tick;
    }
    if (!at.empty() && GetTickCount64() < expiry) return true;
    if (!refresh_locked(key)) return false;
    std::lock_guard<std::mutex> lock(st().m);
    at = st().access_token;
    return !at.empty();
}

/**
 * DELIVER AN EXPLICIT APPEARANCE CHOICE (caller holds token_mutex). `live`:
 * the choice was just made, so it is sent as the newest intent (no base
 * version) and wins. Otherwise it is a change that could not be delivered
 * when it was made (offline) and is replayed AGAINST THE VERSION IT WAS MADE
 * ON: the service applies it only if nothing changed since, and otherwise
 * answers 409 with the preference in force, which this installation adopts.
 * A network failure keeps the change for the next contact.
 */
inline void deliver_appearance_locked(const store::DeviceKey& key, bool live) {
    std::string value;
    long long base = -1;
    {
        std::lock_guard<std::mutex> lock(st().m);
        if (!st().signed_in || st().session.pending_appearance.empty()) return;
        value = st().session.pending_appearance;
        base = st().session.pending_base;
    }
    std::string at;
    if (!access_token_locked(key, at)) return;
    const std::string body = std::string("{\"appearance\":\"") + value + "\"" +
        (live || base < 0 ? std::string() : ",\"base_version\":" + std::to_string(base)) + "}";
    Reply r = call(L"POST", "POST", "/v1/account/preferences", body, key, at);
    if (r.status == 401) {
        if (!refresh_locked(key)) return;
        { std::lock_guard<std::mutex> lock(st().m); at = st().access_token; }
        r = call(L"POST", "POST", "/v1/account/preferences", body, key, at);
    }
    std::lock_guard<std::mutex> lock(st().m);
    if (!st().signed_in) return;
    if (r.status == 0 || r.status >= 500 || r.status == 429) {
        st().offline = true;
        return;
    }
    store::Session& x = st().session;
    // 200: applied. 409: changed elsewhere since; adopt what is in force.
    // Anything else (400, an account the service refuses): drop the change.
    if (r.status == 200 || r.status == 409) (void)apply_preferences(x, r.body);
    if (x.pending_appearance == value) {
        x.pending_appearance.clear();
        x.pending_base = -1;
    }
    st().offline = false;
    if (!store::save_session(x)) log::client("account: could not persist the appearance");
}

/** DELIVER A PENDING INSTALL DEV TOOLS (account_roles.hpp): enroll the
 *  signed-in account as a developer at the service. Cleared once the
 *  service answered (200 enrolled, or 403: the account cannot be enrolled,
 *  e.g. Dev Tools access was turned off); kept for the next contact when
 *  it could not be reached. Caller holds token_mutex. `fresh_at`: the
 *  access token a sign-in just received (the account is not marked signed
 *  in until its roles are read). */
inline void deliver_enrollment_locked(const store::DeviceKey& key, const std::string& fresh_at = "") {
    if (!roles::load().pending_developer) return;
    std::string at = fresh_at;
    if (at.empty() && !access_token_locked(key, at)) return;
    Reply r = call(L"POST", "POST", "/v1/account/developer/enable", "{}", key, at);
    if (r.status == 401) {
        if (!refresh_locked(key)) return;
        { std::lock_guard<std::mutex> lock(st().m); at = st().access_token; }
        r = call(L"POST", "POST", "/v1/account/developer/enable", "{}", key, at);
    }
    if (r.status == 200) {
        roles::clear_developer_intent();
        log::client("account: Install Dev Tools enrolled the account as a developer");
    } else if (r.status == 403) {
        roles::clear_developer_intent();
        log::client("account: the service refused the developer enrollment (403)");
    }
}

/** Re-confirm the account, its capabilities and its preferences with the
 *  service, delivering any appearance change made while offline and any
 *  pending Install Dev Tools first. */
inline void confirm_now() {
    {
        std::lock_guard<std::mutex> lock(st().m);
        ensure_loaded_locked(st());
        if (!st().signed_in) return; // never make a device key while signed out
    }
    store::DeviceKey key;
    if (!store::device_key(key)) return;
    std::lock_guard<std::mutex> tl(token_mutex());
    deliver_appearance_locked(key, false);
    deliver_enrollment_locked(key);
    std::string at;
    if (!access_token_locked(key, at)) return;
    Reply r = call(L"GET", "GET", "/v1/account/me", "", key, at);
    if (r.status == 401) {
        if (!refresh_locked(key)) return;
        { std::lock_guard<std::mutex> lock(st().m); at = st().access_token; }
        r = call(L"GET", "GET", "/v1/account/me", "", key, at);
    }
    std::lock_guard<std::mutex> lock(st().m);
    if (r.status == 200) {
        if (!apply_me(st(), r.body)) st().last_error = "bad_answer";
    } else if (r.status == 0 || r.status >= 500 || r.status == 429) {
        st().offline = true;
    }
}

inline std::atomic<unsigned long long> g_last_confirm_tick{ 0 };

inline void confirm_async() {
    bool expected = false;
    if (!g_refreshing.compare_exchange_strong(expected, true)) return;
    g_last_confirm_tick.store(GetTickCount64());
    std::thread([] { confirm_now(); g_refreshing.store(false); }).detach();
}

/** At most one re-confirmation per window, however often it is asked for
 *  (the Admin asks on every window activation). */
inline void confirm_if_due(unsigned long long min_interval_ms) {
    const unsigned long long last = g_last_confirm_tick.load();
    if (last != 0 && GetTickCount64() - last < min_interval_ms) return;
    confirm_async();
}

// ----------------------------------------------------- loopback callback --

// The page the browser lands on at the end of a desktop sign-in. It wears
// the website's appearance: the authorize page appends `ui=light|dark` (its
// own resolved theme, which follows the signed-in account) to the redirect;
// without it the browser's own light/dark preference decides. `ui` is
// presentation only and never part of the authorization.
inline const char* kDonePage =
    "<!doctype html><html lang=\"en\" class=\"%THEME%\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<meta name=\"referrer\" content=\"no-referrer\"><title>VIRULE</title>"
    // THE VIRULE FAVICON, inline: the website's own favicon.svg (v1_mvp_site
    // public/favicon.svg, the yellow V), because the one-shot listener closes
    // the moment this page is sent and could never answer /favicon.ico.
    "<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'%3E"
    "%3Cpath fill='%23fbbf24' d='M219.389,447.842 L291.758,447.842 C306.013,447.842 315.693,440.535 320.816,425.912 L432.660,83.254 "
    "C433.756,79.964 434.304,77.592 434.304,76.127 C434.304,72.837 433.114,70.010 430.741,67.629 C428.359,65.256 425.532,64.065 422.243,64.065 "
    "L353.163,64.065 C346.944,64.065 342.104,65.436 338.634,68.177 C335.156,70.918 332.877,74.122 331.781,77.771 L255.574,319.003 "
    "L179.366,77.771 C178.270,74.122 175.983,70.918 172.513,68.177 C169.035,65.436 164.195,64.065 157.985,64.065 L88.905,64.065 "
    "C85.615,64.065 82.780,65.256 80.407,67.629 C78.025,70.010 76.843,72.837 76.843,76.127 C76.843,77.592 77.391,79.964 78.488,83.254 "
    "L190.332,425.912 C195.446,440.535 205.134,447.842 219.389,447.842 Z'/%3E%3C/svg%3E\">"
    "<style>"
    // Smoky Blue (STYLE_GUIDE 3.1-3.3), the website's page field,
    // primary ink and muted ink in each theme; the canonical 44px V mark
    // (17.2), identical in both.
    "html{color-scheme:dark;--bg:#10161c;--ink:#e9edf2;--muted:#aab3bf}"
    "html.l{color-scheme:light;--bg:#e2e8ee;--ink:#1a2330;--muted:#465466}"
    "@media (prefers-color-scheme:light){html:not(.d){color-scheme:light;--bg:#e2e8ee;--ink:#1a2330;--muted:#465466}}"
    "html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);font-family:'Segoe UI',system-ui,sans-serif}"
    "main{min-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px;padding:24px;text-align:center}"
    ".m{width:44px;height:44px;border-radius:6px;background:#fbbf24;color:#0f0e0a;display:flex;align-items:center;justify-content:center;font:700 24px 'Segoe UI',sans-serif}"
    "h1{margin:0;font-size:20px;font-weight:600}p{margin:0;color:var(--muted);font-size:14px;line-height:1.6}"
    "</style></head><body><main><div class=\"m\" aria-hidden=\"true\">V</div><h1>%TITLE%</h1><p>%BODY%</p></main></body></html>";

inline std::string done_page(const char* title, const char* body, const std::string& ui = "") {
    std::string s = kDonePage;
    s.replace(s.find("%THEME%"), 7, ui == "light" ? "l" : ui == "dark" ? "d" : "");
    s.replace(s.find("%TITLE%"), 7, title);
    s.replace(s.find("%BODY%"), 6, body);
    return s;
}

struct Callback {
    bool ok = false;
    std::string code, state, iss, error;
    std::string ui; // presentation only: the website's light / dark
};

inline void http_reply(SOCKET c, int status, const std::string& html) {
    const std::string head = "HTTP/1.1 " + std::to_string(status) + (status == 200 ? " OK" : " Not Found") +
        "\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n"
        "X-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:\r\n"
        "Connection: close\r\nContent-Length: " + std::to_string(html.size()) + "\r\n\r\n";
    const std::string all = head + html;
    (void)send(c, all.data(), (int)all.size(), 0);
}

/** Bind the one-shot listener: 127.0.0.1 ONLY, ephemeral port. */
inline SOCKET open_listener(unsigned short& port_out) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return INVALID_SOCKET;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    BOOL excl = TRUE;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&excl, sizeof(excl));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    int len = sizeof(a);
    if (bind(s, (sockaddr*)&a, sizeof(a)) != 0 || listen(s, 4) != 0 || getsockname(s, (sockaddr*)&a, &len) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    port_out = ntohs(a.sin_port);
    return s;
}

/** Wait for GET /callback carrying our state. Anything else is refused and
 *  ignored; the wait ends on success, explicit denial, cancel or timeout. */
inline Callback wait_callback(SOCKET listener, const std::string& expected_state) {
    Callback cb;
    const unsigned long long deadline = GetTickCount64() + kFlowTimeoutMs;
    while (!g_cancel.load() && GetTickCount64() < deadline) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listener, &fds);
        timeval tv{ 0, 250000 };
        if (select(0, &fds, nullptr, nullptr, &tv) <= 0) continue;
        SOCKET c = accept(listener, nullptr, nullptr);
        if (c == INVALID_SOCKET) continue;
        DWORD to = 5000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
        std::string req;
        char buf[1024];
        while (req.find("\r\n\r\n") == std::string::npos && req.size() < 8192) {
            const int r = recv(c, buf, sizeof(buf), 0);
            if (r <= 0) break;
            req.append(buf, (size_t)r);
        }
        const size_t sp1 = req.find(' ');
        const size_t sp2 = sp1 == std::string::npos ? std::string::npos : req.find(' ', sp1 + 1);
        const std::string method = sp1 == std::string::npos ? "" : req.substr(0, sp1);
        const std::string target = sp2 == std::string::npos ? "" : req.substr(sp1 + 1, sp2 - sp1 - 1);
        if (method != "GET" || target.rfind("/callback?", 0) != 0) {
            http_reply(c, 404, "");
            closesocket(c);
            continue;
        }
        Callback got;
        const std::string query = target.substr(10);
        size_t p = 0;
        while (p <= query.size()) {
            size_t amp = query.find('&', p);
            if (amp == std::string::npos) amp = query.size();
            const std::string kv = query.substr(p, amp - p);
            const size_t eq = kv.find('=');
            if (eq != std::string::npos) {
                const std::string k = kv.substr(0, eq), v = url_decode(kv.substr(eq + 1));
                if (k == "code") got.code = v;
                else if (k == "state") got.state = v;
                else if (k == "iss") got.iss = v;
                else if (k == "error") got.error = v;
                else if (k == "ui" && (v == "light" || v == "dark")) got.ui = v;
            }
            p = amp + 1;
        }
        if (!same(got.state, expected_state)) {
            // Not our transaction (a stale tab, a forged link): refuse it and
            // keep waiting for the real one.
            http_reply(c, 404, done_page("This sign-in link isn't valid", "Go back to VIRULE and choose Sign In again.", got.ui));
            closesocket(c);
            continue;
        }
        if (!got.error.empty()) {
            http_reply(c, 200, done_page("Sign-in cancelled", "VIRULE was not signed in. You can close this tab.", got.ui));
            closesocket(c);
            got.ok = false;
            return got;
        }
        // RFC 9207: the issuer must be the service this build talks to.
        if (got.iss != site_origin() || got.code.size() != 43) {
            http_reply(c, 404, done_page("This sign-in link isn't valid", "Go back to VIRULE and choose Sign In again.", got.ui));
            closesocket(c);
            continue;
        }
        http_reply(c, 200, done_page("You are signed into the VIRULE app", "Close this tab and return to the app.", got.ui));
        closesocket(c);
        got.ok = true;
        return got;
    }
    cb.error = g_cancel.load() ? "cancelled" : "timeout";
    return cb;
}

// ------------------------------------------------------------- the flow --

inline std::string device_name() {
    wchar_t buf[64];
    DWORD n = 64;
    std::string out = "Windows PC";
    if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf, &n) && n > 0) {
        std::string s;
        for (DWORD i = 0; i < n; ++i) {
            const wchar_t c = buf[i];
            if ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'-') s += (char)c;
        }
        if (!s.empty()) out = s;
    }
    return out;
}

inline void finish_flow(unsigned long long id, const char* error) {
    std::lock_guard<std::mutex> lock(st().m);
    if (st().flow_id != id) return;
    st().phase = Phase::idle;
    st().last_error = error;
    st().test_authorize_url.clear();
    st().authorize_url.clear();
}

inline void run_flow(unsigned long long id) {
    store::DeviceKey key;
    if (!store::device_key(key)) { finish_flow(id, "device_key"); return; }

    const std::string verifier = random_b64url(32);
    const std::string state = random_b64url(24);
    unsigned char h[32];
    if (verifier.empty() || state.empty() || !sha256(verifier, h)) { finish_flow(id, "entropy"); return; }
    const std::string challenge = b64url(h, 32);

    unsigned short port = 0;
    SOCKET listener = open_listener(port);
    if (listener == INVALID_SOCKET) { finish_flow(id, "listener"); return; }
    const std::string redirect = "http://127.0.0.1:" + std::to_string(port) + "/callback";

    const std::string machine_key = machine_identity::public_key_hex();
    const Reply par = call(L"POST", "POST", "/v1/oauth/par",
        "client_id=" + std::string(kClientId) + "&response_type=code&redirect_uri=" + form_escape(redirect) +
        "&code_challenge=" + challenge + "&code_challenge_method=S256&state=" + state +
        "&device_name=" + form_escape(device_name()) + (machine_key.empty() ? "" : "&machine_key=" + machine_key), key);
    std::string request_uri;
    if (par.status != 201 || !json_scan::find_string_in(par.body, 0, par.body.size(), "request_uri", request_uri)) {
        closesocket(listener);
        finish_flow(id, par.status == 0 ? "offline" : "service");
        return;
    }

    const std::string url = site_origin() + "/authorize/?client_id=" + kClientId + "&request_uri=" + form_escape(request_uri);
    {
        std::lock_guard<std::mutex> lock(st().m);
        if (st().flow_id == id && st().phase == Phase::browser) st().authorize_url = url;
    }
    if (test_seam_active()) {
        // Test seam: a harness plays the browser.
        std::lock_guard<std::mutex> lock(st().m);
        st().test_authorize_url = url;
    } else {
        const std::wstring wurl = widen(url);
        if ((INT_PTR)ShellExecuteW(nullptr, L"open", wurl.c_str(), nullptr, nullptr, SW_SHOWNORMAL) <= 32) {
            closesocket(listener);
            finish_flow(id, "browser");
            return;
        }
    }
    log::client("account: sign-in opened in the browser");

    const Callback cb = wait_callback(listener, state);
    closesocket(listener);
    if (!cb.ok) { finish_flow(id, cb.error.empty() ? "denied" : cb.error.c_str()); return; }

    {
        std::lock_guard<std::mutex> lock(st().m);
        if (st().flow_id == id) { st().phase = Phase::exchanging; st().authorize_url.clear(); }
    }
    std::lock_guard<std::mutex> tl(token_mutex());
    const Reply tok = call(L"POST", "POST", "/v1/oauth/token",
        "grant_type=authorization_code&client_id=" + std::string(kClientId) + "&code=" + form_escape(cb.code) +
        "&code_verifier=" + verifier + "&redirect_uri=" + form_escape(redirect), key);
    {
        std::lock_guard<std::mutex> lock(st().m);
        if (tok.status != 200) {
            st().phase = Phase::idle;
            st().last_error = tok.status == 0 ? "offline" : "service";
            return;
        }
        st().session = store::Session{};
        if (!apply_tokens(st(), tok.body)) { st().phase = Phase::idle; st().last_error = "bad_answer"; return; }
        st().loaded = true;
        // signed_in flips only once the account is known (below), so the
        // Admin never shows a signed-in state with no identity in it.
    }
    std::string at;
    { std::lock_guard<std::mutex> lock(st().m); at = st().access_token; }
    // An Install Dev Tools made while signed out goes to THIS account now,
    // before its roles are read (account_roles.hpp).
    deliver_enrollment_locked(key, at);
    const Reply me = call(L"GET", "GET", "/v1/account/me", "", key, at);
    std::lock_guard<std::mutex> lock(st().m);
    if (me.status == 200) (void)apply_me(st(), me.body);
    else st().offline = true;
    // Signed in either way: the authorization exists and is persisted; an
    // unanswered /me is re-confirmed on the next status read (stale snapshot).
    st().signed_in = true;
    st().phase = Phase::idle;
    log::client("account: signed in");
}

// ------------------------------------------------------ bridge surface --

/** Whether THIS installation holds a QA tester credential, bound to this
 *  machine (the only kind link_qa can prove), that is not yet linked to the
 *  signed-in account. Each tester identity is its own link
 *  (VIRULE_BACKEND docs/ACCOUNTS.md, the QA link), so a second game's or
 *  organization's credential is offered even once the account holds the
 *  qa_tester capability. A session saved before the linked list was kept
 *  falls back to the capability alone until /me answers. */
inline bool qa_link_offered(const store::Session& s) {
    if (!s.qa_linked_known && s.cap_qa == "active") return false;
    const std::string me = machine_identity::public_key_hex();
    const std::string linked = "," + s.qa_linked + ",";
    for (const auto& e : qa_credential::load(paths::security_dir())) {
        if (e.tester_id.size() != 32 || e.machine_key != me || e.signature.size() != 128) continue;
        if (linked.find("," + e.tester_id + ",") == std::string::npos) return true;
    }
    return false;
}



inline std::string cap(const std::string& v) { return v.empty() ? "none" : v; }

inline bool is_hex32(const std::string& v) {
    if (v.size() != 32) return false;
    for (const char c : v) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

/**
 * {"type":"account_open_settings"}: Account Settings in the Admin. Opens the
 * website account page in the person's browser FOR THIS ACCOUNT:
 * `<site>/account/?for=<account hint>#h=<link token>`. The link token is
 * minted here with this installation's DPoP authorization (POST
 * /v1/account/web-link: single use, two minutes) and goes straight to the
 * browser in the URL FRAGMENT (never sent to a server, never in a Referer);
 * no bridge answer carries it. The website signs that browser in to this
 * account only after an explicit click naming it, and a browser signed in to
 * another account is told so instead of showing it. Without a link (signed
 * out, offline) the plain page opens, still with the hint when known.
 */
inline std::string open_settings() {
    std::string url = site_origin() + "/account/";
    std::string hint;
    bool signed_in = false;
    {
        std::lock_guard<std::mutex> lock(st().m);
        ensure_loaded_locked(st());
        signed_in = st().signed_in;
        if (signed_in && is_hex32(st().session.account_hint)) hint = st().session.account_hint;
    }
    std::string token;
    if (signed_in) {
        store::DeviceKey key;
        if (store::device_key(key)) {
            std::lock_guard<std::mutex> tl(token_mutex());
            std::string at;
            if (access_token_locked(key, at)) {
                Reply r = call(L"POST", "POST", "/v1/account/web-link", "", key, at);
                if (r.status == 401 && refresh_locked(key)) {
                    { std::lock_guard<std::mutex> lock(st().m); at = st().access_token; }
                    r = call(L"POST", "POST", "/v1/account/web-link", "", key, at);
                }
                std::string t;
                if (r.status == 201 && json_scan::find_string_in(r.body, 0, r.body.size(), "token", t) && t.size() == 43) token = t;
            }
        }
    }
    if (!hint.empty()) url += "?for=" + hint;
    if (!token.empty()) url += "#h=" + token;
    if (test_seam_active()) {
        std::lock_guard<std::mutex> lock(st().m);
        st().test_settings_url = url;
    } else {
        const std::wstring wurl = widen(url);
        if ((INT_PTR)ShellExecuteW(nullptr, L"open", wurl.c_str(), nullptr, nullptr, SW_SHOWNORMAL) <= 32) {
            return "{\"type\":\"account_open_settings\",\"ok\":false}";
        }
    }
    log::client(token.empty() ? "account: settings opened without a link" : "account: settings opened with a link");
    return "{\"type\":\"account_open_settings\",\"ok\":true}";
}

/** {"type":"account_status",...}: what the Admin shows. Never a token. */
inline std::string status_json() {
    bool stale = false;
    bool pending = false;
    std::string out;
    {
        std::lock_guard<std::mutex> lock(st().m);
        ensure_loaded_locked(st());
        State& s = st();
        const char* phase = s.phase == Phase::idle ? "idle" : s.phase == Phase::browser ? "browser" : "exchanging";
        out = std::string("{\"type\":\"account_status\",\"signed_in\":") + (s.signed_in ? "true" : "false") +
            ",\"phase\":\"" + phase + "\",\"offline\":" + (s.offline ? "true" : "false") +
            ",\"error\":\"" + s.last_error + "\"";
        if (test_seam_active() && s.phase == Phase::browser && !s.test_authorize_url.empty()) {
            out += ",\"test_authorize_url\":\"" + s.test_authorize_url + "\"";
        }
        if (test_seam_active()) out += ",\"test_reopened\":" + std::to_string(s.reopened);
        if (test_seam_active() && !s.test_settings_url.empty()) {
            out += ",\"test_settings_url\":\"" + s.test_settings_url + "\"";
        }
        if (s.signed_in) {
            const bool active = s.session.status == "active";
            auto eff = [&](const std::string& c) { return active && c == "active"; };
            out += ",\"account\":{\"email\":\"" + json_scan::json_escape(s.session.email) +
                "\",\"display_name\":\"" + json_scan::json_escape(s.session.display_name) +
                "\",\"status\":\"" + s.session.status + "\"}" +
                ",\"capabilities\":{\"developer\":\"" + cap(s.session.cap_developer) +
                "\",\"evaluator\":\"" + cap(s.session.cap_evaluator) +
                "\",\"qa_tester\":\"" + cap(s.session.cap_qa) + "\"}" +
                ",\"effective\":{\"developer\":" + (eff(s.session.cap_developer) ? "true" : "false") +
                ",\"evaluator\":" + (eff(s.session.cap_evaluator) ? "true" : "false") + "}" +
                ",\"checked\":" + std::to_string(s.session.checked_epoch) +
                ",\"qa_link_available\":" + (qa_link_offered(s.session) ? "true" : "false") +
                // The account's EXPLICIT appearance as this installation
                // knows it: a choice made here and not yet delivered wins
                // over the last confirmed one. "" = never chosen (follow
                // the local appearance).
                ",\"appearance\":\"" + (!s.session.pending_appearance.empty() ? s.session.pending_appearance
                                                                             : s.session.appearance) + "\"";
            stale = (long long)time(nullptr) - s.session.checked_epoch > kSnapshotFreshSeconds;
            pending = !s.session.pending_appearance.empty();
        }
        // The INSTALLED capabilities (0.9.9, installed_capabilities.hpp),
        // signed in or out: which entry points this installation came
        // through. Local presentation only; the Admin shows a workspace
        // that uses the service only when the account's capability above
        // allows it too.
        out += ",\"enabled\":" + capabilities::enabled_json();
        // The roles the service last confirmed for the account signed in
        // here, kept through sign-out (account_roles.hpp; client 0.9.12):
        // a signed-out Admin keeps that layout. Absent = no account has
        // been confirmed on this installation yet (the entry point decides).
        const roles::Record rr = roles::load();
        if (rr.remembered) {
            out += std::string(",\"remembered\":{\"developer\":") + (rr.developer ? "true" : "false") +
                ",\"evaluator\":" + (rr.evaluator ? "true" : "false") + "}";
        }
        out += "}";
    }
    // Stale snapshot: re-confirm. An undelivered appearance change: try
    // again at most every 30 seconds until the service is reachable.
    if (stale) confirm_async();
    else if (pending) confirm_if_due(30000);
    return out;
}

inline std::string start_sign_in() {
    unsigned long long id = 0;
    std::string reopen;
    {
        std::lock_guard<std::mutex> lock(st().m);
        ensure_loaded_locked(st());
        if (st().phase == Phase::browser && !st().authorize_url.empty()) {
            // ONE PENDING SIGN-IN, REOPENABLE (header): the same page again.
            reopen = st().authorize_url;
            if (test_seam_active()) { ++st().reopened; reopen.clear(); }
        } else if (st().phase != Phase::idle) {
            // Still preparing the request, or exchanging the code: nothing
            // to open yet, and nothing new is started.
            return "{\"type\":\"account_sign_in\",\"started\":true}";
        } else {
            st().phase = Phase::browser;
            st().last_error.clear();
            st().test_authorize_url.clear();
            st().authorize_url.clear();
            id = ++st().flow_id;
        }
    }
    if (id == 0) {
        if (!reopen.empty()) {
            // Off the bridge thread: the shell can take a moment.
            std::thread([reopen] {
                const std::wstring w = widen(reopen);
                ShellExecuteW(nullptr, L"open", w.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                log::client("account: sign-in page opened again");
            }).detach();
        }
        return "{\"type\":\"account_sign_in\",\"started\":true,\"reopened\":true}";
    }
    g_cancel.store(false);
    std::thread([id] { run_flow(id); }).detach();
    return "{\"type\":\"account_sign_in\",\"started\":true}";
}

inline std::string cancel_sign_in() {
    {
        // A cancelled sign-in's page is never opened again, even before its
        // flow notices the cancel.
        std::lock_guard<std::mutex> lock(st().m);
        st().authorize_url.clear();
    }
    g_cancel.store(true);
    return "{\"type\":\"account_sign_in_cancel\",\"ok\":true}";
}

/** Sign out: revoke the device authorization at the service (best effort,
 *  bounded), then forget it locally whatever the network says. */
inline std::string sign_out(bool quick = false) {
    store::DeviceKey key;
    std::string rt;
    {
        std::lock_guard<std::mutex> lock(st().m);
        ensure_loaded_locked(st());
        if (st().signed_in) rt = st().session.refresh_token;
    }
    if (!rt.empty() && store::device_key(key)) {
        std::lock_guard<std::mutex> tl(token_mutex());
        (void)call(L"POST", "POST", "/v1/oauth/revoke",
            "client_id=" + std::string(kClientId) + "&token=" + form_escape(rt), key, "", quick);
    }
    std::lock_guard<std::mutex> lock(st().m);
    sign_out_locally(st(), "");
    log::client("account: signed out");
    return "{\"type\":\"account_sign_out\",\"ok\":true}";
}

/** The Admin asks on start and on every window activation, so a change
 *  made on another installation arrives without a sign-in; at most one
 *  service round trip per 20 seconds. */
inline std::string refresh() {
    confirm_if_due(20000);
    return "{\"type\":\"account_refresh\",\"ok\":true}";
}

/**
 * {"type":"account_set_appearance","appearance":"light"|"dark"}: the person
 * EXPLICITLY chose an appearance in the signed-in Admin. Recorded at once
 * (the status answer reflects it immediately), persisted with the version
 * it was made on, and delivered to the service in the background as the
 * newest intent. If the service cannot be reached it stays pending and is
 * replayed against that version on the next contact. Refused when signed
 * out: a signed-out Admin keeps its local appearance only.
 */
inline std::string set_appearance(const std::string& message) {
    std::string value;
    if (!json_scan::find_string_in(message, 0, message.size(), "appearance", value) ||
        (value != "light" && value != "dark")) {
        return "{\"type\":\"account_set_appearance\",\"ok\":false}";
    }
    {
        std::lock_guard<std::mutex> lock(st().m);
        ensure_loaded_locked(st());
        if (!st().signed_in) return "{\"type\":\"account_set_appearance\",\"ok\":false}";
        store::Session& x = st().session;
        // A change already waiting keeps the version it was made on; the
        // newer choice simply replaces its value.
        if (x.pending_appearance.empty()) x.pending_base = x.appearance_version;
        x.pending_appearance = value;
        if (!store::save_session(x)) log::client("account: could not persist the appearance");
    }
    std::thread([] {
        {
            std::lock_guard<std::mutex> lock(st().m);
            if (!st().signed_in) return;
        }
        store::DeviceKey key;
        if (!store::device_key(key)) return;
        std::lock_guard<std::mutex> tl(token_mutex());
        deliver_appearance_locked(key, true);
    }).detach();
    return "{\"type\":\"account_set_appearance\",\"ok\":true}";
}

/** The explicit QA identity association (the person chose it). Sends the
 *  service-issued tester credential plus a fresh proof by its machine key,
 *  on top of this installation's DPoP authorization. */
inline std::string link_qa() {
    {
        std::lock_guard<std::mutex> lock(st().m);
        ensure_loaded_locked(st());
        if (!st().signed_in) return "{\"type\":\"account_link_qa\",\"ok\":false}";
    }
    store::DeviceKey key;
    if (!store::device_key(key)) return "{\"type\":\"account_link_qa\",\"ok\":false}";
    const auto entries = qa_credential::load(paths::security_dir());
    const std::string my_machine = machine_identity::public_key_hex();
    std::lock_guard<std::mutex> tl(token_mutex());
    std::string at, device;
    {
        std::lock_guard<std::mutex> lock(st().m);
        ensure_loaded_locked(st());
        if (!st().signed_in) return "{\"type\":\"account_link_qa\",\"ok\":false}";
        at = st().access_token;
        device = st().session.device_id;
        if (at.empty() || GetTickCount64() >= st().access_expiry_tick) at.clear();
    }
    if (at.empty()) {
        if (!refresh_locked(key)) return "{\"type\":\"account_link_qa\",\"ok\":false}";
        std::lock_guard<std::mutex> lock(st().m);
        at = st().access_token;
    }
    namespace lp = virule::core::launch_policy;
    const std::string audience = endpoint_override().host.empty()
        ? std::string(lp::kEmbargoApiHost)
        : narrow(endpoint_override().host);
    int linked = 0;
    for (const auto& e : entries) {
        // Only a credential bound to THIS machine's identity can be proven.
        if (e.machine_key != my_machine || e.signature.size() != 128) continue;
        char ts[32];
        const time_t now = time(nullptr);
        tm g{};
        gmtime_s(&g, &now);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &g);
        const std::string msig = machine_identity::sign_hex(
            "virule-account-qa-link.v1|" + audience + "|" + device + "|" + e.tester_id + "|" + ts);
        if (msig.empty()) continue;
        const std::string body = "{\"organization_id\":\"" + e.organization_id + "\",\"tester_id\":\"" + e.tester_id +
            "\",\"machine_key\":\"" + e.machine_key + "\",\"bound_utc\":\"" + e.bound_utc +
            "\",\"credential_signature\":\"" + e.signature + "\",\"timestamp\":\"" + ts +
            "\",\"machine_signature\":\"" + msig + "\"}";
        const Reply r = call(L"POST", "POST", "/v1/account/qa/link", body, key, at);
        if (r.status == 200) ++linked;
    }
    if (linked > 0) confirm_async();
    return std::string("{\"type\":\"account_link_qa\",\"ok\":") + (linked > 0 ? "true" : "false") +
        ",\"linked\":" + std::to_string(linked) + "}";
}

// ------------------------------------------------- the evaluation relay --

/**
 * {"type":"account_api","method":"GET"|"POST","path":"/v1/evaluations...","body":{...}}
 *
 * THE EVALUATION RELAY (VIRULE_BACKEND/docs/EVALUATIONS.md). The Admin's
 * Evaluations and Assignments read and change the service's evaluation
 * records THROUGH this installation's own DPoP authorization: the call is
 * made here, with the device key and the access token, which never leave
 * this process. The Admin names only the method, one of the two evaluation
 * path families and a JSON body (the LAST field of the message, passed as
 * raw JSON and validated by the service); it can reach nothing else
 * (shared/account_relay.hpp). LOCAL ONLY, like every account_* message.
 *
 * Answers {"type":"account_api","status":<HTTP status>,"body":<the service's
 * JSON object>}. status 0 = no answer, with "error": "signed_out" (no
 * authorization here, or the service ended it), "offline" (the service
 * could not be reached), "bad_request" or "too_large". A refused refresh
 * signs this installation out, as anywhere.
 */
inline std::string api_call(const std::string& message) {
    namespace relay = vclient::account_relay;
    const relay::Request req = relay::parse(message);
    if (!req.ok) return relay::failure("bad_request");
    const std::string& method = req.method;
    const std::string& path = req.path;
    const std::string& body = req.body;
    {
        std::lock_guard<std::mutex> lock(st().m);
        ensure_loaded_locked(st());
        if (!st().signed_in) return relay::failure("signed_out");
    }
    store::DeviceKey key;
    if (!store::device_key(key)) return relay::failure("signed_out");
    const wchar_t* wm = method == "GET" ? L"GET" : L"POST";
    const auto no_token = [] {
        std::lock_guard<std::mutex> lock(st().m);
        return relay::failure(st().signed_in ? "offline" : "signed_out");
    };
    std::lock_guard<std::mutex> tl(token_mutex());
    std::string at;
    if (!access_token_locked(key, at)) return no_token();
    Reply r = call(wm, method.c_str(), path, body, key, at);
    if (r.status == 401) {
        if (!refresh_locked(key)) return no_token();
        { std::lock_guard<std::mutex> lock(st().m); at = st().access_token; }
        r = call(wm, method.c_str(), path, body, key, at);
    }
    if (r.status == 0) {
        std::lock_guard<std::mutex> lock(st().m);
        st().offline = true;
        return relay::failure("offline");
    }
    const std::string out = relay::answer(r.status, r.body);
    return out.size() > relay::kMaxAnswerBytes ? relay::failure("too_large") : out;
}

} // namespace vclient::account
