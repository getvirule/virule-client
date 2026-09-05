#pragma once
// The VIRULE Client local bridge: ONE loopback WebSocket listener on
// 127.0.0.1:47612, path /v1.
//
// TRANSPORT / DISCOVERY (fixed and documented):
//   - The browser discovers a local VIRULE Client by opening
//     ws://127.0.0.1:47612/v1 and waiting for the hello
//     {"virule_client":1,"v":1,...}. A refused or silent socket means no
//     client. This is the same loopback-WebSocket mechanism the VIRULE
//     Admin's QA bridge (port 47611) already proved from the HTTPS
//     virule.app origin; the two listeners are separate on purpose so the
//     Admin session and the client can coexist.
//   - /v1 in the handshake path is the API version. An unknown path is
//     refused, so a /v2 can exist later without ambiguity.
//
// SECURITY MODEL:
//   - Binds 127.0.0.1 ONLY. Never a LAN interface, never a remote
//     fallback.
//   - A browser connection always carries an Origin header; only the
//     virule.app origins (plus the explicit local development origins
//     below) are accepted, so a foreign website can neither probe nor
//     drive the bridge. A local no-Origin connection is a control
//     connection: a local process could fake an Origin anyway, and a
//     local process already has this user's power (it could launch
//     virule:// or delete files itself), so origin checks defend against
//     the WEB, not against local code.
//   - There is no generic command endpoint, no filesystem surface, no
//     process-launch surface. The message set is closed and versioned.
//   - Privileged operations carry their own authorization on top of the
//     origin check: QA credential writes require a service-minted,
//     expiring, single-use invitation token that the VIRULE service
//     validates at redemption; uninstall requires a fresh signed
//     authorization from the VIRULE service verified against the embedded
//     public key. The bridge itself never trusts a bare localhost caller
//     with a destructive action.
//
// MESSAGES (text frames, JSON). An invite token is either the current
// 32-character Base64URL mint or the legacy 64-lowercase-hex mint
// (protocol_reg::is_invite_token):
//   page -> client   {"type":"status"}
//                    {"type":"qa_accept","token":"<invite token>"}
//                    {"type":"admin_install","shortcut":true|false}
//                    {"type":"admin_open"}
//                    {"type":"uninstall","nonce":"<32 hex>",
//                     "timestamp":"<UTC>","signature":"<128 hex>",
//                     "delete_data":true|false}
//                    {"type":"surface_ack"}      (page: next view is rendered)
//   local -> client  {"type":"qa_verify_url","token":"<invite token>"} (2nd instance)
//                    {"type":"wake"}                              (2nd instance)
//                    {"type":"shutdown"}                          (Setup replace)
//                    {"type":"admin_install"}          (Admin Settings Update)
//                    {"type":"admin_launch"}           (managed launch handoff)
//                    {"type":"admin_update_check"}     (Admin Settings query)
//                    {"type":"setup_takeover",...}     (Setup envelope transfer)
//                    {"type":"setup_wait"}             (Setup release poll)
//   client -> conn   hello {"virule_client":1,"v":1,"version":...}
//                    {"type":"status","version","capabilities","pages","admin"}
//                      (answered on request, and ALSO PUSHED unsolicited to
//                       every page when the lifecycle state changes: the
//                       admin block's installed/version/running/updating or
//                       the uninstalling flag - the P1 status push,
//                       2026-09-04. Pages treat any status frame as the
//                       current truth; polling remains the backstop.)
//                    {"type":"accepted"}
//                    {"type":"admin_install_started"} / {"type":"admin_opened"}
//                    {"type":"admin_update_status","installed",...,"update"}
//                    {"type":"qa_result","token":...,"state":...}
//                    {"type":"admin_result","state":...,"version":...}
//                    {"type":"uninstall_started"} / {"type":"error"}
//
// admin_install / admin_open are page messages behind the same origin
// policy. They are CLOSED operations, not a filesystem or process surface:
// install runs the verified staged pipeline against the approved virule.app
// manifest (package SHA-256 + Authenticode + the VIRULE signer identity are
// the trust decision, exactly Virule-Setup's), and open launches only the
// managed Admin installation the client itself placed.
//
// The WebSocket plumbing below (handshake, SHA-1 accept, frame codec) is
// ported from the VIRULE Admin's qa_bridge, which is live in production.

#include <atomic>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "shared/json_scan.hpp"
#include "shared/logging.hpp"
#include "shared/protocol_reg.hpp"
#include "shared/version.h"
#include "virule/core/embargo_signing.hpp"
#include "virule/core/launch_policy.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

namespace vclient::bridge {

constexpr unsigned short kPort = 47612;
constexpr size_t kMaxHandshakeBytes = 8192;
constexpr size_t kMaxFrameBytes = 4096;

// Accepted browser origins. Production first; the rest are the explicit
// local development origins (vite dev server for the site, wrangler dev
// for the QA page). Never '*', never a wildcard.
inline const char* kAllowedOrigins[] = {
    "https://virule.app",
    "https://www.virule.app",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "https://localhost:8788",
    "https://127.0.0.1:8788",
};

// What the serving process wires in.
struct Callbacks {
    // ACCEPT arrived from a page (or a second instance forwarded a
    // virule:// URL). Runs the redemption asynchronously.
    std::function<void(const std::string& token)> on_qa_accept;
    // The Admin install/update pipeline was requested. `from_page` = a
    // virule.app page drove it (the page owns the visible flow); a LOCAL
    // caller (the Admin's Settings Update) hands the client the visible
    // feedback too (the native "Updating…" card). Runs asynchronously;
    // the result is pushed as admin_result.
    std::function<void(bool shortcut, bool from_page)> on_admin_install;
    // A local launcher (the managed virule.exe cooperating at startup)
    // handed the client a user-initiated VIRULE launch that needs an
    // update first: update with native feedback, then launch the new
    // Admin. Runs asynchronously.
    std::function<void()> on_admin_launch;
    // A page asked to open the managed Admin installation. Synchronous;
    // false = not installed / could not launch.
    std::function<bool()> on_admin_open;
    // The Admin status block embedded in every status answer
    // ({"installed","version","running"}), or empty = "null".
    std::function<std::string()> admin_status_json;
    // A local caller (the Admin's Settings page through its host, or a
    // managed virule.exe's update-on-launch check) asked whether an
    // approved Admin update exists. Answers the FULL admin_update_status
    // JSON message; may fetch the manifest (bounded) when the cached
    // answer is stale. `launch_context` = the caller declared
    // {"context":"launch"} (the persisted launch-retry hold applies).
    std::function<std::string(bool launch_context)> admin_update_status_json;
    // A verified uninstall authorization arrived from a page. The flag is
    // the page's explicit Delete local data choice; false (the default)
    // preserves every piece of user-owned VIRULE data.
    std::function<void(bool delete_data)> on_uninstall;
    // A local process asked this instance to exit (Setup replacing us).
    std::function<void()> on_shutdown;
    // Virule-Setup transferred the pending-operation envelope (or its
    // explicit absence). The raw payload is handed over; the takeover
    // module validates it.
    std::function<void(const std::string& payload)> on_setup_takeover;
    // Setup's release poll: true once the takeover is complete and the
    // next feedback surface (page or native card) is ready/visible.
    std::function<bool()> setup_released;
};

// Listener ownership: 0 unresolved, 1 this process listens, 2 the port is
// taken or could not be opened.
inline std::atomic<int> g_listen_state{ 0 };
inline std::atomic<SOCKET> g_listener{ INVALID_SOCKET };
inline Callbacks g_callbacks;

// UNINSTALL IN PROGRESS: the ordered teardown has begun. Every lifecycle
// operation (admin_install / admin_launch / admin_open / QA / takeover) is
// refused from here on, the status answer carries "uninstalling":true so
// virule.app renders its Removing state from ground truth, and nothing may
// start a new update or launch. Set only by the uninstall sequence;
// cleared only when a pre-teardown failure (the Admin refused to close)
// returns the client to normal service.
inline std::atomic<bool> g_uninstalling{ false };

// CLIENT SELF-UPDATE DRAIN: the client is seconds from exiting so the
// replacement helper can swap its binary. New lifecycle operations are
// refused during this brief window (the caller retries against the new
// client after the swap; the browser's disconnect hysteresis masks the
// restart). Deliberately NOT surfaced in status: routine self-update is
// quiet plumbing, never a rendered state.
inline std::atomic<bool> g_self_update_draining{ false };

// Activity clock for the idle-exit policy: any accepted connection or
// handled message refreshes it.
inline std::atomic<unsigned long long> g_last_activity_tick{ 0 };
inline std::atomic<int> g_open_connections{ 0 };

inline void touch_activity() { g_last_activity_tick.store(GetTickCount64()); }

// When this instance last handled a QA verification (an ACCEPT from a page
// or a virule:// launch), as a GetTickCount64 value; 0 = never. Surfaced in
// the status answer as qa_last_s so Setup can tell that a browser page is
// driving the flow NATIVELY even when that browser blocks loopback
// WebSockets entirely (Brave does by default) and the page therefore never
// shows up in the "pages" count.
inline std::atomic<unsigned long long> g_last_qa_tick{ 0 };

inline void touch_qa_activity() { g_last_qa_tick.store(GetTickCount64()); }

// Takeover surface signals (read by the takeover module): a PAGE explicitly
// acknowledged that its next state is active (surface_ack), or a PAGE drove
// an operation itself (qa_accept / admin_install), which proves the same
// thing - the browser owns the visible flow.
inline std::atomic<bool> g_page_acked{ false };
inline std::atomic<bool> g_page_drove{ false };
// Which KIND of operation a page drove matters to the takeover's single
// authoritative decision (P1 handoff correction 2026-09-04): a page-driven
// admin_install becomes the native "Finishing up…" continuation, while
// page-driven QA keeps the browser-owns-QA-UX doctrine. Sticky like the
// flags above.
inline std::atomic<bool> g_page_drove_admin{ false };

// ---- page-connection registry (broadcast + liveness) ----
struct PageConn {
    SOCKET socket = INVALID_SOCKET;
    std::mutex send_mutex;
};
inline std::mutex g_pages_mutex;
inline std::vector<PageConn*> g_pages;

// Uninstall replay protection: nonces already accepted this run.
inline std::mutex g_nonce_mutex;
inline std::set<std::string> g_used_nonces;

inline bool send_all(SOCKET s, const char* data, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        const int r = send(s, data + sent, (int)(n - sent), 0);
        if (r <= 0) return false;
        sent += (size_t)r;
    }
    return true;
}

inline bool recv_exact(SOCKET s, unsigned char* out, size_t n) {
    size_t got = 0;
    while (got < n) {
        const int r = recv(s, (char*)(out + got), (int)(n - got), 0);
        if (r <= 0) return false;
        got += (size_t)r;
    }
    return true;
}

// One unmasked server->client frame (0x1 text / 0x8 close / 0xA pong).
inline bool send_frame(SOCKET s, unsigned char opcode, const std::string& payload) {
    std::string frame;
    frame += (char)(0x80 | opcode);
    if (payload.size() < 126) {
        frame += (char)payload.size();
    } else if (payload.size() <= 0xFFFF) {
        frame += (char)126;
        frame += (char)((payload.size() >> 8) & 0xFF);
        frame += (char)(payload.size() & 0xFF);
    } else {
        return false; // the bridge never sends anything that large
    }
    frame += payload;
    return send_all(s, frame.data(), frame.size());
}

inline bool page_send(PageConn* page, unsigned char opcode, const std::string& payload) {
    std::lock_guard<std::mutex> lock(page->send_mutex);
    return send_frame(page->socket, opcode, payload);
}

inline bool any_page_open() {
    std::lock_guard<std::mutex> lock(g_pages_mutex);
    return !g_pages.empty();
}

// How many virule.app PAGES are connected right now. Local control
// connections (a second instance, Setup) are never counted, which is what
// makes this answer usable by Setup: it asks over its own local connection
// whether a BROWSER page reached the freshly installed client, and so
// whether the browser is still driving the flow.
inline int open_page_count() {
    std::lock_guard<std::mutex> lock(g_pages_mutex);
    return (int)g_pages.size();
}

// Push one message to every connected page. Returns whether ANY page was
// open to receive it.
inline bool broadcast_to_pages(const std::string& payload) {
    std::lock_guard<std::mutex> lock(g_pages_mutex);
    bool any = false;
    for (PageConn* p : g_pages) {
        any = true;
        (void)page_send(p, 0x1, payload);
    }
    return any;
}

// Push one QA verification result to every connected page (each page
// filters by token).
inline bool broadcast_qa_result(const std::string& token, const std::string& state) {
    return broadcast_to_pages("{\"type\":\"qa_result\",\"token\":\"" + token +
                              "\",\"state\":\"" + state + "\"}");
}

// ---- the lifecycle status push (P1, 2026-09-04) ----
// Meaningful state changes (Admin running flips, an update starting or
// ending, the uninstall teardown beginning) used to reach an idle page only
// on its 15s status poll, leaving stale CTAs offered against a live
// transaction. The client now PUSHES one ordinary status frame to every
// connected page whenever the lifecycle-relevant core of the status answer
// changes. No new message type, no event framework: pages already treat any
// status frame as current truth, and polling remains the convergence
// backstop.

// The full status message, exactly what the "status" request answers.
inline std::string build_status_message(const std::string& admin_json) {
    const unsigned long long qa_tick = g_last_qa_tick.load();
    const long long qa_last_s = qa_tick == 0
        ? -1
        : (long long)((GetTickCount64() - qa_tick) / 1000ull);
    return std::string("{\"type\":\"status\",\"v\":1,\"version\":\"") +
        VIRULE_CLIENT_VERSION_STRING +
        "\",\"capabilities\":[\"qa\",\"admin\",\"uninstall\"],\"pages\":" +
        std::to_string(open_page_count()) +
        ",\"qa_last_s\":" + std::to_string(qa_last_s) +
        ",\"uninstalling\":" + (g_uninstalling.load() ? "true" : "false") +
        ",\"admin\":" + admin_json + "}";
}

// The last lifecycle core (admin block + uninstalling flag) broadcast to
// pages. Only these fields gate a push: pages/qa_last_s change constantly
// and are per-request detail, not lifecycle state.
inline std::mutex g_push_mutex;
inline std::string g_last_push_key;

// Push a status frame to every page when the lifecycle core changed since
// the last push (or unconditionally with force). Called by the serving
// process's 1s status watcher and directly at operation boundaries (update
// start/end, Admin launched), so every open virule.app tab converges in
// about a second instead of waiting out the 15s poll. Skips all work while
// no page is connected: a connecting page always asks for status itself.
inline void push_lifecycle_status(bool force = false) {
    if (open_page_count() == 0) return;
    const std::string admin = g_callbacks.admin_status_json
        ? g_callbacks.admin_status_json() : std::string("null");
    const std::string key = admin +
        (g_uninstalling.load() ? "|u1" : "|u0");
    {
        std::lock_guard<std::mutex> lock(g_push_mutex);
        if (!force && key == g_last_push_key) return;
        g_last_push_key = key;
    }
    broadcast_to_pages(build_status_message(admin));
}

// Push one uninstall lifecycle transition to every connected page:
// "removing" when the ordered teardown begins, "failed" when it stops
// before any destruction (the Admin refused to close). Success has no
// push by construction (the client exits and the helper owns the visible
// outcome); the site reads sustained bridge absence as completion.
inline bool broadcast_uninstall_state(const std::string& state) {
    return broadcast_to_pages("{\"type\":\"uninstall_state\",\"state\":\"" +
                              state + "\"}");
}

inline std::string b64(const unsigned char* data, size_t n) {
    static const char* kAlpha =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((n + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        const unsigned u = (unsigned(data[i]) << 16) |
                           (unsigned(data[i + 1]) << 8) | unsigned(data[i + 2]);
        out += kAlpha[(u >> 18) & 63];
        out += kAlpha[(u >> 12) & 63];
        out += kAlpha[(u >> 6) & 63];
        out += kAlpha[u & 63];
    }
    if (i < n) {
        const size_t rem = n - i;
        unsigned u = unsigned(data[i]) << 16;
        if (rem == 2) u |= unsigned(data[i + 1]) << 8;
        out += kAlpha[(u >> 18) & 63];
        out += kAlpha[(u >> 12) & 63];
        out += (rem == 2) ? kAlpha[(u >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

inline bool sha1(const std::string& in, unsigned char out[20]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0) {
        return false;
    }
    BCRYPT_HASH_HANDLE h = nullptr;
    bool ok = false;
    if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(h, (PUCHAR)in.data(), (ULONG)in.size(), 0) == 0 &&
            BCryptFinishHash(h, out, 20, 0) == 0) {
            ok = true;
        }
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// One case-insensitive header value out of the raw handshake text.
inline std::string header_value(const std::string& text, const std::string& name) {
    std::string lower;
    lower.reserve(text.size());
    for (const char c : text) {
        lower += (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    const std::string needle = "\r\n" + name + ":";
    const size_t at = lower.find(needle);
    if (at == std::string::npos) return "";
    size_t start = at + needle.size();
    const size_t end = text.find("\r\n", start);
    if (end == std::string::npos) return "";
    std::string value = text.substr(start, end - start);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.erase(value.begin());
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }
    return value;
}

inline bool origin_allowed(const std::string& origin) {
    for (const char* allowed : kAllowedOrigins) {
        if (origin == allowed) return true;
    }
    return false;
}

// The uninstall authorization: a fresh service-signed statement that a
// VIRULE-owned page requested removal. Verifies the exact grammar
//   virule-client-uninstall.v1|<32 hex nonce>|<canonical UTC timestamp>
// against the embedded VIRULE public key, requires the timestamp within
// 600 seconds of local UTC, and refuses a replayed nonce.
inline bool uninstall_authorization_valid(const std::string& nonce,
                                          const std::string& timestamp,
                                          const std::string& signature) {
    namespace lp = virule::core::launch_policy;
    if (nonce.size() != 32 ||
        nonce.find_first_not_of("0123456789abcdef") != std::string::npos) {
        return false;
    }
    if (!lp::is_signature_hex(signature)) return false;
    std::int64_t ts = 0;
    if (!lp::parse_canonical_utc_timestamp(timestamp, ts)) return false;
    const std::int64_t now = static_cast<std::int64_t>(time(nullptr));
    if (ts > now + 600 || ts < now - 600) return false;
    const std::string message = "virule-client-uninstall.v1|" + nonce + "|" + timestamp;
    if (!virule::core::embargo_signing::verify_virule_signature(message, signature)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_nonce_mutex);
    if (g_used_nonces.count(nonce)) return false;
    g_used_nonces.insert(nonce);
    return true;
}

inline void handle_client(SOCKET client) {
    // Handshake first, under a timeout so a stalled connection can never
    // wedge this worker.
    DWORD timeout = 10000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&timeout, sizeof(timeout));
    std::string req;
    while (req.find("\r\n\r\n") == std::string::npos) {
        char buf[1024];
        const int r = recv(client, buf, sizeof(buf), 0);
        if (r <= 0) return;
        req.append(buf, (size_t)r);
        if (req.size() > kMaxHandshakeBytes) return;
    }
    // GET /v1 ... : the versioned path is part of the contract.
    if (req.rfind("GET /v1 ", 0) != 0 && req.rfind("GET /v1/ ", 0) != 0) return;
    std::string upgrade = header_value(req, "upgrade");
    for (char& c : upgrade) c = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    if (upgrade != "websocket") return;
    const std::string origin = header_value(req, "origin");
    if (!origin.empty() && !origin_allowed(origin)) {
        return; // a foreign website's connection is simply dropped
    }
    // A browser page always carries an Origin; a local process carries none.
    const bool is_page = !origin.empty();
    const std::string key = header_value(req, "sec-websocket-key");
    if (key.empty()) return;
    unsigned char digest[20];
    if (!sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", digest)) return;
    const std::string accept =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + b64(digest, sizeof(digest)) + "\r\n\r\n";
    if (!send_all(client, accept.data(), accept.size())) return;

    touch_activity();

    PageConn page;
    page.socket = client;
    struct PageGuard {
        PageConn* p;
        bool armed;
        ~PageGuard() {
            if (!armed) return;
            std::lock_guard<std::mutex> lock(g_pages_mutex);
            g_pages.erase(std::remove(g_pages.begin(), g_pages.end(), p),
                          g_pages.end());
        }
    } page_guard{ &page, is_page };
    if (is_page) {
        std::lock_guard<std::mutex> lock(g_pages_mutex);
        g_pages.push_back(&page);
    }
    auto reply = [&](unsigned char opcode, const std::string& payload) {
        return is_page ? page_send(&page, opcode, payload)
                       : send_frame(client, opcode, payload);
    };

    // Connected: one hello so the page can tell the VIRULE Client from
    // some other local listener, then stay quietly open (the open
    // connection IS the "VIRULE is here" signal).
    if (!reply(0x1, std::string("{\"virule_client\":1,\"v\":1,\"version\":\"")
                    + VIRULE_CLIENT_VERSION_STRING + "\"}")) {
        return;
    }
    timeout = 0; // the open connection is the point; wait as long as the page lives
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&timeout, sizeof(timeout));

    for (;;) {
        unsigned char head[2];
        if (!recv_exact(client, head, 2)) return;
        const unsigned char opcode = head[0] & 0x0F;
        const bool masked = (head[1] & 0x80) != 0;
        size_t len = head[1] & 0x7F;
        if (len == 126) {
            unsigned char ext[2];
            if (!recv_exact(client, ext, 2)) return;
            len = ((size_t)ext[0] << 8) | ext[1];
        } else if (len == 127) {
            return; // absurd for this protocol
        }
        if (!masked || len > kMaxFrameBytes) return; // RFC: client frames are masked
        unsigned char mask[4];
        if (!recv_exact(client, mask, 4)) return;
        std::string payload(len, '\0');
        if (len && !recv_exact(client, (unsigned char*)payload.data(), len)) return;
        for (size_t i = 0; i < len; ++i) payload[i] ^= (char)mask[i & 3];

        if (opcode == 0x8) { // close
            reply(0x8, "");
            return;
        }
        if (opcode == 0x9) { // ping
            if (!reply(0xA, payload)) return;
            continue;
        }
        if (opcode != 0x1) continue; // text only; ignore the rest

        touch_activity();
        namespace js = vclient::json_scan;
        std::string type, token;
        (void)js::find_string_in(payload, 0, payload.size(), "type", type);
        (void)js::find_string_in(payload, 0, payload.size(), "token", token);
        const bool token_ok = protocol_reg::is_invite_token(token);

        if (type == "status") {
            // "pages" is the number of connected virule.app pages (this one
            // included when a page asks). Setup asks over a local control
            // connection, which is not counted, so a non-zero answer there
            // means a browser page found the client and still owns the flow.
            // qa_last_s inside: seconds since this instance last handled a
            // QA verification, -1 = never (see g_last_qa_tick above for why
            // Setup needs it). The same message shape is also PUSHED on
            // lifecycle changes (push_lifecycle_status above).
            const std::string admin = g_callbacks.admin_status_json
                ? g_callbacks.admin_status_json() : std::string("null");
            if (!reply(0x1, build_status_message(admin))) {
                return;
            }
        } else if (g_uninstalling.load() &&
                   (type == "admin_install" || type == "admin_launch" ||
                    type == "admin_open" || type == "qa_accept" ||
                    type == "qa_verify_url" || type == "setup_takeover")) {
            // ORDERED TEARDOWN: once an explicit uninstall has begun, no
            // lifecycle operation is accepted any more (owner precedence
            // rule 2026-09-04). The status answer carries the truth.
            if (!reply(0x1, "{\"type\":\"error\"}")) return;
        } else if (g_self_update_draining.load() &&
                   (type == "admin_install" || type == "admin_launch" ||
                    type == "admin_open" || type == "qa_accept" ||
                    type == "qa_verify_url" || type == "setup_takeover" ||
                    type == "uninstall" || type == "uninstall_local")) {
            // SELF-UPDATE DRAIN: this process exits within moments so its
            // binary can be swapped; nothing new may start in it. The
            // freshly swapped client accepts the retry seconds later.
            if (!reply(0x1, "{\"type\":\"error\"}")) return;
        } else if (type == "admin_install") {
            // The verified staged Admin install/update. The pipeline itself
            // is the authorization (approved manifest hash + Authenticode +
            // the VIRULE signer identity); the caller only expresses intent.
            // A PAGE carries the desktop-shortcut preference it captured; a
            // LOCAL caller is the Admin's own Settings Update (through the
            // Admin host's control connection), which never asks for one.
            // Local trust model: a local process could run Setup itself, so
            // accepting a local install request weakens nothing.
            if (g_callbacks.on_admin_install) {
                const bool shortcut = is_page &&
                    payload.find("\"shortcut\":true") != std::string::npos;
                if (is_page) {
                    g_page_drove.store(true);
                    g_page_drove_admin.store(true);
                }
                g_callbacks.on_admin_install(shortcut, is_page);
                if (!reply(0x1, "{\"type\":\"admin_install_started\"}")) return;
            } else {
                if (!reply(0x1, "{\"type\":\"error\"}")) return;
            }
        } else if (type == "admin_launch" && !is_page) {
            // A managed virule.exe launch handing itself over because an
            // approved update exists (update-on-launch): the client shows
            // the native "Updating…" card, updates, and launches only the
            // new Admin. Local trust model: a local process could run the
            // update itself; nothing here is authorization.
            if (g_callbacks.on_admin_launch) {
                g_callbacks.on_admin_launch();
                if (!reply(0x1, "{\"type\":\"admin_launch_started\"}")) return;
            } else {
                if (!reply(0x1, "{\"type\":\"error\"}")) return;
            }
        } else if (type == "admin_update_check" && !is_page) {
            // The Admin Settings row's availability question, and the
            // managed virule.exe's update-on-launch question. Local-only:
            // virule.app pages read /client/admin-manifest.json themselves.
            // {"context":"launch"} marks the launch cooperation; only that
            // caller observes the long persisted launch-retry hold window
            // (admin_install.hpp). No context (Settings, older Admins) =
            // the short claim-suppression window only.
            std::string context;
            (void)js::find_string_in(payload, 0, payload.size(), "context",
                                     context);
            const std::string answer = g_callbacks.admin_update_status_json
                ? g_callbacks.admin_update_status_json(context == "launch")
                : std::string();
            if (answer.empty()) {
                if (!reply(0x1, "{\"type\":\"error\"}")) return;
            } else {
                if (!reply(0x1, answer)) return;
            }
        } else if (type == "admin_open" && is_page) {
            const bool opened = g_callbacks.on_admin_open &&
                                g_callbacks.on_admin_open();
            if (!reply(0x1, opened ? "{\"type\":\"admin_opened\"}"
                                   : "{\"type\":\"error\"}")) {
                return;
            }
        } else if (type == "qa_accept" && token_ok && is_page) {
            g_page_drove.store(true);
            if (g_callbacks.on_qa_accept) g_callbacks.on_qa_accept(token);
            if (!reply(0x1, "{\"type\":\"accepted\"}")) return;
        } else if (type == "surface_ack" && is_page) {
            // The page states that its next feedback view is rendered and
            // active (the browser-owns-the-flow acknowledgement the Setup
            // takeover waits on).
            g_page_acked.store(true);
            if (!reply(0x1, "{\"type\":\"ok\"}")) return;
        } else if (type == "setup_takeover" && !is_page) {
            // Virule-Setup transferring the pending-operation envelope (or
            // its explicit absence). Local-only; the takeover module
            // validates the fields and nothing here is authorization.
            if (g_callbacks.on_setup_takeover) {
                g_callbacks.on_setup_takeover(payload);
                if (!reply(0x1, "{\"type\":\"takeover\"}")) return;
            } else {
                if (!reply(0x1, "{\"type\":\"error\"}")) return;
            }
        } else if (type == "setup_wait" && !is_page) {
            const bool released = g_callbacks.setup_released &&
                                  g_callbacks.setup_released();
            if (!reply(0x1, released
                    ? "{\"type\":\"setup_wait\",\"released\":true}"
                    : "{\"type\":\"setup_wait\",\"released\":false}")) {
                return;
            }
        } else if (type == "qa_verify_url" && token_ok && !is_page) {
            // A second instance forwarding a virule:// launch. Local
            // trust model: a local process could launch virule:// itself,
            // and the token still has to survive service redemption.
            if (g_callbacks.on_qa_accept) g_callbacks.on_qa_accept(token);
            if (!reply(0x1, "{\"type\":\"accepted\"}")) return;
        } else if (type == "uninstall" && is_page) {
            if (g_uninstalling.load()) {
                // Already removing (a second tab, a double-send): JOIN the
                // running teardown instead of spawning a second one. The
                // fresh authorization is not consumed.
                if (!reply(0x1, "{\"type\":\"uninstall_started\"}")) return;
                continue;
            }
            std::string nonce, timestamp, signature;
            (void)js::find_string_in(payload, 0, payload.size(), "nonce", nonce);
            (void)js::find_string_in(payload, 0, payload.size(), "timestamp", timestamp);
            (void)js::find_string_in(payload, 0, payload.size(), "signature", signature);
            if (uninstall_authorization_valid(nonce, timestamp, signature)) {
                // The explicit destructive option. Absent or false = the
                // default uninstall, which PRESERVES user-owned local data.
                const bool delete_data =
                    payload.find("\"delete_data\":true") != std::string::npos;
                if (!reply(0x1, "{\"type\":\"uninstall_started\"}")) return;
                log::client(std::string("bridge: verified uninstall authorization accepted") +
                            (delete_data ? " (delete local data)" : " (keep local data)"));
                // The ordered teardown runs asynchronously; this page
                // connection stays open so the uninstall_state pushes
                // reach it until the client exits.
                if (g_callbacks.on_uninstall) g_callbacks.on_uninstall(delete_data);
                continue;
            }
            log::client("bridge: uninstall refused (invalid authorization)");
            if (!reply(0x1, "{\"type\":\"error\"}")) return;
        } else if (type == "uninstall_local" && !is_page) {
            // The Windows-initiated uninstall (Apps & Features) forwarding
            // its confirmed removal to the serving instance, so ONE ordered
            // teardown owns the whole flow. Local trust model: a local
            // process could run --uninstall itself; the user confirmation
            // already happened in the forwarding process's native dialog.
            if (g_uninstalling.load()) {
                if (!reply(0x1, "{\"type\":\"uninstall_started\"}")) return;
                continue;
            }
            const bool delete_data =
                payload.find("\"delete_data\":true") != std::string::npos;
            if (!reply(0x1, "{\"type\":\"uninstall_started\"}")) return;
            log::client(std::string("bridge: local uninstall accepted") +
                        (delete_data ? " (delete local data)" : " (keep local data)"));
            if (g_callbacks.on_uninstall) g_callbacks.on_uninstall(delete_data);
            continue;
        } else if (type == "wake" && !is_page) {
            if (!reply(0x1, "{\"type\":\"ok\"}")) return;
        } else if (type == "shutdown" && !is_page) {
            if (!reply(0x1, "{\"type\":\"ok\"}")) return;
            if (g_callbacks.on_shutdown) g_callbacks.on_shutdown();
            return;
        } else {
            if (!reply(0x1, "{\"type\":\"error\"}")) return;
        }
    }
}

struct ClientThreadArg {
    SOCKET socket;
};

inline DWORD WINAPI client_thread_main(LPVOID p) {
    ClientThreadArg* arg = (ClientThreadArg*)p;
    const SOCKET s = arg->socket;
    delete arg;
    g_open_connections.fetch_add(1);
    handle_client(s);
    g_open_connections.fetch_sub(1);
    touch_activity();
    shutdown(s, SD_BOTH);
    closesocket(s);
    return 0;
}

inline DWORD WINAPI listener_thread_main(LPVOID) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        g_listen_state.store(2);
        return 0;
    }
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        g_listen_state.store(2);
        return 0;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // loopback ONLY
    if (bind(listener, (const sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(listener, 4) != 0) {
        // The port is taken: normally another VIRULE Client instance
        // (single-instance handles that before this thread starts); a
        // foreign squatter is logged and the client exits cleanly rather
        // than fighting or falling back to anything less safe.
        g_listen_state.store(2);
        closesocket(listener);
        log::client("bridge: port 47612 unavailable; no listener");
        return 0;
    }
    g_listener.store(listener);
    g_listen_state.store(1);
    log::client("bridge: listening on 127.0.0.1:47612 /v1");
    for (;;) {
        const SOCKET client = accept(listener, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            if (g_listener.load() == INVALID_SOCKET) return 0; // shut down
            Sleep(100); // a transient accept error must never hot-spin
            continue;
        }
        auto* arg = new ClientThreadArg{ client };
        HANDLE h = CreateThread(nullptr, 0, client_thread_main, arg, 0, nullptr);
        if (h) {
            CloseHandle(h);
        } else {
            delete arg;
            closesocket(client);
        }
    }
}

inline void start(const Callbacks& callbacks) {
    g_callbacks = callbacks;
    touch_activity();
    if (HANDLE h = CreateThread(nullptr, 0, listener_thread_main, nullptr, 0, nullptr)) {
        CloseHandle(h);
    }
}

// Close the listener (used before uninstall / shutdown so the port frees
// promptly). Open per-connection threads die with the process.
inline void stop_listening() {
    const SOCKET s = g_listener.exchange(INVALID_SOCKET);
    if (s != INVALID_SOCKET) closesocket(s);
}

// Recovery path for an uninstall whose %TEMP% helper could not be spawned
// after the listener was already closed: reopen the listener so the
// machine is not left with a live client no page can reach.
inline void restart_listening() {
    if (g_listener.load() != INVALID_SOCKET) return;
    g_listen_state.store(0);
    if (HANDLE h = CreateThread(nullptr, 0, listener_thread_main, nullptr, 0,
                                nullptr)) {
        CloseHandle(h);
    }
}

// ---- loopback WebSocket client (talk to an already-running listener) ----
// Used by a second instance to forward its virule:// launch, by Setup to
// ask a running client to exit, and by the QA flow to report a result to a
// running VIRULE Admin GUI session on port 47611 (its qa_bridge speaks the
// same frames). No Origin is sent: that is exactly what marks the
// connection as local.

inline bool client_send_masked(SOCKET s, const std::string& payload) {
    unsigned char mask[4];
    if (BCryptGenRandom(nullptr, mask, sizeof(mask),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return false;
    }
    std::string frame;
    frame += (char)(unsigned char)0x81; // FIN + text
    if (payload.size() < 126) {
        frame += (char)(unsigned char)(0x80 | payload.size());
    } else if (payload.size() <= 0xFFFF) {
        frame += (char)(unsigned char)(0x80 | 126);
        frame += (char)((payload.size() >> 8) & 0xFF);
        frame += (char)(payload.size() & 0xFF);
    } else {
        return false;
    }
    frame.append((const char*)mask, sizeof(mask));
    for (size_t i = 0; i < payload.size(); ++i) {
        frame += (char)(payload[i] ^ (char)mask[i & 3]);
    }
    return send_all(s, frame.data(), frame.size());
}

inline bool client_recv_text(SOCKET s, std::string& payload_out) {
    for (;;) {
        unsigned char head[2];
        if (!recv_exact(s, head, 2)) return false;
        const unsigned char opcode = head[0] & 0x0F;
        if (head[1] & 0x80) return false; // server frames are unmasked
        size_t len = head[1] & 0x7F;
        if (len == 126) {
            unsigned char ext[2];
            if (!recv_exact(s, ext, 2)) return false;
            len = ((size_t)ext[0] << 8) | ext[1];
        } else if (len == 127) {
            return false;
        }
        if (len > kMaxFrameBytes) return false;
        std::string payload(len, '\0');
        if (len && !recv_exact(s, (unsigned char*)payload.data(), len)) return false;
        if (opcode == 0x8) return false;
        if (opcode != 0x1) continue;
        payload_out = std::move(payload);
        return true;
    }
}

// One request/response round trip against a local listener. `hello_marker`
// is the substring that must appear in the listener's hello (so the caller
// knows it reached VIRULE and not some other local service);
// `response_out` receives the first post-hello text frame.
inline bool loopback_roundtrip(unsigned short port, const wchar_t* path_unused,
                               const std::string& hello_marker,
                               const std::string& request,
                               std::string& response_out) {
    (void)path_unused;
    response_out.clear();
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
    bool ok = false;
    const SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        DWORD timeout = 3000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        unsigned char nonce[16];
        if (connect(s, (const sockaddr*)&addr, sizeof(addr)) == 0 &&
            BCryptGenRandom(nullptr, nonce, sizeof(nonce),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
            // Port 47612 serves /v1; the Admin's 47611 bridge serves /.
            const std::string path = (port == kPort) ? "/v1" : "/";
            const std::string handshake =
                "GET " + path + " HTTP/1.1\r\n"
                "Host: 127.0.0.1:" + std::to_string(port) + "\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: " + b64(nonce, sizeof(nonce)) + "\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n";
            if (send_all(s, handshake.data(), handshake.size())) {
                std::string resp;
                while (resp.find("\r\n\r\n") == std::string::npos) {
                    char buf[512];
                    const int r = recv(s, buf, sizeof(buf), 0);
                    if (r <= 0) break;
                    resp.append(buf, (size_t)r);
                    if (resp.size() > kMaxHandshakeBytes) break;
                }
                std::string text;
                if (resp.rfind("HTTP/1.1 101", 0) == 0 &&
                    client_recv_text(s, text) && // the hello
                    text.find(hello_marker) != std::string::npos &&
                    client_send_masked(s, request) &&
                    client_recv_text(s, text)) {
                    response_out = text;
                    ok = true;
                }
            }
        }
        closesocket(s);
    }
    WSACleanup();
    return ok;
}

} // namespace vclient::bridge
