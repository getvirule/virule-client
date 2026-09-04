#pragma once
// The browser -> Setup handoff channel (the bootstrap/handoff pass,
// 2026-09-03). While Virule-Setup.exe is running and the originating
// virule.app page is still alive, the page hands its ONE pending operation
// directly to Setup over this small temporary loopback WebSocket listener.
// Setup then carries the envelope to the freshly installed client. This
// REPLACES the retired originating-browser guessing (process ancestry,
// browser families, default-browser fallback): intent is handed over
// explicitly or it does not exist.
//
// CLOSED, VERSIONED, TEMPORARY:
//   - 127.0.0.1:47613 only, path /handoff, alive only while Setup runs;
//   - browser pages ONLY: a connection must present one of the explicit
//     allowed virule.app / development origins (bridge.hpp's list). A
//     connection with no Origin is dropped: local processes have no
//     business handing Setup intent.
//   - hello {"virule_setup":1,"v":1} so the page knows it reached Setup;
//   - EXACTLY ONE pending-operation envelope is kept (first valid wins;
//     duplicates are acknowledged and ignored), consumed once by Setup's
//     transfer to the client;
//   - the envelope carries NO capability: no URL, no path, no executable,
//     no filesystem anything. Operations are the two known intents, and
//     the client revalidates all authorization itself (a QA token still
//     has to survive service redemption; an Admin install still runs the
//     verified manifest/signature pipeline).
//
// Envelope (page -> Setup), version 1:
//   {"type":"handoff","v":1,"op":"QA_ACCEPT","token":"<invite token>",
//    "game":"<display label>"}
//   {"type":"handoff","v":1,"op":"INSTALL_ADMIN","shortcut":true|false}
// Reply: {"type":"handoff_accepted"} (or {"type":"error"}).
//
// Setup does not understand the operation semantically; it treats the
// validated fields as an opaque envelope to carry to the client.

#include <atomic>
#include <mutex>
#include <string>

#include "client/bridge.hpp" // reuses the proven WS handshake/frame helpers
#include "shared/json_scan.hpp"
#include "shared/logging.hpp"
#include "shared/protocol_reg.hpp"

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
#endif

namespace vclient::setup_handoff {

constexpr unsigned short kPort = 47613;

struct Envelope {
    bool present = false;
    std::string op;      // "QA_ACCEPT" | "INSTALL_ADMIN"
    std::string token;   // QA_ACCEPT only; validated invite-token grammar
    std::string game;    // QA_ACCEPT only; display label, sanitized
    bool shortcut = false; // INSTALL_ADMIN only
};

inline std::mutex g_mutex;
inline Envelope g_envelope;
inline std::atomic<SOCKET> g_listener{ INVALID_SOCKET };

inline Envelope snapshot() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_envelope;
}

// Display label only: bounded, control characters stripped. Never parsed,
// never a path, never trusted for anything but one line of card copy.
inline std::string sanitize_label(const std::string& in) {
    std::string out;
    for (const char c : in) {
        if ((unsigned char)c < 0x20 || c == 0x7f) continue;
        out += c;
        if (out.size() >= 80) break;
    }
    return out;
}

// Validate one handoff frame into an envelope. Strict: an unknown op, a
// malformed token or a wrong version earns nothing.
inline bool parse_envelope(const std::string& payload, Envelope& out) {
    namespace js = vclient::json_scan;
    std::string type, op;
    (void)js::find_string_in(payload, 0, payload.size(), "type", type);
    if (type != "handoff") return false;
    long long v = 0;
    if (!js::find_number_in(payload, 0, payload.size(), "v", v) || v != 1) {
        return false;
    }
    (void)js::find_string_in(payload, 0, payload.size(), "op", op);
    if (op == "QA_ACCEPT") {
        std::string token;
        (void)js::find_string_in(payload, 0, payload.size(), "token", token);
        if (!protocol_reg::is_invite_token(token)) return false;
        std::string game;
        (void)js::find_string_in(payload, 0, payload.size(), "game", game);
        out.present = true;
        out.op = op;
        out.token = token;
        out.game = sanitize_label(game);
        return true;
    }
    if (op == "INSTALL_ADMIN") {
        out.present = true;
        out.op = op;
        out.shortcut = payload.find("\"shortcut\":true") != std::string::npos;
        return true;
    }
    return false;
}

inline void handle_connection(SOCKET client) {
    DWORD timeout = 10000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&timeout, sizeof(timeout));
    std::string req;
    while (req.find("\r\n\r\n") == std::string::npos) {
        char buf[1024];
        const int r = recv(client, buf, sizeof(buf), 0);
        if (r <= 0) return;
        req.append(buf, (size_t)r);
        if (req.size() > bridge::kMaxHandshakeBytes) return;
    }
    if (req.rfind("GET /handoff ", 0) != 0 && req.rfind("GET /handoff/ ", 0) != 0) return;
    std::string upgrade = bridge::header_value(req, "upgrade");
    for (char& c : upgrade) c = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    if (upgrade != "websocket") return;
    // PAGES ONLY: an Origin is required and must be allowed. A local
    // process (no Origin) is dropped; this channel exists for the browser.
    const std::string origin = bridge::header_value(req, "origin");
    if (origin.empty() || !bridge::origin_allowed(origin)) return;
    const std::string key = bridge::header_value(req, "sec-websocket-key");
    if (key.empty()) return;
    unsigned char digest[20];
    if (!bridge::sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", digest)) return;
    const std::string accept =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + bridge::b64(digest, sizeof(digest)) + "\r\n\r\n";
    if (!bridge::send_all(client, accept.data(), accept.size())) return;
    if (!bridge::send_frame(client, 0x1, "{\"virule_setup\":1,\"v\":1}")) return;

    for (;;) {
        unsigned char head[2];
        if (!bridge::recv_exact(client, head, 2)) return;
        const unsigned char opcode = head[0] & 0x0F;
        const bool masked = (head[1] & 0x80) != 0;
        size_t len = head[1] & 0x7F;
        if (len == 126) {
            unsigned char ext[2];
            if (!bridge::recv_exact(client, ext, 2)) return;
            len = ((size_t)ext[0] << 8) | ext[1];
        } else if (len == 127) {
            return;
        }
        if (!masked || len > bridge::kMaxFrameBytes) return;
        unsigned char mask[4];
        if (!bridge::recv_exact(client, mask, 4)) return;
        std::string payload(len, '\0');
        if (len && !bridge::recv_exact(client, (unsigned char*)payload.data(), len)) return;
        for (size_t i = 0; i < len; ++i) payload[i] ^= (char)mask[i & 3];

        if (opcode == 0x8) {
            bridge::send_frame(client, 0x8, "");
            return;
        }
        if (opcode == 0x9) {
            if (!bridge::send_frame(client, 0xA, payload)) return;
            continue;
        }
        if (opcode != 0x1) continue;

        Envelope env;
        if (parse_envelope(payload, env)) {
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (!g_envelope.present) {
                    g_envelope = env;
                    log::setup("handoff: envelope accepted (" + env.op + ") from " + origin);
                } else {
                    // ONE pending operation: the first valid envelope holds;
                    // a duplicate is acknowledged so the page settles.
                    log::setup("handoff: duplicate envelope (" + env.op + ") ignored");
                }
            }
            if (!bridge::send_frame(client, 0x1, "{\"type\":\"handoff_accepted\"}")) return;
        } else {
            if (!bridge::send_frame(client, 0x1, "{\"type\":\"error\"}")) return;
        }
    }
}

inline DWORD WINAPI connection_thread_main(LPVOID p) {
    const SOCKET s = (SOCKET)(ULONG_PTR)p;
    handle_connection(s);
    shutdown(s, SD_BOTH);
    closesocket(s);
    return 0;
}

inline DWORD WINAPI listener_thread_main(LPVOID) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return 0;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // loopback ONLY
    if (bind(listener, (const sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(listener, 4) != 0) {
        // Taken (an earlier Setup instance, a squatter): the page falls
        // back to reaching the installed client's own bridge directly, so
        // this is a logged degradation, never a failure.
        closesocket(listener);
        log::setup("handoff: port 47613 unavailable; no handoff listener");
        return 0;
    }
    g_listener.store(listener);
    log::setup("handoff: listening on 127.0.0.1:47613 /handoff");
    for (;;) {
        const SOCKET client = accept(listener, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            if (g_listener.load() == INVALID_SOCKET) return 0; // stopped
            Sleep(100);
            continue;
        }
        HANDLE h = CreateThread(nullptr, 0, connection_thread_main,
                                (LPVOID)(ULONG_PTR)client, 0, nullptr);
        if (h) CloseHandle(h); else closesocket(client);
    }
}

inline void start() {
    if (HANDLE h = CreateThread(nullptr, 0, listener_thread_main, nullptr, 0, nullptr)) {
        CloseHandle(h);
    }
}

inline void stop() {
    const SOCKET s = g_listener.exchange(INVALID_SOCKET);
    if (s != INVALID_SOCKET) closesocket(s);
}

} // namespace vclient::setup_handoff
