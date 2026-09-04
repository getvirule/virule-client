#pragma once
// THE SETUP TAKEOVER (the bootstrap/handoff pass, 2026-09-03).
//
// Virule-Setup.exe is a visible bootstrapper and temporary courier: it
// installs this client, transfers the browser's one pending-operation
// envelope (or its explicit absence), and then WAITS. This module is the
// client's half of that ownership transition. The hard UX invariant it
// exists for: a VIRULE surface must never disappear until the next VIRULE
// surface is ready to give immediate feedback. Setup's card stays on
// screen until release() answers true, and release() answers true only
// once one of these is demonstrably in place:
//
//   - a live virule.app page acknowledged the next state (surface_ack) or
//     actively drove the operation over the bridge (qa_accept /
//     admin_install), or is at least connected and rendering;
//   - a client-owned native card is visible (the QA continuation card, the
//     Admin install card, or the standalone "VIRULE is ready" card).
//
// THE THREE TAKEOVER SHAPES:
//
//   QA_ACCEPT       browser alive -> the page owns all visible UX (its
//                   "Finishing setup" waiting view); the client redeems
//                   silently and pushes the result. Browser gone -> the
//                   native continuation card ("Finishing setup for
//                   [Game]") shows BEFORE Setup may close, then becomes
//                   "You're all set." / "You can close this window."
//   INSTALL_ADMIN   browser alive -> the page drives admin_install and
//                   shows its own progress. Browser gone -> the client
//                   owns the install with a native progress card, and
//                   launches the Admin when it completes.
//   (no envelope)   a standalone / stale Setup run: there IS no
//                   recoverable intent, and none is invented. The client
//                   shows "VIRULE is ready" with the one explicit
//                   [ Open virule.app ] action. Setup never opens a
//                   browser; only that click does.
//
// INTENT, NEVER AUTHORIZATION: the envelope grants nothing. A QA token
// still has to survive service redemption with this machine's proof; an
// Admin install still runs the verified manifest/signature pipeline.

#include <atomic>
#include <mutex>
#include <string>

#include "client/admin_install.hpp"
#include "client/bridge.hpp"
#include "client/qa_flow.hpp"
#include "client/result_card.hpp"
#include "shared/json_scan.hpp"
#include "shared/logging.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace vclient::takeover {

// How long the client watches for a live page before concluding the
// browser is gone and providing native feedback itself. The page's
// reconnect loop runs every 1.5 s and connects within a couple of
// attempts; this is several.
constexpr unsigned long long kPageGraceMs = 6000;

// The standalone case watches a little longer (a slow page, a pending
// permission ask, a virule://-driven flow) before showing the completion
// card, because showing it to a user whose browser is mid-flow would be
// wrong twice.
constexpr unsigned long long kStandaloneGraceMs = 10000;

inline std::atomic<bool> g_released{ false };
inline std::mutex g_mutex;
inline std::string g_op;               // "" until a takeover arrived
inline std::atomic<bool> g_superseded{ false }; // standalone replaced by an op

inline bool released() { return g_released.load(); }

inline void release() { g_released.store(true); }

// A page is a ready feedback surface once it acknowledged its state or
// drove the operation itself; a merely-connected page still counts after
// the grace (it is rendering SOMETHING), which keeps older page builds and
// odd orderings honest rather than stranding Setup.
inline bool page_ready() {
    return bridge::g_page_acked.load() || bridge::g_page_drove.load();
}

// Wait up to `grace_ms` for a live page. True = a page owns the flow.
inline bool wait_for_page(unsigned long long grace_ms) {
    const ULONGLONG deadline = GetTickCount64() + grace_ms;
    for (;;) {
        if (page_ready()) return true;
        if (GetTickCount64() >= deadline) {
            return bridge::open_page_count() > 0;
        }
        Sleep(150);
    }
}

// Wait for the native card to actually exist before releasing Setup (the
// invariant is about VISIBLE surfaces, not intentions).
inline void release_when_card_visible() {
    for (int i = 0; i < 20 && !result_card::is_visible(); ++i) Sleep(100);
    release();
}

// ---- QA_ACCEPT ----

inline void run_qa(const std::string& token, const std::string& game) {
    bridge::touch_qa_activity();
    if (wait_for_page(kPageGraceMs)) {
        // The page owns all visible UX. Release Setup, then make sure the
        // redemption actually runs: the page normally sends qa_accept
        // itself the moment it reconnects (the debounce collapses the
        // duplicate), but a page that acked without re-sending must not
        // strand the token.
        release();
        qa_flow::run(token);
        return;
    }
    // Browser gone after handoff: the intent is NOT lost. Native
    // continuation surface first, then the work, then the result.
    const std::string primary =
        game.empty() ? std::string("Finishing setup")
                     : "Finishing setup for " + game;
    result_card::show_working(primary, "");
    release_when_card_visible();
    if (!qa_flow::debounce(token)) {
        // Another flow (a late page, a virule:// forward) is redeeming and
        // owns delivery; the card will sit briefly and self-resolve when
        // that flow broadcasts. Nothing more to do here.
        return;
    }
    const auto out = qa_flow::redeem_and_store(token);
    // A page that appeared meanwhile gets the push too; the card shows the
    // same outcome either way.
    (void)bridge::broadcast_qa_result(token, out.wire_state);
    result_card::update(out.primary,
                        out.success ? std::string("You can close this window.")
                                    : out.secondary);
    result_card::wait_closed();
    release();
}

// ---- INSTALL_ADMIN ----

inline void run_admin(bool shortcut) {
    if (wait_for_page(kPageGraceMs)) {
        // The page owns the install UX: it hands admin_install over itself
        // (its pending intent) and renders every state. Release Setup and
        // step aside.
        release();
        return;
    }
    // Browser gone after handoff: the client owns the Admin installation
    // with immediate native feedback, and the Admin itself is the final
    // surface.
    const bool updating = admin_install::admin_installed();
    result_card::show_working(
        updating ? "Updating VIRULE..." : "Installing VIRULE...", "");
    release_when_card_visible();
    const std::string state = admin_install::run(shortcut);
    if (state == "installed") {
        // The fresh install launched the Admin: the Admin window IS the
        // feedback now.
        result_card::close();
    } else if (state == "updated") {
        // The intent was "get VIRULE onto this machine": open it.
        (void)admin_install::open_installed_admin();
        result_card::close();
    } else if (state == "busy") {
        // Another surface already owns a running operation; its own
        // feedback covers this.
        result_card::close();
    } else {
        result_card::update("Something went wrong.", "Try again at virule.app.");
        result_card::wait_closed();
    }
    release();
}

// ---- no envelope (standalone / stale Setup) ----

inline void run_standalone() {
    // A short watch: a slow live page, or a flow arriving through
    // virule:// (QA activity), still gets to own the outcome. An op
    // upgrade (Setup forwarding a late envelope) supersedes this thread.
    const ULONGLONG deadline = GetTickCount64() + kStandaloneGraceMs;
    for (;;) {
        if (g_superseded.load()) return;
        if (page_ready() || bridge::open_page_count() > 0) {
            log::client("takeover: a page owns the flow; no native surface");
            release();
            return;
        }
        if (bridge::g_last_qa_tick.load() != 0) {
            // A QA verification is being driven natively; its own
            // ownership logic (page push / result card) provides the
            // surface.
            log::client("takeover: native QA progress owns the flow");
            release();
            return;
        }
        if (GetTickCount64() >= deadline) break;
        Sleep(200);
    }
    if (g_superseded.load()) return;
    // No recoverable intent exists, and none is invented: the standalone
    // completion surface, with the one explicit way onward.
    log::client("takeover: standalone completion surface");
    result_card::show_ready();
    release_when_card_visible();
}

// ---- entry (bridge callback) ----

struct ThreadArg {
    std::string op;
    std::string token;
    std::string game;
    bool shortcut = false;
};

inline DWORD WINAPI thread_entry(LPVOID p) {
    ThreadArg* a = (ThreadArg*)p;
    if (a->op == "QA_ACCEPT") run_qa(a->token, a->game);
    else if (a->op == "INSTALL_ADMIN") run_admin(a->shortcut);
    else run_standalone();
    delete a;
    return 0;
}

// Handle one setup_takeover message (local, from Setup). Idempotent:
// Setup retries the transfer until acknowledged, and a repeat of the same
// takeover starts nothing new. A real operation arriving after a
// standalone takeover UPGRADES it (the late-envelope forward): the
// standalone watch stands down, its card (if any) closes, and the
// operation runs.
inline void on_setup_takeover(const std::string& payload) {
    namespace js = vclient::json_scan;
    std::string op, token, game;
    (void)js::find_string_in(payload, 0, payload.size(), "op", op);
    (void)js::find_string_in(payload, 0, payload.size(), "token", token);
    (void)js::find_string_in(payload, 0, payload.size(), "game", game);
    const bool shortcut = payload.find("\"shortcut\":true") != std::string::npos;
    if (op != "QA_ACCEPT" && op != "INSTALL_ADMIN") op = "STANDALONE";
    if (op == "QA_ACCEPT" && !protocol_reg::is_invite_token(token)) {
        op = "STANDALONE"; // never trust a malformed token
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_op == op) return; // Setup's retry; already running
        if (!g_op.empty()) {
            if (g_op == "STANDALONE" && op != "STANDALONE") {
                // The late-envelope upgrade.
                g_superseded.store(true);
                result_card::close();
                g_released.store(false);
            } else {
                return; // one takeover per Setup run
            }
        }
        g_op = op;
    }
    log::client("takeover: " + op);

    auto* arg = new ThreadArg{ op, token, game, shortcut };
    HANDLE h = CreateThread(nullptr, 0, thread_entry, arg, 0, nullptr);
    if (h) {
        CloseHandle(h);
    } else {
        delete arg;
        release(); // never strand Setup on a thread failure
    }
}

} // namespace vclient::takeover
