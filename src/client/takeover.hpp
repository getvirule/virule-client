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
// THE THREE TAKEOVER SHAPES (lifecycle continuity pass, 2026-09-03):
//
//   QA_ACCEPT       the native continuation card "Finishing up…" ALWAYS
//                   shows BEFORE Setup may close (owner spec: the user
//                   watching Setup must never have to hunt for the
//                   browser to learn whether VIRULE finished), then
//                   becomes "You're all set." and closes itself. A live
//                   page still receives the same result push and reaches
//                   its own success state simultaneously; the card never
//                   waits on the browser.
//   INSTALL_ADMIN   browser alive -> the page drives admin_install and
//                   shows its own progress. Browser gone -> the client
//                   owns the install with a native progress card, and
//                   launches the Admin when it completes.
//   (no envelope)   a standalone / stale Setup run: there IS no
//                   recoverable intent, and none is invented. The client
//                   shows "VIRULE is ready" with the one explicit
//                   [ Continue ] action (opens virule.app). Setup never
//                   opens a browser; only that click does.
//
// THE STANDALONE CONCLUSION IS REVOCABLE (P1 corrective pass 2026-09-04).
// A browser-owned pending operation is INVISIBLE to this machine while no
// page is talking (a closed or throttled virule.app tab holds its durable
// INSTALL_ADMIN intent in browser storage), so "no envelope + no page for
// the grace" can never be a positive proof of standalone-ness. The
// measured incident: Setup transferred no envelope, the standalone card
// showed at +10s, and the browser delivered its pending admin_install 18
// seconds LATER - two surfaces claiming the same run. So any browser-owned
// operation arriving at ANY point after a STANDALONE takeover
// (a page-driven admin_install or qa_accept, or Setup's late-envelope
// upgrade) SUPERSEDES the standalone conclusion: the watch stands down and
// a standing "VIRULE is ready" card closes itself immediately - the page
// owns the flow from that moment.
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

// Show a Working card, retrying briefly: a superseded standalone card
// closes asynchronously, and the one-card-at-a-time rule makes show a
// no-op until its thread is reaped. Idempotent when a card is already up.
inline void show_working_retry(const char* primary) {
    for (int i = 0; i < 12; ++i) {
        result_card::show_working(primary, "");
        if (result_card::is_visible()) return;
        Sleep(100);
    }
}

// ---- QA_ACCEPT ----

inline void run_qa(const std::string& token) {
    bridge::touch_qa_activity();
    // The native continuation ALWAYS appears for a Setup QA handoff (owner
    // spec 2026-09-03): "Finishing up…" the moment Setup may close, then
    // "You're all set." - so the user watching the native flow never has
    // to find the browser to learn whether VIRULE finished. A live page
    // still gets the result push and completes its own view in parallel.
    show_working_retry("Finishing up\xE2\x80\xA6");
    release_when_card_visible();
    qa_flow::run(token);
    // qa_flow::run resolves the visible card itself. If the redemption was
    // already being driven by another flow (the page's own qa_accept won
    // the debounce), adopt its recorded outcome onto the card instead of
    // stranding it in the working state.
    if (result_card::is_working_visible()) {
        const ULONGLONG deadline = GetTickCount64() + 90000;
        qa_flow::Outcome out;
        for (;;) {
            if (qa_flow::try_last_outcome(token, out)) {
                result_card::update(out.primary,
                                    out.success ? std::string() : out.secondary);
                break;
            }
            if (GetTickCount64() >= deadline) {
                result_card::update("Something went wrong.", "Try again.");
                break;
            }
            Sleep(300);
        }
    }
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
    // The card is branded; the copy never repeats VIRULE (owner copy rule).
    const bool updating = admin_install::admin_installed();
    show_working_retry(updating ? "Updating\xE2\x80\xA6" : "Installing\xE2\x80\xA6");
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
    // completion surface, with the one explicit way onward. The
    // conclusion stays REVOCABLE: supersede_standalone() closes this card
    // the moment a browser-owned operation surfaces.
    log::client("takeover: standalone completion surface");
    result_card::show_ready();
    release_when_card_visible();
    // A supersession that raced the card's creation still wins: the show
    // above is what it could not close yet.
    if (g_superseded.load()) result_card::close();
}

// A browser-owned operation surfaced (a page drove admin_install or
// qa_accept over the bridge, or Setup forwarded a late envelope): the
// STANDALONE conclusion, if one was reached or is being reached, is
// revoked. The pending watch stands down and a standing "VIRULE is
// ready" card closes; the page owns the flow now. A no-op unless this
// Setup run actually concluded standalone.
inline void supersede_standalone() {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_op != "STANDALONE") return;
        if (g_superseded.exchange(true)) return; // already revoked
    }
    log::client("takeover: standalone superseded by a browser-owned operation");
    result_card::close();
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
    if (a->op == "QA_ACCEPT") run_qa(a->token);
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
