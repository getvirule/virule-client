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
// THE SINGLE AUTHORITATIVE DECISION (owner handoff rule, P1 final
// correction 2026-09-04). A Setup takeover terminates in exactly ONE of
// two native surfaces, and Setup is never released into neither:
//
//   PENDING INTENT EXISTS  ->  the native continuation "Finishing up…"
//   NO PENDING INTENT      ->  the standalone "VIRULE is ready" card
//
// The existence of a live browser page does NOT waive the native
// continuation: the page renders its own progress IN PARALLEL, it never
// replaces the native surface. (The prior page-alive branches released
// Setup quietly and the owner's real reinstall sat in native dead air for
// the whole Admin installation.)
//
//   QA_ACCEPT       "Finishing up…" the moment Setup may close, then
//                   "You're all set." and the card closes itself. A live
//                   page still receives the result push and reaches its
//                   own success state simultaneously.
//   INSTALL_ADMIN   "Finishing up…" unconditionally, held until the Admin
//                   installation completes and the Admin launches, then
//                   the card closes. Envelope-driven and page-driven
//                   installs converge on ONE operation (g_busy); the card
//                   outlives whichever started it.
//   (no envelope)   the watch waits a bounded grace for an operation to
//                   identify itself (a late envelope upgrade, a
//                   page-driven admin_install, native QA progress). One
//                   arriving becomes the continuation; the grace expiring
//                   with nothing is as positive a "no pending intent"
//                   conclusion as this machine can ever reach, and the
//                   standalone card shows. TERMINAL from then on - but
//                   still REVOCABLE: a browser-owned operation arriving
//                   late (a closed/throttled tab delivering its durable
//                   intent) supersedes the standing card and closes it.
//   (page-driven QA during the watch)  QA keeps its own browser/native
//                   ownership doctrine (the page owns ALL visible
//                   verification UX); the watch stands down quietly.
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

// How long the standalone watch waits for a pending operation to identify
// itself (a slow page, a pending permission ask, a virule://-driven flow)
// before the no-intent conclusion becomes terminal.
constexpr unsigned long long kStandaloneGraceMs = 10000;

// A held operation never holds the continuation card forever: the Admin
// package is large, but a whole multiple of the page's own install
// timeout still bounds it.
constexpr unsigned long long kContinuationHoldMs = 15ull * 60ull * 1000ull;

inline std::atomic<bool> g_released{ false };
inline std::mutex g_mutex;
inline std::string g_op;               // "" until a takeover arrived
inline std::atomic<bool> g_superseded{ false }; // standalone replaced by an op
inline std::atomic<bool> g_standalone_terminal{ false }; // watch concluded

inline bool released() { return g_released.load(); }

// A Setup takeover is in flight: one arrived and Setup has not yet been
// released into the next surface. The client self-update's safe-point
// check reads this so a binary swap never lands mid-handoff.
inline bool takeover_in_flight() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return !g_op.empty() && !g_released.load();
}

inline void release() { g_released.store(true); }

// Wait for the native card to actually exist before releasing Setup (the
// invariant is about VISIBLE surfaces, not intentions).
inline void release_when_card_visible() {
    for (int i = 0; i < 20 && !result_card::is_visible(); ++i) Sleep(100);
    release();
}

// Show a Working card, retrying briefly: a superseded standalone card
// closes asynchronously, and the one-card-at-a-time rule makes show a
// no-op until its thread is reaped. Idempotent when a Working card is
// already up. SUCCESS IS A WORKING CARD SPECIFICALLY (dead-air fix
// 2026-09-05): a card that close() has already condemned can keep its
// window alive for a few more milliseconds, and accepting that dying
// window as "the next surface is visible" released Setup into ~15s of
// nothing while the Admin package installed. A non-Working card here is
// never the surface this handoff needs, so keep retrying until the
// Working card actually exists.
inline void show_working_retry(const char* primary) {
    for (int i = 0; i < 12; ++i) {
        result_card::show_working(primary, "");
        if (result_card::is_working_visible()) return;
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
    // THE NATIVE CONTINUATION IS UNCONDITIONAL (owner handoff rule): Setup
    // may close only into a ready native surface, and a live browser page
    // does not waive that - it renders its own progress in parallel.
    log::client("takeover: INSTALL_ADMIN; native continuation");
    show_working_retry("Finishing up\xE2\x80\xA6");
    release_when_card_visible();

    // Already present and current: the intent ("get VIRULE onto this
    // machine") is satisfied by opening it; re-running the verified
    // pipeline would re-download the whole package for nothing. Unknown
    // versions never short-circuit (no currency claims from unknowns).
    if (admin_install::admin_installed()) {
        admin_install::refresh_update_check(admin_install::kUpdateCheckFreshMs);
        std::string approved;
        {
            std::lock_guard<std::mutex> lock(admin_install::g_update_mutex);
            approved = admin_install::g_approved_version;
        }
        const std::string installed = admin_install::authoritative_admin_version();
        if (!approved.empty() && !installed.empty() &&
            !admin_install::version_is_upgrade(approved, installed)) {
            log::client("takeover: Admin already current; opening it");
            (void)admin_install::open_installed_admin();
            result_card::close();
            release();
            return;
        }
    }

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
        // The page's own admin_install won the start race; ONE operation
        // runs either way, and this card holds until it finishes (a fresh
        // install launches the Admin itself at completion).
        const ULONGLONG deadline = GetTickCount64() + kContinuationHoldMs;
        while (admin_install::g_busy.load() && GetTickCount64() < deadline) {
            Sleep(300);
        }
        result_card::close();
    } else {
        result_card::update("Something went wrong.", "Try again at virule.app.");
        result_card::wait_closed();
    }
    release();
}

// The STANDALONE watch identified a browser-driven Admin operation: the
// same continuation surface, held until that (page-owned) operation ends.
inline void run_admin_continuation() {
    log::client("takeover: browser-owned Admin operation; native continuation");
    show_working_retry("Finishing up\xE2\x80\xA6");
    release_when_card_visible();
    // The page's operation may still be spinning up (the drove flag
    // precedes the busy flag by a thread hop); give it a moment to exist,
    // then hold until it ends. A fresh install launches the Admin itself.
    const ULONGLONG start_deadline = GetTickCount64() + 5000;
    while (!admin_install::g_busy.load() &&
           GetTickCount64() < start_deadline) {
        Sleep(100);
    }
    const ULONGLONG deadline = GetTickCount64() + kContinuationHoldMs;
    while (admin_install::g_busy.load() && GetTickCount64() < deadline) {
        Sleep(300);
    }
    result_card::close();
    release();
}

// ---- no envelope (standalone / stale Setup) ----

inline void run_standalone() {
    // THE SINGLE AUTHORITATIVE DECISION: this watch terminates in exactly
    // one of two surfaces - a pending operation's continuation, or the
    // standalone completion card. It never releases Setup into neither
    // (a merely-connected idle page is NOT an operation and no longer
    // suppresses the card: with no pending intent anywhere, Ready +
    // Continue IS the correct standalone experience).
    const ULONGLONG deadline = GetTickCount64() + kStandaloneGraceMs;
    for (;;) {
        if (g_superseded.load()) return; // a late envelope owns the run
        if (bridge::g_last_qa_tick.load() != 0) {
            // A QA verification is being driven; QA's own browser/native
            // ownership doctrine provides the surface (unchanged, on
            // purpose - QA semantics are locked).
            log::client("takeover: native QA progress owns the flow");
            release();
            return;
        }
        if (bridge::g_page_drove_admin.load() ||
            admin_install::g_busy.load()) {
            // A browser-driven Admin operation identified itself DURING
            // the watch: pending intent exists, the continuation wins,
            // and Ready/Continue never flashes first.
            run_admin_continuation();
            return;
        }
        if (GetTickCount64() >= deadline) break;
        Sleep(200);
    }
    // The grace expired with no operation: as positively as this machine
    // can ever conclude, no pending intent exists. TERMINAL from here (a
    // late browser-owned operation revokes the standing card through
    // supersede_standalone).
    g_standalone_terminal.store(true);
    log::client("takeover: standalone completion surface");
    result_card::show_ready();
    release_when_card_visible();
    // A revocation that raced the card's creation still wins: the show
    // above is what it could not close yet.
    if (g_superseded.load() || bridge::g_page_drove_admin.load() ||
        admin_install::g_busy.load()) {
        result_card::close();
    }
}

// A browser-owned operation surfaced AFTER the standalone conclusion
// became terminal (a closed/throttled tab delivering its durable intent
// late): the standing "VIRULE is ready" card closes; the operation owns
// the flow now. BEFORE the conclusion is terminal this is deliberately a
// no-op - the watch itself converts a live arrival into the native
// continuation (and Setup is still waiting on that thread's release, so
// standing it down here would strand Setup with no surface at all).
inline void supersede_standalone() {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_op != "STANDALONE") return;
        if (!g_standalone_terminal.load()) return; // the watch converts
        if (g_superseded.exchange(true)) return;   // already revoked
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
                // The late-envelope upgrade. A LIVE WORKING CARD IS KEPT
                // (dead-air fix 2026-09-05): when the standalone watch has
                // already converted into the continuation ("Finishing up…"),
                // that card IS the surface the upgraded operation wants.
                // Closing it here just to re-show the identical card opened
                // a race - the re-show accepted the dying window as visible,
                // Setup was released, the queued close then destroyed the
                // card, and the owner's real install ran behind ~15s of
                // dead air. Only a non-Working card (the standalone Ready
                // card) still closes; the standalone conclusion stays
                // revocable exactly as before.
                g_superseded.store(true);
                if (!result_card::is_working_visible()) result_card::close();
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
