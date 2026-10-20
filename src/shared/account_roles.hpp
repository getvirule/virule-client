#pragma once
// ACCOUNT ROLES ON THIS INSTALLATION (owner ruling 2026-10-20).
//
// Roles are the ACCOUNT's, granted by the VIRULE service through two
// enrollment actions only: Install Dev Tools enrolls `developer`, an
// accepted evaluator invitation enrolls `evaluator`. Once signed in, the
// Admin's navigation follows the account's service-confirmed roles; the
// installed capability record (installed_capabilities.hpp, the entry point)
// decides only what a never-signed-in installation shows. This file keeps
// the two local facts that model needs, in its own small file so the
// pinned Virule-Setup, which rewrites state.json with its own field list,
// can never drop them:
//
//   pending_developer  an EXPLICIT Install Dev Tools on this installation
//                      that the service has not been told yet. Only the
//                      person's own Get VIRULE Dev Tools / Install Dev Tools
//                      action records it (owner rule 2026-10-20, the
//                      explicit-enrollment-only law): the bridge's
//                      capability_enable dev_tools (the homepage's Get VIRULE
//                      Dev Tools on an installation without them, or the
//                      Admin's Settings > Install Dev Tools), a page's
//                      admin_install carrying "enroll_developer":true (the
//                      homepage's Get VIRULE Dev Tools resumed through the
//                      client), or Setup's INSTALL_ADMIN dev_tools envelope
//                      (the website hands Setup one only for Get VIRULE Dev
//                      Tools). Never an update, an open, a repair, a sign-in
//                      or the Dev Tools files already installed here. The
//                      VIRULE Client delivers it (POST
//                      /v1/account/developer/enable) to the account it is
//                      signed in to, at once; one made SIGNED OUT goes to the
//                      account that signs in next. One made signed in belongs
//                      to that account only and is dropped at sign-out, so it
//                      can never reach a different account. One intent, one
//                      delivery: it is cleared once the service answered it.
//                      Version 1 records (client 0.9.12, which recorded an
//                      intent on every homepage Update) are read with no
//                      intent: theirs cannot be told apart from a real one.
//   remembered         the roles the service last confirmed for the account
//                      signed in here. Kept through sign-out, so a
//                      signed-out VIRULE keeps the previous layout; the next
//                      sign-in replaces it with that account's roles.
//
// LOCAL PRESENTATION ONLY: nothing here grants anything at the service,
// which enforces the account's capabilities on every call. Removed with
// the client state directory by every uninstall.

#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>

#include "shared/paths.hpp"

namespace vclient::roles {

struct Record {
    bool pending_developer = false;
    // The intent was recorded while signed in: it belongs to that account
    // and is dropped at sign-out (never carried to the next sign-in).
    bool pending_bound = false;
    bool remembered = false;
    bool developer = false;
    bool evaluator = false;
};

inline std::mutex g_mutex;

inline std::filesystem::path file() {
    const auto d = paths::client_state_dir();
    return d.empty() ? d : d / L"account_roles.json";
}

inline Record load_unlocked() {
    Record r;
    const auto f = file();
    if (f.empty()) return r;
    std::ifstream in(f, std::ios::binary);
    if (!in) return r;
    const std::string t((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    // Only a version 2 record carries a trustworthy intent (header).
    const bool v2 = t.find("\"version\":2") != std::string::npos;
    r.pending_developer = v2 && t.find("\"pending_developer\":true") != std::string::npos;
    r.pending_bound = r.pending_developer && t.find("\"pending_bound\":true") != std::string::npos;
    r.remembered = t.find("\"remembered\":true") != std::string::npos;
    r.developer = t.find("\"developer\":true") != std::string::npos;
    r.evaluator = t.find("\"evaluator\":true") != std::string::npos;
    return r;
}

inline bool save_unlocked(const Record& r) {
    const auto f = file();
    if (f.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(f.parent_path(), ec);
    const auto b = [](bool v) { return v ? "true" : "false"; };
    const std::string body = std::string("{\"version\":2,\"pending_developer\":") + b(r.pending_developer) +
        ",\"pending_bound\":" + b(r.pending_bound) +
        ",\"remembered\":" + b(r.remembered) + ",\"developer\":" + b(r.developer) +
        ",\"evaluator\":" + b(r.evaluator) + "}";
    std::ofstream out(f, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(body.data(), (std::streamsize)body.size());
    return out.good();
}

inline Record load() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return load_unlocked();
}

// Read-modify-write under the one lock; `change` returns whether to save.
template <class F>
inline bool update(F change) {
    std::lock_guard<std::mutex> lock(g_mutex);
    Record r = load_unlocked();
    if (!change(r)) return true;
    return save_unlocked(r);
}

// Set by the account module at startup: deliver a pending enrollment now
// (it does nothing while signed out), and whether an account is signed in
// here right now (an intent made signed in is bound to that account).
inline std::function<void()> g_on_developer_intent;
inline std::function<bool()> g_signed_in;

// The person explicitly chose Install Dev Tools on this installation (the
// callers listed in the header, and no other). The remembered layout gains
// Dev Tools at once (the person asked for them here, so a signed-out VIRULE
// shows them); the account receives the grant on delivery.
inline void mark_developer_intent() {
    const bool bound = g_signed_in && g_signed_in();
    (void)update([&](Record& r) {
        if (r.pending_developer && r.pending_bound == bound && (!r.remembered || r.developer)) return false;
        r.pending_developer = true;
        r.pending_bound = bound;
        if (r.remembered) r.developer = true;
        return true;
    });
    if (g_on_developer_intent) g_on_developer_intent();
}

inline void clear_developer_intent() {
    (void)update([](Record& r) {
        if (!r.pending_developer) return false;
        r.pending_developer = false;
        r.pending_bound = false;
        return true;
    });
}

// Sign-out: an undelivered intent made while signed in belonged to that
// account and must never reach the next one. One made signed out is kept
// for the next sign-in.
inline void drop_bound_intent() {
    (void)update([](Record& r) {
        if (!r.pending_developer || !r.pending_bound) return false;
        r.pending_developer = false;
        r.pending_bound = false;
        return true;
    });
}

// The roles the service just confirmed for the signed-in account.
inline void remember(bool developer, bool evaluator) {
    (void)update([&](Record& r) {
        if (r.remembered && r.developer == developer && r.evaluator == evaluator) return false;
        r.remembered = true;
        r.developer = developer;
        r.evaluator = evaluator;
        return true;
    });
}

} // namespace vclient::roles
