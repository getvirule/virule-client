#pragma once
// INSTALLED CAPABILITIES (owner ruling 2026-10-16, client 0.9.9).
//
// VIRULE is ONE installation (one Virule-Setup.exe, one managed Admin
// package) whose capabilities are acquired through different ENTRY POINTS:
//
//   dev_tools   the homepage "Get VIRULE Dev Tools" entry: the Admin shows
//               Games, Evaluations and Campaigns;
//   evaluator   an evaluator's "Install VIRULE" entry (the website account
//               page): the Admin shows Assignments.
//
// The entry point determines the capability and the existing browser /
// native handoff carries it (the page's admin_install, the Setup envelope,
// or capability_enable on an installation that already exists). They are
// ADDITIVE: receiving one never removes another, and an existing
// installation gains a capability without reinstalling. QA invitations
// record nothing here (a QA credential is not a capability of this record).
//
// LOCAL PRESENTATION ONLY, NEVER AUTHORIZATION: this record decides what
// the Admin and the website PRESENT. It grants nothing at the VIRULE
// service, which enforces the account's own capabilities on every call.
//
// Persisted in client\state.json (`enabled_recorded`, `enabled_dev_tools`,
// `enabled_evaluator`; shared/client_state.hpp), so it is removed with the
// client state directory by every uninstall and a reinstall starts fresh.
//
// MIGRATION (one time, at client startup): an installation without a
// record gains dev_tools when the managed Admin is installed (every Admin
// installed before 0.9.9 came through the Dev Tools entry point) and never
// evaluator. The migration only ADDS, so a capability recorded in the
// moment between the bridge starting and the migration running survives.

#include <string>

#include "shared/client_state.hpp"

namespace vclient::capabilities {

struct Enabled {
    bool dev_tools = false;
    bool evaluator = false;
};

// The closed capability vocabulary.
inline bool is_known(const std::string& name) {
    return name == "dev_tools" || name == "evaluator";
}

// The ENTRY-POINT grammar shared by the page's admin_install, the Setup
// handoff envelope and the Setup takeover: only a known name is kept;
// absent or anything else is the Dev Tools entry (every caller that
// predates 0.9.9 is the homepage "Get VIRULE Dev Tools" entry).
inline std::string entry_capability(const std::string& requested) {
    return is_known(requested) ? requested : std::string("dev_tools");
}

inline Enabled enabled() {
    const auto s = state::load();
    return Enabled{ s.enabled_dev_tools, s.enabled_evaluator };
}

// Record one capability (additive). `changed_out` (optional) reports
// whether it was newly enabled. False = an unknown name or a failed save.
// INSTALLED SOFTWARE IS NOT ENROLLMENT (owner rule 2026-10-20): recording
// dev_tools here never makes the account a developer. Only the callers
// that carry the person's explicit Install Dev Tools also record the
// enrollment intent (roles::mark_developer_intent, account_roles.hpp).
inline bool enable(const std::string& name, bool* changed_out = nullptr) {
    if (changed_out) *changed_out = false;
    if (!is_known(name)) return false;
    bool changed = false;
    const bool ok = state::update([&](state::State& s) {
        bool& flag = name == "dev_tools" ? s.enabled_dev_tools
                                         : s.enabled_evaluator;
        if (flag) return false;
        flag = true;
        changed = true;
        return true;
    });
    if (changed_out) *changed_out = ok && changed;
    return ok;
}

// {"dev_tools":true,"evaluator":false}: the one wire shape, embedded as
// "enabled" in the bridge status and the account_status answer.
inline std::string enabled_json(const Enabled& e) {
    return std::string("{\"dev_tools\":") + (e.dev_tools ? "true" : "false") +
           ",\"evaluator\":" + (e.evaluator ? "true" : "false") + "}";
}

inline std::string enabled_json() { return enabled_json(enabled()); }

// The one-time startup migration (see MIGRATION above). Returns true when
// it ran now (false = already recorded, or the save failed).
inline bool migrate_once(bool admin_installed) {
    bool ran = false;
    (void)state::update([&](state::State& s) {
        if (s.enabled_recorded) return false;
        if (admin_installed) s.enabled_dev_tools = true;
        s.enabled_recorded = true;
        ran = true;
        return true;
    });
    return ran;
}

} // namespace vclient::capabilities
