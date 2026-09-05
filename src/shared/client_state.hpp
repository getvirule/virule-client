#pragma once
// VIRULE Client machine-local state: %LOCALAPPDATA%\VIRULE\client\state.json.
// Tiny, flat, and owned exclusively by the client (removed by uninstall).
//
//   { "version": 1,
//     "created_dev_machine_cred": true|false,   // uninstall provenance
//     "installed_version": "x.y.z",             // the installed CLIENT
//     "admin_version": "x.y.z-alpha.n",         // the managed Admin install
//     "created_desktop_shortcut": true|false,   // uninstall provenance
//     "admin_hold_version": "x.y.z-alpha.n",    // launch-update failure hold
//     "admin_hold_failed_utc": 1756944000,      //   when the failure happened
//     "admin_hold_until_utc": 1756965600 }      //   launch retry-after expiry
//
// `created_dev_machine_cred` records that THIS product created the machine
// identity file. A full VIRULE uninstall removes dev_machine.cred only when
// this is true AND no VIRULE Admin database exists, because on an Admin
// machine that file is the developer's press/QA signing identity and is
// never the client's to destroy.
//
// `admin_version` is the version of the managed Admin installation under
// %LOCALAPPDATA%\Programs\VIRULE\Admin\, recorded from the approved release
// manifest at install/update time (the Admin binaries are never probed for
// a version). It is meaningful only while the installed Admin executable
// actually exists.
//
// `created_desktop_shortcut` records that THIS client created the desktop
// shortcut to the installed Admin, so uninstall removes exactly what it
// created and never a shortcut the user made themselves.
//
// The `admin_hold_*` triple is THE PERSISTED LAUNCH-UPDATE FAILURE HOLD
// (audit M2, P2 pass 2026-09-04): a launch-time Admin update to
// `admin_hold_version` failed at `admin_hold_failed_utc`, and launch-time
// update claims for that exact version stay suppressed until
// `admin_hold_until_utc`, across client restarts. Empty version = no hold.
// admin_install.hpp owns every rule (set, clear, expiry, contexts).

#include <filesystem>
#include <fstream>
#include <string>

#include "shared/json_scan.hpp"
#include "shared/paths.hpp"

namespace vclient::state {

struct State {
    bool created_dev_machine_cred = false;
    std::string installed_version;
    std::string admin_version;
    bool created_desktop_shortcut = false;
    std::string admin_hold_version;      // "" = no launch-update hold
    long long admin_hold_failed_utc = 0;
    long long admin_hold_until_utc = 0;
};

inline State load() {
    State s;
    const auto file = paths::client_state_file();
    if (file.empty()) return s;
    std::ifstream in(file, std::ios::binary);
    if (!in) return s;
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    s.created_dev_machine_cred =
        text.find("\"created_dev_machine_cred\":true") != std::string::npos;
    (void)json_scan::find_string_in(text, 0, text.size(), "installed_version",
                                    s.installed_version);
    (void)json_scan::find_string_in(text, 0, text.size(), "admin_version",
                                    s.admin_version);
    s.created_desktop_shortcut =
        text.find("\"created_desktop_shortcut\":true") != std::string::npos;
    (void)json_scan::find_string_in(text, 0, text.size(), "admin_hold_version",
                                    s.admin_hold_version);
    (void)json_scan::find_number_in(text, 0, text.size(),
                                    "admin_hold_failed_utc",
                                    s.admin_hold_failed_utc);
    (void)json_scan::find_number_in(text, 0, text.size(),
                                    "admin_hold_until_utc",
                                    s.admin_hold_until_utc);
    return s;
}

inline bool save(const State& s) {
    const auto file = paths::client_state_file();
    if (file.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    std::string body = "{\"version\":1,\"created_dev_machine_cred\":";
    body += s.created_dev_machine_cred ? "true" : "false";
    body += ",\"installed_version\":\"" + json_scan::json_escape(s.installed_version) + "\"";
    body += ",\"admin_version\":\"" + json_scan::json_escape(s.admin_version) + "\"";
    body += ",\"created_desktop_shortcut\":";
    body += s.created_desktop_shortcut ? "true" : "false";
    body += ",\"admin_hold_version\":\"" +
            json_scan::json_escape(s.admin_hold_version) + "\"";
    body += ",\"admin_hold_failed_utc\":" + std::to_string(s.admin_hold_failed_utc);
    body += ",\"admin_hold_until_utc\":" + std::to_string(s.admin_hold_until_utc);
    body += "}";
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(body.data(), (std::streamsize)body.size());
    return out.good();
}

inline void mark_created_dev_machine_cred() {
    State s = load();
    if (s.created_dev_machine_cred) return;
    s.created_dev_machine_cred = true;
    (void)save(s);
}

} // namespace vclient::state
