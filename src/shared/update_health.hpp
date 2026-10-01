#pragma once
// UPDATE CONNECTIVITY HEALTH (owner spec 2026-10-01).
//
// A persisted record of whether this client can REACH the VIRULE update
// service, kept so the Admin can show one passive notice when it has been
// unreachable for a long time:
//
//   blocked = more than 48 hours since the last contact
//             AND at least 3 scheduled checks failed to connect since then.
//
// WHAT COUNTS. Only connectivity counts: a check that received ANY HTTP
// response reached VIRULE infrastructure, whatever the status (a 500, a
// 404, a manifest this client refuses) and is recorded as contact. A check
// that got no HTTP response at all (DNS failure, timeout, refused
// connection, TLS failure) is a failed attempt. Service-side failures are
// never evidence that the user's network blocks VIRULE.
//
// WHICH ATTEMPTS. Every check updates the last-contact instant when it
// reaches the service, but only SCHEDULED checks (startup and the periodic
// recheck) add to the failure count: an Admin Settings ask or an install
// retried by the user must not fast-forward the notice.
//
// The 48-hour clock starts at the last contact, or, on a machine that has
// never reached the service, at its first recorded attempt. One success
// clears everything, which is what removes the notice.
//
// State: <client state dir>\update_health.json, its own small file rather
// than state.json so no other writer's load-modify-save can drop it and an
// older binary cannot erase it. Fail-soft: an unreadable file is "never
// attempted", and a write that fails is retried on the next result.

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <system_error>

#include "shared/json_scan.hpp"

namespace vclient::update_health {

constexpr long long kBlockedAfterSeconds = 48ll * 60ll * 60ll;
constexpr long long kBlockedAfterAttempts = 3;

struct State {
    long long last_contact_utc = 0; // 0 = nothing recorded yet
    long long failed_attempts = 0;  // scheduled connectivity failures since
};

// Apply one finished update-service request.
inline void note_result(State& s, long long now, bool reached, bool scheduled) {
    if (reached) {
        s.last_contact_utc = now;
        s.failed_attempts = 0;
        return;
    }
    if (s.last_contact_utc <= 0 || s.last_contact_utc > now) {
        // Never reached (or the clock moved backwards past the record):
        // the 48 hours are measured from this attempt.
        s.last_contact_utc = now;
    }
    if (scheduled && s.failed_attempts < 1000000) ++s.failed_attempts;
}

inline bool blocked(const State& s, long long now) {
    return s.last_contact_utc > 0 &&
           s.failed_attempts >= kBlockedAfterAttempts &&
           now - s.last_contact_utc > kBlockedAfterSeconds;
}

inline std::string to_json(const State& s) {
    return "{\"last_contact_utc\":" + std::to_string(s.last_contact_utc) +
           ",\"failed_attempts\":" + std::to_string(s.failed_attempts) + "}\n";
}

inline State from_json(const std::string& text) {
    State s;
    (void)json_scan::find_number_in(text, 0, text.size(), "last_contact_utc",
                                    s.last_contact_utc);
    (void)json_scan::find_number_in(text, 0, text.size(), "failed_attempts",
                                    s.failed_attempts);
    return s;
}

inline std::mutex& mutex() {
    static std::mutex m;
    return m;
}

inline State load(const std::filesystem::path& file) {
    if (file.empty()) return {};
    std::ifstream f(file, std::ios::binary);
    if (!f) return {};
    std::string text((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    return from_json(text);
}

inline bool save(const std::filesystem::path& file, const State& s) {
    if (file.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    const auto tmp = file.parent_path() / (file.filename().string() + ".tmp");
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        const std::string body = to_json(s);
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        if (!f) return false;
    }
    std::filesystem::rename(tmp, file, ec);
    if (ec) {
        std::error_code ec2;
        std::filesystem::remove(tmp, ec2);
        return false;
    }
    return true;
}

// Record one finished request against the persisted state.
inline void record(const std::filesystem::path& file, long long now,
                   bool reached, bool scheduled) {
    std::lock_guard<std::mutex> lock(mutex());
    State s = load(file);
    const State before = s;
    note_result(s, now, reached, scheduled);
    if (s.last_contact_utc == before.last_contact_utc &&
        s.failed_attempts == before.failed_attempts) {
        return;
    }
    (void)save(file, s);
}

inline bool is_blocked(const std::filesystem::path& file, long long now) {
    std::lock_guard<std::mutex> lock(mutex());
    return blocked(load(file), now);
}

} // namespace vclient::update_health
