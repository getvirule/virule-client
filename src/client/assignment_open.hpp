#pragma once
// OPEN VIRULE ON AN ASSIGNMENT (2026-10-22; docs/ARCHITECTURE.md, the
// message set: assignment_open / assignment_open_take, and admin_launch's
// fallback).
//
// The evaluation wrapper's "Quit and Open VIRULE" used to send
// admin_launch, which is the update-on-launch handoff: the native
// "Updating..." card showed even when no update existed. The wrapper now
// sends {"type":"assignment_open","assignment_id"}: the Client records an
// OPEN INTENT here (in memory: the latest wins, it expires after ten
// minutes, and it survives an Admin update relaunch because this process
// stays) and opens or focuses the Admin through the ordinary admin_open
// path. The Admin host takes the intent once it is up
// ({"type":"assignment_open_take"}) and shows that assignment.
//
// THE admin_launch FALLBACK (OWNER RULING 2026-10-22, for games built
// before this release): an admin_launch with NO approved Admin update opens
// or focuses the Admin normally, with no card; with a real approved update
// it is the update-on-launch handoff exactly as before (admin_launch_route).

#include <cstdint>
#include <mutex>
#include <string>

namespace vclient::assignment_open {

inline constexpr std::uint64_t kIntentLifeMs = 10ull * 60 * 1000;

class Intent {
public:
    void set(const std::string& assignment_id, std::uint64_t now_ms) {
        std::lock_guard<std::mutex> lock(m_);
        id_ = assignment_id;
        at_ms_ = now_ms;
    }
    // The intent, cleared; "" when there is none or it expired.
    std::string take(std::uint64_t now_ms) {
        std::lock_guard<std::mutex> lock(m_);
        std::string out;
        if (!id_.empty() && now_ms >= at_ms_ && now_ms - at_ms_ <= kIntentLifeMs) out = id_;
        id_.clear();
        at_ms_ = 0;
        return out;
    }

private:
    std::mutex m_;
    std::string id_;
    std::uint64_t at_ms_ = 0;
};

inline Intent& intent() { static Intent i; return i; }

inline std::string take_json(const std::string& id) {
    return "{\"type\":\"assignment_open_intent\",\"assignment_id\":\"" + id + "\"}";
}

inline bool is_hex32(const std::string& s) {
    if (s.size() != 32) return false;
    for (const char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

// What an admin_launch does: the update handoff only for a real approved
// update, else the ordinary open (no card).
enum class LaunchRoute { UpdateHandoff, OpenAdmin };
inline LaunchRoute admin_launch_route(bool approved_update_available) {
    return approved_update_available ? LaunchRoute::UpdateHandoff : LaunchRoute::OpenAdmin;
}

} // namespace vclient::assignment_open
