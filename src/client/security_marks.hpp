#pragma once
// THE SERVICE'S SECURITY STATE OF AN ASSIGNMENT on this computer (owner
// brief 2026-10-30; VIRULE_BACKEND src/evaluations/security.ts).
//
// The runtime report's answer (client/runtime_report.hpp) carries two
// facts the service decides, and this computer keeps the last answer as two
// marker files beside the assignment's launch ticket
// (%LOCALAPPDATA%\VIRULE\evaluator\assignments\<id>\):
//
//   security_hold       the game is HELD after a security detection (on any
//                       VIRULE computer): Play is refused here
//                       (client/launcher.hpp) and by the wrapper's local
//                       check (virule/core/verified_content.hpp), whatever
//                       ticket is cached. The launcher also sets and clears
//                       it from the service's answer before every Play, and
//                       the wrapper's own online check, signed at every
//                       launch on every path, refuses a held game besides.
//   security_protected  the assignment is protected from the automatic
//                       expiry: this computer never applies its own offline
//                       absolute cut to it.
//
// Each is written when the service says so and removed when it says
// otherwise, so a release reaches this computer at its next report. A
// marker that cannot be written is logged and tried again next cycle.

#include <filesystem>
#include <string>
#include <system_error>

#include "virule/core/evaluation_evidence.hpp"

namespace vclient::security_marks {

namespace fs = std::filesystem;
namespace ev = virule::core::evaluation_evidence;

inline constexpr const wchar_t* kHold = L"security_hold";
inline constexpr const wchar_t* kProtected = L"security_protected";

inline fs::path dir_of(const fs::path& root, const std::string& assignment_id) {
    return root / L"evaluator" / L"assignments" / fs::path(std::wstring(assignment_id.begin(), assignment_id.end()));
}

inline bool has(const fs::path& root, const std::string& assignment_id, const wchar_t* name) {
    if (!ev::is_hex32(assignment_id)) return false;
    std::error_code ec;
    return fs::exists(dir_of(root, assignment_id) / name, ec);
}

/** Record what the service said; true when the marker now matches it. */
inline bool set(const fs::path& root, const std::string& assignment_id, const wchar_t* name, bool on) {
    if (!ev::is_hex32(assignment_id)) return false;
    std::error_code ec;
    const fs::path p = dir_of(root, assignment_id) / name;
    if (!on) { fs::remove(p, ec); return !fs::exists(p, ec); }
    if (fs::exists(p, ec)) return true;
    fs::create_directories(p.parent_path(), ec);
    return ev::write_file_atomic(p, "1\n");
}

/** The answer's `"<key>":true`. */
inline bool says(const std::string& body, const char* key) {
    return body.find(std::string("\"") + key + "\":true") != std::string::npos;
}

} // namespace vclient::security_marks
