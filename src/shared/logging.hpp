#pragma once
// Bounded diagnostic logging. Technical detail belongs here, never in the
// primary experience (browser copy stays sparse; native UI stays minimal).
// The log is size-capped: when it exceeds the cap it is rotated once to
// .old, so the pair can never grow past ~2 * kMaxLogBytes.

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <system_error>

#include "shared/paths.hpp"
#include "virule/core/time.hpp"

namespace vclient::log {

inline constexpr std::uintmax_t kMaxLogBytes = 256 * 1024;

inline std::mutex& mutex() {
    static std::mutex m;
    return m;
}

inline void write(const char* file_name, const std::string& text) {
    try {
        std::lock_guard<std::mutex> lock(mutex());
        const auto dir = paths::client_logs_dir();
        if (dir.empty()) return;
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        const auto path = dir / file_name;
        const auto size = std::filesystem::exists(path, ec)
            ? std::filesystem::file_size(path, ec) : 0;
        if (!ec && size > kMaxLogBytes) {
            const auto old = dir / (std::string(file_name) + ".old");
            std::filesystem::remove(old, ec);
            ec.clear();
            std::filesystem::rename(path, old, ec);
        }
        std::ofstream f(path, std::ios::app);
        if (f) f << virule::core::utc_timestamp_rfc3339() << " " << text << "\n";
    } catch (...) {
    }
}

inline void client(const std::string& text) { write("virule-client.log", text); }
inline void setup(const std::string& text)  { write("virule-setup.log", text); }

} // namespace vclient::log
