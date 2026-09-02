#pragma once
#include <chrono>
#include <string>

namespace virule::core {

std::string utc_timestamp_rfc3339(); // e.g., 2026-01-05T12:34:56Z

class MonotonicClock {
 public:
  using time_point = std::chrono::steady_clock::time_point;
  static time_point now() { return std::chrono::steady_clock::now(); }
};

} // namespace virule::core
