#include "virule/core/time.hpp"
#include <ctime>
#include <iomanip>
#include <sstream>

namespace virule::core {

std::string utc_timestamp_rfc3339() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

} // namespace virule::core
