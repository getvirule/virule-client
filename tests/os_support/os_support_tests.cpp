// Supported Windows versions (shared/os_support.hpp; owner decision
// 2026-10-30, VIRULE/docs/specs/evaluation-security.md "Windows support").
// Built and run by tests\os_support\run_tests.bat. The pure rule over every
// Windows NT version that matters, the sentence, and the running computer's
// real version (this computer must be supported, and must not be read
// through the manifest-dependent APIs that report 6.2 on Windows 10).

#include <cstdio>
#include <cwchar>

#include "shared/os_support.hpp"

namespace os = vclient::os_support;

static int g_pass = 0, g_fail = 0;
static void check(const char* what, bool ok) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    (ok ? g_pass : g_fail)++;
}

static os::WindowsVersion v(unsigned long major, unsigned long minor, unsigned long build) {
    os::WindowsVersion w;
    w.known = true;
    w.major = major;
    w.minor = minor;
    w.build = build;
    return w;
}

int main() {
    check("Windows XP (5.1) refused", !os::is_supported(v(5, 1, 2600)));
    check("Windows Vista (6.0) refused", !os::is_supported(v(6, 0, 6002)));
    check("Windows 7 (6.1) refused", !os::is_supported(v(6, 1, 7601)));
    check("Windows 8 (6.2) refused", !os::is_supported(v(6, 2, 9200)));
    check("Windows 8.1 (6.3) refused", !os::is_supported(v(6, 3, 9600)));
    check("Windows 10 1507 (10.0.10240) accepted", os::is_supported(v(10, 0, 10240)));
    check("Windows 10 22H2 (10.0.19045) accepted", os::is_supported(v(10, 0, 19045)));
    check("Windows 11 21H2 (10.0.22000) accepted", os::is_supported(v(10, 0, 22000)));
    check("Windows 11 24H2 (10.0.26100) accepted", os::is_supported(v(10, 0, 26100)));
    check("a later major version accepted", os::is_supported(v(11, 0, 30000)));
    check("an unreadable version is not taken for an old Windows", os::is_supported(os::WindowsVersion{}));
    check("the sentence states the requirement, no em dash",
          std::wcscmp(os::kUnsupportedSentence, L"VIRULE requires Windows 10 or later.") == 0 &&
              std::wcschr(os::kUnsupportedSentence, L'\u2014') == nullptr);
    const os::WindowsVersion here = os::current_windows();
    std::printf("this computer: %lu.%lu.%lu (known %d)\n", here.major, here.minor, here.build, here.known ? 1 : 0);
    check("this computer's real version is read (not the manifest's 6.2)", here.known && here.major >= 10);
    check("this computer is supported", os::is_supported(here));
    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
