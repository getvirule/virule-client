// The game's launch file name (shared/launch_name.hpp; audit L-25,
// 2026-11-11). Built and run by tests\launch_name\run_tests.bat. Pure: starts
// NO client, touches no file.

#include <cstdio>
#include <string>

#include "shared/launch_name.hpp"

namespace ln = vclient::launch_name;

static int g_pass = 0, g_fail = 0;
static void check(const char* what, bool ok) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    (ok ? g_pass : g_fail)++;
}

int main() {
    check("a bare .exe name is accepted", ln::is_safe("Game.exe"));
    check("the extension is case-insensitive", ln::is_safe("GAME.EXE"));
    check("spaces, dots and brackets in the name are accepted", ln::is_safe("My Game v1.2 (final).exe"));
    check("a non-ASCII name is accepted", ln::is_safe("\xE3\x82\xB2\xE3\x83\xBC\xE3\x83\xA0.exe"));
    check("a 120-character stem (the service's maximum) is accepted",
          ln::is_safe(std::string(120, 'a') + ".exe"));

    check("empty is refused", !ln::is_safe(""));
    check("a backslash is refused", !ln::is_safe("bin\\Game.exe"));
    check("a forward slash is refused", !ln::is_safe("bin/Game.exe"));
    check("a parent step is refused", !ln::is_safe("..\\..\\Windows\\System32\\cmd.exe"));
    check("a drive root is refused", !ln::is_safe("C:\\Windows\\System32\\cmd.exe"));
    check("a UNC path is refused", !ln::is_safe("\\\\server\\share\\Game.exe"));
    check("an alternate data stream is refused", !ln::is_safe("Game.exe:stream.exe"));
    check("a drive-relative name is refused", !ln::is_safe("C:Game.exe"));
    check("'..' is refused", !ln::is_safe(".."));
    check("a control character is refused", !ln::is_safe(std::string("Game\x01.exe")));
    check("an embedded NUL is refused", !ln::is_safe(std::string("Game\0.exe", 9)));
    check("a quote is refused", !ln::is_safe("Game\".exe"));
    check("wildcards are refused", !ln::is_safe("*.exe") && !ln::is_safe("Game?.exe"));
    check("redirection characters are refused", !ln::is_safe("a<b.exe") && !ln::is_safe("a>b.exe") && !ln::is_safe("a|b.exe"));
    check("a name that is only the extension is refused", !ln::is_safe(".exe"));
    check("a non-.exe file is refused", !ln::is_safe("Game.bat") && !ln::is_safe("Game.exe.lnk"));
    check("an oversized name is refused", !ln::is_safe(std::string(2000, 'a') + ".exe"));

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
