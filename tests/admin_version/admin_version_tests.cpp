// THE ONE DESKTOP UPDATE RULE (client/admin_version.hpp; owner ruling
// 2026-11-13: an operator rollback also updates Desktops that already
// installed the withdrawn version). Built and run by
// tests\admin_version\run_tests.bat. Pure: starts NO client, touches no file.

#include <cstdio>
#include <string>
#include <vector>

#include "client/admin_version.hpp"

namespace av = vclient::admin_install;
using List = std::vector<std::string>;

static int g_pass = 0, g_fail = 0;
static void check(const char* what, bool ok) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    (ok ? g_pass : g_fail)++;
}

static std::string manifest(const std::string& tail) {
    return std::string("{\"version\":\"0.1.1-alpha.81\",\"channel\":\"alpha\",\"url\":\"https://x/y.zip\","
                       "\"sha256\":\"") + std::string(64, 'a') + "\",\"size\":1,\"minimumClientVersion\":\"0.9.30\"" + tail + "}";
}

int main() {
    // ---- the ordering the rule keeps (owner correction 2026-09-04) ----
    check("upgrade: alpha.82 over alpha.81", av::version_is_upgrade("0.1.1-alpha.82", "0.1.1-alpha.81"));
    check("upgrade: alpha.100 over alpha.99 (numeric, not lexical)", av::version_is_upgrade("0.1.1-alpha.100", "0.1.1-alpha.99"));
    check("no upgrade: equal", !av::version_is_upgrade("0.1.1-alpha.81", "0.1.1-alpha.81"));
    check("no upgrade: older", !av::version_is_upgrade("0.1.1-alpha.80", "0.1.1-alpha.81"));
    check("upgrade: a release over its pre-release", av::version_is_upgrade("0.1.1", "0.1.1-alpha.81"));
    check("upgrade: the triple first", av::version_is_upgrade("0.1.2-alpha.1", "0.1.1-alpha.99"));
    check("no claim: unparseable approved", !av::version_is_upgrade("garbage", "0.1.1-alpha.1"));
    check("no claim: unparseable installed", !av::version_is_upgrade("0.1.1-alpha.2", "garbage"));
    check("a 60-digit identifier orders and never throws",
          av::version_is_upgrade("0.1.1-alpha." + std::string(60, '9'), "0.1.1-alpha.81") &&
          !av::version_is_upgrade("0.1.1-alpha.81", "0.1.1-alpha." + std::string(60, '9')));
    check("leading zeros order numerically", !av::version_is_upgrade("0.1.1-alpha.081", "0.1.1-alpha.81") &&
          !av::version_is_upgrade("0.1.1-alpha.81", "0.1.1-alpha.081"));
    check("a huge triple component is no claim, never an overflow",
          !av::version_is_upgrade(std::string(40, '9') + ".0.0", "0.1.1"));

    // ---- the withdrawn list, read strictly ----
    check("no field: nothing withdrawn (every forward release)", av::parse_withdrawn(manifest("")).empty());
    check("empty list: nothing withdrawn", av::parse_withdrawn(manifest(",\"withdrawn\":[]")).empty());
    {
        const List w = av::parse_withdrawn(manifest(",\"withdrawn\":[\"0.1.1-alpha.82\"]"));
        check("one entry", w.size() == 1 && w[0] == "0.1.1-alpha.82");
    }
    {
        const List w = av::parse_withdrawn(manifest(",\"withdrawn\": [ \"0.1.1-alpha.83\" , \"0.1.1-alpha.82\" ]"));
        check("two entries, whitespace between tokens", w.size() == 2 && w[0] == "0.1.1-alpha.83" && w[1] == "0.1.1-alpha.82");
    }
    check("a non-string entry withdraws nothing", av::parse_withdrawn(manifest(",\"withdrawn\":[82]")).empty());
    check("an ungrammatical entry withdraws nothing", av::parse_withdrawn(manifest(",\"withdrawn\":[\"0.1.1 alpha\"]")).empty());
    check("an escaped entry withdraws nothing", av::parse_withdrawn(manifest(",\"withdrawn\":[\"0.1.1-alpha.82\\\\\"]")).empty());
    check("an empty-string entry withdraws nothing", av::parse_withdrawn(manifest(",\"withdrawn\":[\"\"]")).empty());
    check("a missing bracket withdraws nothing", av::parse_withdrawn(manifest(",\"withdrawn\":\"0.1.1-alpha.82\"")).empty());
    check("an unterminated list withdraws nothing", av::parse_withdrawn("{\"withdrawn\":[\"0.1.1-alpha.82\"").empty());
    check("a trailing comma withdraws nothing", av::parse_withdrawn(manifest(",\"withdrawn\":[\"0.1.1-alpha.82\",]")).empty());
    check("an object withdraws nothing", av::parse_withdrawn(manifest(",\"withdrawn\":{\"v\":\"0.1.1-alpha.82\"}")).empty());
    check("two withdrawn fields withdraw nothing (ambiguous)",
          av::parse_withdrawn(manifest(",\"withdrawn\":[\"0.1.1-alpha.82\"],\"withdrawn\":[\"0.1.1-alpha.83\"]")).empty());
    {
        std::string many = ",\"withdrawn\":[";
        for (int i = 0; i < 32; ++i) many += std::string(i ? "," : "") + "\"0.1.1-alpha." + std::to_string(100 + i) + "\"";
        check("32 entries are read", av::parse_withdrawn(manifest(many + "]")).size() == 32);
        many += ",\"0.1.1-alpha.200\"]";
        check("33 entries withdraw nothing (the bound)", av::parse_withdrawn(manifest(many)).empty());
    }

    // ---- THE RULE ----
    const List none;
    const List w82 = { "0.1.1-alpha.82" };
    check("ordinary update: approved newer, nothing withdrawn", av::update_wanted("0.1.1-alpha.82", "0.1.1-alpha.81", none));
    check("current: equal versions", !av::update_wanted("0.1.1-alpha.81", "0.1.1-alpha.81", none));
    check("NO ARBITRARY DOWNGRADE: approved older, nothing withdrawn", !av::update_wanted("0.1.1-alpha.81", "0.1.1-alpha.82", none));
    check("ROLLBACK: the installed version is exactly withdrawn -> the approved release is its update",
          av::update_wanted("0.1.1-alpha.81", "0.1.1-alpha.82", w82));
    check("a Desktop on another newer version, not listed, is not moved",
          !av::update_wanted("0.1.1-alpha.81", "0.1.1-alpha.83", w82));
    check("a Desktop already on the restored release is current", !av::update_wanted("0.1.1-alpha.81", "0.1.1-alpha.81", w82));
    check("a Desktop OLDER than the restored release still upgrades to it",
          av::update_wanted("0.1.1-alpha.81", "0.1.1-alpha.80", w82));
    check("a list naming the approved version itself never makes an installed copy of it 'update'",
          !av::update_wanted("0.1.1-alpha.81", "0.1.1-alpha.81", List{ "0.1.1-alpha.81" }));
    check("exact match only: a prefix is not the withdrawn version",
          !av::update_wanted("0.1.1-alpha.8", "0.1.1-alpha.82", List{ "0.1.1-alpha.8" }));
    check("exact match only: case matters",
          !av::update_wanted("0.1.1-alpha.81", "0.1.1-alpha.82", List{ "0.1.1-ALPHA.82" }));
    check("unknown installed version: no claim", !av::update_wanted("0.1.1-alpha.81", "", w82));
    check("unknown approved version: no claim", !av::update_wanted("", "0.1.1-alpha.82", w82));
    check("ungrammatical installed version: no claim even if listed",
          !av::update_wanted("0.1.1-alpha.81", "0.1.1 alpha.82", List{ "0.1.1 alpha.82" }));
    check("a chain: every listed version returns to the restored release",
          av::update_wanted("0.1.1-alpha.80", "0.1.1-alpha.83", List{ "0.1.1-alpha.83", "0.1.1-alpha.82", "0.1.1-alpha.81" }) &&
          av::update_wanted("0.1.1-alpha.80", "0.1.1-alpha.81", List{ "0.1.1-alpha.83", "0.1.1-alpha.82", "0.1.1-alpha.81" }));
    check("an unreadable list falls back to the ordinary rule (no pull-back)",
          !av::update_wanted("0.1.1-alpha.81", "0.1.1-alpha.82", av::parse_withdrawn(manifest(",\"withdrawn\":[82]"))));

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
