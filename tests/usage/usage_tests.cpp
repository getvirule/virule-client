// Usage spool, check-in and update-health tests (docs\ARCHITECTURE.md,
// "Usage batches ride the update check" and "Update connectivity health").
//
// Built and run by tests\usage\run_tests.bat. Compiles the REAL headers the
// client ships (the vendored usage_spool.hpp, usage_checkin.hpp,
// manifest_request.hpp, update_health.hpp, http_client.hpp); nothing is
// stubbed. No resident client, no port 47612, no machine credential.
//
//   usage_tests.exe                       the unit sections below
//   usage_tests.exe seed <dir> <n> [s]    spool n events through the Writer
//                                         and seal them ([s] = staging)
//   usage_tests.exe request <url> <dir> <health file> <0|1 scheduled> [admin] [mode]
//                                         ONE manifest request exactly as the
//                                         client makes it; prints the result.
//                                         [admin] = installed Admin version or
//                                         "-"; [mode] "anon" = no identity,
//                                         "rekey" = a second machine key
//
// The two helper modes are driven by tools\usage_checkin_test.mjs, which
// stands the real VIRULE service code up behind a local HTTP server.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "shared/manifest_request.hpp"
#include "shared/update_health.hpp"
#include "shared/usage_checkin.hpp"
#include "virule/core/dev_machine_proof.hpp"
#include "virule/core/time.hpp"
#include "virule/core/usage_spool.hpp"

namespace fs = std::filesystem;
namespace us = virule::usage_spool;
namespace uc = vclient::usage_checkin;
namespace uh = vclient::update_health;
namespace dmp = virule::core::dev_machine::proof;

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_passed; } \
    else { ++g_failed; std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
} while (0)
#define SECTION(name) std::printf("-- %s\n", name)

// A fixed test identity: the same Ed25519 code the product signs with.
// `salt` selects a different key for the same installation (a re-key).
static uc::Identity test_identity(int salt = 3) {
    std::vector<unsigned char> seed(32);
    for (int i = 0; i < 32; ++i) seed[static_cast<size_t>(i)] = static_cast<unsigned char>(i * 7 + salt);
    unsigned char pk[32];
    dmp::detail::public_from_seed(seed.data(), pk);
    uc::Identity id;
    id.public_key_hex = dmp::detail::to_hex(pk, 32);
    id.install_id = "0123456789abcdef0123456789abcdef";
    id.sign_hex = [seed](const std::string& m) {
        unsigned char pk2[32];
        dmp::detail::public_from_seed(seed.data(), pk2);
        unsigned char sig[64];
        dmp::detail::sign_detached(seed.data(), pk2,
            reinterpret_cast<const unsigned char*>(m.data()), m.size(), sig);
        return dmp::detail::to_hex(sig, sizeof(sig));
    };
    return id;
}

static fs::path fresh_dir(const char* name) {
    const fs::path d = fs::temp_directory_path() / "virule-usage-tests" / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d, ec);
    return d;
}

static std::string read_all(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static const char* kWorkspace = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char* kGame = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static us::Event ev(const char* code, const char* detail = "") {
    us::Event e;
    e.code = code;
    e.game_uuid = kGame;
    e.detail = detail;
    return e;
}

static void test_spool_persistence() {
    SECTION("local persistence: records survive a restart and a crash");
    const fs::path dir = fresh_dir("persist");
    const std::string header = us::header_line(kWorkspace, us::random_hex(32), "0.1.1-alpha.40");
    {
        us::Writer w;
        w.start(dir, false, header);
        CHECK(w.append(ev("admin_opened")));
        CHECK(w.append(ev("game_created")));
        // The process dies here: no seal(), nothing in memory matters.
    }
    CHECK(fs::exists(dir / "open.jsonl"));
    CHECK(us::sealed_count(dir, false) == 0);
    // Nothing unsealed is ever offered for delivery.
    CHECK(us::load_sealed(dir, false, 8, 1 << 20).empty());

    us::Writer next;
    next.start(dir, false, us::header_line(kWorkspace, us::random_hex(32), "0.1.1-alpha.40"));
    CHECK(!fs::exists(dir / "open.jsonl"));
    const auto batches = us::load_sealed(dir, false, 8, 1 << 20);
    CHECK(batches.size() == 1);
    if (batches.size() == 1) {
        CHECK(us::is_hex(batches[0].id, 32));
        CHECK(batches[0].lines.size() == 3);
        CHECK(batches[0].lines[0] == header);
        CHECK(batches[0].lines[1].find("\"e\":\"admin_opened\"") != std::string::npos);
        CHECK(batches[0].lines[2].find(std::string("\"g\":\"") + kGame + "\"") != std::string::npos);
    }
    // A restart with nothing recorded creates no empty batch.
    us::Writer idle;
    idle.start(dir, false, header);
    idle.seal();
    CHECK(us::sealed_count(dir, false) == 1);
}

static void test_spool_batching() {
    SECTION("batching: sealed by size, by count, by age and at shutdown");
    {
        const fs::path dir = fresh_dir("count");
        us::Writer w;
        w.start(dir, false, us::header_line(kWorkspace, us::random_hex(32), "v"));
        for (size_t i = 0; i < us::kSealLines + 5; ++i) CHECK(w.append_at(ev("game_edited"), 1000));
        CHECK(us::sealed_count(dir, false) >= 1);
        const auto first = us::load_sealed(dir, false, 1, 1 << 20);
        CHECK(first.size() == 1 && first[0].lines.size() <= us::kSealLines);
        CHECK(first.size() == 1 && fs::file_size(first[0].path) <= us::kSealBytes);
        // Every sealed batch starts with the session header.
        CHECK(first.size() == 1 && first[0].lines[0].find("\"h\":1") != std::string::npos);
    }
    {
        const fs::path dir = fresh_dir("age");
        us::Writer w;
        w.start(dir, false, us::header_line(kWorkspace, us::random_hex(32), "v"));
        CHECK(w.append_at(ev("admin_opened"), 1000));
        CHECK(w.append_at(ev("game_edited"), 1000 + us::kSealAgeSeconds - 1));
        CHECK(us::sealed_count(dir, false) == 0);
        CHECK(w.append_at(ev("game_edited"), 1000 + us::kSealAgeSeconds));
        CHECK(us::sealed_count(dir, false) == 1);
        w.seal();
        CHECK(us::sealed_count(dir, false) == 2);
        CHECK(!fs::exists(dir / "open.jsonl"));
    }
    {
        const fs::path dir = fresh_dir("lines");
        us::Writer w;
        w.start(dir, false, us::header_line(kWorkspace, us::random_hex(32), "v"));
        CHECK(!w.append(ev("Not A Code")));
        CHECK(!w.append(ev("")));
        us::Event e = ev("tool_set", "ov=1 \"quoted\" {brace}\n\tnext");
        e.campaign_id = "not hex";
        CHECK(w.append(e));
        w.seal();
        const auto b = us::load_sealed(dir, false, 1, 1 << 20);
        CHECK(b.size() == 1 && b[0].lines.size() == 2);
        if (b.size() == 1 && b[0].lines.size() == 2) {
            const std::string& line = b[0].lines[1];
            CHECK(line.find("\"x\":\"ov=1 quoted bracenext\"") != std::string::npos);
            CHECK(line.find("\"c\":") == std::string::npos);
            CHECK(line.find('\n') == std::string::npos);
        }
    }
}

static void test_spool_bound() {
    SECTION("bounded: a long offline period drops the oldest, never grows");
    const fs::path dir = fresh_dir("bound");
    us::Writer w;
    w.start(dir, false, us::header_line(kWorkspace, us::random_hex(32), "v"));
    for (size_t i = 0; i < us::kMaxSealed + 12; ++i) {
        CHECK(w.append(ev(i + 1 == us::kMaxSealed + 12 ? "newest_marker" : "game_edited")));
        w.seal();
    }
    CHECK(us::sealed_count(dir, false) == us::kMaxSealed);
    size_t bytes = 0;
    bool newest_kept = false;
    for (const auto& entry : fs::directory_iterator(dir)) {
        bytes += static_cast<size_t>(fs::file_size(entry.path()));
        if (read_all(entry.path()).find("newest_marker") != std::string::npos) newest_kept = true;
    }
    CHECK(newest_kept);
    CHECK(bytes <= us::kMaxSealed * (us::kSealBytes + 1024));
}

static void test_environment_separation() {
    SECTION("staging and production spools never mix");
    const fs::path dir = fresh_dir("env");
    us::Writer prod, staging;
    prod.start(dir, false, us::header_line(kWorkspace, us::random_hex(32), "v"));
    CHECK(prod.append(ev("admin_opened")));
    prod.seal();
    staging.start(dir, true, us::header_line(kWorkspace, us::random_hex(32), "v"));
    CHECK(staging.append(ev("admin_opened")));
    CHECK(staging.append(ev("game_created")));
    staging.seal();
    const auto p = us::load_sealed(dir, false, 8, 1 << 20);
    const auto s = us::load_sealed(dir, true, 8, 1 << 20);
    CHECK(p.size() == 1 && p[0].lines.size() == 2);
    CHECK(s.size() == 1 && s[0].lines.size() == 3);
    CHECK(p.size() == 1 && p[0].path.filename().string().rfind("b-", 0) == 0);
    CHECK(s.size() == 1 && s[0].path.filename().string().rfind("s-", 0) == 0);
}

static void test_checkin_body_and_ack() {
    SECTION("check-in body and acknowledgement");
    const fs::path dir = fresh_dir("checkin");
    us::Writer w;
    w.start(dir, false, us::header_line(kWorkspace, us::random_hex(32), "v"));
    for (int i = 0; i < 3; ++i) {
        CHECK(w.append(ev("game_edited")));
        w.seal();
    }
    const uc::Identity id = test_identity();
    const uc::Install install{ "0.8.6", "0.1.1-alpha.40", "" };
    // Nothing pending is STILL a check-in: the installation identifies
    // itself with no batch at all.
    const uc::Pending none = uc::prepare(fresh_dir("empty"), false, id, "2026-10-01T00:00:00Z", install);
    CHECK(none.batches.empty() && !none.body.empty());
    CHECK(none.body.find("\"b\":") == std::string::npos);
    CHECK(none.body.find("\"n\":\"" + id.install_id + "\"") != std::string::npos);
    CHECK(none.body.find("\"cv\":\"0.8.6\"") != std::string::npos);
    CHECK(none.body.find("\"a\":\"0.1.1-alpha.40\"") != std::string::npos);
    CHECK(none.body.find("\"pk\":") == std::string::npos);
    CHECK(none.public_key_hex == id.public_key_hex);
    CHECK(uc::signed_message(id.install_id, none.batches, "T") ==
          "virule-checkin.v1|" + id.install_id + "||T");
    // No Admin installed: the field is present and empty.
    CHECK(uc::prepare(fresh_dir("empty"), false, id, "T", uc::Install{ "0.8.6", "", "" })
              .body.find("\"a\":\"\"") != std::string::npos);

    uc::Pending p = uc::prepare(dir, false, id, "2026-10-01T00:00:00Z", install);
    CHECK(p.batches.size() == 3);
    CHECK(!p.body.empty());
    CHECK(p.body.find("\"n\":\"" + id.install_id + "\"") != std::string::npos);
    CHECK(p.body.find("\"cv\":\"0.8.6\"") != std::string::npos);
    CHECK(p.body.find("\"developer_public_key\":\"" + id.public_key_hex + "\"") != std::string::npos);
    // Lines travel as JSON strings, so their quotes are escaped.
    CHECK(p.body.find("\"l\":[\"{\\\"h\\\":1") != std::string::npos);
    CHECK(uc::signed_message(id.install_id, p.batches, "T") ==
          "virule-checkin.v1|" + id.install_id + "|" + p.batches[0].id + "," +
          p.batches[1].id + "," + p.batches[2].id + "|T");

    // An identity that cannot sign sends nothing and loses nothing.
    uc::Identity mute = id;
    mute.sign_hex = [](const std::string&) { return std::string(); };
    CHECK(uc::prepare(dir, false, mute, "T", install).body.empty());
    CHECK(uc::prepare(fresh_dir("empty"), false, mute, "T", install).body.empty());
    CHECK(us::sealed_count(dir, false) == 3);

    // No acknowledgement (an old service, a failed store): nothing removed.
    CHECK(uc::apply_ack("{\"version\":\"1.0.0\"}", p) == 0);
    CHECK(uc::apply_ack("{\"version\":\"1.0.0\",\"ack\":\"\"}", p) == 0);
    CHECK(us::sealed_count(dir, false) == 3);
    // A foreign id acknowledges nothing of ours.
    CHECK(uc::apply_ack("{\"ack\":\"ffffffffffffffffffffffffffffffff\"}", p) == 0);
    // Only the named batches go.
    CHECK(uc::apply_ack("{\"ack\":\"" + p.batches[0].id + "," + p.batches[2].id + "\"}", p) == 2);
    CHECK(us::sealed_count(dir, false) == 1);
    const auto left = us::load_sealed(dir, false, 8, 1 << 20);
    CHECK(left.size() == 1 && left[0].id == p.batches[1].id);

    // A check never carries more than its bound, however long the backlog.
    const fs::path big = fresh_dir("backlog");
    us::Writer bw;
    bw.start(big, false, us::header_line(kWorkspace, us::random_hex(32), "v"));
    for (int i = 0; i < 20; ++i) {
        CHECK(bw.append(ev("game_edited")));
        bw.seal();
    }
    const uc::Pending capped = uc::prepare(big, false, id, "2026-10-01T00:00:00Z", install);
    CHECK(capped.batches.size() == uc::kMaxBatches);
    CHECK(capped.body.size() < 64 * 1024);
}

static void test_previous_key_link() {
    SECTION("previous-key link: sent while unlinked, stopped once the service saw it");
    const fs::path file = fresh_dir("link") / "checkin.json";
    const fs::path spool = fresh_dir("link-spool");
    const uc::Identity id = test_identity();
    const std::string old_key(64, 'a');
    CHECK(uc::load_checked_key(file).empty()); // first run: nothing to link

    // First accepted check-in: the key is remembered, no link was sent.
    uc::Pending first = uc::prepare(spool, false, id, "T",
        uc::Install{ "0.8.6", "", uc::load_checked_key(file) });
    CHECK(first.body.find("\"pk\":") == std::string::npos);
    CHECK(uc::seen("{\"version\":\"1.0.0\",\"ack\":\"\",\"seen\":1}"));
    CHECK(!uc::seen("{\"version\":\"1.0.0\",\"ack\":\"\",\"seen\":0}"));
    CHECK(!uc::seen("{\"version\":\"1.0.0\"}")); // an older service
    uc::note_seen(file, first);
    CHECK(uc::load_checked_key(file) == id.public_key_hex);
    // Same key again: nothing to link, nothing rewritten.
    CHECK(uc::prepare(spool, false, id, "T", uc::Install{ "0.8.6", "", uc::load_checked_key(file) })
              .body.find("\"pk\":") == std::string::npos);

    // The machine key changed (the Admin issued its own): the old one is
    // named until a check-in is accepted, and survives restarts on disk.
    CHECK(uc::save_checked_key(file, old_key));
    for (int restart = 0; restart < 3; ++restart) {
        const uc::Pending again = uc::prepare(spool, false, id, "T",
            uc::Install{ "0.8.6", "0.1.1-alpha.40", uc::load_checked_key(file) });
        CHECK(again.body.find("\"pk\":\"" + old_key + "\"") != std::string::npos);
        // Not accepted (offline, older service): the link stays pending.
    }
    const uc::Pending landed = uc::prepare(spool, false, id, "T",
        uc::Install{ "0.8.6", "0.1.1-alpha.40", uc::load_checked_key(file) });
    uc::note_seen(file, landed);
    CHECK(uc::load_checked_key(file) == id.public_key_hex);
    CHECK(uc::prepare(spool, false, id, "T", uc::Install{ "0.8.6", "", uc::load_checked_key(file) })
              .body.find("\"pk\":") == std::string::npos);

    // Damaged state is "nothing to link", never a malformed request.
    { std::ofstream f(file, std::ios::binary | std::ios::trunc); f << "{\"key\":\"zz\"}"; }
    CHECK(uc::load_checked_key(file).empty());
    CHECK(!uc::save_checked_key(file, "not a key"));
    CHECK(uc::prepare(spool, false, id, "T", uc::Install{ "0.8.6", "", "not a key" })
              .body.find("\"pk\":") == std::string::npos);
}

static void test_update_health() {
    SECTION("update connectivity: 48 hours AND 3 scheduled attempts");
    const long long H = 3600;
    const long long t0 = 1790000000;
    {
        uh::State s;
        uh::note_result(s, t0, true, true);
        CHECK(!uh::blocked(s, t0));
        // Three failed scheduled checks, but only 47 hours: not yet.
        uh::note_result(s, t0 + 6 * H, false, true);
        uh::note_result(s, t0 + 12 * H, false, true);
        uh::note_result(s, t0 + 47 * H, false, true);
        CHECK(s.failed_attempts == 3);
        CHECK(!uh::blocked(s, t0 + 47 * H));
        CHECK(!uh::blocked(s, t0 + 48 * H)); // "more than" 48 hours
        CHECK(uh::blocked(s, t0 + 48 * H + 1));
        // One successful contact removes it immediately.
        uh::note_result(s, t0 + 60 * H, true, false);
        CHECK(!uh::blocked(s, t0 + 60 * H));
        CHECK(s.failed_attempts == 0 && s.last_contact_utc == t0 + 60 * H);
    }
    {
        // More than 48 hours but only two scheduled attempts: not yet.
        uh::State s;
        uh::note_result(s, t0, true, true);
        uh::note_result(s, t0 + 50 * H, false, true);
        uh::note_result(s, t0 + 56 * H, false, true);
        CHECK(!uh::blocked(s, t0 + 60 * H));
        uh::note_result(s, t0 + 62 * H, false, true);
        CHECK(uh::blocked(s, t0 + 62 * H));
    }
    {
        // Unscheduled failures (Settings asks, a retried install) never
        // count as attempts, however many there are.
        uh::State s;
        uh::note_result(s, t0, true, true);
        for (int i = 0; i < 20; ++i) uh::note_result(s, t0 + 50 * H + i, false, false);
        CHECK(s.failed_attempts == 0);
        CHECK(!uh::blocked(s, t0 + 100 * H));
    }
    {
        // A machine that has NEVER reached the service: the clock starts at
        // its first attempt, not at the epoch.
        uh::State s;
        uh::note_result(s, t0, false, true);
        uh::note_result(s, t0 + 1, false, true);
        uh::note_result(s, t0 + 2, false, true);
        CHECK(s.last_contact_utc == t0);
        CHECK(!uh::blocked(s, t0 + 2));
        CHECK(!uh::blocked(s, t0 + 48 * H));
        CHECK(uh::blocked(s, t0 + 48 * H + 1));
    }
    {
        // A clock that moved backwards restarts the measurement.
        uh::State s;
        s.last_contact_utc = t0 + 1000 * H;
        s.failed_attempts = 5;
        uh::note_result(s, t0, false, true);
        CHECK(s.last_contact_utc == t0);
        CHECK(!uh::blocked(s, t0 + H));
    }
    {
        // Persistence: the record survives a restart; an absent or damaged
        // file is "nothing recorded", never a block.
        const fs::path file = fresh_dir("health") / "update_health.json";
        CHECK(!uh::is_blocked(file, t0));
        uh::record(file, t0, true, true);
        uh::record(file, t0 + 10 * H, false, true);
        uh::record(file, t0 + 20 * H, false, true);
        uh::record(file, t0 + 30 * H, false, true);
        CHECK(!uh::is_blocked(file, t0 + 30 * H));
        CHECK(uh::is_blocked(file, t0 + 49 * H));
        const uh::State loaded = uh::load(file);
        CHECK(loaded.last_contact_utc == t0 && loaded.failed_attempts == 3);
        uh::record(file, t0 + 50 * H, true, true);
        CHECK(!uh::is_blocked(file, t0 + 50 * H));
        { std::ofstream f(file, std::ios::binary | std::ios::trunc); f << "garbage"; }
        CHECK(!uh::is_blocked(file, t0 + 500 * H));
    }
}

static int run_seed(int argc, char** argv) {
    if (argc < 4) return 2;
    const fs::path dir = argv[2];
    const int n = std::atoi(argv[3]);
    const bool staging = argc > 4 && std::strcmp(argv[4], "s") == 0;
    us::Writer w;
    w.start(dir, staging, us::header_line(kWorkspace, us::random_hex(32), "0.1.1-alpha.40"));
    for (int i = 0; i < n; ++i) {
        if (!w.append(ev(i == 0 ? "admin_opened" : "game_edited"))) return 1;
    }
    w.seal();
    std::printf("sealed=%zu\n", us::sealed_count(dir, staging));
    return 0;
}

static int run_request(int argc, char** argv) {
    if (argc < 6) return 2;
    const std::string url = argv[2];
    vclient::http::Url u;
    if (!vclient::http::parse_url(std::wstring(url.begin(), url.end()), u)) return 2;
    const fs::path dir = argv[3];
    const fs::path health = argv[4];
    const bool scheduled = std::strcmp(argv[5], "1") == 0;
    const std::string admin = argc > 6 && std::strcmp(argv[6], "-") != 0 ? argv[6] : "";
    const std::string mode = argc > 7 ? argv[7] : "";
    const fs::path link = health.parent_path() / "checkin.json";
    uc::Identity id = mode == "rekey" ? test_identity(91) : test_identity();
    if (mode == "anon") id = uc::Identity{}; // no usable VIRULE identity
    const uc::Pending pending = uc::prepare(dir, false, id,
        virule::core::utc_timestamp_rfc3339(),
        uc::Install{ "0.8.6", admin, uc::load_checked_key(link) });
    const auto r = vclient::manifest_request::run(u, 16 * 1024, pending);
    uh::record(health, static_cast<long long>(time(nullptr)), r.reached, scheduled);
    if (r.seen) uc::note_seen(link, pending);
    std::string version;
    (void)vclient::json_scan::find_string_in(r.body, 0, r.body.size(), "version", version);
    std::printf("offered=%zu answered=%d reached=%d status=%lu delivered=%zu remaining=%zu seen=%d linked=%d version=%s\n",
        pending.batches.size(), r.answered ? 1 : 0, r.reached ? 1 : 0, r.status,
        r.delivered, us::sealed_count(dir, false), r.seen ? 1 : 0,
        pending.body.find("\"pk\":") != std::string::npos ? 1 : 0, version.c_str());
    return 0;
}

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "seed") == 0) return run_seed(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "request") == 0) return run_request(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "identity") == 0) {
        std::printf("%s %s\n", test_identity().public_key_hex.c_str(),
                    test_identity(91).public_key_hex.c_str());
        return 0;
    }
    test_spool_persistence();
    test_spool_batching();
    test_spool_bound();
    test_environment_separation();
    test_checkin_body_and_ack();
    test_previous_key_link();
    test_update_health();
    std::printf("%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
