// Evaluation evidence delivery tests (docs\ARCHITECTURE.md, "Evaluation
// evidence delivery"; v2_mvp/docs/EVALUATION_VIRULE.md section 6).
//
// Built and run by tests\evidence\run_tests.bat. Compiles the REAL headers
// the client ships (shared/evidence_queue.hpp and the vendored
// virule/core/evaluation_evidence.hpp); only the transport is scripted in
// the unit sections. No resident client, no port 47612, never the real
// %LOCALAPPDATA%\VIRULE: the units use explicit roots under %TEMP%, and the
// helper modes refuse to run unless LOCALAPPDATA is redirected.
//
//   evidence_tests.exe                          the unit sections below
//   evidence_tests.exe seed <assignment> <frames> [bytes]
//                                               hand one package off into
//                                               the sandbox outbox the way
//                                               the wrapper does (stage +
//                                               publish), prints its id; no
//                                               wake (the harness signals)
//   evidence_tests.exe signal <event name>      set the named wake event
//   evidence_tests.exe drive <event name> <endpoint>
//                                               THE CLIENT'S EVIDENCE THREAD
//                                               (run_driver + select_transport,
//                                               exactly as main.cpp wires
//                                               them) until killed or the
//                                               "<event name>.Stop" event
//   evidence_tests.exe status <assignment>      the bridge's evidence_status
//
// The helper modes are driven by tools\evidence_queue_test.mjs.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "shared/environment.hpp"
#include "shared/evidence_queue.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"

namespace fs = std::filesystem;
namespace ev = vclient::evidence;
namespace ee = virule::core::evaluation_evidence;

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_passed; } \
    else { ++g_failed; std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
} while (0)
#define SECTION(name) std::printf("-- %s\n", name)

static const std::string kAssignment = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const std::string kOtherAssignment = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static std::string random_hex32() {
    static unsigned long long counter = 0;
    unsigned char b[16];
    BCryptGenRandom(nullptr, b, sizeof(b), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    b[0] ^= (unsigned char)(++counter);
    static const char* k = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += k[c >> 4]; s += k[c & 15]; }
    return s;
}

static ee::Root fresh_root(const char* name) {
    const fs::path d = fs::temp_directory_path() / "virule-evidence-tests" / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d, ec);
    return ee::Root{ d / "evidence" };
}

// Hand a package off exactly as the wrapper does: frames waiting in a
// capture directory, stage() moves and hashes them, publish() renames.
static std::string make_package(const ee::Root& root, const std::string& assignment,
                                int frames, size_t bytes = 2048) {
    ee::Package p;
    p.package_id = random_hex32();
    p.assignment_id = assignment;
    p.evaluator_id = "evaluator";
    p.game_uuid = "game";
    p.build_uuid = "build";
    p.session.index = 1;
    p.session.end_reason = "exit";
    p.session.session_ms = 600000;
    const fs::path src = root.dir.parent_path() / "captures" / p.package_id;
    std::error_code ec;
    fs::create_directories(src, ec);
    for (int i = 1; i <= frames; ++i) {
        ee::Capture c;
        c.seq = i;
        c.status = "ok";
        c.file = ee::capture_file_name(i);
        c.source = src / c.file;
        std::ofstream f(c.source, std::ios::binary);
        for (size_t k = 0; k < bytes; ++k) f.put((char)((k * 31 + i * 7) & 0xFF));
        p.captures.push_back(c);
    }
    ee::Capture gap;
    gap.seq = frames + 1;
    gap.status = "gap";
    gap.reason = "minimized";
    p.captures.push_back(gap);
    if (!ee::stage(root, p) || !ee::publish(root, p.package_id)) return {};
    return p.package_id;
}

static size_t outbox_count(const ee::Root& r) { return ev::outbox_ids(r).size(); }
static std::string read_all(const fs::path& p) { return ee::read_document(p); }

// A scripted transport. `script` decides each answer; `sent` records the
// files each call would put on the wire (all minus already_acked).
struct Fake final : ev::Transport {
    std::function<ev::Answer(const ev::Offer&, int call)> script;
    std::vector<std::vector<std::string>> sent;
    bool sim = true;
    int calls = 0;
    const char* name() const override { return "fake"; }
    bool simulated() const override { return sim; }
    ev::Answer deliver(const ev::Offer& o) override {
        std::vector<std::string> wire;
        for (const auto& f : o.files) {
            if (!ev::contains(o.already_acked, f.file)) wire.push_back(f.file);
        }
        sent.push_back(wire);
        return script(o, calls++);
    }
};

static std::vector<std::string> all_files(const ev::Offer& o) {
    std::vector<std::string> v;
    for (const auto& f : o.files) v.push_back(f.file);
    return v;
}

static ev::Answer complete(const ev::Offer& o, const std::string& rid = "r-1") {
    ev::Answer a;
    a.kind = ev::Answer::Kind::Answered;
    a.acked = all_files(o);
    a.complete = true;
    a.receipt_id = rid;
    return a;
}

static ev::Answer failed() {
    ev::Answer a;
    a.kind = ev::Answer::Kind::Failed;
    a.error = "no answer from the test endpoint";
    return a;
}

static const std::int64_t T0 = 1790000000; // 2026-09

static void test_pickup_and_complete_ack() {
    SECTION("pickup, complete ack: receipt then payload removed");
    const ee::Root r = fresh_root("complete");
    const std::string id = make_package(r, kAssignment, 3);
    CHECK(!id.empty());
    CHECK(outbox_count(r) == 1);
    Fake t;
    t.script = [](const ev::Offer& o, int) { return complete(o, "receipt-42"); };
    const auto res = ev::run_pass(r, t, T0, false, nullptr);
    CHECK(res.delivered == 1 && res.pending == 0 && t.calls == 1);
    CHECK(t.sent.size() == 1 && t.sent[0].size() == 4); // package.json + 3 frames, gap carries no file
    CHECK(t.sent[0][0] == "package.json");
    ee::Receipt rc;
    CHECK(ee::read_receipt(r, id, rc));
    CHECK(rc.receipt_id == "receipt-42" && rc.assignment_id == kAssignment && rc.simulated);
    CHECK(rc.files.size() == 4 && ee::is_sha256_hex(rc.files[1].sha256));
    CHECK(!ee::exists_quiet(ee::outbox_dir(r, id)));
    CHECK(!ee::exists_quiet(ev::delivery_path(r, id)));
    // A second pass: nothing to do, nothing re-reported.
    const auto again = ev::run_pass(r, t, T0 + 100, true, nullptr);
    CHECK(t.calls == 1 && again.delivered == 0 && again.cleaned == 0);
    // The header's assignment view agrees.
    const auto ds = ee::assignment_delivery_state(r, kAssignment);
    CHECK(ds.simulated_acknowledged.size() == 1 && ds.pending.empty());
}

static void test_oldest_first() {
    SECTION("oldest package first");
    const ee::Root r = fresh_root("order");
    const std::string a = make_package(r, kAssignment, 1);
    Sleep(30);
    const std::string b = make_package(r, kAssignment, 1);
    Sleep(30);
    const std::string c = make_package(r, kAssignment, 1);
    const auto ids = ev::outbox_ids(r);
    CHECK(ids.size() == 3 && ids[0] == a && ids[1] == b && ids[2] == c);
    std::vector<std::string> order;
    Fake t;
    t.script = [&](const ev::Offer& o, int) { order.push_back(o.package_id); return complete(o); };
    ev::run_pass(r, t, T0, false, nullptr);
    CHECK(order.size() == 3 && order[0] == a && order[2] == c);
}

static void test_partial_ack_resends_only_missing() {
    SECTION("partial ack keeps payload, resends only missing files");
    const ee::Root r = fresh_root("partial");
    const std::string id = make_package(r, kAssignment, 4);
    Fake t;
    t.script = [](const ev::Offer& o, int call) {
        if (call == 0) {
            ev::Answer a;
            a.kind = ev::Answer::Kind::Answered;
            a.acked = { "package.json", "000001.jpg", "000002.jpg" };
            a.complete = false;
            return a;
        }
        return complete(o);
    };
    auto res = ev::run_pass(r, t, T0, false, nullptr);
    CHECK(res.pending == 1 && res.delivered == 0);
    CHECK(ee::exists_quiet(ee::outbox_dir(r, id)));
    CHECK(!ee::exists_quiet(ee::receipt_path(r, id)));
    ev::State st = ev::load_state(r, id);
    CHECK(st.acked.size() == 3 && st.attempts == 1 && st.failures == 1);
    CHECK(st.next_attempt_utc == T0 + 10); // progress restarts the ladder
    CHECK(st.last_error == "partial acknowledgment");
    // Not due yet: no call.
    res = ev::run_pass(r, t, T0 + 5, false, nullptr);
    CHECK(t.calls == 1 && res.skipped_not_due == 1 && res.next_due_utc == T0 + 10);
    res = ev::run_pass(r, t, T0 + 11, false, nullptr);
    CHECK(t.calls == 2 && res.delivered == 1);
    CHECK(t.sent[1].size() == 2 && t.sent[1][0] == "000003.jpg" && t.sent[1][1] == "000004.jpg");
    CHECK(!ee::exists_quiet(ee::outbox_dir(r, id)));
}

static void test_duplicate_ack_noop() {
    SECTION("duplicate acknowledgment is a no-op");
    const ee::Root r = fresh_root("duplicate");
    const std::string id = make_package(r, kAssignment, 2);
    Fake t;
    t.script = [](const ev::Offer&, int) {
        ev::Answer a;
        a.kind = ev::Answer::Kind::Answered;
        a.acked = { "package.json", "package.json", "000001.jpg", "000001.jpg", "not-ours.jpg" };
        return a;
    };
    ev::run_pass(r, t, T0, false, nullptr);
    ev::State st = ev::load_state(r, id);
    CHECK(st.acked.size() == 2 && st.failures == 1);
    // The same acknowledgment again: no progress, the ladder climbs, the
    // acked set is unchanged, nothing is removed.
    ev::run_pass(r, t, T0 + 20, false, nullptr);
    st = ev::load_state(r, id);
    CHECK(st.acked.size() == 2 && st.failures == 2 && st.next_attempt_utc == T0 + 20 + 60);
    CHECK(ee::exists_quiet(ee::outbox_dir(r, id)));
    // A complete answer with a receipt, then a duplicate complete answer
    // would find a receipt and never be asked.
    t.script = [](const ev::Offer& o, int) { return complete(o, "r-dup"); };
    ev::run_pass(r, t, T0 + 200, false, nullptr);
    const std::string first = read_all(ee::receipt_path(r, id));
    const int calls = t.calls;
    ev::run_pass(r, t, T0 + 400, true, nullptr);
    CHECK(t.calls == calls && read_all(ee::receipt_path(r, id)) == first);
    // A "complete" that does not cover every file is not complete.
    const std::string id2 = make_package(r, kAssignment, 2);
    t.script = [](const ev::Offer&, int) {
        ev::Answer a;
        a.kind = ev::Answer::Kind::Answered;
        a.acked = { "package.json" };
        a.complete = true;
        a.receipt_id = "liar";
        return a;
    };
    ev::run_pass(r, t, T0 + 500, false, nullptr);
    CHECK(ee::exists_quiet(ee::outbox_dir(r, id2)) && !ee::exists_quiet(ee::receipt_path(r, id2)));
    CHECK(ev::load_state(r, id2).last_error == "the acknowledgment did not cover every file");
}

static void test_failure_never_gives_up() {
    SECTION("transport failure: pending forever, growing backoff, never dropped");
    const ee::Root r = fresh_root("failure");
    const std::string id = make_package(r, kAssignment, 2);
    Fake t;
    t.script = [](const ev::Offer&, int) { return failed(); };
    std::int64_t now = T0;
    const std::int64_t expect[] = { 10, 60, 300, 900, 1800, 1800, 1800 };
    for (int i = 0; i < 7; ++i) {
        ev::run_pass(r, t, now, false, nullptr);
        const ev::State st = ev::load_state(r, id);
        CHECK(st.next_attempt_utc - now == expect[i]);
        now = st.next_attempt_utc;
    }
    // Then 500 more failures across two years of elapsed time.
    for (int i = 0; i < 500; ++i) {
        now += 2 * 365 * 24 * 3600 / 500;
        ev::run_pass(r, t, now, false, nullptr);
    }
    const ev::State st = ev::load_state(r, id);
    CHECK(st.attempts == 507 && st.failures == 507);
    CHECK(st.next_attempt_utc - now == ev::kBackoffCap);
    CHECK(st.last_error == "no answer from the test endpoint");
    CHECK(ee::exists_quiet(ee::outbox_dir(r, id) / "package.json"));
    CHECK(ee::exists_quiet(ee::outbox_dir(r, id) / "000002.jpg"));
    CHECK(!ee::exists_quiet(ee::receipt_path(r, id)));
    // Recovery after the long outage still delivers.
    t.script = [](const ev::Offer& o, int) { return complete(o); };
    const auto res = ev::run_pass(r, t, now + ev::kBackoffCap, false, nullptr);
    CHECK(res.delivered == 1);
    // A clock that moved backwards cannot strand a package.
    const std::string id2 = make_package(r, kAssignment, 1);
    t.script = [](const ev::Offer&, int) { return failed(); };
    ev::run_pass(r, t, T0 + 100000, false, nullptr);
    const int calls = t.calls;
    ev::run_pass(r, t, T0, false, nullptr); // a day earlier than the record
    CHECK(t.calls == calls + 1);
    (void)id2;
}

static void test_receipt_before_removal_crash() {
    SECTION("crash between receipt and payload removal: cleanup only");
    const ee::Root r = fresh_root("crash");
    const std::string id = make_package(r, kAssignment, 2);
    ev::State st;
    st.package_id = id;
    st.attempts = 3;
    CHECK(ev::save_state(r, st));
    ee::Receipt rc;
    rc.package_id = id;
    rc.assignment_id = kAssignment;
    rc.receipt_id = "before-crash";
    rc.acknowledged_utc = "2026-10-14T00:00:00Z";
    rc.simulated = true;
    CHECK(ee::write_receipt(r, rc)); // the step before the crash
    const std::string before = read_all(ee::receipt_path(r, id));
    Fake t;
    t.script = [](const ev::Offer& o, int) { return complete(o, "second"); };
    const auto res = ev::run_pass(r, t, T0, true, nullptr);
    CHECK(t.calls == 0 && res.cleaned == 1 && res.delivered == 0);
    CHECK(!ee::exists_quiet(ee::outbox_dir(r, id)));
    CHECK(!ee::exists_quiet(ev::delivery_path(r, id)));
    CHECK(read_all(ee::receipt_path(r, id)) == before);
}

static void test_damaged_kept() {
    SECTION("damaged packages are reported and never deleted");
    const ee::Root r = fresh_root("damaged");
    const std::string missing = make_package(r, kAssignment, 2);
    const std::string tampered = make_package(r, kAssignment, 2);
    const std::string garbage = make_package(r, kAssignment, 1);
    std::error_code ec;
    fs::remove(ee::outbox_dir(r, missing) / "000002.jpg", ec);
    {
        std::fstream f(ee::outbox_dir(r, tampered) / "000001.jpg", std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(10);
        f.put('X');
        f.put('Y');
    }
    {
        std::ofstream f(ee::outbox_dir(r, garbage) / "package.json", std::ios::binary | std::ios::trunc);
        f << "{not json";
    }
    Fake t;
    t.script = [](const ev::Offer& o, int) { return complete(o); };
    std::int64_t now = T0;
    for (int i = 0; i < 20; ++i) {
        const auto res = ev::run_pass(r, t, now, true, nullptr);
        CHECK(res.damaged == 3);
        now += 4000;
    }
    CHECK(t.calls == 0);
    CHECK(outbox_count(r) == 3);
    CHECK(ee::exists_quiet(ee::outbox_dir(r, tampered) / "000001.jpg"));
    CHECK(ee::exists_quiet(ee::outbox_dir(r, garbage) / "000001.jpg"));
    const ev::State a = ev::load_state(r, missing);
    const ev::State b = ev::load_state(r, tampered);
    CHECK(a.damaged && a.last_error == "missing file 000002.jpg");
    CHECK(b.damaged && b.last_error == "hash mismatch in 000001.jpg");
    CHECK(ev::load_state(r, garbage).damaged);
    const std::string s = ev::status_json(r, kAssignment);
    CHECK(s.find("\"damaged\":2") != std::string::npos); // the garbage one has no readable owner
    CHECK(s.find("\"state\":\"damaged\"") != std::string::npos);
    // A repaired package (a transient read failure) delivers.
    fs::remove_all(ee::outbox_dir(r, garbage), ec);
    fs::remove_all(ee::outbox_dir(r, tampered), ec);
    const std::string fine = make_package(r, kAssignment, 1);
    const auto res = ev::run_pass(r, t, now, true, nullptr);
    CHECK(res.delivered == 1 && res.damaged == 1);
    CHECK(!ee::exists_quiet(ev::delivery_path(r, garbage))); // stale state swept
    (void)fine;
}

static void test_production_transport_pending() {
    SECTION("production transport: deferred, everything stays pending");
    const ee::Root r = fresh_root("production");
    const std::string a = make_package(r, kAssignment, 1);
    const std::string b = make_package(r, kAssignment, 2);
    ev::ProductionTransport p;
    std::vector<std::string> lines;
    ev::LogOnce once;
    const ev::Log log = [&](const std::string& l) { lines.push_back(l); };
    std::int64_t now = T0;
    for (int i = 0; i < 30; ++i) {
        const auto res = ev::run_pass(r, p, now, i == 0, log, &once);
        CHECK(res.delivered == 0);
        now += ev::kBackoffCap;
    }
    CHECK(outbox_count(r) == 2);
    CHECK(!ee::exists_quiet(ee::receipt_path(r, a)) && !ee::exists_quiet(ee::receipt_path(r, b)));
    CHECK(lines.size() == 2); // once per package, not once per pass
    CHECK(ev::load_state(r, a).last_error == "evidence upload is not available yet");
    CHECK(!p.simulated());
    const std::string s = ev::status_json(r, kAssignment);
    CHECK(s.find("\"pending\":2") != std::string::npos && s.find("\"acknowledged\":0") != std::string::npos);
}

static void test_transport_selection() {
    SECTION("test transport honored only in staging or a redirected sandbox");
    const std::wstring ep = L"http://127.0.0.1:5555/evidence";
    CHECK(std::string(ev::select_transport(ep, false, false, nullptr)->name()) == "production");
    CHECK(std::string(ev::select_transport(ep, true, false, nullptr)->name()) == "test");
    CHECK(std::string(ev::select_transport(ep, false, true, nullptr)->name()) == "test");
    CHECK(std::string(ev::select_transport(L"", true, true, nullptr)->name()) == "production");
    CHECK(std::string(ev::select_transport(L"http://example.com/x", true, true, nullptr)->name()) == "production");
    CHECK(std::string(ev::select_transport(L"file:///c:/x", true, true, nullptr)->name()) == "production");
    CHECK(ev::select_transport(ep, true, false, nullptr)->simulated());
    std::vector<std::string> lines;
    (void)ev::select_transport(ep, false, false, [&](const std::string& l) { lines.push_back(l); });
    CHECK(lines.size() == 1 && lines[0].find("ignored") != std::string::npos);
    // This exe is not a staging build: the guard rests on the sandbox alone.
    CHECK(!vclient::env::kStaging);
}

static void test_status_shape() {
    SECTION("evidence_status shape and frame bound");
    const ee::Root r = fresh_root("status");
    Fake t;
    t.script = [](const ev::Offer& o, int) { return complete(o); };
    for (int i = 0; i < 30; ++i) make_package(r, kAssignment, 1, 64);
    ev::run_pass(r, t, T0, false, nullptr);
    for (int i = 0; i < 30; ++i) make_package(r, kAssignment, 1, 64);
    make_package(r, kOtherAssignment, 1, 64);
    const std::string s = ev::status_json(r, kAssignment);
    CHECK(s.size() <= ev::kStatusMaxBytes && s.size() <= 4096);
    CHECK(s.rfind("{\"type\":\"evidence_status\"", 0) == 0);
    CHECK(s.find("\"pending\":31") == std::string::npos);
    CHECK(s.find("\"pending\":30") != std::string::npos && s.find("\"acknowledged\":30") != std::string::npos);
    CHECK(s.find("\"truncated\":true") != std::string::npos);
    // Pending rows come before acknowledged ones under truncation.
    CHECK(s.find("\"state\":\"pending\"") != std::string::npos);
    const std::string other = ev::status_json(r, kOtherAssignment);
    CHECK(other.find("\"pending\":1") != std::string::npos && other.find("\"truncated\":false") != std::string::npos);
    std::string_view raw;
    CHECK(ee::json::member(other, "packages", raw));
}

static void test_wake_and_driver() {
    SECTION("wake event and driver thread");
    CHECK(std::wstring(ee::kWakeEventName) == L"Local\\VIRULE.Evidence.Wake");
    const ee::Root r = fresh_root("driver");
    const std::wstring name = L"Local\\VIRULE.Evidence.Wake.UnitTest." + std::to_wstring(GetCurrentProcessId());
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<int> delivered{ 0 };
    Fake t;
    t.script = [&](const ev::Offer& o, int) { ++delivered; return complete(o); };
    ev::DriverConfig cfg;
    cfg.root = r;
    cfg.transport = &t;
    cfg.wake_name = name;
    cfg.stop_event = stop;
    // Startup pass with a package already waiting (the restart recovery).
    make_package(r, kAssignment, 1);
    std::thread th([&] { ev::run_driver(cfg); });
    for (int i = 0; i < 100 && delivered.load() < 1; ++i) Sleep(20);
    CHECK(delivered.load() == 1);
    // A new package and a wake from another opener (the wrapper's side).
    Sleep(100);
    make_package(r, kAssignment, 1);
    HANDLE w = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
    CHECK(w != nullptr);
    if (w) { SetEvent(w); CloseHandle(w); }
    for (int i = 0; i < 100 && delivered.load() < 2; ++i) Sleep(20);
    CHECK(delivered.load() == 2);
    // Idle: nothing happens without a signal.
    Sleep(300);
    CHECK(delivered.load() == 2 && t.calls == 2);
    SetEvent(stop);
    const auto t0 = GetTickCount64();
    th.join();
    CHECK(GetTickCount64() - t0 < 2000);
    CloseHandle(stop);
    // Paused (an uninstall) delivers nothing and still stops.
    make_package(r, kAssignment, 1);
    stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    cfg.stop_event = stop;
    cfg.paused = [] { return true; };
    std::thread th2([&] { ev::run_driver(cfg); });
    Sleep(200);
    SetEvent(stop);
    th2.join();
    CHECK(t.calls == 2);
    CloseHandle(stop);
}

// ---------------------------------------------------------------- helpers

static bool sandboxed() {
    if (vclient::paths::environment_redirected()) return true;
    std::fprintf(stderr, "refused: LOCALAPPDATA is not redirected (this mode only runs in a sandbox)\n");
    return false;
}

static int run_seed(int argc, char** argv) {
    if (argc < 4 || !sandboxed()) return 2;
    const ee::Root root = ee::default_root();
    const size_t bytes = argc > 4 ? (size_t)std::atoll(argv[4]) : 4096;
    const std::string id = make_package(root, argv[2], std::atoi(argv[3]), bytes);
    if (id.empty()) return 1;
    std::printf("%s\n", id.c_str());
    return 0;
}

static std::wstring widen(const char* s) { std::string n(s); return std::wstring(n.begin(), n.end()); }

static int run_signal(int argc, char** argv) {
    if (argc < 3) return 2;
    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, widen(argv[2]).c_str());
    if (!h) return 1;
    SetEvent(h);
    CloseHandle(h);
    return 0;
}

static int run_drive(int argc, char** argv) {
    if (argc < 4 || !sandboxed()) return 2;
    const std::wstring wake = widen(argv[2]);
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, (wake + L".Stop").c_str());
    const ev::Log log = [](const std::string& t) {
        vclient::log::client(t);
        std::printf("%s\n", t.c_str());
        std::fflush(stdout);
    };
    auto transport = ev::select_transport(widen(argv[3]), vclient::env::kStaging,
                                          vclient::paths::environment_redirected(), log);
    ev::DriverConfig cfg;
    cfg.root = ee::default_root();
    cfg.transport = transport.get();
    cfg.wake_name = wake;
    cfg.stop_event = stop;
    cfg.log = log;
    std::printf("driving %s\n", transport->name());
    std::fflush(stdout);
    ev::run_driver(cfg);
    CloseHandle(stop);
    return 0;
}

static int run_status(int argc, char** argv) {
    if (argc < 3 || !sandboxed()) return 2;
    std::printf("%s\n", ev::status_json(ee::default_root(), argv[2]).c_str());
    return 0;
}

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "seed") == 0) return run_seed(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "signal") == 0) return run_signal(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "drive") == 0) return run_drive(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "status") == 0) return run_status(argc, argv);
    test_pickup_and_complete_ack();
    test_oldest_first();
    test_partial_ack_resends_only_missing();
    test_duplicate_ack_noop();
    test_failure_never_gives_up();
    test_receipt_before_removal_crash();
    test_damaged_kept();
    test_production_transport_pending();
    test_transport_selection();
    test_status_shape();
    test_wake_and_driver();
    std::printf("%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
