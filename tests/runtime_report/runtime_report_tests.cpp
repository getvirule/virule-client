// THE RUNTIME REPORT'S HARNESS (owner decision 2026-10-26;
// client/runtime_report.hpp). Two modes:
//
//   runtime_report_tests.exe
//       the units (and, since 2026-10-28, the expired assignment's answer,
//       the local absolute cut, the wake at the absolute instant, the
//       mandatory cleanup and the launcher's refusal): the canonical instant, the signed message and the body
//       byte for byte, which assignments are reported (installed here with
//       a ticket; never one being removed, never an upload), the cycle
//       (sampled per assignment at signing, only the evaluator's own,
//       nothing without a machine identity or a signature, a failed post
//       counted out), every signature verifying under the machine key.
//
//   runtime_report_tests.exe cycle <seed hex> <assignment> <evaluator> <0|1>
//       one REAL cycle over a sandboxed root holding that one installed
//       assignment, signed with the machine identity of <seed>, the game
//       running or not; prints `KEY <machine key>` then one `POST <path>
//       <body>` line per report. tools/runtime_report_test.mjs sends those
//       bodies to the REAL service code (VIRULE_BACKEND, in process) and
//       checks the service keeps exactly what the Client observed.
//
// Starts no client and touches nothing outside its own temporary folder.

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "client/runtime_report.hpp"
#include "client/assignment_cleanup.hpp"
#include "client/launcher.hpp"
#include "virule/core/dev_machine_proof.hpp"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")

namespace rr = vclient::runtime_report;
namespace ac = vclient::assignment_cleanup;
namespace ed = virule::core::evaluation_distribution;
namespace dmp = virule::core::dev_machine::proof;
namespace fs = std::filesystem;

static int g_pass = 0, g_fail = 0;
static void check(const char* name, bool ok, const std::string& extra = {}) {
    if (ok) { ++g_pass; std::printf("ok   %s\n", name); }
    else { ++g_fail; std::printf("FAIL %s :: %s\n", name, extra.c_str()); }
}

static std::string hex32(std::mt19937_64& r) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 32; ++i) s += d[r() % 16];
    return s;
}

// A machine identity from a 32-byte seed: its public key and a signer.
struct Machine {
    unsigned char seed[32]{};
    unsigned char pk[32]{};
    std::string key;
    explicit Machine(const std::string& seed_hex) {
        (void)dmp::detail::hex_to_bytes(seed_hex, seed, 32);
        dmp::detail::public_from_seed(seed, pk);
        key = dmp::detail::to_hex(pk, 32);
    }
    std::string sign(const std::string& m) const {
        unsigned char sig[64];
        dmp::detail::sign_detached(seed, pk, reinterpret_cast<const unsigned char*>(m.data()), m.size(), sig);
        return dmp::detail::to_hex(sig, 64);
    }
    bool verifies(const std::string& m, const std::string& sig_hex) const {
        unsigned char sig[64];
        if (!dmp::detail::hex_to_bytes(sig_hex, sig, 64)) return false;
        return dmp::detail::verify_detached(pk, reinterpret_cast<const unsigned char*>(m.data()), m.size(), sig);
    }
};

static fs::path sandbox() {
    std::random_device rd;
    const fs::path p = fs::temp_directory_path() / ("virule-runtime-report-" + std::to_string(rd()) + std::to_string(rd()));
    fs::create_directories(p);
    return p;
}

static void install(const fs::path& root, const std::string& assignment, const std::string& state,
                    const std::string& evaluator, const std::string& kind = "install", const std::string& accepted_utc = "") {
    static std::mt19937_64 r(7);
    ed::Job j;
    j.id = hex32(r);
    j.kind = kind;
    j.state = state;
    j.assignment_id = assignment;
    j.account_email = "ev@example.test";
    (void)ed::write_job(root, j);
    if (!evaluator.empty()) {
        const fs::path dir = root / L"evaluator" / L"assignments" / fs::path(assignment);
        fs::create_directories(dir);
        std::ofstream(dir / L"ticket.json", std::ios::binary) << "{\"version\":1,\"assignment_id\":\"" << assignment
            << "\",\"evaluator_id\":\"" << evaluator << "\""
            << (accepted_utc.empty() ? std::string() : ",\"accepted_utc\":\"" + accepted_utc + "\"") << "}";
    }
}

static int cycle_mode(int argc, char** argv) {
    if (argc != 6) { std::fprintf(stderr, "usage: cycle <seed hex> <assignment> <evaluator> <0|1>\n"); return 2; }
    const Machine m(argv[2]);
    const std::string assignment = argv[3], evaluator = argv[4];
    const bool running = std::strcmp(argv[5], "1") == 0;
    const fs::path root = sandbox();
    install(root, assignment, "installed", evaluator);
    rr::Config cfg;
    cfg.root = root;
    cfg.running = [&](const std::string&) { return running; };
    cfg.may_report = [](const std::string&, const std::string&) { return true; };
    cfg.machine_key = [&] { return m.key; };
    cfg.sign = [&](const std::string& msg) { return m.sign(msg); };
    std::printf("KEY %s\n", m.key.c_str());
    cfg.post = [](const std::string& path, const std::string& body) {
        std::printf("POST %s %s\n", path.c_str(), body.c_str());
        return rr::Answer{ 200, "{\"ok\":true,\"state\":\"active\"}" };
    };
    rr::Reporter rep(std::move(cfg));
    const int n = rep.cycle();
    std::error_code ec;
    fs::remove_all(root, ec);
    return n == 1 ? 0 : 1;
}

int main(int argc, char** argv) {
    if (argc >= 2 && std::strcmp(argv[1], "cycle") == 0) return cycle_mode(argc, argv);

    std::mt19937_64 r(42);
    const std::string A = hex32(r), B = hex32(r), C = hex32(r), D = hex32(r), E = hex32(r), F = hex32(r);
    const std::string EV = hex32(r), OTHER = hex32(r);
    const Machine m("0101010101010101010101010101010101010101010101010101010101010101");

    // ---- the wire
    check("the canonical instant", rr::canonical_utc(0) == "1970-01-01T00:00:00Z" &&
          rr::canonical_utc(1792972800) == "2026-10-26T00:00:00Z", rr::canonical_utc(1792972800));
    check("the signed message, byte for byte",
          rr::message(A, EV, m.key, true, "2026-10-26T12:00:00Z") ==
          "virule-evaluation-runtime.v1|" + A + "|" + EV + "|" + m.key + "|1|2026-10-26T12:00:00Z");
    check("not running is 0", rr::message(A, EV, m.key, false, "t").find("|0|t") != std::string::npos);
    check("the body, byte for byte", rr::body(m.key, false, "2026-10-26T12:00:00Z", "ab") ==
          "{\"machine_key\":\"" + m.key + "\",\"running\":false,\"timestamp\":\"2026-10-26T12:00:00Z\",\"machine_signature\":\"ab\"}");

    // ---- which assignments
    const fs::path root = sandbox();
    install(root, A, "installed", EV);
    install(root, B, "installed", EV);
    install(root, C, "removing", EV);
    install(root, D, "removed", EV);
    install(root, E, "installed", "");          // no ticket yet
    install(root, F, "installed", OTHER);       // another account's
    install(root, hex32(r), "uploading", EV, "upload");
    const auto t = rr::targets(root);
    auto has = [&](const std::string& id) { for (const auto& x : t) if (x.assignment_id == id) return true; return false; };
    check("installed assignments with a ticket are reported", has(A) && has(B) && has(F));
    check("never one being removed or removed", !has(C) && !has(D));
    check("never one without a ticket, never an upload job", !has(E) && t.size() == 3, std::to_string(t.size()));
    check("the evaluator is the ticket's", [&] { for (const auto& x : t) if (x.assignment_id == F) return x.evaluator_id == OTHER; return false; }());

    // ---- the cycle
    struct Sent { std::string path, body; };
    std::vector<Sent> sent;
    std::vector<std::string> sampled;
    rr::Config cfg;
    cfg.root = root;
    cfg.running = [&](const std::string& id) { sampled.push_back(id); return id == A; };
    cfg.may_report = [&](const std::string&, const std::string& ev) { return ev == EV; };
    cfg.machine_key = [&] { return m.key; };
    cfg.sign = [&](const std::string& msg) { return m.sign(msg); };
    cfg.now = [] { return static_cast<std::time_t>(1793016000); };   // 2026-10-26T12:00:00Z
    unsigned long answer = 200;
    std::string answer_body = "{\"ok\":true,\"state\":\"active\"}";
    cfg.post = [&](const std::string& path, const std::string& body) { sent.push_back({ path, body }); return rr::Answer{ answer, answer_body }; };
    std::vector<std::string> logs;
    cfg.log = [&](const std::string& l) { logs.push_back(l); };
    {
        rr::Reporter rep(cfg);
        const int n = rep.cycle();
        check("one report per own installed assignment, accepted", n == 2 && sent.size() == 2, std::to_string(n));
        check("another account's assignment is neither sampled nor sent", [&] {
            for (const auto& s : sampled) if (s == F) return false;
            for (const auto& s : sent) if (s.path.find(F) != std::string::npos) return false;
            return true; }());
        bool ok = true;
        for (const auto& s : sent) {
            const std::string id = s.path.substr(std::strlen("/v1/assignments/"), 32);
            const bool running = id == A;
            ok = ok && s.path == "/v1/assignments/" + id + "/runtime";
            const std::string sig = s.body.substr(s.body.find("\"machine_signature\":\"") + 21, 128);
            ok = ok && s.body == rr::body(m.key, running, "2026-10-26T12:00:00Z", sig);
            ok = ok && m.verifies(rr::message(id, EV, m.key, running, "2026-10-26T12:00:00Z"), sig);
        }
        check("each report states what was sampled, at its instant, signed by the machine", ok, sent.empty() ? "" : sent[0].body);
    }
    sent.clear();
    answer = 503;
    {
        rr::Reporter rep(cfg);
        check("a refused or unanswered post is not counted, and is logged", rep.cycle() == 0 && sent.size() == 2 && !logs.empty());
    }
    sent.clear();
    {
        rr::Config c2 = cfg;
        c2.machine_key = [] { return std::string(); };
        rr::Reporter rep(c2);
        check("no machine identity: nothing is sent", rep.cycle() == 0 && sent.empty());
    }
    {
        rr::Config c2 = cfg;
        c2.sign = [](const std::string&) { return std::string(); };
        rr::Reporter rep(c2);
        check("a signature that fails: nothing is sent", rep.cycle() == 0 && sent.empty());
    }
    {
        rr::Config c2 = cfg;
        c2.may_report = [](const std::string&, const std::string&) { return false; };
        rr::Reporter rep(c2);
        check("signed out or another account: nothing is sent", rep.cycle() == 0 && sent.empty());
    }
    {
        // The stop event ends the thread at once; the first cycle runs before.
        rr::Config c2 = cfg;
        answer = 200;
        HANDLE stop = CreateEventW(nullptr, TRUE, TRUE, nullptr);
        c2.stop_event = stop;
        rr::Reporter rep(c2);
        rep.run();
        check("the thread reports once at start and stops on its event", sent.size() == 2);
        CloseHandle(stop);
    }

    // ---- THE ANSWER'S STATE AND THE ABSOLUTE DEADLINE (owner brief 2026-10-28)
    {
        const fs::path r2 = sandbox();
        const std::string X = hex32(r), Y = hex32(r);
        // Accepted 2026-10-19T12:00:00Z: the absolute instant is 2026-10-26T12:00:00Z (1793016000).
        install(r2, X, "installed", EV, "install", "2026-10-19T12:00:00Z");
        install(r2, Y, "installed", EV, "install", "2026-10-25T12:00:00Z");
        check("the ticket's acceptance is read", [&] { for (const auto& x : rr::targets(r2)) if (x.assignment_id == X) return x.accepted == 1793016000 - 7 * 86400; return false; }());
        std::vector<std::pair<std::string, std::string>> expired;
        rr::Config c = cfg;
        c.root = r2;
        c.expired = [&](const std::string& id, const std::string& src) { expired.push_back({ id, src }); };
        std::time_t clock = 1793016000 + 5 * 60;   // 5 minutes past X's absolute instant
        c.now = [&] { return clock; };
        answer = 200;
        answer_body = "{\"ok\":true,\"state\":\"active\"}";
        { rr::Reporter rep(c); rep.cycle(); }
        check("the service answers active: nothing expires, even past the absolute instant locally", expired.empty());
        answer_body = "{\"ok\":true,\"state\":\"expired\"}";
        { rr::Reporter rep(c); rep.cycle(); }
        check("the service answers expired: the cleanup starts, from the service", expired.size() == 2 && expired[0].second == "service");
        expired.clear();
        answer = 0;
        { rr::Reporter rep(c); rep.cycle(); }
        check("unreachable within the local margin: nothing expires locally", expired.empty());
        clock = 1793016000 + 15 * 60 + 1;
        { rr::Reporter rep(c); rep.cycle(); }
        check("unreachable past the margin: only the assignment past its absolute deadline expires locally",
              expired.size() == 1 && expired[0].first == X && expired[0].second == "local");
        expired.clear();
        answer = 400;   // "The report timestamp is not current.": this clock is off
        { rr::Reporter rep(c); rep.cycle(); }
        check("a refusal (4xx, the clock-skew 400 above all) is the service deciding: no local cut", expired.empty());
        answer = 503;
        { rr::Reporter rep(c); rep.cycle(); }
        check("an unavailable service (5xx) leaves the cut to the computer", expired.size() == 1 && expired[0].second == "local");
        expired.clear();
        answer = 0;
        rr::Config signed_out = c;
        signed_out.may_report = [](const std::string&, const std::string&) { return false; };
        { rr::Reporter rep(signed_out); rep.cycle(); }
        check("signed out (the service cannot be asked): the local cut applies too", expired.size() == 1 && expired[0].first == X);
        clock = 1793016000 - 100;
        { rr::Reporter rep(c); check("the next wake is just after the absolute instant", rep.next_wait_ms() == 160 * 1000, std::to_string(rep.next_wait_ms())); }
        clock = 1793016000 + 61;
        { rr::Reporter rep(c); check("then at the end of the local margin", rep.next_wait_ms() == (15 * 60 + 1 - 61) * 1000, std::to_string(rep.next_wait_ms())); }
        answer = 200;
        std::error_code e2;
        fs::remove_all(r2, e2);
    }

    // ---- THE MANDATORY CLEANUP (client/assignment_cleanup.hpp)
    {
        const fs::path r3 = sandbox();
        const fs::path installs = r3 / L"installs";
        const std::string G = hex32(r), X = hex32(r), Z = hex32(r);
        auto installed = [&](const std::string& id, const fs::path& dir) {
            ed::Job j;
            j.id = hex32(r); j.kind = "install"; j.state = "installed"; j.assignment_id = id; j.game_uuid = G;
            j.install_root = installs.u8string().size() ? std::string(reinterpret_cast<const char*>(installs.u8string().c_str())) : "";
            j.install_dir = std::string(reinterpret_cast<const char*>(dir.u8string().c_str()));
            fs::create_directories(dir);
            std::ofstream(dir / L"Game.exe", std::ios::binary) << "x";
            (void)ed::write_job(r3, j);
            fs::create_directories(ac::assignment_dir(r3, id));
            std::ofstream(ac::draft_path(r3, id), std::ios::binary) << "{\"logline\":\"unsent\"}";
            std::ofstream(ac::assignment_dir(r3, id) / L"ledger.json", std::ios::binary) << "{}";
        };
        installed(X, installs / fs::path(G));
        int terminated = 0, recovered = 0;
        bool busy = false;
        ac::Config cc;
        cc.root = r3;
        cc.terminate = [&](const std::string&) { ++terminated; return !busy; };
        cc.recover = [&](const std::string&) { ++recovered; };
        cc.busy = [&](const std::string&) { return busy; };
        check("unmarked: the cleanup does nothing", ac::run(cc, X) && terminated == 0 && fs::exists(installs / fs::path(G)));
        check("the mark is written first, and read back", ac::mark(r3, X, "service", 1793016000) && ac::is_expired(r3, X) &&
              ac::marked(r3).size() == 1);
        busy = true;
        check("a game still running after the close: removal waits, nothing undone", !ac::run(cc, X) && fs::exists(installs / fs::path(G)) &&
              ac::is_expired(r3, X) && terminated == 1 && recovered == 1);
        busy = false;
        const bool done = ac::run(cc, X);
        ed::Job after;
        (void)ed::install_for_assignment(r3, X, after);
        check("closed, recovered, then the game folder removed and the job removed", done && !fs::exists(installs / fs::path(G)) &&
              after.state == "removed" && terminated == 2 && recovered == 2, after.state);
        check("the unsubmitted draft is deleted", !fs::exists(ac::draft_path(r3, X)));
        check("the evidence folder (ledger, ticket) is kept", fs::exists(ac::assignment_dir(r3, X) / L"ledger.json"));
        check("the mark stays", ac::is_expired(r3, X));
        check("repeated: nothing more to do, nothing closed again", ac::run(cc, X) && terminated == 2);
        // A job whose folder is not its own under the installs location is never deleted.
        const fs::path elsewhere = r3 / L"not-installs" / fs::path(G);
        installed(Z, elsewhere);
        (void)ac::mark(r3, Z, "local", 1793016000);
        (void)ac::run(cc, Z);
        check("a folder outside the installs location is never deleted", fs::exists(elsewhere / L"Game.exe"));

        // The launcher never launches an expired assignment.
        const std::string W = hex32(r);
        installed(W, installs / fs::path(hex32(r)));
        (void)ac::mark(r3, W, "service", 1793016000);
        vclient::launcher::Config lc;
        lc.root = r3;
        vclient::launcher::Launcher la(lc);
        const std::string refusal = la.launch("{\"assignment_id\":\"" + W + "\"}");
        check("the launcher refuses an expired assignment", refusal.find("\"code\":\"expired\"") != std::string::npos, refusal);
        std::error_code e3;
        fs::remove_all(r3, e3);
    }

    std::error_code ec;
    fs::remove_all(root, ec);
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
