// Game distribution transfer tests (docs\ARCHITECTURE.md "Game
// distribution"; v2_mvp/docs/EVALUATION_VIRULE.md sections 3 and 9).
//
// Built and run by tests\transfers\run_tests.bat. Compiles the REAL headers
// the client ships (src/client/transfers.hpp and the vendored
// virule/core/evaluation_distribution.hpp). No resident client, no port
// 47612, never the real %LOCALAPPDATA%\VIRULE: the units use explicit roots
// under %TEMP%, and the helper modes refuse to run unless LOCALAPPDATA is
// redirected.
//
//   transfers_tests.exe                             the unit sections below
//   transfers_tests.exe package <root> <game_uuid> <bytes>
//                                                   write a packaged upload job
//                                                   (a random package of `bytes`,
//                                                   its manifest) the way the
//                                                   Admin host hands one over;
//                                                   prints "<job id> <sha256>"
//   transfers_tests.exe install <root> <assignment> <game_uuid> <revision> <sha256> <bytes> <launch>
//                                                   write a queued install job
//                                                   the way the Admin's Install
//                                                   does; prints the job id
//   transfers_tests.exe signal <event name>         set the named wake event
//   transfers_tests.exe drive <event name> <endpoint> <email> [machine_key]
//                                                   THE CLIENT'S TRANSFER THREAD
//                                                   (run_driver over a loopback
//                                                   Service) until killed or the
//                                                   "<event name>.Stop" event
//   transfers_tests.exe control <root> <json>       the bridge's transfer_control
//   transfers_tests.exe status <root>               the bridge's transfer_status
//
// The helper modes are driven by tools\transfer_test.mjs.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <fstream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "shared/environment.hpp"
#include "shared/evidence_queue.hpp"
#include "shared/http_client.hpp"
#include "shared/paths.hpp"
#include "client/transfers.hpp"
#include "client/game_art.hpp"
#include "client/evidence_owner.hpp"
#include "client/evaluation_recovery.hpp"
#include "client/assignment_open.hpp"

namespace fs = std::filesystem;
namespace ed = virule::core::evaluation_distribution;
namespace tr = vclient::transfers;
namespace ev = virule::core::evaluation_evidence;

static int g_passed = 0;
static int g_failed = 0;
#define CHECK(cond) do { \
    if (cond) { ++g_passed; } \
    else { ++g_failed; std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
} while (0)
#define SECTION(name) std::printf("-- %s\n", name)

static fs::path temp_root(const char* tag) {
    wchar_t buf[MAX_PATH];
    GetTempPathW(MAX_PATH, buf);
    const fs::path p = fs::path(buf) / (std::wstring(L"virule-transfers-") + std::wstring(tag, tag + std::strlen(tag)) + L"-" +
                                       std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    fs::create_directories(p);
    return p;
}

static std::string utf8(const fs::path& p) { const auto u = p.u8string(); return std::string(u.begin(), u.end()); }

static void write_random(const fs::path& p, std::uint64_t bytes, std::string* sha_out) {
    std::mt19937_64 rng(12345);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    std::vector<unsigned char> chunk(1024 * 1024);
    std::uint64_t left = bytes;
    while (left > 0) {
        const size_t n = static_cast<size_t>(std::min<std::uint64_t>(left, chunk.size()));
        for (size_t i = 0; i < n; ++i) chunk[i] = static_cast<unsigned char>(rng());
        f.write(reinterpret_cast<const char*>(chunk.data()), (std::streamsize)n);
        left -= n;
    }
    f.close();
    if (sha_out) tr::sha256_file_hex(p, *sha_out);
}

// ---------------------------------------------------------------- units ----

static void test_contract() {
    SECTION("the contract: the cap, the parts, the sentence");
    CHECK(ed::kGameMaxBytes == 21474836480ull);
    CHECK(ed::kPartBytes == 33554432ull);
    CHECK(ed::within_cap(ed::kGameMaxBytes));
    CHECK(!ed::within_cap(ed::kGameMaxBytes + 1));
    CHECK(ed::format_gb(23ull * ed::kGiB) == "23 GB");
    CHECK(ed::format_gb(ed::kGameMaxBytes) == "20 GB");
    CHECK(ed::format_gb(static_cast<std::uint64_t>(23.4 * static_cast<double>(ed::kGiB))) == "23.4 GB");
    CHECK(ed::too_large_sentence(23ull * ed::kGiB) == "This game is 23 GB. The limit is 20 GB.");
    CHECK(ed::parts_total(0) == 1);
    CHECK(ed::parts_total(1) == 1);
    CHECK(ed::parts_total(ed::kPartBytes) == 1);
    CHECK(ed::parts_total(ed::kPartBytes + 1) == 2);
    CHECK(ed::parts_total(ed::kGameMaxBytes) == 640);
    CHECK(ed::part_bytes(ed::kPartBytes + 4096, 1) == ed::kPartBytes);
    CHECK(ed::part_bytes(ed::kPartBytes + 4096, 2) == 4096);
}

static void test_job_record() {
    SECTION("the job record round-trips and is listed newest first");
    const fs::path root = temp_root("job");
    ed::Job j;
    j.id = ed::random_hex32();
    j.kind = "upload";
    j.state = "packaged";
    j.account_email = "dev@example.test";
    j.game_id = "g1";
    j.game_uuid = std::string(32, 'a');
    j.build_uuid = std::string(32, 'b');
    j.package_path = "C:\\x\\p.zip";
    j.package_bytes = 123456789;
    j.package_sha256 = std::string(64, 'c');
    j.launch_exe = "Game \"quoted\".exe";
    j.parts_total = 4;
    j.parts_done = { 1, 3 };
    j.created_utc = "2026-10-20T10:00:00Z";
    CHECK(ed::write_job(root, j));
    ed::Job back;
    CHECK(ed::read_job(root, j.id, back));
    CHECK(back.kind == "upload" && back.state == "packaged" && back.package_bytes == 123456789 && back.parts_total == 4);
    CHECK(back.parts_done.size() == 2 && back.parts_done[1] == 3);
    CHECK(back.launch_exe == "Game \"quoted\".exe");
    CHECK(back.account_email == "dev@example.test");
    ed::Job k = j;
    k.id = ed::random_hex32();
    k.created_utc = "2026-10-20T11:00:00Z";
    CHECK(ed::write_job(root, k));
    const auto all = ed::list_jobs(root);
    CHECK(all.size() == 2 && all[0].id == k.id);
    ed::Job newest;
    CHECK(ed::newest_upload_for_game(root, "g1", newest) && newest.id == k.id);
    CHECK(!ed::read_job(root, std::string(32, 'f'), back));
    // A malformed document reads as absent, never as a partial job.
    const fs::path bad = ed::job_dir(root, std::string(32, '1'));
    fs::create_directories(bad);
    std::ofstream(bad / "job.json") << "{\"format\":\"virule-transfer-job.v1\",\"id\":\"zz\"}";
    CHECK(!ed::read_job(root, std::string(32, '1'), back));
    CHECK(ed::list_jobs(root).size() == 2);
    fs::remove_all(root);
}

static void test_digests_and_zip() {
    SECTION("digests, the part reader, and the zip-slip guard");
    CHECK(tr::sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(tr::md5_hex("abc") == "900150983cd24fb0d6963f7d28e17f72");
    const fs::path root = temp_root("zip");
    std::string sha;
    write_random(root / "pkg.bin", 5000, &sha);
    CHECK(sha.size() == 64);
    fs::path rel;
    CHECK(tr::detail::safe_entry("a/b/c.txt", rel) && utf8(rel) == "a\\b\\c.txt");
    CHECK(!tr::detail::safe_entry("../x", rel));
    CHECK(!tr::detail::safe_entry("/abs", rel));
    CHECK(!tr::detail::safe_entry("C:/x", rel));
    CHECK(!tr::detail::safe_entry("a/../b", rel));
    CHECK(!tr::detail::safe_entry("", rel));
    // A real archive: two files, extracted, byte-identical.
    const fs::path src = root / "src";
    fs::create_directories(src / "bin");
    std::ofstream(src / "Game.exe") << "exe bytes";
    std::ofstream(src / "bin" / "data.bin") << std::string(70000, 'x');
    mz_zip_archive zip{};
    const fs::path zp = root / "p.zip";
    FILE* zf = nullptr;
    _wfopen_s(&zf, zp.wstring().c_str(), L"wb");
    CHECK(mz_zip_writer_init_cfile(&zip, zf, MZ_ZIP_FLAG_WRITE_ZIP64));
    for (const char* name : { "Game.exe", "bin/data.bin" }) {
        FILE* sf = nullptr;
        _wfopen_s(&sf, (src / fs::path(std::string(name))).wstring().c_str(), L"rb");
        std::error_code ec;
        const auto sz = fs::file_size(src / fs::path(std::string(name)), ec);
        CHECK(mz_zip_writer_add_cfile(&zip, name, sf, sz, nullptr, nullptr, 0, MZ_NO_COMPRESSION, nullptr, 0, nullptr, 0));
        fclose(sf);
    }
    CHECK(mz_zip_writer_finalize_archive(&zip));
    mz_zip_writer_end(&zip);
    fclose(zf);
    std::string why;
    const fs::path dst = root / "out";
    CHECK(tr::detail::extract_zip(zp, dst, why, {}));
    std::error_code ec;
    CHECK(fs::file_size(dst / "bin" / "data.bin", ec) == 70000);
    CHECK(fs::is_regular_file(dst / "Game.exe", ec));
    fs::remove_all(root);
}

static void test_controls() {
    SECTION("transfer_control: pause and resume are recorded on a queued install");
    const fs::path root = temp_root("ctl");
    ed::Job j;
    j.id = ed::random_hex32();
    j.kind = "install";
    j.state = "queued";
    j.assignment_id = std::string(32, 'a');
    j.created_utc = "2026-10-20T10:00:00Z";
    ed::write_job(root, j);
    const std::string a1 = tr::control("{\"type\":\"transfer_control\",\"assignment_id\":\"" + j.assignment_id + "\",\"action\":\"pause\"}", root);
    CHECK(a1.find("\"ok\":true") != std::string::npos);
    ed::Job back;
    CHECK(ed::read_job(root, j.id, back) && back.state == "paused" && back.paused);
    CHECK(tr::is_paused(j.assignment_id));
    tr::control("{\"type\":\"transfer_control\",\"assignment_id\":\"" + j.assignment_id + "\",\"action\":\"resume\"}", root);
    CHECK(ed::read_job(root, j.id, back) && back.state == "downloading" && !back.paused);
    CHECK(!tr::is_paused(j.assignment_id));
    CHECK(tr::control("{\"type\":\"transfer_control\",\"assignment_id\":\"nope\",\"action\":\"pause\"}", root).find("error") != std::string::npos);
    CHECK(tr::control("{\"type\":\"transfer_control\",\"assignment_id\":\"" + j.assignment_id + "\",\"action\":\"explode\"}", root).find("error") != std::string::npos);
    const std::string st = tr::status_json(root);
    CHECK(st.rfind("{\"type\":\"transfer_status\"", 0) == 0 && st.find(j.id) != std::string::npos);
    fs::remove_all(root);
}

// THE LAUNCH CHAIN MADE CURRENT (0.9.15; transfers.hpp ensure_launch_chain,
// transfer_control "verify"): the ticket and the evaluator credential the
// wrapper verifies at launch, written at install and written AGAIN before a
// launch when this computer's machine key is no longer the one the held
// credential was bound to (the Admin re-issues dev_machine.cred on its
// first run). The machine key is read at every call, never remembered.
struct MemoryService final : tr::Service {
    std::string machine;
    int ticket_calls = 0;
    int credential_calls = 0;
    std::string evaluator = std::string(32, 'e');
    std::string last_credential_body;
    bool signed_in(std::string& out) override { out = "eva@example.com"; return true; }
    tr::Reply call(const char* method, const std::string& path, const std::string& body,
                   const std::string&, const std::vector<tr::Header>&) override {
        tr::Reply r;
        if (std::string(method) == "GET" && path.find("/ticket") != std::string::npos) {
            ++ticket_calls;
            const std::string aid = path.substr(std::string("/v1/assignments/").size(), 32);
            r.status = 200;
            r.body = "{\"ticket\":{\"assignment_id\":\"" + aid + "\",\"evaluator_id\":\"" + evaluator +
                     "\",\"game_uuid\":\"" + std::string(32, '7') + "\",\"accepted_utc\":\"2026-10-20T10:00:00Z\",\"signature\":\"" +
                     std::string(128, 'f') + "\"}}";
            return r;
        }
        if (std::string(method) == "POST" && path == "/v1/assignments/credential") {
            ++credential_calls;
            last_credential_body = body;
            std::string key;
            (void)vclient::json_scan::find_string_in(body, 0, body.size(), "machine_key", key);
            r.status = 200;
            r.body = "{\"credential\":{\"evaluator_id\":\"" + evaluator + "\",\"machine_key\":\"" + key +
                     "\",\"bound_utc\":\"2026-10-20T10:00:00Z\",\"signature\":\"" + std::string(128, 'c') + "\"}}";
            return r;
        }
        r.status = 404;
        return r;
    }
    bool get_range_to_file(const std::string&, std::uint64_t, std::uint64_t, FILE*, std::uint64_t&, unsigned long& status_out,
                           const std::function<bool()>&) override { status_out = 0; return false; }
    std::string machine_key() override { return machine; }
};

// AN UPDATE AND THE REMOVAL (2026-10-21): the same install job moved on to
// a newer revision waits while the game runs, keeps the installed game's own
// files (its saves) and replaces the rest; a report acknowledged starts the
// removal, which also waits while the game runs and removes only its folder.
struct AckService final : tr::Service {
    std::string machine = std::string(64, '1');
    int completes = 0;
    bool signed_in(std::string& out) override { out = "eva@example.com"; return true; }
    tr::Reply call(const char* method, const std::string& path, const std::string& body,
                   const std::string&, const std::vector<tr::Header>&) override {
        tr::Reply r;
        r.status = 200;
        if (std::string(method) == "GET" && path.find("/ticket") != std::string::npos) {
            const std::string aid = path.substr(std::string("/v1/assignments/").size(), 32);
            r.body = "{\"ticket\":{\"assignment_id\":\"" + aid + "\",\"evaluator_id\":\"" + std::string(32, 'e') +
                     "\",\"game_uuid\":\"" + std::string(32, '7') + "\",\"accepted_utc\":\"2026-10-20T10:00:00Z\",\"signature\":\"" +
                     std::string(128, 'f') + "\"}}";
            return r;
        }
        if (path == "/v1/assignments/credential") {
            std::string key;
            (void)vclient::json_scan::find_string_in(body, 0, body.size(), "machine_key", key);
            r.body = "{\"credential\":{\"evaluator_id\":\"" + std::string(32, 'e') + "\",\"machine_key\":\"" + key +
                     "\",\"bound_utc\":\"2026-10-20T10:00:00Z\",\"signature\":\"" + std::string(128, 'c') + "\"}}";
            return r;
        }
        if (path.size() > 9 && path.compare(path.size() - 9, 9, "/complete") == 0) { ++completes; r.body = "{\"ok\":true}"; return r; }
        r.status = 404;
        return r;
    }
    bool get_range_to_file(const std::string&, std::uint64_t, std::uint64_t, FILE*, std::uint64_t&, unsigned long& status_out,
                           const std::function<bool()>&) override { status_out = 0; return false; }
    std::string machine_key() override { return machine; }
};

static void write_zip(const fs::path& zp, const std::vector<std::pair<std::string, std::string>>& files) {
    mz_zip_archive zip{};
    FILE* zf = nullptr;
    _wfopen_s(&zf, zp.wstring().c_str(), L"wb");
    mz_zip_writer_init_cfile(&zip, zf, MZ_ZIP_FLAG_WRITE_ZIP64);
    for (const auto& f : files) {
        mz_zip_writer_add_mem(&zip, f.first.c_str(), f.second.data(), f.second.size(), MZ_NO_COMPRESSION);
    }
    mz_zip_writer_finalize_archive(&zip);
    mz_zip_writer_end(&zip);
    fclose(zf);
}

static std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static void test_update_and_removal() {
    SECTION("an update waits while the game runs, keeps its saves, replaces the rest; the removal after the report");
    const fs::path root = temp_root("update");
    const std::string assignment = "c" + std::string(31, '0');
    const std::string game(32, '7');
    const fs::path installs = root / "games";
    const fs::path dst = installs / game;
    fs::create_directories(dst / "saves");
    std::ofstream(dst / "Game.exe", std::ios::binary) << "old exe";
    std::ofstream(dst / "data.bin", std::ios::binary) << "old data";
    std::ofstream(dst / "saves" / "slot1.sav", std::ios::binary) << "the evaluator's save";
    const fs::path zp = root / "update.zip";
    write_zip(zp, { { "Game.exe", "new exe" }, { "data.bin", "new data" }, { "extra/new.txt", "added" } });
    std::string sha;
    tr::sha256_file_hex(zp, sha);
    ed::Job j;
    j.id = ed::random_hex32();
    j.kind = "install";
    j.state = "extracting";
    j.account_email = "eva@example.com";
    j.assignment_id = assignment;
    j.game_uuid = game;
    j.revision_id = std::string(32, '2');
    j.download_id = std::string(32, 'd');
    j.package_sha256 = sha;
    j.launch_exe = "Game.exe";
    j.install_root = utf8(installs);
    j.install_dir = utf8(dst);
    j.temp_path = utf8(zp);
    j.created_utc = "2026-10-21T10:00:00Z";
    ed::write_job(root, j);
    AckService svc;
    tr::DriverConfig cfg;
    cfg.root = root;
    cfg.service = &svc;
    cfg.log = [](const std::string&) {};

    // The game is up (the wrapper's presence): nothing on disk changes.
    HANDLE presence = CreateMutexW(nullptr, FALSE, ev::running_mutex_name(assignment).c_str());
    CHECK(presence != nullptr && ev::session_running(assignment));
    tr::detail::run_install(cfg, j, "eva@example.com");
    ed::Job back;
    CHECK(ed::read_job(root, j.id, back) && back.state == "extracting" && back.error.find("Close the game") != std::string::npos);
    CHECK(back.next_attempt_utc > 0);
    CHECK(slurp(dst / "Game.exe") == "old exe");
    CloseHandle(presence);
    CHECK(!ev::session_running(assignment));

    // Closed: the update lands.
    tr::detail::run_install(cfg, back, "eva@example.com");
    CHECK(ed::read_job(root, j.id, back) && back.state == "installed");
    CHECK(slurp(dst / "Game.exe") == "new exe");
    CHECK(slurp(dst / "data.bin") == "new data");
    CHECK(slurp(dst / "extra" / "new.txt") == "added");
    CHECK(slurp(dst / "saves" / "slot1.sav") == "the evaluator's save");   // THE SAVE IS KEPT
    CHECK(svc.completes == 1);
    std::error_code ec;
    CHECK(!fs::exists(installs / ".virule-staging" / (game + ".old"), ec));

    // The report acknowledged: the game removes itself, never while it runs.
    CHECK(tr::begin_removal(root, assignment));
    CHECK(ed::read_job(root, j.id, back) && back.state == "removing" && !ed::is_terminal(back));
    presence = CreateMutexW(nullptr, FALSE, ev::running_mutex_name(assignment).c_str());
    tr::detail::run_removal(cfg, back);
    CHECK(ed::read_job(root, j.id, back) && back.state == "removing" && fs::exists(dst, ec));
    CloseHandle(presence);
    tr::detail::run_removal(cfg, back);
    CHECK(ed::read_job(root, j.id, back) && back.state == "removed" && ed::is_terminal(back));
    CHECK(!fs::exists(dst, ec) && fs::exists(installs, ec));   // only its own folder
    CHECK(!tr::begin_removal(root, assignment));                // once
    fs::remove_all(root, ec);
}

static void test_launch_chain() {
    SECTION("transfer_control verify: the launch chain of an installed assignment is made current");
    const fs::path root = temp_root("chain");
    const std::string assignment(32, 'b');
    const std::string k1(64, '1'), k2(64, '2');
    MemoryService svc;
    svc.machine = k1;
    tr::DriverConfig cfg;
    cfg.root = root;
    cfg.service = &svc;
    cfg.log = [](const std::string&) {};
    const std::string verify = "{\"type\":\"transfer_control\",\"assignment_id\":\"" + assignment + "\",\"action\":\"verify\"}";

    // No driver configuration (the harness's control mode): a truthful no.
    tr::control_config() = nullptr;
    CHECK(tr::control(verify, root).find("\"ok\":false") != std::string::npos);
    tr::control_config() = &cfg;
    // Not installed: nothing to verify, and the record is only read.
    ed::Job j;
    j.id = ed::random_hex32();
    j.kind = "install";
    j.state = "downloading";
    j.assignment_id = assignment;
    j.install_dir = utf8(root / "games" / std::string(32, '7'));
    j.launch_exe = "Game.exe";
    j.revision_id = std::string(32, '9');
    j.created_utc = "2026-10-20T10:00:00Z";
    ed::write_job(root, j);
    const std::string a0 = tr::control(verify, root);
    CHECK(a0.find("\"ok\":false") != std::string::npos && a0.find("isn't installed") != std::string::npos);
    CHECK(svc.ticket_calls == 0 && svc.credential_calls == 0);
    ed::Job same;
    CHECK(ed::read_job(root, j.id, same) && same.state == "downloading");

    // Installed: the ticket is asked and written, the credential issued for
    // THIS computer's key.
    j.state = "installed";
    ed::write_job(root, j);
    CHECK(tr::control(verify, root).find("\"ok\":true") != std::string::npos);
    CHECK(svc.ticket_calls == 1 && svc.credential_calls == 1);
    const std::string ticket = ev::read_document(tr::detail::ticket_path(root, assignment));
    const std::string cred = ev::read_document(tr::detail::credential_path(root));
    CHECK(ticket.find("\"assignment_id\":\"" + assignment + "\"") != std::string::npos &&
          ticket.find("\"install_path\":") != std::string::npos && ticket.find("\"launch_exe\":\"Game.exe\"") != std::string::npos);
    CHECK(cred.find("\"machine_key\":\"" + k1 + "\"") != std::string::npos);
    // The same key again: the key is PROVED again (owner brief 2026-11-02:
    // the credential request carries the proof of possession and is always
    // made, so a binding the service does not count as proved is proved
    // before a launch); the service answers the held credential unchanged.
    CHECK(tr::control(verify, root).find("\"ok\":true") != std::string::npos);
    CHECK(svc.ticket_calls == 2 && svc.credential_calls == 2);
    CHECK(svc.last_credential_body.find(k1) != std::string::npos);
    // The machine key changed under the credential (the Admin re-issued
    // dev_machine.cred): the credential is issued again for the NEW key.
    svc.machine = k2;
    CHECK(tr::control(verify, root).find("\"ok\":true") != std::string::npos);
    CHECK(svc.credential_calls == 3);
    CHECK(svc.last_credential_body.find(k2) != std::string::npos);
    CHECK(ev::read_document(tr::detail::credential_path(root)).find("\"machine_key\":\"" + k2 + "\"") != std::string::npos);
    // No machine identity at all: a plain, non-retryable refusal; nothing written over the held files.
    svc.machine.clear();
    const std::string a3 = tr::control(verify, root);
    CHECK(a3.find("\"ok\":false") != std::string::npos && a3.find("no VIRULE identity") != std::string::npos);
    CHECK(ev::read_document(tr::detail::credential_path(root)).find("\"machine_key\":\"" + k2 + "\"") != std::string::npos);
    // The job record was never touched by any of it.
    CHECK(ed::read_job(root, j.id, same) && same.state == "installed" && same.error.empty());
    tr::control_config() = nullptr;
    fs::remove_all(root);
}

// ------------------------------------------------------------ helpers ----

static bool redirected_or_die() {
    if (!vclient::paths::environment_redirected()) {
        std::printf("refusing: LOCALAPPDATA is not redirected\n");
        return false;
    }
    return true;
}

static int run_package(int argc, char** argv) {
    if (argc < 5 || !redirected_or_die()) return 2;
    const fs::path root = fs::path(std::string(argv[2]));
    const std::string game_uuid = argv[3];
    std::uint64_t bytes = std::strtoull(argv[4], nullptr, 10);
    fs::create_directories(root / "packages");
    ed::Job j;
    j.id = ed::random_hex32();
    j.kind = "upload";
    j.state = "packaged";
    j.game_id = "local-" + game_uuid.substr(0, 6);
    j.game_uuid = game_uuid;
    j.build_uuid = ed::random_hex32();
    j.built_utc = tr::utc_now();
    j.launch_exe = "Game.exe";
    j.file_count = 3;
    const fs::path pkg = root / "packages" / fs::path(j.build_uuid + ".zip");
    // A REAL package (2026-11-02: the Client extracts and verifies it before
    // any upload): one stored Game.exe, sized so the archive is exactly
    // `bytes` long (a stored zip's overhead is constant for one entry).
    std::string content(static_cast<size_t>(bytes > 512 ? bytes - 512 : 1), '\0');
    {
        std::mt19937_64 rng(std::hash<std::string>{}(j.build_uuid));
        for (auto& c : content) c = static_cast<char>(rng());
    }
    write_zip(pkg, { { "Game.exe", content } });
    {
        std::error_code ec;
        const std::uint64_t got = fs::file_size(pkg, ec);
        if (bytes > 512 && got != bytes) { content.resize(static_cast<size_t>(content.size() + bytes - got)); write_zip(pkg, { { "Game.exe", content } }); }
    }
    std::string sha;
    tr::sha256_file_hex(pkg, sha);
    bytes = fs::file_size(pkg);
    j.package_path = utf8(pkg);
    j.manifest_path = utf8(root / "packages" / fs::path(j.build_uuid + ".manifest.json"));
    j.package_bytes = bytes;
    j.content_bytes = bytes > 64 ? bytes - 64 : bytes;
    j.bytes_total = bytes;
    j.package_sha256 = sha;
    j.parts_total = static_cast<std::int64_t>(ed::parts_total(bytes));
    j.created_utc = tr::utc_now();
    if (!ed::write_job(root, j)) return 1;
    std::printf("%s %s\n", j.id.c_str(), sha.c_str());
    return 0;
}

static int run_install(int argc, char** argv) {
    if (argc < 9 || !redirected_or_die()) return 2;
    const fs::path root = fs::path(std::string(argv[2]));
    ed::Job j;
    j.id = ed::random_hex32();
    j.kind = "install";
    j.state = "queued";
    j.assignment_id = argv[3];
    j.game_uuid = argv[4];
    j.revision_id = argv[5];
    j.package_sha256 = argv[6];
    j.package_bytes = std::strtoull(argv[7], nullptr, 10);
    j.bytes_total = j.package_bytes;
    j.launch_exe = argv[8];
    j.install_root = utf8(root / "installs");
    j.install_dir = utf8(root / "installs" / fs::path(j.game_uuid));
    j.temp_path = utf8(root / "installs" / ".virule-downloads" / fs::path(j.game_uuid + "-" + j.revision_id + ".zip.part"));
    j.created_utc = tr::utc_now();
    if (!ed::write_job(root, j)) return 1;
    std::printf("%s\n", j.id.c_str());
    return 0;
}

static int run_signal(int argc, char** argv) {
    if (argc < 3) return 2;
    const std::string n = argv[2];
    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, std::wstring(n.begin(), n.end()).c_str());
    if (!h) return 1;
    SetEvent(h);
    CloseHandle(h);
    return 0;
}

// THE LOOPBACK SERVICE: the driver's Service over plain HTTP to the
// harness's stand-in (no DPoP; the harness checks what the driver sends).
struct LoopbackService final : tr::Service {
    std::wstring host;
    unsigned short port = 0;
    std::string email;
    std::string machine;
    bool signed_in(std::string& out) override { out = email; return !email.empty(); }
    tr::Reply call(const char* method, const std::string& path, const std::string& body,
                   const std::string& content_type, const std::vector<tr::Header>& headers) override {
        tr::Reply r;
        std::wstring h;
        if (!content_type.empty()) h += L"Content-Type: " + std::wstring(content_type.begin(), content_type.end()) + L"\r\n";
        for (const auto& x : headers) h += std::wstring(x.name.begin(), x.name.end()) + L": " + std::wstring(x.value.begin(), x.value.end()) + L"\r\n";
        vclient::http::Timeouts t;
        (void)vclient::http::request(std::wstring(method, method + std::strlen(method)).c_str(), host.c_str(), port, false,
                                     std::wstring(path.begin(), path.end()), h, body, 256 * 1024, r.status, r.body, t);
        return r;
    }
    bool get_range_to_file(const std::string& path, std::uint64_t from, std::uint64_t to, FILE* out,
                           std::uint64_t& bytes_out, unsigned long& status_out,
                           const std::function<bool()>& keep_going) override {
        const std::wstring h = L"Range: bytes=" + std::to_wstring(from) + L"-" + std::to_wstring(to) + L"\r\n";
        unsigned long long got = 0;
        const bool okd = vclient::http::request_to_file(host.c_str(), port, false, std::wstring(path.begin(), path.end()), h,
                                                        to - from + 1, out, got, status_out, keep_going);
        bytes_out = got;
        return okd;
    }
    std::string machine_key() override { return machine; }
};

static int run_drive(int argc, char** argv) {
    if (argc < 5 || !redirected_or_die()) return 2;
    const std::string event = argv[2];
    const std::string endpoint = argv[3];   // http://127.0.0.1:<port>
    LoopbackService svc;
    svc.email = argv[4];
    svc.machine = argc > 5 ? argv[5] : std::string(64, 'a');
    vclient::http::Url u;
    if (!vclient::http::parse_url(std::wstring(endpoint.begin(), endpoint.end()), u)) return 2;
    svc.host = u.host;
    svc.port = u.port;
    tr::DriverConfig cfg;
    cfg.root = vclient::paths::virule_data_root();
    cfg.service = &svc;
    cfg.stop_event = CreateEventW(nullptr, TRUE, FALSE, std::wstring(event.begin(), event.end()).append(L".Stop").c_str());
    cfg.log = [](const std::string& t) { std::printf("%s\n", t.c_str()); std::fflush(stdout); };
    cfg.resume_headless = [](const ed::Job& j) { std::printf("transfers: would resume headless %s\n", j.id.c_str()); std::fflush(stdout); return false; };
    // THE CLIENT'S OWN VERIFICATION runs for every upload; here its scan is a
    // stand-in (VIRULE_TEST_SCAN: clean, the default; detected; unavailable).
    // The install's scan stays the real one; the shipped Client has no seam.
    cfg.scan = [](const std::vector<fs::path>& targets, const std::string&, const std::function<bool()>&) {
        char v[32] = {};
        const DWORD n = GetEnvironmentVariableA("VIRULE_TEST_SCAN", v, sizeof(v));
        const std::string mode = n > 0 && n < sizeof(v) ? std::string(v) : "clean";
        tr::ms::Result r;
        r.scanner = "Test scanner";
        r.path = "defender";
        r.outcome = mode == "detected" ? tr::ms::Outcome::detected : mode == "unavailable" ? tr::ms::Outcome::unavailable : tr::ms::Outcome::clean;
        if (r.outcome == tr::ms::Outcome::detected) r.threats.push_back({ "Test:Detected", tr::ms::detail::path_utf8(targets.front()), "Quarantine" });
        std::printf("transfers: test scan %s of %zu target(s)\n", mode.c_str(), targets.size());
        std::fflush(stdout);
        return r;
    };
    HANDLE wake = vclient::evidence::create_wake_event(std::wstring(event.begin(), event.end()).c_str());
    // "<event>.Release" stands in for main.cpp's release on a changed
    // Evaluations view (a purchase): held uploads asked again, the driver woken.
    HANDLE release = CreateEventW(nullptr, FALSE, FALSE, std::wstring(event.begin(), event.end()).append(L".Release").c_str());
    std::thread releaser([&] {
        HANDLE hs[2] = { cfg.stop_event, release };
        while (WaitForMultipleObjects(2, hs, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {
            tr::release_held_uploads();
            SetEvent(wake);
        }
    });
    std::printf("driver: up\n");
    std::fflush(stdout);
    tr::run_driver(cfg, wake);
    releaser.join();
    std::printf("driver: stopped\n");
    return 0;
}

static int run_control(int argc, char** argv) {
    if (argc < 4) return 2;
    std::printf("%s\n", tr::control(argv[3], fs::path(std::string(argv[2]))).c_str());
    return 0;
}

static int run_status(int argc, char** argv) {
    if (argc < 3) return 2;
    std::printf("%s\n", tr::status_json(fs::path(std::string(argv[2]))).c_str());
    return 0;
}

// GAME ART (client/game_art.hpp, 0.9.16): the service stand-in holds one
// image per game; a ranged GET answers it 206 (the route honors Range).
struct ArtService final : tr::Service {
    std::string held, held_sha, last_put_path, last_put_sha;
    int puts = 0, gets = 0;
    std::string corrupt;   // when set, a GET answers these bytes instead
    bool signed_in(std::string& out) override { out = "dev@example.com"; return true; }
    tr::Reply call(const char* method, const std::string& path, const std::string& body,
                   const std::string&, const std::vector<tr::Header>& headers) override {
        tr::Reply r;
        if (std::string(method) == "PUT" && path.size() > 4 && path.compare(path.size() - 4, 4, "/art") == 0) {
            ++puts;
            last_put_path = path;
            for (const auto& h : headers) if (h.name == "x-virule-art-sha256") last_put_sha = h.value;
            held = body;
            held_sha = last_put_sha;
            r.status = 200;
            r.body = "{\"art\":{\"sha256\":\"" + held_sha + "\"},\"replaced\":true}";
            return r;
        }
        r.status = 404;
        r.body = "{\"error\":{\"code\":\"not_found\",\"message\":\"No such game.\"}}";
        return r;
    }
    bool get_range_to_file(const std::string& path, std::uint64_t, std::uint64_t, FILE* out, std::uint64_t& bytes_out,
                           unsigned long& status_out, const std::function<bool()>&) override {
        ++gets;
        last_put_path = path;
        if (held.empty()) { status_out = 404; return false; }
        const std::string& b = corrupt.empty() ? held : corrupt;
        bytes_out = fwrite(b.data(), 1, b.size(), out);
        status_out = 206;
        return bytes_out == b.size();
    }
    std::string machine_key() override { return std::string(64, '1'); }
};

static void test_game_art() {
    SECTION("game_art: the developer's art is stored by digest; the service's art is fetched, verified and cached");
    namespace ga = vclient::game_art;
    const fs::path root = temp_root("art");
    const std::string game(32, 'a');
    ArtService svc;
    // A PNG of known bytes on the developer's computer (a path with a space).
    std::string png("\x89PNG\r\n\x1a\n", 8);
    for (int i = 0; i < 3000; ++i) png.push_back(static_cast<char>((i * 31) & 0xff));
    const fs::path art_file = root / L"box art.png";
    { std::ofstream f(art_file, std::ios::binary); f.write(png.data(), static_cast<std::streamsize>(png.size())); }
    const std::string sha = tr::sha256_hex(png);

    CHECK(ga::handle("{\"type\":\"game_art\",\"action\":\"upload\",\"game_uuid\":\"" + game + "\",\"path\":\"x\"}", root, nullptr)
              .find("\"ok\":false") != std::string::npos);
    CHECK(ga::handle("{\"type\":\"game_art\",\"action\":\"steal\"}", root, &svc) == "{\"type\":\"error\"}");
    CHECK(ga::handle("{\"type\":\"game_art\",\"action\":\"upload\",\"game_uuid\":\"nope\",\"path\":\"x\"}", root, &svc) == "{\"type\":\"error\"}");

    // Not an image: refused here, nothing sent.
    const fs::path text_file = root / L"notes.txt";
    { std::ofstream f(text_file, std::ios::binary); f << "these are not pixels"; }
    const std::string refused = ga::handle("{\"type\":\"game_art\",\"action\":\"upload\",\"game_uuid\":\"" + game +
                                           "\",\"path\":" + ev::json::quote(utf8(text_file)) + "}", root, &svc);
    CHECK(refused.find("\"ok\":false") != std::string::npos && svc.puts == 0);

    // Upload: the file's own digest travels with it; the bytes are cached.
    const std::string up = ga::handle("{\"type\":\"game_art\",\"action\":\"upload\",\"game_uuid\":\"" + game +
                                      "\",\"path\":" + ev::json::quote(utf8(art_file)) + "}", root, &svc);
    CHECK(up.find("\"ok\":true") != std::string::npos && up.find(sha) != std::string::npos);
    CHECK(svc.puts == 1 && svc.last_put_path == "/v1/evaluations/games/" + game + "/art" && svc.last_put_sha == sha && svc.held == png);
    const fs::path cached = root / L"art" / fs::path(std::wstring(sha.begin(), sha.end()) + L".png");
    CHECK(fs::exists(cached) && fs::file_size(cached) == png.size());

    // Fetch on this computer: the cache answers, nothing is downloaded.
    const std::string here = ga::handle("{\"type\":\"game_art\",\"action\":\"fetch\",\"game_uuid\":\"" + game +
                                        "\",\"sha256\":\"" + sha + "\"}", root, &svc);
    CHECK(here.find("\"ok\":true") != std::string::npos && here.find("art") != std::string::npos && svc.gets == 0);

    // ANOTHER COMPUTER (an empty root): downloaded, verified, cached.
    const fs::path other = temp_root("art-other");
    const std::string there = ga::handle("{\"type\":\"game_art\",\"action\":\"fetch\",\"game_uuid\":\"" + game +
                                         "\",\"sha256\":\"" + sha + "\"}", other, &svc);
    CHECK(there.find("\"ok\":true") != std::string::npos && svc.gets == 1 && svc.last_put_path == "/v1/evaluations/games/" + game + "/art");
    const fs::path other_cached = other / L"art" / fs::path(std::wstring(sha.begin(), sha.end()) + L".png");
    CHECK(fs::exists(other_cached) && fs::file_size(other_cached) == png.size());
    CHECK(!fs::exists(other / L"art" / fs::path(std::wstring(sha.begin(), sha.end()) + L".part")));

    // The evaluator: through their own assignment's route.
    const fs::path evaluator_pc = temp_root("art-evaluator");
    const std::string asg(32, 'c');
    const std::string ev_fetch = ga::handle("{\"type\":\"game_art\",\"action\":\"fetch\",\"game_uuid\":\"" + game +
                                            "\",\"sha256\":\"" + sha + "\",\"assignment_id\":\"" + asg + "\"}", evaluator_pc, &svc);
    CHECK(ev_fetch.find("\"ok\":true") != std::string::npos && svc.last_put_path == "/v1/assignments/" + asg + "/art");

    // Bytes that do not match the digest are never cached.
    const fs::path tampered_pc = temp_root("art-tampered");
    svc.corrupt = png;
    svc.corrupt[100] ^= 0x55;
    const std::string bad = ga::handle("{\"type\":\"game_art\",\"action\":\"fetch\",\"game_uuid\":\"" + game +
                                       "\",\"sha256\":\"" + sha + "\"}", tampered_pc, &svc);
    CHECK(bad.find("\"ok\":false") != std::string::npos && bad.find("does not match") != std::string::npos);
    std::error_code ec;
    CHECK(!fs::exists(tampered_pc / L"art", ec) || fs::is_empty(tampered_pc / L"art", ec));
}

// ---- 2026-10-22: the evaluator workflow completion ----

// A one-shot loopback HTTP server: answers every connection with `answer`.
struct OneShotServer {
    SOCKET listener = INVALID_SOCKET;
    unsigned short port = 0;
    std::string answer;
    HANDLE thread = nullptr;
    bool start(const std::string& a) {
        answer = a;
        WSADATA w{};
        WSAStartup(MAKEWORD(2, 2), &w);
        listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (bind(listener, (sockaddr*)&addr, sizeof(addr)) != 0 || listen(listener, 4) != 0) return false;
        int len = sizeof(addr);
        getsockname(listener, (sockaddr*)&addr, &len);
        port = ntohs(addr.sin_port);
        thread = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            auto* self = (OneShotServer*)p;
            for (;;) {
                SOCKET c = accept(self->listener, nullptr, nullptr);
                if (c == INVALID_SOCKET) return 0;
                std::string req;
                char buf[4096];
                while (req.find("\r\n\r\n") == std::string::npos) {
                    const int n = recv(c, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    req.append(buf, (size_t)n);
                }
                send(c, self->answer.data(), (int)self->answer.size(), 0);
                shutdown(c, SD_BOTH);
                closesocket(c);
            }
        }, this, 0, nullptr);
        return thread != nullptr;
    }
    ~OneShotServer() {
        if (listener != INVALID_SOCKET) closesocket(listener);
        if (thread) { WaitForSingleObject(thread, 2000); CloseHandle(thread); }
    }
};

static std::string fetch_with(const std::string& answer, unsigned long long whole_length, unsigned long& status,
                              unsigned long long& got, bool& ok) {
    OneShotServer srv;
    if (!srv.start(answer)) { ok = false; return {}; }
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    const fs::path out_path = fs::path(tmp) / (L"virule-whole-" + std::to_wstring(GetTickCount64()) + L".bin");
    FILE* out = nullptr;
    _wfopen_s(&out, out_path.wstring().c_str(), L"wb");
    got = 0;
    ok = vclient::http::request_to_file(L"127.0.0.1", srv.port, false, L"/f", L"Range: bytes=0-4\r\n", 5, out, got, status,
                                        {}, whole_length);
    fclose(out);
    const std::string body = slurp(out_path);
    std::error_code ec;
    fs::remove(out_path, ec);
    return body;
}

static void test_whole_object_fetch() {
    SECTION("request_to_file: a 200 of the whole object is taken only when asked from byte 0 with that length");
    const std::string ok200 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    const std::string ok206 = "HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\nContent-Range: bytes 0-4/5\r\nConnection: close\r\n\r\nhello";
    const std::string long200 = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nhello1234";
    unsigned long status = 0;
    unsigned long long got = 0;
    bool ok = false;
    // The ranged (game package) mode keeps requiring 206.
    std::string body = fetch_with(ok200, 0, status, got, ok);
    CHECK(status == 200 && !ok && got == 0 && body.empty());
    body = fetch_with(ok206, 0, status, got, ok);
    CHECK(status == 206 && ok && got == 5 && body == "hello");
    // The whole-object mode takes a 200 of exactly the asked length...
    body = fetch_with(ok200, 5, status, got, ok);
    CHECK(status == 200 && ok && got == 5 && body == "hello");
    // ...never a 200 of another length.
    body = fetch_with(long200, 5, status, got, ok);
    CHECK(status == 200 && !ok && got == 0 && body.empty());
    // A 206 is still a 206 in it.
    body = fetch_with(ok206, 5, status, got, ok);
    CHECK(status == 206 && ok && body == "hello");
}

// THE OWNER RESOLVER (client/evidence_owner.hpp) over a scripted service.
struct OwnerService final : tr::Service {
    std::string email;
    std::map<std::string, unsigned long> ticket_status;   // assignment -> status
    std::string evaluator = std::string(32, 'e');
    int ticket_calls = 0;
    bool signed_in(std::string& out) override { out = email; return !email.empty(); }
    tr::Reply call(const char* method, const std::string& path, const std::string&, const std::string&,
                   const std::vector<tr::Header>&) override {
        tr::Reply r;
        if (std::string(method) == "GET" && path.find("/ticket") != std::string::npos) {
            ++ticket_calls;
            const std::string aid = path.substr(std::string("/v1/assignments/").size(), 32);
            const auto it = ticket_status.find(aid);
            r.status = it == ticket_status.end() ? 404 : it->second;
            if (r.status == 200) r.body = "{\"ticket\":{\"assignment_id\":\"" + aid + "\",\"evaluator_id\":\"" + evaluator + "\"}}";
            return r;
        }
        r.status = 404;
        return r;
    }
    bool get_range_to_file(const std::string&, std::uint64_t, std::uint64_t, FILE*, std::uint64_t&, unsigned long& s,
                           const std::function<bool()>&) override { s = 0; return false; }
    std::string machine_key() override { return std::string(64, '1'); }
};

static void write_ticket(const fs::path& root, const std::string& assignment, const std::string& evaluator) {
    const fs::path p = root / L"evaluator" / L"assignments" / fs::path(assignment) / L"ticket.json";
    fs::create_directories(p.parent_path());
    ev::write_file_atomic(p, "{\"version\":1,\"assignment_id\":\"" + assignment + "\",\"evaluator_id\":\"" + evaluator + "\"}\n");
}

static void test_evidence_owner() {
    SECTION("whose evidence: local install jobs, then the ticket read; another account or signed out waits");
    namespace eo = vclient::evidence_owner;
    using vclient::evidence::Owner;
    const fs::path root = temp_root("owner");
    const std::string mine_a(32, 'a'), other_a(32, 'b'), unknown_a(32, 'c');
    const std::string eva(32, 'e'), dev(32, 'd');
    OwnerService svc;
    eo::Resolver res(root, &svc);
    // Signed out.
    CHECK(res.owner(mine_a, eva) == Owner::SignedOut);
    // The developer signed in on the shared computer: no install job of its
    // own, the ticket read answers 404 for the evaluator's assignment.
    svc.email = "dev@example.com";
    eo::note_account_changed();
    CHECK(res.owner(mine_a, eva) == Owner::OtherAccount);
    const int calls = svc.ticket_calls;
    CHECK(res.owner(mine_a, eva) == Owner::OtherAccount && svc.ticket_calls == calls);   // remembered
    // 403 (the account lacks the evaluator capability): other, asked again.
    svc.ticket_status[other_a] = 403;
    CHECK(res.owner(other_a, eva) == Owner::OtherAccount);
    CHECK(res.owner(other_a, eva) == Owner::OtherAccount && svc.ticket_calls == calls + 2);
    // No answer: unknown (the attempt goes, the service decides).
    svc.ticket_status[unknown_a] = 0;
    CHECK(res.owner(unknown_a, eva) == Owner::Unknown);
    // The evaluator signs in: her install job and its ticket name her id
    // locally, no network.
    ed::Job j;
    j.id = ed::random_hex32();
    j.kind = "install";
    j.state = "installed";
    j.assignment_id = mine_a;
    j.account_email = "eva@example.com";
    j.created_utc = "2026-10-22T10:00:00Z";
    ed::write_job(root, j);
    write_ticket(root, mine_a, eva);
    svc.email = "eva@example.com";
    eo::note_account_changed();
    const int before = svc.ticket_calls;
    CHECK(res.owner(mine_a, eva) == Owner::Mine && svc.ticket_calls == before);
    CHECK(res.owner(other_a, dev) == Owner::OtherAccount && svc.ticket_calls == before);   // another evaluator's package
    // A reinstalled computer (no job, no ticket): the ticket read answers 200 and teaches the id.
    const fs::path root2 = temp_root("owner2");
    eo::Resolver res2(root2, &svc);
    svc.ticket_status[mine_a] = 200;
    CHECK(res2.owner(mine_a, eva) == Owner::Mine);
    const int after = svc.ticket_calls;
    CHECK(res2.owner(other_a, dev) == Owner::OtherAccount && svc.ticket_calls == after);   // the learned id decides
    // 409 (the caller's own assignment, not active): the service decides.
    const fs::path root3 = temp_root("owner3");
    eo::Resolver res3(root3, &svc);
    svc.ticket_status[unknown_a] = 409;
    CHECK(res3.owner(unknown_a, "") == Owner::Mine);
}

// THE SESSION RECOVERY RULES (client/evaluation_recovery.hpp).
static void install_game(const fs::path& root, const std::string& assignment, const fs::path& exe_source, fs::path& dir_out) {
    dir_out = root / L"games" / fs::path(assignment);
    fs::create_directories(dir_out);
    if (!exe_source.empty()) fs::copy_file(exe_source, dir_out / L"Game.exe", fs::copy_options::overwrite_existing);
    else { std::ofstream f(dir_out / L"Game.exe", std::ios::binary); f << "MZ an old wrapper without the mode"; }
    ed::Job j;
    j.id = ed::random_hex32();
    j.kind = "install";
    j.state = "installed";
    j.assignment_id = assignment;
    j.account_email = "eva@example.com";
    j.install_dir = utf8(dir_out);
    j.launch_exe = "Game.exe";
    j.created_utc = "2026-10-22T10:00:00Z";
    ed::write_job(root, j);
}

static void write_ledger(const fs::path& root, const std::string& assignment, const std::vector<std::string>& sessions) {
    const fs::path p = root / L"evaluator" / L"assignments" / fs::path(assignment) / L"ledger.json";
    fs::create_directories(p.parent_path());
    std::string s = "{\"version\":1,\"assignment_id\":\"" + assignment + "\",\"sessions\":[";
    for (size_t i = 0; i < sessions.size(); ++i) {
        if (i) s += ",";
        s += "{\"session_id\":\"" + sessions[i] + "\",\"index\":" + std::to_string(i + 1) + ",\"session_ms\":1000,\"idle_ms\":0}";
    }
    ev::write_file_atomic(p, s + "]}\n");
}

static void test_recovery_rules() {
    SECTION("session recovery: needed, marker, running, received, rate limit; the real recovery-only start");
    namespace rv = vclient::evaluation_recovery;
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    const fs::path me(self);
    CHECK(rv::binary_has_marker(me));   // this test exe carries the marker literal
    const fs::path root = temp_root("recovery");
    const std::string a_new(32, '1'), a_old(32, '2'), a_recv(32, '3');
    const std::string s1(32, 'a'), s2(32, 'b');
    fs::path d_new, d_old, d_recv;
    install_game(root, a_new, me, d_new);
    install_game(root, a_old, fs::path(), d_old);
    install_game(root, a_recv, me, d_recv);
    CHECK(!rv::binary_has_marker(d_old / L"Game.exe"));
    bool running = false;
    std::vector<std::string> started;
    std::int64_t clock = 1790000000;
    rv::Config cfg;
    cfg.root = root;
    cfg.busy = [&](const std::string&) { return running; };
    cfg.run = [&](const fs::path& exe, const fs::path&, DWORD) { started.push_back(utf8(exe)); return 0L; };
    cfg.now = [&] { return clock; };
    cfg.synchronous = true;
    rv::Recovery r(cfg);
    // Nothing to recover: no ledger, no checkpoint.
    CHECK(r.check(a_new) == rv::Verdict::NotNeeded && started.empty());
    // A ledger session with no package anywhere: recovery needed.
    write_ledger(root, a_new, { s1 });
    std::string why;
    CHECK(rv::needs_recovery(root, a_new, why));
    // The game running: never.
    running = true;
    CHECK(r.check(a_new) == rv::Verdict::Running && started.empty());
    running = false;
    // An old wrapper (no marker): never, whatever is needed.
    write_ledger(root, a_old, { s2 });
    ev::write_file_atomic(root / L"evaluator" / L"assignments" / fs::path(a_old) / L"open_session.json", "{}\n");
    CHECK(r.check(a_old) == rv::Verdict::NoMarker && started.empty());
    // A session the service received (progress received[]): never.
    write_ledger(root, a_recv, { s2 });
    const ev::Root er = ev::root_under(root);
    fs::create_directories(ev::progress_dir(er));
    ev::write_file_atomic(ev::progress_path(er, a_recv),
                          "{\"sessions\":1,\"session_ms\":1000,\"idle_ms\":0,\"received\":[{\"session_id\":\"" + s2 + "\",\"session_ms\":1000,\"idle_ms\":0,\"index\":1}]}\n");
    CHECK(!rv::needs_recovery(root, a_recv, why));
    CHECK(r.check(a_recv) == rv::Verdict::NotNeeded && started.empty());
    // A receipt also settles a session.
    const std::string s3(32, 'c');
    write_ledger(root, a_recv, { s3 });
    fs::create_directories(ev::receipts_dir(er));
    ev::write_file_atomic(ev::receipt_path(er, s3), "{}\n");
    CHECK(!rv::needs_recovery(root, a_recv, why));
    // Needed, idle, a wrapper with the mode: started once, then not again for five minutes.
    CHECK(r.check(a_new) == rv::Verdict::Start && started.size() == 1);
    CHECK(r.check(a_new) == rv::Verdict::TooSoon && started.size() == 1);
    clock += 301;
    CHECK(r.check(a_new) == rv::Verdict::Start && started.size() == 2);
    // HELD CONTENT IS NEVER RUN (owner brief 2026-11-05): the service's hold
    // or review (the hold marker), and an assignment TERMINATED for security,
    // never start the wrapper; a RELEASED one whose content is not held does.
    {
        const fs::path adir = root / L"evaluator" / L"assignments" / fs::path(a_new);
        clock += 301;
        ev::write_file_atomic(adir / L"security_hold", "1\n");
        CHECK(r.check(a_new) == rv::Verdict::Held && started.size() == 2);
        fs::remove(adir / L"security_hold");
        ev::write_file_atomic(adir / L"security_end.json", "{\"version\":1,\"outcome\":\"terminated\",\"marked_utc\":\"2026-11-05T00:00:00Z\"}\n");
        CHECK(r.check(a_new) == rv::Verdict::Held && started.size() == 2);
        ev::write_file_atomic(adir / L"security_end.json", "garbled");
        CHECK(r.check(a_new) == rv::Verdict::Held && started.size() == 2);   // an unreadable mark revokes like terminated
        ev::write_file_atomic(adir / L"security_end.json", "{\"version\":1,\"outcome\":\"released\",\"marked_utc\":\"2026-11-05T00:00:00Z\"}\n");
        CHECK(r.check(a_new) == rv::Verdict::Start && started.size() == 3);
        fs::remove(adir / L"security_end.json");
    }
    // An open checkpoint alone is a reason.
    write_ledger(root, a_new, {});
    ev::write_file_atomic(root / L"evaluator" / L"assignments" / fs::path(a_new) / L"open_session.json", "{}\n");
    CHECK(rv::needs_recovery(root, a_new, why));
    // THE REAL START: the installed copy of this exe in its recovery-only
    // mode, hidden, the game folder as working directory; exit 0.
    const long code = rv::run_hidden(d_new / L"Game.exe", d_new, 30000);
    CHECK(code == 0);
    CHECK(fs::exists(d_new / L"recovered.txt"));   // written by the recovery mode in its working directory
}

// THE OPEN INTENT and the admin_launch route (client/assignment_open.hpp).
static void test_assignment_open() {
    SECTION("assignment_open: the intent (latest wins, taken once, ten minutes); admin_launch without an update opens");
    namespace ao = vclient::assignment_open;
    ao::Intent i;
    CHECK(i.take(1000).empty());
    i.set(std::string(32, 'a'), 1000);
    i.set(std::string(32, 'b'), 2000);                        // the latest wins
    CHECK(i.take(3000) == std::string(32, 'b'));
    CHECK(i.take(3001).empty());                              // taken once
    i.set(std::string(32, 'c'), 5000);
    CHECK(i.take(5000 + ao::kIntentLifeMs).size() == 32);     // still inside ten minutes
    i.set(std::string(32, 'c'), 5000);
    CHECK(i.take(5001 + ao::kIntentLifeMs).empty());          // expired
    CHECK(ao::take_json("") == "{\"type\":\"assignment_open_intent\",\"assignment_id\":\"\"}");
    CHECK(ao::admin_launch_route(false) == ao::LaunchRoute::OpenAdmin);
    CHECK(ao::admin_launch_route(true) == ao::LaunchRoute::UpdateHandoff);
    CHECK(ao::is_hex32(std::string(32, 'f')) && !ao::is_hex32("XYZ"));
}

// ------------------------------------------------------- the upload gate ----
// THE CLIENT OWNS THE DEVELOPER'S VERDICT (owner brief 2026-11-02, "Client
// Security Authority Phase 2" sections 4 to 9 and 19). Every case builds the
// state the transfer driver sees DIRECTLY (a job file as the Admin host, a
// patched host or any local program could write it), never through the
// Admin, and asserts what reaches the service.

// The service's upload half, in memory: sessions by build, the parts held,
// and every byte it was sent.
struct UploadService final : tr::Service {
    struct Session { std::string build, sha; std::uint64_t bytes = 0; std::map<std::int64_t, std::string> parts; bool done = false; };
    std::map<std::string, Session> sessions;   // session id -> session
    int opens = 0, puts = 0, completes = 0, incidents = 0, incident_calls = 0, refuse_incidents = 0;
    std::string last_open, last_incident, last_incident_route;
    bool signed_in(std::string& out) override { out = "dev@example.com"; return true; }
    tr::Reply call(const char* method, const std::string& path, const std::string& body,
                   const std::string&, const std::vector<tr::Header>&) override {
        tr::Reply r;
        const std::string m = method;
        auto uploaded = [](const Session& s) {
            std::string o = "[";
            for (const auto& [n, _] : s.parts) o += (o.size() > 1 ? "," : "") + std::to_string(n);
            return o + "]";
        };
        if (m == "POST" && path.find("/security/incident") != std::string::npos) {
            ++incident_calls;
            if (refuse_incidents > 0) { --refuse_incidents; r.status = 401; r.body = "{\"error\":{\"code\":\"machine_not_bound\",\"message\":\"x\"}}"; return r; }
            ++incidents; last_incident = body; last_incident_route = path; r.status = 201; r.body = "{}"; return r;
        }
        if (m == "POST" && path.size() > 8 && path.compare(path.size() - 8, 8, "/uploads") == 0) {
            ++opens;
            last_open = body;
            std::string build, sha;
            std::int64_t bytes = 0;
            (void)vclient::json_scan::find_string_in(body, 0, body.size(), "build_uuid", build);
            (void)vclient::json_scan::find_string_in(body, 0, body.size(), "package_sha256", sha);
            (void)ev::json::get_int(body, "package_bytes", bytes);
            for (auto& [id, s] : sessions) {
                if (s.build == build) {
                    if (s.sha != sha) { r.status = 409; r.body = "{\"error\":{\"code\":\"conflict\",\"message\":\"Different contents.\"}}"; return r; }
                    r.status = 200; r.body = "{\"session_id\":\"" + id + "\",\"state\":\"uploading\",\"uploaded\":" + uploaded(s) + "}"; return r;
                }
            }
            const std::string id = ed::random_hex32();
            sessions[id] = Session{ build, sha, static_cast<std::uint64_t>(bytes), {}, false };
            r.status = 201; r.body = "{\"session_id\":\"" + id + "\",\"state\":\"uploading\",\"uploaded\":[]}"; return r;
        }
        const std::string up = "/v1/evaluations/uploads/";
        if (path.compare(0, up.size(), up) == 0) {
            const std::string id = path.substr(up.size(), 32);
            auto it = sessions.find(id);
            if (it == sessions.end()) { r.status = 404; r.body = "{\"error\":{\"code\":\"not_found\",\"message\":\"No.\"}}"; return r; }
            Session& s = it->second;
            const std::string rest = path.substr(up.size() + 32);
            if (m == "GET" && rest.empty()) { r.status = 200; r.body = "{\"state\":\"uploading\",\"uploaded\":" + uploaded(s) + "}"; return r; }
            if (m == "PUT" && rest.compare(0, 7, "/parts/") == 0) {
                ++puts;
                s.parts[std::strtoll(rest.substr(7).c_str(), nullptr, 10)] = body;
                r.status = 200; r.body = "{\"uploaded\":" + uploaded(s) + "}"; return r;
            }
            if (m == "POST" && rest == "/complete") {
                ++completes;
                std::string all;
                for (const auto& [n, b] : s.parts) all += b;
                if (tr::sha256_hex(all) != s.sha) { r.status = 409; r.body = "{\"error\":{\"code\":\"integrity\",\"message\":\"No.\"}}"; return r; }
                s.done = true;
                r.status = 200; r.body = "{}"; return r;
            }
        }
        r.status = 404;
        return r;
    }
    bool get_range_to_file(const std::string&, std::uint64_t, std::uint64_t, FILE*, std::uint64_t&, unsigned long& status_out,
                           const std::function<bool()>&) override { status_out = 0; return false; }
    std::string machine_key() override { return std::string(64, '1'); }
    // Everything the service holds for the build, as one byte string.
    std::string received(const std::string& build) const {
        for (const auto& [_, s] : sessions) if (s.build == build) { std::string all; for (const auto& [n, b] : s.parts) all += b; return all; }
        return {};
    }
};

// A packaged job exactly as the Admin host hands one over (or as anything
// else could write one): a real stored package of one Game.exe.
static ed::Job packaged_job(const fs::path& root, const std::string& content) {
    ed::Job j;
    j.id = ed::random_hex32();
    j.kind = "upload";
    j.state = "packaged";
    j.account_email = "dev@example.com";
    j.game_uuid = ed::random_hex32();
    j.game_id = "local-" + j.game_uuid.substr(0, 8);
    j.build_uuid = ed::random_hex32();
    j.built_utc = "2026-11-02T10:00:00Z";
    j.launch_exe = "Game.exe";
    j.created_utc = tr::utc_now();
    const fs::path dir = root / "builds" / "package";
    fs::create_directories(dir);
    const fs::path pkg = dir / fs::path(j.build_uuid + ".zip");
    write_zip(pkg, { { "Game.exe", content } });
    j.package_path = utf8(pkg);
    j.package_bytes = fs::file_size(pkg);
    tr::sha256_file_hex(pkg, j.package_sha256);
    j.parts_total = static_cast<std::int64_t>(ed::parts_total(j.package_bytes));
    j.bytes_total = j.package_bytes;
    ed::write_job(root, j);
    return j;
}

static std::string random_bytes_str(size_t n, unsigned seed) {
    std::mt19937_64 rng(seed);
    std::string s(n, '\0');
    for (auto& c : s) c = static_cast<char>(rng());
    return s;
}

static void drive_once(tr::DriverConfig& cfg) {
    std::map<std::string, std::int64_t> last;
    (void)tr::run_pass(cfg, last);
}

// ---- 2026-11-05 (owner decision): RESUMED AFTER A CLEARANCE, the cleared
// revision is verified again here; an earlier refusal is no permanent veto.
static void test_reverify_after_resume() {
    SECTION("resumed after a clearance: the cleared revision is verified again here (durable request; no historical veto)");
    const fs::path root = temp_root("reverify");
    UploadService svc;
    tr::DriverConfig cfg;
    cfg.root = root;
    cfg.service = &svc;
    cfg.log = [](const std::string&) {};
    const std::string A = ed::random_hex32(), B = ed::random_hex32(), C2 = ed::random_hex32(), R = ed::random_hex32(), R2 = ed::random_hex32();
    auto held = [&](const std::string& assignment, const std::string& revision) {
        ed::Job j;
        j.id = ed::random_hex32(); j.kind = "install"; j.state = "failed"; j.account_email = "dev@example.com";
        j.assignment_id = assignment; j.revision_id = revision; j.security_held = true; j.scan_outcome = "detected";
        j.scan_revision_id = revision; j.error = tr::detail::kInstallThreat; j.created_utc = tr::utc_now();
        ed::write_job(root, j);
        return j;
    };
    const ed::Job a = held(A, R), other_rev = held(A, R2), other_asg = held(B, R);
    // A computer that NEVER refused: an installed, verified copy of the cleared revision.
    ed::Job clean;
    clean.id = ed::random_hex32(); clean.kind = "install"; clean.state = "installed"; clean.account_email = "dev@example.com";
    clean.assignment_id = C2; clean.revision_id = R; clean.installed_revision_id = R; clean.scan_revision_id = R; clean.scan_outcome = "clean";
    clean.install_dir = utf8(root / "absent-folder"); clean.created_utc = tr::utc_now();
    ed::write_job(root, clean);
    for (const auto& id : { a.id, clean.id }) {
        fs::create_directories(tr::vc::record_path(root, id).parent_path());
        std::ofstream(tr::vc::record_path(root, id)) << "{}";
    }
    CHECK(tr::detail::revision_held_here(root, A, R));
    drive_once(cfg);
    ed::Job got;
    CHECK(ed::read_job(root, a.id, got) && got.security_held);   // nothing asked: nothing changes
    CHECK(tr::request_reverification(root, A, R) && tr::request_reverification(root, C2, R));
    CHECK(fs::exists(tr::reverify_dir(root) / A));                // DURABLE: on disk before the driver ran
    // (a Client that exits here keeps the request: nothing in memory carries it)
    drive_once(cfg);
    CHECK(ed::read_job(root, a.id, got) && !got.security_held && got.scan_revision_id.empty() && got.scan_outcome != "detected");
    CHECK(!fs::exists(tr::vc::record_path(root, a.id)));          // verified again from the start
    CHECK(!tr::detail::revision_held_here(root, A, R));
    CHECK(ed::read_job(root, clean.id, got) && got.state == "installed" && got.scan_revision_id.empty() &&
          !fs::exists(tr::vc::record_path(root, clean.id)));      // EVERY computer: the installed copy is verified whole again
    CHECK(ed::read_job(root, other_rev.id, got) && got.security_held);   // another revision's refusal stays
    CHECK(ed::read_job(root, other_asg.id, got) && got.security_held);   // another assignment's stays
    CHECK(!fs::exists(tr::reverify_dir(root) / A) && !fs::exists(tr::reverify_dir(root) / C2));   // applied, then removed
    CHECK(!tr::request_reverification(root, "short", R));         // malformed: refused
    // The pure rule.
    ed::Job j = held(A, R);
    CHECK(tr::detail::set_aside_refusal(j, A, R) && j.state == "queued" && j.attempts == 0 && !j.security_held);
    ed::Job k = held(A, R);
    CHECK(!tr::detail::set_aside_refusal(k, A, R2) && k.security_held);
    k.kind = "upload";
    CHECK(!tr::detail::set_aside_refusal(k, A, R));
}

static void test_upload_gate() {
    SECTION("the upload gate: no Client verification, no upload");
    namespace uv = vclient::upload_verification;
    namespace ms = virule::core::malware_scan;
    const fs::path root = temp_root("gate");
    UploadService svc;
    int scans = 0;
    ms::Outcome next = ms::Outcome::clean;
    tr::DriverConfig cfg;
    cfg.root = root;
    cfg.service = &svc;
    cfg.log = [](const std::string&) {};
    cfg.scan = [&](const std::vector<fs::path>& targets, const std::string&, const std::function<bool()>&) {
        ++scans;
        ms::Result r;
        r.scanner = "Test scanner";
        r.path = "defender";
        r.outcome = next;
        if (next == ms::Outcome::detected) r.threats.push_back({ "Test:Detected", ms::detail::path_utf8(targets.front()), "Quarantine" });
        return r;
    };
    ed::Job got;

    // 1. A FORGED "CLEAN" JOB: every field the Admin could set says verified
    // and mid-upload; the Client has no record of its own. It verifies first,
    // and with an unsupported scanner nothing is ever sent.
    {
        ed::Job j = packaged_job(root, random_bytes_str(4000, 1));
        j.state = "uploading";
        j.scan_outcome = "clean";
        j.session_id = ed::random_hex32();
        j.parts_done = { 1 };
        ed::write_job(root, j);
        next = ms::Outcome::unavailable;
        drive_once(cfg);
        CHECK(ed::read_job(root, j.id, got) && got.state == "failed" && got.scan_outcome == "unavailable");
        CHECK(svc.opens == 0 && svc.puts == 0 && scans == 1);
        CHECK(!fs::exists(uv::record_path(root, j.id)));
    }
    // 2. A DETECTION never uploads: the job fails with the threat sentence,
    // the incident is this Client's own (sealed) and is what is reported.
    {
        ed::Job j = packaged_job(root, random_bytes_str(4000, 2));
        next = ms::Outcome::detected;
        drive_once(cfg);
        CHECK(ed::read_job(root, j.id, got) && got.state == "failed" && got.error.find("found a threat") != std::string::npos);
        CHECK(svc.opens == 0 && svc.puts == 0);
        uv::Incident inc;
        CHECK(uv::read_incident(root, j.id, inc) && inc.incident.find("\"scan_package\"") != std::string::npos &&
              inc.incident.find(j.build_uuid) != std::string::npos);
        drive_once(cfg);   // the next pass reports it
        CHECK(svc.incidents == 1 && svc.last_incident_route == "/v1/evaluations/games/" + j.game_uuid + "/security/incident");
        drive_once(cfg);
        CHECK(svc.incidents == 1);   // reported once
    }
    // 2b. A REFUSED PROOF (401: the key not proved yet, a clock) is never
    // final: the incident is sent again and recorded exactly once.
    {
        ed::Job j = packaged_job(root, random_bytes_str(4000, 21));
        next = ms::Outcome::detected;
        svc.refuse_incidents = 1;
        const int before = svc.incidents, calls = svc.incident_calls;
        drive_once(cfg);   // the verification fails, the incident is kept
        drive_once(cfg);   // reported: 401
        uv::Incident inc;
        CHECK(svc.incident_calls == calls + 1 && svc.incidents == before && uv::read_incident(root, j.id, inc) && !inc.reported);
        drive_once(cfg);   // reported again: recorded
        drive_once(cfg);   // and never again
        CHECK(svc.incident_calls == calls + 2 && svc.incidents == before + 1 && uv::read_incident(root, j.id, inc) && inc.reported);
    }
    // 2c. THE EVALUATOR'S PRE-PLAY CHECK finds a threat in the installed game:
    // this Client's own incident, reported to the assignment once.
    {
        const fs::path games = root / "installs";
        const std::string assignment = ed::random_hex32(), revision = ed::random_hex32(), game = ed::random_hex32();
        fs::create_directories(games / game);
        std::ofstream(games / game / "Game.exe") << "installed";
        ed::Job j;
        j.id = ed::random_hex32();
        j.kind = "install";
        j.state = "installed";
        j.account_email = "dev@example.com";
        j.assignment_id = assignment;
        j.game_uuid = game;
        j.revision_id = revision;
        j.installed_revision_id = revision;
        j.launch_exe = "Game.exe";
        j.install_root = utf8(games);
        j.install_dir = utf8(games / game);
        j.created_utc = tr::utc_now();
        ed::write_job(root, j);
        next = ms::Outcome::detected;
        const int before = svc.incidents;
        drive_once(cfg);   // the check finds it
        drive_once(cfg);   // the next pass reports it
        ed::Job got2;
        CHECK(ed::read_job(root, j.id, got2) && got2.security_held && got2.incident.empty());
        CHECK(svc.incidents == before + 1 && svc.last_incident_route == "/v1/assignments/" + assignment + "/security/incident" &&
              svc.last_incident.find("\"launch\"") != std::string::npos && svc.last_incident.find(revision) != std::string::npos);
        drive_once(cfg);
        CHECK(svc.incidents == before + 1);
    }
    // 3. AN INCIDENT WRITTEN INTO A JOB FILE is never sent (the host, or
    // anything else, cannot make this Client hold a game).
    {
        ed::Job j = packaged_job(root, random_bytes_str(3000, 3));
        j.state = "failed";
        j.incident = "{\"incident_id\":\"" + ed::random_hex32() + "\",\"operation\":\"scan_package\",\"outcome\":\"detected\"}";
        j.incident_reported = false;
        ed::write_job(root, j);
        const int before = svc.incidents;
        drive_once(cfg);
        CHECK(svc.incidents == before);
    }
    // 4. A FORGED RECORD (unsealed, or sealed by another key) authorizes nothing.
    {
        ed::Job j = packaged_job(root, random_bytes_str(5000, 4));
        fs::create_directories(uv::record_path(root, j.id).parent_path());
        std::ofstream(uv::record_path(root, j.id)) << "{\"format\":\"virule-upload-verification.v1\",\"job_id\":\"" << j.id
            << "\",\"package_sha256\":\"" << j.package_sha256 << "\",\"part_sha256\":[\"" << j.package_sha256 << "\"],\"seal\":\"" << std::string(64, 'a') << "\"}";
        uv::Record forged;
        CHECK(!uv::read_record(root, j.id, forged));
        next = ms::Outcome::unavailable;
        const int s0 = scans;
        drive_once(cfg);
        CHECK(scans == s0 + 1 && ed::read_job(root, j.id, got) && got.state == "failed" && svc.opens == 0);
    }
    // 5. THE HEALTHY PATH: verified, then uploaded with THIS CLIENT'S figures,
    // and the service holds exactly the verified bytes.
    ed::Job ok_job;
    {
        ok_job = packaged_job(root, random_bytes_str(6000, 5));
        // The host's figures are wrong on purpose (a patched host): the
        // Client's own are what the service is told.
        ok_job.content_bytes = 1;
        ok_job.file_count = 99;
        ed::write_job(root, ok_job);
        next = ms::Outcome::clean;
        drive_once(cfg);
        CHECK(ed::read_job(root, ok_job.id, got) && got.state == "done");
        uv::Record rec;
        CHECK(uv::read_record(root, ok_job.id, rec) && rec.package_sha256 == ok_job.package_sha256 && rec.file_count == 1 && rec.content_bytes == 6000);
        CHECK(svc.last_open.find("\"file_count\":1,") != std::string::npos && svc.last_open.find("\"content_bytes\":6000,") != std::string::npos);
        CHECK(tr::sha256_hex(svc.received(ok_job.build_uuid)) == ok_job.package_sha256);
    }
    // 6. BYTES CHANGED AFTER VERIFICATION (same size, the write time put
    // back): the changed part is never sent; the upload stops.
    {
        ed::Job j = packaged_job(root, random_bytes_str(7000, 6));
        next = ms::Outcome::clean;
        // Verify only: a session that refuses to open keeps it at packaged.
        CHECK(tr::detail::verify_package(cfg, j));
        const fs::path pkg = tr::path_of(j.package_path);
        const auto t = fs::last_write_time(pkg);
        {
            std::fstream f(pkg, std::ios::in | std::ios::out | std::ios::binary);
            f.seekp(200);
            f.put('X');
        }
        fs::last_write_time(pkg, t);
        const int p0 = svc.puts;
        drive_once(cfg);
        CHECK(ed::read_job(root, j.id, got) && got.state == "failed" && got.error.find("changed since it was built") != std::string::npos);
        CHECK(svc.puts == p0 && svc.received(j.build_uuid).empty());
        CHECK(!fs::exists(uv::record_path(root, j.id)));
    }
    // 7. A RESTART MID-UPLOAD WITHOUT THE CLIENT'S RECORD (it was lost, or
    // never this Client's): verified again before another byte is sent.
    {
        ed::Job j = packaged_job(root, random_bytes_str(3000, 7));
        next = ms::Outcome::clean;
        CHECK(tr::detail::verify_package(cfg, j));
        uv::remove_record(root, j.id);
        j.state = "uploading";
        j.session_id = ed::random_hex32();
        ed::write_job(root, j);
        const int s0 = scans;
        drive_once(cfg);
        CHECK(scans == s0 + 1 && ed::read_job(root, j.id, got) && got.state == "done");
    }
    // 8. A HELD UPLOAD keeps its verification while the package is unchanged,
    // and verifies again once it moved (a rebuilt package at the same path).
    {
        ed::Job j = packaged_job(root, random_bytes_str(3000, 8));
        next = ms::Outcome::clean;
        CHECK(tr::detail::verify_package(cfg, j));
        ed::read_job(root, j.id, j);
        j.state = "held";
        ed::write_job(root, j);
        const int s0 = scans;
        drive_once(cfg);
        CHECK(scans == s0 && ed::read_job(root, j.id, got) && got.state == "done");
        ed::Job k = packaged_job(root, random_bytes_str(3000, 9));
        CHECK(tr::detail::verify_package(cfg, k));
        ed::read_job(root, k.id, k);
        k.state = "held";
        ed::write_job(root, k);
        write_zip(tr::path_of(k.package_path), { { "Game.exe", random_bytes_str(3100, 10) } });
        const int s1 = scans;
        drive_once(cfg);
        // Rebuilt under the job: not the package the host recorded, so it stops.
        CHECK(scans == s1 && ed::read_job(root, k.id, got) && got.state == "failed" && got.error.find("changed since it was built") != std::string::npos);
    }
    // 9. ANOTHER BUILD under the same job id (the job re-pointed): the record
    // is of another build, so it is verified again.
    {
        ed::Job j = packaged_job(root, random_bytes_str(2000, 11));
        next = ms::Outcome::clean;
        CHECK(tr::detail::verify_package(cfg, j));
        uv::Record rec;
        std::string why;
        ed::read_job(root, j.id, j);
        CHECK(uv::vouches(root, j, rec, why));
        j.build_uuid = ed::random_hex32();
        CHECK(!uv::vouches(root, j, rec, why) && why.find("another build") != std::string::npos);
    }
    // 10. THE HOST'S PRECHECK SAID "detected": the Client establishes it from
    // its own scan of the game's folder before anything is reported.
    {
        const fs::path source = root / "game";
        fs::create_directories(source);
        std::ofstream(source / "Game.exe") << "game";
        ed::Job j;
        j.id = ed::random_hex32();
        j.kind = "upload";
        j.state = "failed";
        j.account_email = "dev@example.com";
        j.game_id = "precheck";
        j.game_uuid = ed::random_hex32();
        j.scan_outcome = "detected";
        j.source_path = utf8(source);
        j.created_utc = tr::utc_now();
        ed::write_job(root, j);
        next = ms::Outcome::clean;
        const int i0 = svc.incidents;
        drive_once(cfg);
        uv::Incident inc;
        CHECK(svc.incidents == i0 && uv::read_incident(root, j.id, inc) && inc.examined && inc.incident.empty());
        ed::Job j2 = j;
        j2.id = ed::random_hex32();
        ed::write_job(root, j2);
        next = ms::Outcome::detected;
        drive_once(cfg);
        drive_once(cfg);
        CHECK(svc.incidents == i0 + 1 && svc.last_incident.find("\"scan_source\"") != std::string::npos);
    }
    fs::remove_all(root);
}

// THE HEALTHY DEFENDER PATH, for real: Microsoft Defender on this computer
// verifies a small clean package; where it cannot scan, it never uploads.
static void test_upload_gate_real_defender() {
    SECTION("the upload gate with the real scanner of this computer");
    namespace ms = virule::core::malware_scan;
    const fs::path root = temp_root("gate-real");
    UploadService svc;
    tr::DriverConfig cfg;
    cfg.root = root;
    cfg.service = &svc;
    cfg.log = [](const std::string& t) { std::printf("   %s\n", t.c_str()); };
    ed::Job j = packaged_job(root, "a small clean game file " + random_bytes_str(64, 12));
    const bool usable = ms::scanning_availability().usable;
    drive_once(cfg);
    ed::Job got;
    CHECK(ed::read_job(root, j.id, got));
    if (usable) {
        CHECK(got.state == "done" && svc.completes == 1);
        std::printf("   (Defender available: verified and uploaded)\n");
    } else {
        CHECK(got.state == "failed" && svc.opens == 0);
        std::printf("   (no supported scanner here: refused, nothing uploaded)\n");
    }
    fs::remove_all(root);
}

// ---- 2026-11-06 (owner brief, the corrective pass after the external
// malware-analysis research): WHAT THE CLIENT ESTABLISHES OF A FLAGGED FILE.
// Digests come from the bytes VIRULE itself wrote or copied, in the same pass;
// a file the antivirus took before VIRULE read it has none; Defender's Threat
// ID is passed on only when valid. Every scan here is a stand-in naming
// files; nothing is malware and nothing leaves this computer.
static void put32(std::string& s, std::uint32_t v) { s.append(reinterpret_cast<const char*>(&v), 4); }
static void put64(std::string& s, std::uint64_t v) { s.append(reinterpret_cast<const char*>(&v), 8); }
/** A VIRULE wrapper as the Admin builds it: a stub, a VRULPK1 archive holding
 *  the original executable raw, and the 24-byte VRULEND1 footer. */
static std::string wrapper_bytes(const std::string& stub, const std::string& member, const std::string& original) {
    std::string table;
    put32(table, static_cast<std::uint32_t>(member.size()));
    table += member;
    put64(table, 0);
    put64(table, original.size());
    std::string payload("VRULPK1\0", 8);
    put32(payload, 1);
    payload += table;
    payload += original;
    std::string footer("VRULEND1", 8);
    put64(footer, payload.size());
    put64(footer, 24);
    return stub + payload + footer;
}
static std::string lower_utf8(const fs::path& p) {
    std::wstring w = p.wstring();
    for (auto& c : w) c = static_cast<wchar_t>(towlower(c));
    return utf8(fs::path(w));
}

static void test_finding_identity() {
    SECTION("finding identity: digests of the bytes VIRULE wrote, never after the antivirus took them (owner brief 2026-11-06)");
    namespace ms = virule::core::malware_scan;
    namespace fi = vclient::finding_identity;
    namespace vd = vclient::verified_digests;
    namespace uv = vclient::upload_verification;
    namespace vc = virule::core::verified_content;
    const fs::path root = temp_root("identity");
    const std::string dll = random_bytes_str(5000, 61), original = "MZ original game " + random_bytes_str(3000, 62);
    const std::string exe = wrapper_bytes("MZ virule stub " + random_bytes_str(700, 63), "__virule__/orig/Game.exe", original);
    const std::string data_zip = random_bytes_str(900, 64);
    const fs::path pkg = root / "pkg.zip";
    write_zip(pkg, { { "Game.exe", exe }, { "bin/game.dll", dll }, { "bin/data.zip", data_zip } });

    // 1. THE EXTRACTOR hashes each entry as it writes it.
    const fs::path dir = root / "x";
    std::vector<fi::WrittenEntry> written;
    std::string why;
    CHECK(tr::detail::extract_zip(pkg, dir, why, {}, &written));
    CHECK(written.size() == 3);
    bool hashed_all = written.size() == 3;
    for (const auto& w : written) {
        const std::string& want = w.name == "Game.exe" ? exe : w.name == "bin/game.dll" ? dll : data_zip;
        hashed_all = hashed_all && w.sha256 == tr::sha256_hex(want) && w.bytes == want.size() && w.size_after == want.size();
    }
    CHECK(hashed_all);   // each digest is the digest of exactly the entry's bytes

    // 2. THE WRAPPED ORIGINAL is hashed as it is copied out.
    const fs::path copies = root / "copies";
    const ms::Extracted x = ms::extract_wrapped_originals(dir, copies, {});
    CHECK(x.ok && x.originals.size() == 1);
    if (x.originals.size() == 1) {
        const auto& o = x.originals[0];
        CHECK(o.member == "__virule__/orig/Game.exe" && o.bytes == original.size() && o.sha256 == tr::sha256_hex(original));
        CHECK(fs::equivalent(o.wrapper, dir / "Game.exe") && slurp(o.copy) == original);
    }

    // 3. THE INDEX and every reported shape (attach).
    fi::Index idx;
    idx.package = fi::key_of(pkg);
    fi::add_package(idx, written);
    fi::add_originals(idx, x.originals, dir);
    const fs::path dllPath = dir / "bin" / "game.dll";
    const fs::path local = dir / "save.dat";
    std::ofstream(local, std::ios::binary) << "a save the game wrote";
    const fs::path takenLocal = dir / "dropped.tmp";   // the antivirus took it: never read
    ms::Result r;
    r.outcome = ms::Outcome::removed;
    r.scanner = "Test scanner";
    r.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(dllPath), "Quarantine", "2147519003" });
    r.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(pkg) + "; file:_" + utf8(pkg) + "->bin/game.dll", "Quarantine" });
    r.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(dir / "bin" / "data.zip") + "; file:_" + utf8(dir / "bin" / "data.zip") + "->inner.exe", "Quarantine" });
    r.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(x.originals.empty() ? fs::path() : x.originals[0].copy), "Quarantine" });
    r.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(local), "Quarantine" });
    r.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(takenLocal), "Quarantine" });
    r.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(pkg) + "; file:_" + utf8(pkg) + "->bin/data.zip->inner.exe", "Quarantine" });
    r.missing.push_back(lower_utf8(dllPath));          // Defender's "removed from disk" entry, as the inventory states it
    r.missing.push_back(utf8(takenLocal));
    r.missing.push_back("Game.exe");                      // a refused launch file: a bare entry name
    r.missing.push_back("A game file could not be written.");
    fi::attach(r, idx);
    const auto& t = r.threats;
    CHECK(t[0].identity.stated && t[0].identity.origin == "package" && t[0].identity.entry == "bin/game.dll" &&
          t[0].identity.sha256 == tr::sha256_hex(dll) && t[0].identity.bytes == dll.size());
    CHECK(r.missing_identity.size() == 4 && r.missing_identity[0].sha256 == t[0].identity.sha256);   // the removal entry: the same content
    CHECK(t[1].identity.origin == "package" && t[1].identity.entry == "bin/game.dll" && t[1].identity.sha256.empty());   // inside the package zip: named, no digest
    CHECK(t[2].identity.origin == "package" && t[2].identity.entry == "bin/data.zip" && t[2].identity.sha256.empty());   // never a container's digest
    CHECK(t[3].identity.origin == "wrapped_original" && t[3].identity.entry == "Game.exe" &&
          t[3].identity.member == "__virule__/orig/Game.exe" && t[3].identity.sha256 == tr::sha256_hex(original));
    CHECK(t[4].identity.origin == "local" && t[4].identity.sha256 == tr::sha256_hex(std::string("a save the game wrote")));   // still there: hashed now
    CHECK(t[5].identity.origin == "local" && t[5].identity.sha256.empty());   // taken by the antivirus: nothing fabricated
    CHECK(t[6].identity.origin == "package" && t[6].identity.sha256.empty());   // nested content: not identified
    CHECK(r.missing_identity[1].origin == "local" && r.missing_identity[1].sha256.empty());
    CHECK(r.missing_identity[2].origin == "package" && r.missing_identity[2].entry == "Game.exe" && r.missing_identity[2].sha256.empty());
    CHECK(r.missing_identity[3].origin == "unknown" && r.missing_identity[3].sha256.empty());
    // A CONTAINER NAMED WITH A LITERAL TRAILING SPACE is not the package VIRULE
    // wrote: the package's own entry digest is never given to it (the same
    // shape without the spaces gets it: t[1] above).
    {
        ms::Result r8;
        r8.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(pkg) + " ; file:_" + utf8(pkg) + " ->bin/game.dll", "Quarantine" });
        r8.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(pkg) + "; file:_" + utf8(pkg) + "->bin/game.dll ", "Quarantine" });
        r8.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(pkg) + "; file:_" + utf8(dir / "other.zip") + "->bin/game.dll", "Quarantine" });
        fi::attach(r8, idx);
        CHECK(r8.threats[0].identity.sha256.empty());   // the container's name carries a literal space
        CHECK(r8.threats[1].identity.sha256.empty() && r8.threats[1].identity.entry == "bin/game.dll ");   // an inner name is looked up exactly
        CHECK(r8.threats[2].identity.sha256.empty());   // the two container names must be the same text
    }

    // 4. A FILE CHANGED SINCE IT WAS WRITTEN loses its digest (the index is
    // built right before the scan, from files still exactly as written).
    {
        std::ofstream(dllPath, std::ios::binary | std::ios::app) << "tampered";
        fi::Index later;
        fi::add_package(later, written);
        ms::Result r2;
        r2.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(dllPath), "Quarantine" });
        r2.missing.push_back(utf8(dllPath));
        fi::attach(r2, later);
        CHECK(r2.threats[0].identity.origin == "package" && r2.threats[0].identity.sha256.empty());
    }
    // 5. A FILE MORE THAN ONE ENTRY WROTE has no digest (which entry's bytes
    // the antivirus saw cannot be established): the same name twice, a case
    // variant, and a name Windows maps onto the same file (a trailing dot);
    // a name carried twice identifies neither entry by name, and nothing in
    // VIRULE's own extraction folder is hashed after the fact.
    {
        const fs::path dup = root / "dup.zip";
        write_zip(dup, { { "a.dll", "first" }, { "a.dll", "second" }, { "B.dll", "upper" }, { "b.dll", "lower" },
                         { "c.dll", "plain" }, { "c.dll.", "dotted" }, { "d.dll", "alone" } });
        std::vector<fi::WrittenEntry> w2;
        CHECK(tr::detail::extract_zip(dup, root / "dup", why, {}, &w2) && w2.size() == 7);
        fi::Index i2;
        i2.package = fi::key_of(dup);
        fi::own(i2, root / "dup");
        fi::add_package(i2, w2);
        ms::Result r3;
        r3.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(dup) + "; file:_" + utf8(dup) + "->a.dll", "Quarantine" });
        for (const char* f : { "a.dll", "b.dll", "c.dll", "d.dll" }) r3.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(root / "dup" / f), "Quarantine" });
        fi::attach(r3, i2);
        CHECK(r3.threats[0].identity.sha256.empty() && i2.ambiguous.count("a.dll") == 1);
        CHECK(r3.threats[1].identity.sha256.empty() && r3.threats[2].identity.sha256.empty() && r3.threats[3].identity.sha256.empty());
        CHECK(r3.threats[4].identity.sha256 == tr::sha256_hex(std::string("alone")));   // written once: its digest stands
        // The alias written AFTER the first file was taken (real-time
        // protection on close, simulated by removing it before the alias's
        // entry): the extractor sees no file there, yet both names are one
        // file, so neither keeps a digest.
        const fs::path alias = root / "alias.zip";
        write_zip(alias, { { "c.dll", "plain" }, { "x.dll", "other" }, { "c.dll.", "dotted" } });
        std::vector<fi::WrittenEntry> w3;
        int entries = 0;
        CHECK(tr::detail::extract_zip(alias, root / "alias", why, [&]() {
            if (++entries == 3) { std::error_code rec; fs::remove(root / "alias" / "c.dll", rec); }
            return true;
        }, &w3) && w3.size() == 3 && !w3[0].sha256.empty() && !w3[2].sha256.empty());   // neither write saw the other
        fi::Index i3;
        i3.package = fi::key_of(alias);
        fi::own(i3, root / "alias");
        fi::add_package(i3, w3);
        ms::Result r5;
        r5.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(root / "alias" / "c.dll"), "Quarantine" });
        r5.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(root / "alias" / "x.dll"), "Quarantine" });
        r5.missing.push_back(lower_utf8(root / "alias" / "c.dll"));
        fi::attach(r5, i3);
        CHECK(r5.threats[0].identity.sha256.empty() && r5.missing_identity[0].sha256.empty());
        CHECK(r5.threats[1].identity.sha256 == tr::sha256_hex(std::string("other")));
        CHECK(fi::key_of(root / "a" / "c.dll. ") == fi::key_of(root / "A" / "C.DLL"));
        // A REPORTED name with a literal trailing dot or space (a file or
        // folder the game created so, beside an installed file VIRULE placed)
        // never borrows the placed file's recorded digest, and is never read.
        const fs::path inst = root / "inst";
        fs::create_directories(inst / "bin");   // a real installed folder (its case behavior is established)
        vd::Record placed;
        placed.revision_id = "rev";
        placed.files["bin/game.dll"] = vd::Digest{ 10, 20, tr::sha256_hex(std::string("placed")), "bin/game.dll" };
        vc::Inventory walk;
        walk["bin/game.dll"] = vc::Seen{ 10, 20 };
        fi::Index i4;
        fi::add_installed(i4, placed, "rev", inst, walk);
        ms::Result r6;
        r6.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(inst / "bin" / "game.dll"), "Quarantine" });
        r6.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(inst) + "\\bin \\game.dll", "Quarantine" });
        r6.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(inst) + "\\bin\\game.dll.", "Quarantine" });
        r6.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(inst) + "\\bin\\game.dll ; file:_x->y", "Quarantine" });
        fi::attach(r6, i4);
        CHECK(r6.threats[0].identity.sha256 == tr::sha256_hex(std::string("placed")));   // the placed file itself
        // THE FOLDER CASE RULE (owner decision 2026-11-06), through the probe
        // seam (no folder's flag is ever changed): a fingerprint is trusted
        // only when every folder on the file's path is established as
        // case-insensitive. A case-sensitive folder, or one whose case
        // behavior cannot be established, gives no trusted digest: not the
        // placed file's recorded one, and nothing hashed now.
        {
            const fs::path local = inst / "saves" / "slot.sav";
            fs::create_directories(local.parent_path());
            std::ofstream(local, std::ios::binary) << "a save";
            const auto run = [&](std::function<int(const fs::path&)> probe) {
                fi::Index ic = i4;
                ic.case_probe = std::move(probe);
                ms::Result rc;
                rc.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(inst / "bin" / "game.dll"), "Quarantine" });
                rc.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(local), "Quarantine" });
                rc.missing.push_back(lower_utf8(inst / "bin" / "game.dll"));
                fi::attach(rc, ic);
                return rc;
            };
            const fs::path binDir = inst / "bin";
            const auto ok = run([](const fs::path&) { return 0; });
            CHECK(ok.threats[0].identity.sha256 == tr::sha256_hex(std::string("placed")) && ok.missing_identity[0].sha256 == ok.threats[0].identity.sha256 &&
                  ok.threats[1].identity.sha256 == tr::sha256_hex(std::string("a save")));   // all established: trusted
            const auto sensitive = run([&](const fs::path& d) { return fi::exact_key_of(d) == fi::exact_key_of(inst) ? 1 : 0; });
            CHECK(sensitive.threats[0].identity.sha256.empty() && sensitive.missing_identity[0].sha256.empty() &&
                  sensitive.threats[0].identity.origin == "package" && sensitive.threats[1].identity.sha256.empty());   // a case-sensitive install folder
            const auto unknown = run([&](const fs::path& d) { return fi::exact_key_of(d) == fi::exact_key_of(binDir) ? -1 : 0; });
            CHECK(unknown.threats[0].identity.sha256.empty() && unknown.missing_identity[0].sha256.empty() &&
                  unknown.threats[1].identity.sha256 == tr::sha256_hex(std::string("a save")));   // only what lies under the unestablished folder
            const auto above = run([&](const fs::path& d) { return fi::exact_key_of(d) == fi::exact_key_of(root) ? 1 : 0; });
            CHECK(above.threats[0].identity.sha256.empty() && above.threats[1].identity.sha256.empty());   // a case-sensitive folder above the install folder
            // Windows' own answer for this computer's temporary folder: not case-sensitive.
            CHECK(fi::detail::dir_case_sensitivity(inst) == 0 && fi::detail::dir_case_sensitivity(root / "no such folder") == -1);
        }
        CHECK(r6.threats[1].identity.origin == "local" && r6.threats[1].identity.sha256.empty());
        CHECK(r6.threats[2].identity.origin == "local" && r6.threats[2].identity.sha256.empty());
        CHECK(r6.threats[3].identity.sha256.empty());
        ms::Result r7;
        r7.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(inst / "bin" / "game.dll") + " ", "Quarantine" });
        fi::attach(r7, i4);
        CHECK(r7.threats[0].identity.origin == "local" && r7.threats[0].identity.sha256.empty());   // a literal trailing space at the end
        // A ';' IS PART OF A NAME, never a separator (except in Defender's exact
        // container form): `data;1\x.dll` is not the indexed file `data`.
        const fs::path semi = root / "semi.zip";
        write_zip(semi, { { "data", "indexed" } });
        std::vector<fi::WrittenEntry> w5;
        CHECK(tr::detail::extract_zip(semi, root / "semi", why, {}, &w5) && w5.size() == 1);
        fi::Index i5;
        i5.package = fi::key_of(semi);
        fi::own(i5, root / "semi");
        fi::add_package(i5, w5);
        ms::Result r9;
        r9.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(root / "semi") + "\\data;1\\x.dll", "Quarantine" });
        r9.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(root / "semi" / "data"), "Quarantine" });
        r9.missing.push_back(lower_utf8(root / "semi") + "\\data;1\\x.dll");
        fi::attach(r9, i5);
        CHECK(r9.threats[0].identity.sha256.empty() && r9.missing_identity[0].sha256.empty());
        CHECK(r9.threats[1].identity.sha256 == tr::sha256_hex(std::string("indexed")));   // the file itself keeps it
        // A PARTIAL EXTRACTION (the list ends where a write failed): content
        // inside the package named `a.dll ` never borrows `a.dll`'s digest.
        const fs::path part = root / "part.zip";
        write_zip(part, { { "a.dll", "first" } });
        std::vector<fi::WrittenEntry> w6;
        CHECK(tr::detail::extract_zip(part, root / "part", why, {}, &w6) && w6.size() == 1);
        fi::Index i6;
        i6.package = fi::key_of(part);
        fi::add_package(i6, w6);
        ms::Result r10;
        r10.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(part) + "; file:_" + utf8(part) + "->a.dll ", "Quarantine" });
        r10.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(part) + "; file:_" + utf8(part) + "->a.dll", "Quarantine" });
        fi::attach(r10, i6);
        CHECK(r10.threats[0].identity.sha256.empty() && r10.threats[1].identity.sha256.empty() && r10.threats[1].identity.entry == "a.dll");
        // A REAL PARTIAL EXTRACTION, a second `a.dll` never reached: content
        // inside the package named `a.dll` never gets the written one's digest.
        const fs::path part2 = root / "part2.zip";
        write_zip(part2, { { "a.dll", "first" }, { "x:y", "refused name" }, { "a.dll", "second" } });
        std::vector<fi::WrittenEntry> w7;
        CHECK(!tr::detail::extract_zip(part2, root / "part2", why, {}, &w7) && w7.size() == 1);   // stops at the unsafe name
        fi::Index i7;
        i7.package = fi::key_of(part2);
        fi::add_package(i7, w7);
        ms::Result r11;
        r11.threats.push_back({ "Simulated:Test/Detection", "containerfile:_" + utf8(part2) + "; file:_" + utf8(part2) + "->a.dll", "Quarantine" });
        r11.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(root / "part2" / "a.dll"), "Quarantine" });
        fi::attach(r11, i7);
        CHECK(r11.threats[0].identity.sha256.empty());
        CHECK(r11.threats[1].identity.sha256 == tr::sha256_hex(std::string("first")));   // the file VIRULE wrote keeps its own
    }

    // 6. THE INCIDENT carries the identity and a valid Threat ID only.
    {
        const std::string body = ms::incident_json(r, ed::random_hex32(), "install", "", ed::random_hex32());
        CHECK(body.find("\"sha256\":\"" + tr::sha256_hex(dll) + "\",\"bytes\":" + std::to_string(dll.size())) != std::string::npos);
        CHECK(body.find("\"origin\":\"wrapped_original\"") != std::string::npos && body.find("\"member\":\"__virule__/orig/Game.exe\"") != std::string::npos);
        CHECK(body.find("\"threat_id\":\"2147519003\"") != std::string::npos && body.find("\"origin\":\"unknown\"") != std::string::npos);
        ms::Result legacy;
        legacy.outcome = ms::Outcome::detected;
        legacy.threats.push_back({ "Simulated:Test/Detection", "file:_C:\\x.dll", "Quarantine", "12a" });
        const std::string lb = ms::incident_json(legacy, ed::random_hex32(), "scan_source", "", "");
        CHECK(lb.find("origin") == std::string::npos && lb.find("threat_id") == std::string::npos && lb.find("sha256") == std::string::npos);
    }
    // 6b. THE BODY IS BOUNDED: 50 entries at every field's worst (long paths
    // of backslashes, long entries and members, control characters) stay
    // inside the service's incident body limit (512 KiB), each field cut as the
    // service keeps it, never inside a character.
    {
        ms::Result big;
        big.outcome = ms::Outcome::removed;
        big.scanner = std::string(500, 'S');
        ms::Identity id;
        id.stated = true;
        id.origin = "wrapped_original";
        id.entry = std::string(3000, '\\');
        id.member = "__virule__/orig/" + std::string(5000, '"');
        id.sha256 = tr::sha256_hex(std::string("x"));
        id.bytes = 1;
        for (int i = 0; i < 30; ++i) {
            ms::Threat t{ std::string(900, 'N') + "\x01", "file:_C:" + std::string(40000, '\\'), std::string(300, 'A'), "2147519003", id };
            big.threats.push_back(t);
            big.missing.push_back("c:" + std::string(40000, '\\'));
            big.missing_identity.push_back(id);
        }
        const std::string body = ms::incident_json(big, ed::random_hex32(), "install", "", ed::random_hex32());
        CHECK(body.size() < 512u * 1024u);
        CHECK(body.find('\x01') == std::string::npos && body.find(std::string(1025, 'N')) == std::string::npos);
        CHECK(ms::bounded(std::string("ab\xC3\xA9", 4), 3) == "ab");   // never half a character
    }
    // 7. DEFENDER'S EVENT: the Threat ID when valid, never malformed data.
    {
        const ms::Threat a = ms::detail::threat_from_event_xml(
            L"<Event><EventData><Data Name='Threat ID'>2147519003</Data><Data Name='Threat Name'>Virus:DOS/EICAR_Test_File</Data>"
            L"<Data Name='Path'>file:_C:\\x\\a.exe</Data><Data Name='Action Name'>Quarantine</Data></EventData></Event>");
        CHECK(a.threat_id == "2147519003" && a.name == "Virus:DOS/EICAR_Test_File" && a.path == "file:_C:\\x\\a.exe" && a.action == "Quarantine");
        const ms::Threat b = ms::detail::threat_from_event_xml(L"<Data Name=\"Threat ID\">21475;DROP</Data><Data Name=\"Threat Name\">X</Data>");
        CHECK(b.threat_id.empty() && b.name == "X");
        const ms::Threat c = ms::detail::threat_from_event_xml(L"<Data Name='Threat Name'>Y</Data>");
        CHECK(c.threat_id.empty() && c.name == "Y");
        CHECK(ms::detail::threat_from_event_xml(L"<Data Name='Threat ID'>123456789012345678901</Data>").threat_id.empty());   // 21 digits
    }

    // 8. THE VERIFIED DIGESTS RECORD: round trip, foreign or damaged = nothing.
    {
        vd::Record rec;
        rec.revision_id = ed::random_hex32();
        rec.files["bin/game.dll"] = vd::Digest{ 5000, 133, tr::sha256_hex(dll), "bin/Game.DLL" };
        rec.files["odd\tname"] = vd::Digest{ 1, 2, tr::sha256_hex(std::string("x")), "odd\tname" };
        const fs::path p = root / "digests.txt";
        CHECK(vd::write_record(p, rec));
        vd::Record back;
        CHECK(vd::read_record(p, back) && back.revision_id == rec.revision_id && back.files.size() == 2 &&
              back.files["bin/game.dll"].entry == "bin/Game.DLL" && back.files["odd\tname"].mtime == 2);
        std::ofstream(p, std::ios::binary | std::ios::app) << "zz\t1\n";
        CHECK(!vd::read_record(p, back));
        // At placement: only files still exactly as the scan began with them.
        vc::Inventory delivered;
        CHECK(vc::inventory(dir, delivered));
        const vd::Record placed = tr::detail::digests_of_placed("rev", dir, written, delivered);
        CHECK(placed.files.count("game.exe") == 1 && placed.files.count("bin/data.zip") == 1 && placed.files.count("bin/game.dll") == 0);   // game.dll was changed above
        // A CASE-SENSITIVE install folder: `A.dll` and `a.dll` are two files,
        // neither a rewrite of the other, both with a digest, and one key in
        // the record. Neither is recorded (the multi-write rule).
        const fs::path cs = root / "cs";
        fs::create_directories(cs);
        std::ofstream(cs / "a.dll", std::ios::binary) << "lower";
        vc::Inventory csDelivered;
        CHECK(vc::inventory(cs, csDelivered) && csDelivered.count("a.dll") == 1);
        std::vector<fi::WrittenEntry> csWritten(2);
        for (int n = 0; n < 2; ++n) {
            csWritten[n].name = n == 0 ? "A.dll" : "a.dll";
            csWritten[n].target = cs / csWritten[n].name;
            csWritten[n].bytes = csDelivered["a.dll"].size;
            csWritten[n].sha256 = tr::sha256_hex(std::string(n == 0 ? "upper" : "lower"));
            csWritten[n].size_after = csDelivered["a.dll"].size;
            csWritten[n].mtime_after = csDelivered["a.dll"].mtime;
        }
        CHECK(tr::detail::digests_of_placed("rev", cs, csWritten, csDelivered).files.count("a.dll") == 0);
    }
    // 8b. THE USUAL QUARANTINE PATH: real-time protection takes a file VIRULE
    // wrote whole BEFORE the scan (here: removed), and the wrapped original's
    // scan copy too. Defender evaluated the bytes VIRULE wrote, so their
    // digests stand; the removal entry carries the same one.
    {
        const fs::path dir2 = root / "x2";
        std::vector<fi::WrittenEntry> w2;
        CHECK(tr::detail::extract_zip(pkg, dir2, why, {}, &w2) && w2.size() == 3);
        const ms::Extracted x2 = ms::extract_wrapped_originals(dir2, root / "copies2", {});
        CHECK(x2.ok && x2.originals.size() == 1);
        std::error_code ec;
        fs::remove(dir2 / "bin" / "game.dll", ec);
        if (!x2.originals.empty()) fs::remove(x2.originals[0].copy, ec);
        fi::Index i2;
        i2.package = fi::key_of(pkg);
        fi::add_package(i2, w2);
        fi::add_originals(i2, x2.originals, dir2);
        ms::Result r4;
        r4.outcome = ms::Outcome::removed;
        r4.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(dir2 / "bin" / "game.dll"), "Quarantine" });
        if (!x2.originals.empty()) r4.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(x2.originals[0].copy), "Quarantine" });
        r4.missing.push_back(lower_utf8(dir2 / "bin" / "game.dll"));
        fi::attach(r4, i2);
        CHECK(r4.threats[0].identity.sha256 == tr::sha256_hex(dll) && r4.missing_identity[0].sha256 == tr::sha256_hex(dll));
        CHECK(r4.threats.size() == 2 && r4.threats[1].identity.origin == "wrapped_original" && r4.threats[1].identity.sha256 == tr::sha256_hex(original));
    }

    // 9. THE DEVELOPER'S VERIFICATION: a stand-in scan names an extracted file
    // and Defender's removal entry; the incident states the entry's digest.
    {
        UploadService svc;
        tr::DriverConfig cfg;
        cfg.root = root;
        cfg.service = &svc;
        cfg.log = [](const std::string&) {};
        const std::string content = random_bytes_str(4000, 65);
        cfg.scan = [&](const std::vector<fs::path>& targets, const std::string&, const std::function<bool()>&) {
            ms::Result s;
            s.scanner = "Test scanner";
            s.path = "defender";
            s.outcome = ms::Outcome::removed;
            const fs::path f = targets.size() > 1 ? targets[1] / "Game.exe" : fs::path();
            s.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(f), "Quarantine", "2147519003" });
            s.missing.push_back(lower_utf8(f));
            return s;
        };
        ed::Job j = packaged_job(root, content);
        drive_once(cfg);
        uv::Incident inc;
        CHECK(uv::read_incident(root, j.id, inc));
        const std::string want = "\"sha256\":\"" + tr::sha256_hex(content) + "\"";
        const size_t first = inc.incident.find(want);
        CHECK(first != std::string::npos && inc.incident.find(want, first + 1) != std::string::npos);   // the detection AND its removal entry
        CHECK(inc.incident.find("\"origin\":\"package\",\"entry\":\"Game.exe\"") != std::string::npos);
    }

    // 10. THE EVALUATOR'S PRE-PLAY CHECK: an installed file still exactly as
    // recorded at placement keeps its recorded digest once the antivirus takes
    // it; a file the game wrote is hashed only while it is still there.
    {
        UploadService svc;
        tr::DriverConfig cfg;
        cfg.root = root;
        cfg.service = &svc;
        cfg.log = [](const std::string&) {};
        const fs::path games = root / "installs";
        const std::string assignment = ed::random_hex32(), revision = ed::random_hex32(), game = ed::random_hex32();
        const fs::path gdir = games / game;
        fs::create_directories(gdir);
        const std::string installed = "installed game file " + random_bytes_str(2000, 66);
        std::ofstream(gdir / "Game.exe", std::ios::binary) << installed;
        std::ofstream(gdir / "save.dat", std::ios::binary) << "the game's own save";
        ed::Job j;
        j.id = ed::random_hex32();
        j.kind = "install";
        j.state = "installed";
        j.account_email = "dev@example.com";
        j.assignment_id = assignment;
        j.game_uuid = game;
        j.revision_id = revision;
        j.installed_revision_id = revision;
        j.launch_exe = "Game.exe";
        j.install_root = utf8(games);
        j.install_dir = utf8(gdir);
        j.created_utc = tr::utc_now();
        ed::write_job(root, j);
        vc::Inventory now;
        CHECK(vc::inventory(gdir, now) && now.count("game.exe") == 1);
        vd::Record rec;
        rec.revision_id = revision;
        rec.files["game.exe"] = vd::Digest{ now["game.exe"].size, now["game.exe"].mtime, tr::sha256_hex(installed), "Game.exe" };
        CHECK(vd::write_record(vd::record_path(root, j.id), rec));
        cfg.scan = [&](const std::vector<fs::path>&, const std::string&, const std::function<bool()>&) {
            ms::Result s;
            s.scanner = "Test scanner";
            s.path = "defender";
            s.outcome = ms::Outcome::removed;
            // The antivirus takes Game.exe (as Defender's default quarantine would).
            std::error_code ec;
            fs::remove(gdir / "Game.exe", ec);
            s.threats.push_back({ "Simulated:Test/Detection", "file:_" + utf8(gdir / "Game.exe"), "Quarantine" });
            s.threats.push_back({ "Simulated:Other/Detection", "file:_" + utf8(gdir / "save.dat"), "Quarantine" });
            s.missing.push_back(lower_utf8(gdir / "Game.exe"));
            return s;
        };
        drive_once(cfg);
        uv::Incident inc;
        CHECK(uv::read_incident(root, j.id, inc));
        const std::string want = "\"sha256\":\"" + tr::sha256_hex(installed) + "\"";
        const size_t first = inc.incident.find(want);
        CHECK(first != std::string::npos && inc.incident.find(want, first + 1) != std::string::npos);
        CHECK(inc.incident.find("\"sha256\":\"" + tr::sha256_hex(std::string("the game's own save")) + "\"") != std::string::npos &&
              inc.incident.find("\"origin\":\"local\"") != std::string::npos);
        CHECK(inc.incident.find("\"launch\"") != std::string::npos);
    }
    fs::remove_all(root);
}

int main(int argc, char** argv) {
    // The recovery-only mode as an installed wrapper with the marker runs
    // it (test_recovery_rules starts a copy of this exe as Game.exe).
    if (argc > 1 && std::strcmp(argv[1], "--virule-evaluation-recover") == 0) {
        std::ofstream("recovered.txt") << "ok";
        return 0;
    }
    if (argc > 1 && std::strcmp(argv[1], "package") == 0) return run_package(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "install") == 0) return run_install(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "signal") == 0) return run_signal(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "drive") == 0) return run_drive(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "control") == 0) return run_control(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "status") == 0) return run_status(argc, argv);
    test_contract();
    test_job_record();
    test_digests_and_zip();
    test_controls();
    test_launch_chain();
    test_update_and_removal();
    test_game_art();
    test_whole_object_fetch();
    test_evidence_owner();
    test_recovery_rules();
    test_assignment_open();
    test_upload_gate();
    test_reverify_after_resume();
    test_finding_identity();
    test_upload_gate_real_defender();
    std::printf("%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
