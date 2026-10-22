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
    // The same key again: the held credential stays (no second issue).
    CHECK(tr::control(verify, root).find("\"ok\":true") != std::string::npos);
    CHECK(svc.ticket_calls == 2 && svc.credential_calls == 1);
    // The machine key changed under the credential (the Admin re-issued
    // dev_machine.cred): the credential is issued again for the NEW key.
    svc.machine = k2;
    CHECK(tr::control(verify, root).find("\"ok\":true") != std::string::npos);
    CHECK(svc.credential_calls == 2);
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
    const std::uint64_t bytes = std::strtoull(argv[4], nullptr, 10);
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
    std::string sha;
    write_random(pkg, bytes, &sha);
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
    HANDLE wake = vclient::evidence::create_wake_event(std::wstring(event.begin(), event.end()).c_str());
    std::printf("driver: up\n");
    std::fflush(stdout);
    tr::run_driver(cfg, wake);
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
    std::printf("%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
