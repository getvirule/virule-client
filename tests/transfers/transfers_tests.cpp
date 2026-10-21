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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "shared/environment.hpp"
#include "shared/evidence_queue.hpp"
#include "shared/http_client.hpp"
#include "shared/paths.hpp"
#include "client/transfers.hpp"

namespace fs = std::filesystem;
namespace ed = virule::core::evaluation_distribution;
namespace tr = vclient::transfers;

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

int main(int argc, char** argv) {
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
    std::printf("%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
