// THE LAUNCHER'S LIVE HARNESS (2026-10-22): the VIRULE Client's REAL launcher
// (client/launcher.hpp), transfer driver (client/transfers.hpp) and evidence
// delivery (shared/evidence_queue.hpp ServiceTransport), in one test
// process, driven line by line on stdin by
// VIRULE_BACKEND tools/launcher_lifecycle_staging_e2e.mjs.
//
// The ONE thing that is not the Client's is how the service is reached:
// every call goes to a loopback proxy the driver runs, which signs it as the
// evaluator's installation (DPoP, exactly what the Client's account calls
// carry) and forwards it to LIVE STAGING. Everything else (the job record,
// the ranged download, the verification, the extraction, the ticket and the
// credential, the launch, the running set, the change counter, the evidence
// package) is the Client's own code.
//
//   launcher_harness.exe serve <virule root> <proxy port> <account email>
//
// Commands (one per line; one `REPLY {...}` line each):
//   launch <assignment> [<required revision>]   game_launch
//   state                                       launcher_state
//   busy <assignment>                           {"busy":bool}
//   wake                                        a transfer pass now
//   evidence                                    one evidence and requests pass
//   progress <assignment>                       the service's progress, kept
//   quit
// Unsolicited: `CHANGE <n>` whenever the change counter moves.
//
// Refuses to run unless LOCALAPPDATA is redirected away from the real one
// (the root must be inside it).

#include <atomic>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>

#include "client/launcher.hpp"
#include "client/transfers.hpp"
#include "shared/evidence_queue.hpp"
#include "shared/machine_identity.hpp"

#include <shlobj.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

namespace tr = vclient::transfers;
namespace la = vclient::launcher;
namespace evq = vclient::evidence;
namespace ee = virule::core::evaluation_evidence;
namespace fs = std::filesystem;

static unsigned short g_port = 0;
static std::string g_email;
static std::mutex g_out;

static void emit(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_out);
    std::fwrite(line.data(), 1, line.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

static std::wstring widen(const std::string& s) { return std::wstring(s.begin(), s.end()); }

// One call through the proxy: the method and path in headers, the body raw.
static tr::Reply proxy_call(const char* method, const std::string& path, const std::string& body,
                            const std::string& content_type, const std::vector<tr::Header>& headers) {
    std::wstring h = L"X-Virule-Method: " + widen(method) + L"\r\nX-Virule-Path: " + widen(path) + L"\r\n";
    if (!content_type.empty()) h += L"Content-Type: " + widen(content_type) + L"\r\n";
    for (const auto& x : headers) h += widen(x.name) + L": " + widen(x.value) + L"\r\n";
    tr::Reply r;
    vclient::http::Timeouts t;
    t.receive_ms = 120000;
    (void)vclient::http::request(L"POST", L"127.0.0.1", g_port, false, L"/call", h, body, 256 * 1024, r.status, r.body, t);
    return r;
}

struct ProxyService final : tr::Service {
    bool signed_in(std::string& email_out) override { email_out = g_email; return true; }
    tr::Reply call(const char* method, const std::string& path, const std::string& body,
                   const std::string& content_type, const std::vector<tr::Header>& headers) override {
        return proxy_call(method, path, body, content_type, headers);
    }
    bool get_range_to_file(const std::string& path, std::uint64_t from, std::uint64_t to, FILE* out,
                           std::uint64_t& bytes_out, unsigned long& status_out,
                           const std::function<bool()>& keep_going) override {
        std::wstring h = L"X-Virule-Method: GET\r\nX-Virule-Path: " + widen(path) + L"\r\nRange: bytes=" +
                         std::to_wstring(from) + L"-" + std::to_wstring(to) + L"\r\n";
        unsigned long long got = 0;
        const bool okd = vclient::http::request_to_file(L"127.0.0.1", g_port, false, L"/range", h, to - from + 1, out, got,
                                                        status_out, keep_going);
        bytes_out = got;
        return okd;
    }
    std::string machine_key() override { return vclient::machine_identity::public_key_hex(); }
};

static bool refresh_progress(const fs::path& root, const std::string& assignment) {
    const tr::Reply r = proxy_call("GET", "/v1/assignments/" + assignment + "/progress", "", "", {});
    if (r.status != 200) return false;
    std::string_view progress;
    if (!ee::json::member(r.body, "progress", progress)) return false;
    if (ee::store_progress(ee::root_under(root), assignment, progress)) evq::note_change();
    return true;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 5 || std::wstring(argv[1]) != L"serve") {
        std::fprintf(stderr, "usage: launcher_harness serve <root> <port> <email>\n");
        return 2;
    }
    const fs::path root = argv[2];
    g_port = static_cast<unsigned short>(_wtoi(argv[3]));
    {
        const std::wstring w = argv[4];
        g_email.assign(w.begin(), w.end());
    }
    // The sandbox guard: LOCALAPPDATA is redirected and holds the root.
    {
        wchar_t env[MAX_PATH * 4];
        const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", env, MAX_PATH * 4);
        PWSTR real = nullptr;
        std::wstring real_path;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &real))) { real_path = real; CoTaskMemFree(real); }
        const std::wstring here = n ? std::wstring(env, n) : std::wstring();
        if (here.empty() || _wcsicmp(here.c_str(), real_path.c_str()) == 0 ||
            la::detail::lower(root.wstring()).rfind(la::detail::lower(here), 0) != 0) {
            std::fprintf(stderr, "REFUSED: LOCALAPPDATA is not a sandbox holding the root\n");
            return 2;
        }
    }
    static ProxyService service;
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    const auto on_change = [] { evq::note_change(); };

    la::Config lc;
    lc.root = root;
    lc.on_change = on_change;
    lc.refresh_progress = [root](const std::string& a) { return refresh_progress(root, a); };
    lc.log = [](const std::string& t) { emit("LOG " + t); };
    lc.stop_event = stop;
    static la::Launcher launcher(std::move(lc));
    std::thread([] { launcher.run(); }).detach();

    static tr::DriverConfig dc;
    dc.root = root;
    dc.service = &service;
    dc.stop_event = stop;
    dc.log = [](const std::string& t) { emit("LOG " + t); };
    dc.busy = [](const std::string& a) { return launcher.busy(a); };
    dc.on_change = on_change;
    dc.after_install = [root](const std::string& a) { (void)refresh_progress(root, a); };
    tr::control_config() = &dc;
    std::thread([wake] { tr::run_driver(dc, wake); }).detach();

    // The change counter, reported as it moves.
    std::thread([] {
        std::uint64_t seen = evq::change_counter().load();
        for (;;) {
            Sleep(100);
            const std::uint64_t now = evq::change_counter().load();
            if (now != seen) { seen = now; emit("CHANGE " + std::to_string(now)); }
        }
    }).detach();

    evq::ServiceTransport transport(
        [](const char* m, const std::string& p, const std::string& b, const std::string& ct,
           const std::vector<std::pair<std::string, std::string>>& h) {
            std::vector<tr::Header> hh;
            for (const auto& x : h) hh.push_back({ x.first, x.second });
            const tr::Reply r = proxy_call(m, p, b, ct, hh);
            return evq::ServiceReply{ r.status, r.body };
        },
        [] { return true; });

    emit("READY");
    std::string line;
    while (std::getline(std::cin, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        std::string cmd = line, a, b;
        if (const auto sp = line.find(' '); sp != std::string::npos) {
            cmd = line.substr(0, sp);
            const std::string rest = line.substr(sp + 1);
            const auto sp2 = rest.find(' ');
            a = rest.substr(0, sp2);
            if (sp2 != std::string::npos) b = rest.substr(sp2 + 1);
        }
        if (cmd == "quit") break;
        if (cmd == "launch") {
            std::string payload = "{\"type\":\"game_launch\",\"assignment_id\":\"" + a + "\"";
            if (!b.empty()) payload += ",\"required_revision_id\":\"" + b + "\"";
            emit("REPLY " + launcher.launch(payload + "}"));
        } else if (cmd == "state") {
            emit("REPLY " + launcher.state_json());
        } else if (cmd == "busy") {
            emit(std::string("REPLY {\"busy\":") + (launcher.busy(a) ? "true" : "false") + "}");
        } else if (cmd == "wake") {
            SetEvent(wake);
            emit("REPLY {\"ok\":true}");
        } else if (cmd == "evidence") {
            const ee::Root er = ee::root_under(root);
            const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
            const auto p = evq::run_pass(er, transport, now, true, [](const std::string& t) { emit("LOG " + t); });
            const auto q = evq::run_requests(er, transport, now, true, [](const std::string& t) { emit("LOG " + t); });
            emit("REPLY {\"delivered\":" + std::to_string(p.delivered) + ",\"pending\":" + std::to_string(p.pending) +
                 ",\"requests_acknowledged\":" + std::to_string(q.acknowledged) + "}");
        } else if (cmd == "progress") {
            emit(std::string("REPLY {\"ok\":") + (refresh_progress(root, a) ? "true" : "false") + "}");
        } else {
            emit("REPLY {\"error\":\"unknown command\"}");
        }
    }
    SetEvent(stop);
    Sleep(200);
    return 0;
}
