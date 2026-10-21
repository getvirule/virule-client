// virule-client.exe - the persistent local VIRULE component.
//
// PLUMBING, NOT PRODUCT: virule.app is the interface; this process has no
// Admin UI, no launcher UI, no tray icon. It exists to answer the browser
// over the loopback bridge, to handle virule:// launches, to perform
// authenticated local actions (Phase 1: writing the QA tester credential
// after a service-verified handoff), and to remove VIRULE completely when
// asked. Native UI appears only as the minimal result card when no browser
// page is open to own an outcome, and as the minimal removal confirmation
// when uninstall is started from Windows itself.
//
// PROCESS MODEL / STATE MACHINE:
//
//     Starting -> Serving -> Draining -> exit
//                    |                     ^
//                    +--> Uninstalling ----+   (helper spawned first)
//
//   Starting      argument parsing, single-instance resolution
//   Serving       bridge listening; virule:// launches are forwarded here
//   Draining      shutdown requested (Setup replacing the exe, the
//                 self-update swap, a port this process can never own);
//                 the listener closes and the process exits cleanly
//   Uninstalling  a verified uninstall began; the %TEMP% helper takes
//                 over after this process exits
//
// SINGLE INSTANCE: one named mutex; a second launch forwards its work
// (a virule:// URL, or a plain wake) to the running instance over the
// loopback bridge and exits immediately. Two launches can never produce
// two active clients or two listeners.
//
// RESIDENT (2026-09-10; replaces the original 20-minute idle exit): an
// installed client stays running, so 127.0.0.1:47612 is normally always
// there for the browser. Idle costs nothing: every background thread
// sleeps, no connected page means no pushes, and the update checks are
// one manifest fetch per 6 hours. It comes back after login/reboot
// through a per-user Run value (shared/login_start.hpp) and after a
// crash through Windows Error Reporting's application restart
// (RegisterApplicationRestart in serve()); both are managed-install only,
// no Windows SCM service and no scheduled task. It leaves only on request:
// Setup's shutdown, the self-update swap, an uninstall, or a port it can
// never own.
//
// MUTUAL RECOVERY (2026-10-06): an ending this process did not choose (End
// task, a kill) is restored by VIRULE Service (ViruleService.exe), which this
// process in turn starts and keeps resident (client/service_watch.hpp; the
// contract is shared/residency.hpp). This process owns the login start; it
// starts the service when it begins serving. An intentional exit announces
// itself first so the service holds off instead of fighting a replacement.
// virule:// and the Admin's client_health remain fallbacks.

#include <atomic>
#include <string>
#include <vector>

#include "client/account.hpp"
#include "client/admin_install.hpp"
#include "client/bridge.hpp"
#include "client/qa_flow.hpp"
#include "client/result_card.hpp"
#include "client/self_update.hpp"
#include "client/service_install.hpp"
#include "client/service_watch.hpp"
#include "client/takeover.hpp"
#include "client/transfers.hpp"
#include "client/game_art.hpp"
#include "client/uninstall_dialog.hpp"
#include "shared/client_state.hpp"
#include "shared/environment.hpp"
#include "shared/evidence_queue.hpp"
#include "client/evaluation_inbox.hpp"
#include "shared/installed_capabilities.hpp"
#include "shared/lifecycle_intent.hpp"
#include "shared/logging.hpp"
#include "shared/login_start.hpp"
#include "shared/paths.hpp"
#include "shared/protocol_reg.hpp"
#include "shared/residency.hpp"
#include "shared/uninstall.hpp"
#include "shared/version.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

namespace {

enum class RunState { Starting, Serving, Draining, Uninstalling };
std::atomic<RunState> g_state{ RunState::Starting };
std::atomic<bool> g_exit_requested{ false };
// An Admin update is waiting on this client's own swap (admin_install.hpp
// g_on_client_update_required): the swap monitor drops its cadence.
std::atomic<bool> g_swap_asap{ false };
// Signaled with g_exit_requested by Setup's shutdown, so the serve loop
// starts draining AT ONCE instead of at its next one-second wake: Setup
// replaces this exe on a fixed two-second wait after the reply
// (setup/main.cpp stop_running_client) without seeing the process end,
// and every millisecond of that wait belongs to the exit.
HANDLE g_exit_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

// The evidence test transport seam (--evidence-test-endpoint=); honored only
// in a staging build or a redirected sandbox (shared/evidence_queue.hpp).
std::wstring g_evidence_test_endpoint;
HANDLE g_evidence_stop = nullptr;

// GAME DISTRIBUTION (client/transfers.hpp; docs/ARCHITECTURE.md "Game
// distribution"): the transfer thread. One forced pass at startup (the
// recovery after a crash or a restart), then a blocked wait on
// Local\VIRULE.Transfers.Wake, the earliest retry, or the stop event. An
// uninstall pauses it. Every service call is this installation's DPoP
// authorization (client/account.hpp transfer_headers); nothing here holds
// a token for longer than one request.
HANDLE g_transfer_stop = nullptr;
HANDLE g_transfer_wake = nullptr;

// THE DEVELOPER'S EVALUATION INBOX (client/evaluation_inbox.hpp): its own
// thread, woken only by communication the Client already has (startup, the
// scheduled check's cadence, a changed Evaluations read through the relay).
HANDLE g_inbox_stop = nullptr;
HANDLE g_inbox_wake = nullptr;
// What the developer's last relayed Evaluations read answered (a hash): a
// different answer is news worth one inbox pass.
std::atomic<std::uint64_t> g_last_view_hash{ 0 };
// This process's identity in the change counter's generation, so an Admin
// never mistakes a restarted Client's count for the same one.
const unsigned long long g_boot_id = GetTickCount64() ^ ((unsigned long long)GetCurrentProcessId() << 32);

struct AccountTransferService final : vclient::transfers::Service {
    bool signed_in(std::string& email_out) override { return vclient::account::signed_in_email(email_out); }
    vclient::transfers::Reply call(const char* method, const std::string& path, const std::string& body,
                                   const std::string& content_type, const std::vector<vclient::transfers::Header>& headers) override {
        namespace acct = vclient::account;
        vclient::transfers::Reply r;
        const acct::Endpoint e = acct::api_endpoint();
        const std::wstring wmethod = acct::widen(method);
        for (int attempt = 0; attempt < 2; ++attempt) {
            std::wstring h;
            if (!acct::transfer_headers(method, path, h, attempt == 1)) { r.status = 0; return r; }
            if (!content_type.empty()) h += L"Content-Type: " + acct::widen(content_type) + L"\r\n";
            for (const auto& x : headers) h += acct::widen(x.name) + L": " + acct::widen(x.value) + L"\r\n";
            vclient::http::Timeouts t;
            t.send_ms = 120000;
            t.receive_ms = 120000;
            (void)vclient::http::request(wmethod.c_str(), e.host.c_str(), e.port, e.secure, acct::widen(path),
                                         h, body, 256 * 1024, r.status, r.body, t);
            if (r.status != 401) break;
        }
        return r;
    }
    bool get_range_to_file(const std::string& path, std::uint64_t from, std::uint64_t to, FILE* out,
                           std::uint64_t& bytes_out, unsigned long& status_out,
                           const std::function<bool()>& keep_going) override {
        namespace acct = vclient::account;
        const acct::Endpoint e = acct::api_endpoint();
        for (int attempt = 0; attempt < 2; ++attempt) {
            std::wstring h;
            if (!acct::transfer_headers("GET", path, h, attempt == 1)) { status_out = 0; return false; }
            h += L"Range: bytes=" + std::to_wstring(from) + L"-" + std::to_wstring(to) + L"\r\n";
            unsigned long long got = 0;
            const bool okd = vclient::http::request_to_file(e.host.c_str(), e.port, e.secure, acct::widen(path), h,
                                                            to - from + 1, out, got, status_out, keep_going);
            bytes_out = got;
            if (status_out != 401) return okd;
        }
        return false;
    }
    std::string machine_key() override { return vclient::machine_identity::public_key_hex(); }
};
AccountTransferService g_transfer_service;

// A Build for Evaluation whose build or packaging stage lost its owner (the
// Admin closed): start the Admin host headless to finish it, never while an
// Admin is running (its singleton says so).
bool resume_delivery_headless(const virule::core::evaluation_distribution::Job& job) {
    if (job.admin_host_exe.empty() || job.admin_data_root.empty()) return false;
    HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, L"Local\\VIRULE.AdminHost.Singleton");
    if (m) { CloseHandle(m); return false; }
    const std::wstring exe = vclient::account::widen(job.admin_host_exe);
    std::error_code ec;
    if (!std::filesystem::is_regular_file(std::filesystem::path(exe), ec) || ec) return false;
    std::wstring cmd = L"\"" + exe + L"\" --data-root=\"" + vclient::account::widen(job.admin_data_root) +
                       L"\" --resume-delivery=" + vclient::account::widen(job.id);
    // THE CEF RUNTIME DIRECTORY IS THE WORKING DIRECTORY (2026-10-21): the
    // host's libcef.dll import resolves from it (virule.exe starts the host
    // the same way); started from anywhere else the host never gets to its
    // own main and the stage stays stalled.
    const std::wstring cwd = (std::filesystem::path(vclient::account::widen(job.admin_data_root)) / L".resources" / L"bin" / L"x64").wstring();
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, cwd.c_str(), &si, &pi)) return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

void start_transfers() {
    namespace tr = vclient::transfers;
    g_transfer_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_transfer_stop) {
        vclient::log::client("transfers: stop event unavailable; driver not started");
        return;
    }
    g_transfer_wake = vclient::evidence::create_wake_event(virule::core::evaluation_distribution::kWakeEventName);
    auto* cfg = new tr::DriverConfig{};
    cfg->root = vclient::paths::virule_data_root();
    cfg->service = &g_transfer_service;
    cfg->stop_event = g_transfer_stop;
    // The bridge's transfer_control "verify" (0.9.15) reaches the service
    // through the same configuration.
    tr::control_config() = cfg;
    cfg->paused = [] {
        return vclient::bridge::g_uninstalling.load() ||
               vclient::lifecycle::uninstall_intent_active();
    };
    cfg->log = [](const std::string& t) { vclient::log::client(t); };
    cfg->resume_headless = resume_delivery_headless;
    HANDLE h = CreateThread(nullptr, 0,
        [](LPVOID p) -> DWORD {
            auto* c = (tr::DriverConfig*)p;
            tr::run_driver(*c, g_transfer_wake);
            delete c;
            return 0;
        },
        cfg, 0, nullptr);
    if (h) CloseHandle(h); else delete cfg;
}

// EVALUATION EVIDENCE DELIVERY (EVALUATION_VIRULE.md section 6): the
// dedicated evidence thread. One forced recovery pass now, then a blocked
// wait on Local\VIRULE.Evidence.Wake, the earliest retry, or the stop event
// set when this process stops serving. An uninstall pauses it. Runs on every
// client (managed or not): the evidence root is the env-resolved
// %LOCALAPPDATA%\VIRULE\evidence, so a sandboxed run only sees its sandbox.
void start_evidence_delivery() {
    namespace ev = vclient::evidence;
    g_evidence_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_evidence_stop) {
        vclient::log::client("evidence: stop event unavailable; delivery not started");
        return;
    }
    struct Arg { ev::DriverConfig cfg; std::unique_ptr<ev::Transport> transport; };
    auto* arg = new Arg{};
    // THE REAL DELIVERY (2026-10-21): this installation's DPoP calls, the
    // same ones the transfer driver makes (AccountTransferService).
    ev::ServiceCall service = [](const char* method, const std::string& path, const std::string& body,
                                 const std::string& content_type,
                                 const std::vector<std::pair<std::string, std::string>>& headers) {
        std::vector<vclient::transfers::Header> h;
        for (const auto& x : headers) h.push_back({ x.first, x.second });
        const vclient::transfers::Reply r = g_transfer_service.call(method, path, body, content_type, h);
        return ev::ServiceReply{ r.status, r.body };
    };
    arg->transport = ev::select_transport(g_evidence_test_endpoint, vclient::env::kStaging,
                                          vclient::paths::environment_redirected(),
                                          [](const std::string& t) { vclient::log::client(t); },
                                          service, [] { return vclient::account::signed_in(); });
    // A REPORT ACKNOWLEDGED: the game removes itself (client/transfers.hpp
    // begin_removal), never while it runs.
    arg->cfg.on_ack = [](const std::string& kind, const std::string& assignment_id) {
        if (kind != "report") return;
        if (vclient::transfers::begin_removal(vclient::paths::virule_data_root(), assignment_id)) {
            vclient::log::client("evidence: report acknowledged; the game of " + assignment_id + " removes itself");
            if (g_transfer_wake) SetEvent(g_transfer_wake);
        }
    };
    arg->cfg.root = ev::ee::root_under(vclient::paths::virule_data_root());
    arg->cfg.transport = arg->transport.get();
    arg->cfg.stop_event = g_evidence_stop;
    arg->cfg.paused = [] {
        return vclient::bridge::g_uninstalling.load() ||
               vclient::lifecycle::uninstall_intent_active();
    };
    arg->cfg.log = [](const std::string& t) { vclient::log::client(t); };
    HANDLE h = CreateThread(nullptr, 0,
        [](LPVOID p) -> DWORD {
            Arg* a = (Arg*)p;
            vclient::evidence::run_driver(a->cfg);
            delete a;
            return 0;
        },
        arg, 0, nullptr);
    if (h) CloseHandle(h); else delete arg;
}

// THE DEVELOPER'S EVALUATION INBOX: one pass now (the startup recovery),
// then only on a wake.
void start_inbox() {
    namespace ib = vclient::evaluation_inbox;
    g_inbox_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_inbox_wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_inbox_stop) return;
    auto* cfg = new ib::Config{};
    cfg->root = vclient::paths::virule_data_root();
    cfg->service = &g_transfer_service;
    cfg->stop_event = g_inbox_stop;
    cfg->wake = g_inbox_wake;
    cfg->paused = [] {
        return vclient::bridge::g_uninstalling.load() || vclient::lifecycle::uninstall_intent_active();
    };
    cfg->log = [](const std::string& t) { vclient::log::client(t); };
    HANDLE h = CreateThread(nullptr, 0,
        [](LPVOID p) -> DWORD {
            auto* c = (ib::Config*)p;
            ib::run_driver(*c);
            delete c;
            return 0;
        },
        cfg, 0, nullptr);
    if (h) CloseHandle(h); else delete cfg;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return "";
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), n,
                        nullptr, nullptr);
    return out;
}

// Forward one message to the already-running instance's bridge. True when
// the running instance answered.
bool forward_to_running_instance(const std::string& message) {
    std::string response;
    return vclient::bridge::loopback_roundtrip(
        vclient::bridge::kPort, nullptr, "\"virule_client\"", message, response);
}

// CLIENT SELF-UPDATE SAFE TAKEOVER POINT (owner spec 2026-09-04).
// Downloading and verifying in advance is always fine; the actual binary
// swap defers while ANY lifecycle transaction is live: an uninstall, an
// Admin install/update/launch handoff, a QA credential provisioning that
// just ran, a Setup takeover, or any native lifecycle card the swap's exit
// would tear down. An idle client with only quiet page connections is the
// normal swap moment (the browser's disconnect hysteresis masks the
// restart).
bool self_update_safe_point() {
    namespace ai = vclient::admin_install;
    if (vclient::bridge::g_uninstalling.load()) return false;
    if (ai::g_busy.load()) return false;                       // Admin install/update
    if (vclient::takeover::takeover_in_flight()) return false; // Setup handoff
    if (vclient::result_card::is_visible()) return false;      // a native surface is live
    const unsigned long long now = GetTickCount64();
    const unsigned long long qa = vclient::bridge::g_last_qa_tick.load();
    if (qa != 0 && now - qa < 120000) return false;            // QA redemption settling
    const unsigned long long launch = ai::g_last_admin_launch_tick.load();
    if (launch != 0 && now - launch < 15000) return false;     // Admin launch in flight
    return true;
}

// THE ORDERED UNINSTALL (owner corrective spec 2026-09-04). Explicit user
// uninstall outranks every automatic recovery behavior, and the order is
// the contract:
//
//   1. record the durable uninstall intent (registry latch) FIRST;
//   2. stop accepting new lifecycle operations (bridge refusals) and show
//      the immediate "Removing VIRULE…" surface (zero dead air);
//   3. cancel any active Admin update back to a known-good state;
//   4. gracefully close the Admin and wait until every managed
//      Admin-directory process is gone (never partially uninstall under a
//      live Admin; a refusal aborts with visible feedback and changes
//      nothing);
//   5. hand the removal to the visible %TEMP% helper, which removes
//      files, removes registrations LAST, verifies, clears the intent
//      latch LAST and shows the terminal outcome;
//   6. tell every connected page the removal is COMMITTED (uninstall_state
//      "complete", 2026-09-10): the helper is running and the only work
//      left is deleting this executable, so the site may leave "Removing
//      VIRULE…" now instead of counting out its absence window (that
//      window stays as the fallback for a client that dies before this
//      step); give the message a bounded moment to land, then exit.
//
// Never deletes anything in-process. `delete_data` is the explicit
// destructive option; the default preserves every piece of user-owned
// VIRULE data.
void run_uninstall_sequence(bool delete_data) {
    namespace ai = vclient::admin_install;
    namespace rc = vclient::result_card;

    if (vclient::bridge::g_uninstalling.exchange(true)) return; // one teardown
    g_state.store(RunState::Uninstalling);

    // 1. Durable intent, before anything else. A machine that cannot even
    // record the intent does not get a destructive teardown.
    if (!vclient::lifecycle::set_uninstall_intent()) {
        vclient::log::client("uninstall: intent latch could not be written; aborted");
        vclient::bridge::broadcast_uninstall_state("failed");
        vclient::bridge::g_uninstalling.store(false);
        g_state.store(RunState::Serving);
        return;
    }
    vclient::log::client(std::string("uninstall: intent recorded; teardown starting (") +
                         (delete_data ? "delete local data)" : "keep local data)"));
    // VIRULE Service lives in the install directory and must be gone before
    // the helper can remove it; with the latch written nothing restores it.
    vclient::residency::request_service_stop();

    // 2. Immediate visible feedback + the site's Removing state.
    vclient::bridge::broadcast_uninstall_state("removing");
    rc::show_working("Removing VIRULE\xE2\x80\xA6", "");

    // 3. UNINSTALL WINS: an in-flight update is cancelled to a known-good
    // filesystem state, never finished merely because it started first.
    if (!ai::cancel_active_operation_and_wait(120000)) {
        vclient::log::client("uninstall: active update did not unwind; aborted");
        vclient::bridge::broadcast_uninstall_state("failed");
        rc::update("Something went wrong.", "Try again in a moment.");
        vclient::bridge::g_uninstalling.store(false);
        g_state.store(RunState::Serving);
        return;
    }
    vclient::uninstall::reconcile_admin_update_residue();
    // A staged-but-uncommitted client self-update is discarded, never
    // applied: uninstall wins over every pending update.
    vclient::self_update::discard_pending();

    // 4. Admin first, gracefully (the update path's own machinery). A
    // refusal aborts the whole uninstall with nothing destroyed: the
    // intent latch stays (self-heal keeps standing down) and the user
    // gets clear feedback with a retry path.
    if (ai::admin_running()) {
        vclient::log::client("uninstall: closing the running Admin gracefully");
        if (!ai::close_running_admin(30000)) {
            vclient::log::client("uninstall: the Admin did not close; nothing removed");
            vclient::bridge::broadcast_uninstall_state("failed");
            rc::update("Something went wrong.", "Close VIRULE and try again.");
            vclient::bridge::g_uninstalling.store(false);
            g_state.store(RunState::Serving);
            return;
        }
        vclient::log::client("uninstall: the Admin closed");
    }

    // 4b. Sign this installation out of its VIRULE account at the service
    // (bounded; offline is fine): the session file goes with the client
    // state directory in both modes, and a removed installation must not
    // leave a live device authorization behind.
    (void)vclient::account::sign_out(true);

    // 5. Helper handoff. The listener closes so the freed port reads as
    // removal in progress (existing page connections stay open for the
    // terminal message below); the helper (a %TEMP% copy of this exe)
    // owns the visible surface from here.
    vclient::bridge::stop_listening();
    if (!vclient::uninstall::spawn_uninstall_helper(delete_data)) {
        vclient::log::client("uninstall: helper could not be started; nothing removed");
        vclient::bridge::restart_listening();
        vclient::bridge::broadcast_uninstall_state("failed");
        rc::update("Something went wrong.", "Try again in a moment.");
        vclient::bridge::g_uninstalling.store(false);
        g_state.store(RunState::Serving);
        return;
    }

    // 6. THE POSITIVE TERMINAL SIGNAL. The removal is committed: the
    // helper is running and will finish with or without this process, and
    // the only remaining work is the unavoidable deletion of this very
    // executable plus the helper's own cleanup. Tell the connected pages
    // over the bridge they already hold, let the message land (the site
    // closes its socket on receipt; 1.5 s is the bound), then leave.
    if (vclient::bridge::broadcast_uninstall_state("complete")) {
        vclient::log::client("uninstall: committed; complete pushed to pages");
        vclient::bridge::wait_pages_closed(1500);
    } else {
        vclient::log::client("uninstall: committed; no page connected");
    }
    ExitProcess(0);
}

// Run the ordered teardown off the bridge connection thread (it waits on
// update cancellation and the Admin's graceful close).
void begin_uninstall_async(bool delete_data) {
    struct Arg { bool delete_data; };
    auto* arg = new Arg{ delete_data };
    HANDLE h = CreateThread(nullptr, 0,
        [](LPVOID p) -> DWORD {
            Arg* a = (Arg*)p;
            run_uninstall_sequence(a->delete_data);
            delete a;
            return 0;
        },
        arg, 0, nullptr);
    if (h) CloseHandle(h); else delete arg;
}

// ---- the %TEMP% helper's whole job (run under --finish-uninstall) ----
// Waits out every managed process, owns the visible removal surface,
// removes FILES, then REGISTRATIONS LAST, verifies the terminal state,
// clears the intent latch LAST, and reports the outcome. A failure keeps
// the latch and the registrations (the Windows-recoverable retry path)
// and offers Try again right on the card.
int run_finish_uninstall(unsigned long parent_pid, bool delete_data) {
    namespace un = vclient::uninstall;
    namespace rc = vclient::result_card;

    un::temp_log(std::string("helper: starting (") +
                 (delete_data ? "delete local data)" : "keep local data)"));
    // Idempotent: the serving client already asked; a launcher-driven
    // removal reaches here with the service possibly still resident.
    vclient::residency::request_service_stop();
    if (parent_pid != 0) {
        if (HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, parent_pid)) {
            WaitForSingleObject(h, 30000);
            CloseHandle(h);
        }
    }

    // Zero dead air: the removal surface is up before anything happens.
    rc::show_working("Removing VIRULE\xE2\x80\xA6", "");
    for (int i = 0; i < 20 && !rc::is_visible(); ++i) Sleep(100);
    un::temp_log(std::string("helper: removal card ") +
                 (rc::is_visible() ? "visible" : "NOT visible"));

    const std::wstring installed_exe = vclient::paths::installed_client_exe().wstring();

    for (;;) {
        // Every managed process must be gone before files can go. The
        // parent client just exited; the Admin was closed before the
        // handoff; this is the verification, not the mechanism.
        if (!un::wait_install_dir_processes_gone(30000)) {
            un::temp_log("helper: managed processes still running; removal blocked");
            rc::update_to_action("Something went wrong.", "Try again");
        } else {
            un::reconcile_admin_update_residue();
            if (un::remove_files(delete_data)) {
                // 6-7. Files are gone; registrations go LAST, then the
                // terminal state is verified and the latch cleared LAST.
                un::remove_registrations(installed_exe);
                std::error_code ec;
                const bool clean =
                    !std::filesystem::exists(vclient::paths::install_dir(), ec);
                if (clean) {
                    vclient::lifecycle::clear_uninstall_intent();
                    un::temp_log("helper: uninstall complete; intent cleared");
                    // The completion confirmation stays 5 s (audit
                    // 2026-09-10; every other result keeps the default
                    // life). Still click/Escape/Enter dismissible; the
                    // wait below returns whenever the card goes.
                    rc::update("VIRULE has been uninstalled.",
                               delete_data ? "" : "Your local data was kept.",
                               /*life_ms=*/5000);
                    rc::wait_closed(12000);
                    un::schedule_self_delete();
                    return 0;
                }
            }
            un::temp_log("helper: file removal did not complete; latch and registrations kept");
            rc::update_to_action("Something went wrong.", "Try again");
            un::temp_log(std::string("helper: failure card ") +
                         (rc::is_visible() ? "visible" : "NOT visible"));
        }

        // Recoverable failure: intent latch kept, Apps & Features entry
        // kept (registrations are only ever removed after success), user
        // offered an explicit retry. Dismissing the card leaves the
        // machine recoverable through Apps & Features or a fresh Setup.
        for (;;) {
            if (rc::take_action_clicked()) break;
            if (!rc::is_visible()) {
                un::temp_log("helper: failure card dismissed; leaving (retry via Apps & Features)");
                un::schedule_self_delete();
                return 1;
            }
            Sleep(250);
        }
        un::temp_log("helper: retry requested");
        rc::wait_closed(3000); // reap the clicked card's thread
        rc::show_working("Removing VIRULE\xE2\x80\xA6", "");
    }
}

void serve(const std::string& initial_qa_token, bool register_protocol,
           const std::wstring& restart_args, const std::wstring& residency_seams) {
    // Self-heal the pieces an installed client owns. Registration mirrors
    // the Admin's behavior: whichever VIRULE component ran last holds
    // virule://, and both handle qa/verify identically. (--no-register is
    // a development seam so a directly-run build does not take over a
    // machine's real registration.)
    if (register_protocol) vclient::protocol_reg::register_protocol();

    // RESIDENCY (2026-09-10), managed installs only, the same guard and the
    // same self-heal posture as virule:// above: the per-user login start,
    // so the client is back after every login and reboot, and Windows
    // Error Reporting's application restart, so a crash brings it straight
    // back. WER restarts a process that has run for at least 60 s and died
    // on an unhandled exception, or that WER judged hung (never a clean
    // exit, so an uninstall, the self-update swap and Setup's shutdown are
    // never restarted); only patch/reboot relaunches are opted out. The
    // uninstall-intent gate in wWinMain still wins over a restart that
    // races a removal. No service, no scheduled task.
    if (register_protocol && vclient::self_update::g_enabled.load()) {
        vclient::login_start::register_login_start(
            vclient::paths::installed_client_exe().wstring());
        const HRESULT hr = RegisterApplicationRestart(
            restart_args.empty() ? nullptr : restart_args.c_str(),
            RESTART_NO_PATCH | RESTART_NO_REBOOT);
        vclient::log::client(SUCCEEDED(hr)
            ? "residency: login start registered; crash restart armed"
            : "residency: login start registered; crash restart unavailable");
    }

    vclient::bridge::Callbacks callbacks;
    callbacks.account_message = [](const std::string& type, const std::string& payload) -> std::string {
        namespace acct = vclient::account;
        if (type == "account_status") return acct::status_json();
        if (type == "account_sign_in") return acct::start_sign_in();
        if (type == "account_sign_in_cancel") return acct::cancel_sign_in();
        if (type == "account_sign_out") return acct::sign_out();
        if (type == "account_refresh") return acct::refresh();
        if (type == "account_link_qa") return acct::link_qa();
        if (type == "account_set_appearance") return acct::set_appearance(payload);
        if (type == "account_open_settings") return acct::open_settings();
        if (type == "account_api") {
            const std::string answer = acct::api_call(payload);
            // The developer's own Evaluations read answered something new
            // (an acceptance, a delivery): one inbox pass rides it.
            if (payload.find("\"GET\"") != std::string::npos && payload.find("\"/v1/evaluations\"") != std::string::npos &&
                answer.find("\"status\":200") != std::string::npos) {
                const std::uint64_t h = std::hash<std::string>{}(answer);
                if (g_last_view_hash.exchange(h) != h && g_inbox_wake) SetEvent(g_inbox_wake);
            }
            return answer;
        }
        return std::string();
    };
    callbacks.transfer_message = [](const std::string& type, const std::string& payload) -> std::string {
        namespace tr = vclient::transfers;
        const auto root = vclient::paths::virule_data_root();
        if (type == "transfer_control") {
            const std::string answer = tr::control(payload, root);
            if (g_transfer_wake) SetEvent(g_transfer_wake);
            return answer;
        }
        if (type == "transfer_wake") {
            if (g_transfer_wake) SetEvent(g_transfer_wake);
            return "{\"type\":\"transfer_wake\",\"ok\":true}";
        }
        if (type == "transfer_status") return tr::status_json(root);
        if (type == "evaluation_changes") {
            // THE CHANGE COUNTER (shared/evidence_queue.hpp): the Admin
            // reads it locally and reads again what changed.
            return "{\"type\":\"evaluation_changes\",\"generation\":\"" + std::to_string(g_boot_id) + ":" +
                   std::to_string(vclient::evidence::change_counter().load()) + "\"}";
        }
        if (type == "game_art") {
            const tr::DriverConfig* cfg = tr::control_config();
            return vclient::game_art::handle(payload, root, cfg ? cfg->service : nullptr);
        }
        return std::string();
    };
    callbacks.on_qa_accept = [](const std::string& token) {
        // A page is driving the redemption: any standalone Setup
        // conclusion is revoked (the browser owns the flow).
        vclient::takeover::supersede_standalone();
        // Redemption runs off the connection thread; the flow pushes its
        // result to watching pages (or the Admin bridge, or the card).
        struct Arg { std::string token; };
        auto* arg = new Arg{ token };
        HANDLE h = CreateThread(nullptr, 0,
            [](LPVOID p) -> DWORD {
                Arg* a = (Arg*)p;
                vclient::qa_flow::run(a->token);
                delete a;
                return 0;
            },
            arg, 0, nullptr);
        if (h) CloseHandle(h); else delete arg;
    };
    callbacks.on_admin_install = [](bool shortcut, bool from_page) {
        // The verified staged pipeline runs off the connection thread. Once
        // accepted it finishes even if every page closes (g_busy keeps the
        // idle-exit policy from ending the process mid-operation), and a
        // fresh install still launches the Admin at the end. A LOCAL
        // caller is the Admin's own Settings Update: the client owns the
        // visible feedback there (the native "Updating…" card after the
        // Admin closes - the dead-air fix); a page-driven operation leaves
        // the visible flow to the page - and REVOKES any standalone Setup
        // conclusion (P1 2026-09-04: a browser that was asleep or closed
        // during the takeover grace delivers its pending INSTALL_ADMIN
        // late; the page owns the flow from that moment and a standing
        // standalone card must close, never stand beside it).
        if (from_page) vclient::takeover::supersede_standalone();
        struct Arg { bool shortcut; bool native_feedback; };
        auto* arg = new Arg{ shortcut, !from_page };
        HANDLE h = CreateThread(nullptr, 0,
            [](LPVOID p) -> DWORD {
                Arg* a = (Arg*)p;
                vclient::admin_install::run(a->shortcut, a->native_feedback);
                delete a;
                return 0;
            },
            arg, 0, nullptr);
        if (h) CloseHandle(h); else delete arg;
    };
    callbacks.on_admin_launch = []() {
        // Update-on-launch: a managed virule.exe handed its user-initiated
        // launch over because an approved update exists. Native "Updating…"
        // feedback, verified update, then ONLY the new Admin launches.
        HANDLE h = CreateThread(nullptr, 0,
            [](LPVOID) -> DWORD {
                vclient::admin_install::launch_after_update_handoff();
                return 0;
            },
            nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    };
    callbacks.on_admin_open = []() {
        // ONE update transaction: an open that arrives while the
        // install/update operation runs JOINS it (the operation relaunches
        // the Admin itself at completion) rather than launching a binary
        // out of a directory that is mid-swap.
        if (vclient::admin_install::g_busy.load()) {
            vclient::log::client("admin: open requested during an active update; joining it");
            return true;
        }
        return vclient::admin_install::open_installed_admin();
    };
    callbacks.admin_status_json = []() {
        return vclient::admin_install::status_json();
    };
    callbacks.admin_update_status_json = [](bool launch_context) {
        return vclient::admin_install::update_status_json(launch_context);
    };
    callbacks.update_health_json = []() {
        return vclient::admin_install::update_health_json();
    };
    callbacks.evidence_status_json = [](const std::string& assignment_id) {
        return vclient::evidence::status_json(
            vclient::evidence::ee::root_under(vclient::paths::virule_data_root()),
            assignment_id);
    };
    callbacks.on_uninstall = [](bool delete_data) {
        begin_uninstall_async(delete_data);
    };
    // An Install Dev Tools while signed in enrolls the account at once
    // (shared/account_roles.hpp); signed out, the next sign-in delivers it.
    vclient::roles::g_on_developer_intent = []() { vclient::account::confirm_async(); };
    vclient::roles::g_signed_in = []() { return vclient::account::signed_in(); };
    callbacks.on_shutdown = []() {
        vclient::log::client("shutdown requested (local)");
        g_exit_requested.store(true);
        if (g_exit_event) SetEvent(g_exit_event);
    };
    callbacks.on_setup_takeover = [](const std::string& payload) {
        vclient::takeover::on_setup_takeover(payload);
    };
    callbacks.setup_released = []() {
        return vclient::takeover::released();
    };
    vclient::bridge::start(callbacks);
    g_state.store(RunState::Serving);
    vclient::log::client(std::string("serving, version ") + VIRULE_CLIENT_VERSION_STRING);

    // THE STARTUP RECONCILIATION ORDER (P2 pass 2026-09-04, one contract,
    // not five patches). Client startup and every Admin launch decision
    // settle state in ONE fixed precedence:
    //
    //   1. explicit uninstall intent (already honored in wWinMain: a
    //      latched machine never reaches serve());
    //   2. this client's OWN self-update transaction (this very binary
    //      must be settled before it makes decisions for anything else);
    //   3. managed-Admin filesystem state: stale staging/download debris,
    //      and 4. a stranded known-good Admin.previous restored (validated;
    //      never arbitrary junk) when the live Admin\ is missing, so an
    //      interrupted swap never forces a needless full re-download;
    //   5. installed-release metadata reconciled (the authoritative
    //      version record heals the state.json mirror, and vice versa);
    //   6. the persisted launch-update failure hold loaded/expired;
    //   7-8. only then do update-availability answers and launch/update
    //      decisions get made (the bridge callbacks and check threads).
    //
    // The bridge listener is already up (a takeover/serve contract), so
    // step 2 first waits for the listen state it needs.

    // 2. CLIENT SELF-UPDATE housekeeping (managed installs only): bring any
    // interrupted self-update transaction to one deterministic state, then
    // heal the outward version mirrors (state.json installed_version, the
    // Apps & Features DisplayVersion) from this executable's own compiled
    // version constant - the one authority. The short wait resolves the
    // listener state first: a freshly swapped-in client clears the
    // helper's rollback material only once it is demonstrably serving.
    {
        for (int i = 0; i < 30 && vclient::bridge::g_listen_state.load() == 0; ++i) {
            Sleep(100);
        }
        vclient::self_update::reconcile_startup_residue(
            vclient::bridge::g_listen_state.load() == 1);
        vclient::self_update::refresh_installed_identity();
    }

    // 3-4. Managed-Admin residue: an interrupted update (crash, power
    // loss, a cancelled uninstall, a kill between the two swap renames)
    // must not strand Admin.previous / Admin.staging / admin-download.zip
    // in an ambiguous state. A stranded VALIDATED known-good
    // Admin.previous with no live Admin\ is restored locally.
    vclient::admin_install::reconcile_startup_residue();

    // 5. Version recovery (the false-"up to date" fix): if a managed Admin
    // exists, its ACTUAL installed version is reconciled from the
    // authoritative in-install metadata immediately, so a reinstalled or
    // reset client never serves stale/empty version knowledge.
    vclient::admin_install::reconcile_installed_version();

    // 5b. Installed capabilities (0.9.9), ONE TIME: an installation with
    // no record gains dev_tools when the managed Admin is installed (every
    // Admin installed before 0.9.9 came through the Dev Tools entry point)
    // and never evaluator. Additive, so a capability a page recorded in
    // the moments since the bridge started is kept.
    if (vclient::capabilities::migrate_once(
            vclient::admin_install::admin_installed())) {
        vclient::log::client("capabilities: recorded " +
                             vclient::capabilities::enabled_json() +
                             " (one-time migration)");
    }

    // 6. The persisted launch-update failure hold: loaded into this
    // process, or cleared when expired/moot (audit M2).
    vclient::admin_install::reconcile_launch_update_hold();

    // MUTUAL RECOVERY (2026-10-06), managed installs only: settle any
    // interrupted service replacement, start watching (and if need be
    // starting) VIRULE Service, and tell a running service this Core
    // Services is serving so it binds to it at once. A missing service is
    // repaired through the update check below (service_install.hpp).
    if (vclient::self_update::g_enabled.load()) {
        vclient::service_install::reconcile_startup_residue();
        vclient::service_watch::start(residency_seams);
        vclient::residency::signal_event(vclient::residency::kServiceWakeEvent);
    }

    // The silent Admin update check (AUTOMATIC CHECKING, USER-INITIATED
    // INSTALLING): one check at startup, then a quiet periodic recheck
    // while this process happens to be serving. The scheduled Admin check
    // is ALSO this installation's check-in (owner spec 2026-10-01), so it
    // runs with or without a managed Admin; without one the manifest answer
    // is simply unused. The thread is detached and dies with the process.
    // The client's OWN self-update check rides the same quiet cadence
    // (startup, then the 6-hour recheck) and never blocks the bridge: the
    // listener is already up before this thread runs its first fetch.
    // Checking (and even staging) is automatic and silent; the SWAP waits
    // for the safe takeover point in the serve loop below.
    if (HANDLE h = CreateThread(nullptr, 0,
            [](LPVOID) -> DWORD {
                // `true` = scheduled: only these checks count toward the
                // update-connectivity record (shared/update_health.hpp).
                vclient::admin_install::refresh_update_check(
                    vclient::admin_install::kUpdateCheckFreshMs, true);
                vclient::self_update::refresh_check(
                    vclient::self_update::kCheckFreshMs);
                ULONGLONG last_inbox = GetTickCount64();
                for (;;) {
                    Sleep(60000);
                    vclient::admin_install::refresh_update_check(
                        vclient::admin_install::kUpdateCheckPeriodMs, true);
                    vclient::self_update::refresh_check(
                        vclient::self_update::kCheckPeriodMs);
                    // The developer's evaluation inbox rides the same quiet
                    // cadence as the scheduled check (no polling of its own).
                    if (GetTickCount64() - last_inbox >= vclient::admin_install::kUpdateCheckPeriodMs) {
                        last_inbox = GetTickCount64();
                        if (g_inbox_wake) SetEvent(g_inbox_wake);
                    }
                }
            },
            nullptr, 0, nullptr)) {
        CloseHandle(h);
    }

    // Evaluation evidence: delivered by this process whether or not a
    // wrapper or the Admin is running (survives both closing, a client
    // restart and a Windows restart: the startup pass is the recovery).
    start_evidence_delivery();

    // Game distribution: Build for Evaluation's upload and the evaluator's
    // install are carried by this process (client/transfers.hpp), whether
    // or not the Admin is running; the startup pass is the recovery.
    start_transfers();

    // The developer's evaluation evidence, fetched in the background
    // (client/evaluation_inbox.hpp); the startup pass is its recovery.
    start_inbox();

    // AN ADMIN UPDATE THE PREVIOUS CLIENT COULD NOT RUN (0.9.15): the
    // record it left is honored once, now that this (newer) client serves
    // (admin_install.hpp resume_pending_update). Its own thread: the Admin
    // is closed gracefully, the native card shows, the pipeline runs.
    if (vclient::self_update::g_enabled.load()) {
        if (HANDLE h = CreateThread(nullptr, 0,
                [](LPVOID) -> DWORD {
                    Sleep(1500); // the bridge is serving; let the first status asks land
                    vclient::admin_install::resume_pending_update();
                    return 0;
                },
                nullptr, 0, nullptr)) {
            CloseHandle(h);
        }
    }

    // THE LIFECYCLE STATUS WATCHER (P1 status push, 2026-09-04): while any
    // virule.app page is connected, re-read the lifecycle core (the admin
    // block + the uninstalling flag) once a second and push a status frame
    // to every page when it changed, so open tabs learn about Admin
    // launches/exits, update start/end and teardown starts in about a
    // second instead of their 15s poll. push_lifecycle_status does nothing
    // at all with no pages connected, so an idle client stays idle. The
    // thread is detached and dies with the process.
    if (HANDLE h = CreateThread(nullptr, 0,
            [](LPVOID) -> DWORD {
                for (;;) {
                    Sleep(1000);
                    vclient::bridge::push_lifecycle_status();
                }
            },
            nullptr, 0, nullptr)) {
        CloseHandle(h);
    }

    // A virule:// launch that made this process the instance carries its
    // work in. The grace window lets the invitation page reconnect to
    // this fresh listener before the ownership decision.
    if (!initial_qa_token.empty()) {
        vclient::qa_flow::run(initial_qa_token);
    }

    unsigned long long last_swap_attempt_tick = 0;
    unsigned long long swap_asap_since = 0;
    for (;;) {
        if (g_exit_event) WaitForSingleObject(g_exit_event, 1000);
        else Sleep(1000);
        if (g_exit_requested.load()) break;

        // THE SELF-UPDATE SWAP MONITOR: a verified staged client waits
        // here for the safe takeover point. UNINSTALL ALWAYS WINS: a
        // standing uninstall intent discards the staged update instead of
        // applying it. The drain flag closes the tiny race between the
        // safety check and the exit: nothing new starts in a process that
        // is about to hand its binary to the replacement helper.
        // AN ADMIN UPDATE IS WAITING ON THIS SWAP (0.9.15): the cadence
        // gives way to every second for up to two minutes, so the new
        // client takes over moments after the operation released the safe
        // point.
        if (g_swap_asap.load()) {
            const unsigned long long now = GetTickCount64();
            if (swap_asap_since == 0) swap_asap_since = now;
            if (now - swap_asap_since > 120000) { g_swap_asap.store(false); swap_asap_since = 0; }
            else last_swap_attempt_tick = 0;
        } else {
            swap_asap_since = 0;
        }
        if (vclient::self_update::g_swap_ready.load() &&
            vclient::bridge::g_listen_state.load() == 1) {
            const unsigned long long now = GetTickCount64();
            if (now - last_swap_attempt_tick >= 15000) {
                last_swap_attempt_tick = now;
                if (vclient::lifecycle::uninstall_intent_active()) {
                    vclient::log::client(
                        "self-update: uninstall intent active; staged update discarded");
                    vclient::self_update::discard_pending();
                } else if (self_update_safe_point()) {
                    vclient::bridge::g_self_update_draining.store(true);
                    Sleep(250);
                    if (self_update_safe_point() &&
                        vclient::self_update::begin_swap()) {
                        g_exit_requested.store(true);
                        break; // drain and exit; the helper owns the swap
                    }
                    vclient::bridge::g_self_update_draining.store(false);
                }
            }
        }

        if (vclient::bridge::g_listen_state.load() == 2) {
            // The port is genuinely unavailable (a foreign squatter; the
            // single-instance gate already ruled out a second client).
            // Nothing to serve: leave rather than linger uselessly.
            vclient::log::client("no listener could be established; exiting");
            break;
        }
        // No idle exit: the client is RESIDENT (see the header). With no
        // page connected and no operation running this loop is the whole
        // cost of staying alive: one wake-up a second.
    }
    g_state.store(RunState::Draining);
    // An exit this process chose (Setup's shutdown, the self-update swap)
    // is announced so VIRULE Service holds off for the replacement instead
    // of restoring the binary being replaced. A port that can never be
    // owned is not a choice: that exit stays "unexpected" and residency's
    // backoff governs any retry.
    if (g_exit_requested.load()) vclient::residency::announce_client_exit_intent();
    if (g_evidence_stop) SetEvent(g_evidence_stop);
    if (g_inbox_stop) SetEvent(g_inbox_stop);
    if (g_transfer_stop) SetEvent(g_transfer_stop);
    vclient::bridge::stop_listening();
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    // OWN THE WORKING DIRECTORY (the 2026-09-04 update-loop root cause).
    // A client started by another process INHERITS that process's current
    // directory; the managed virule.exe runs with the Admin install dir as
    // its CWD (desktop shortcut and admin_open both set it), so a client it
    // started on demand held an open handle on that very directory, and the
    // update's atomic rename of the live install could never succeed. The
    // client's CWD is its own exe directory, always, no matter who launched
    // it: nothing this process later renames or removes may ever be its own
    // current directory.
    {
        wchar_t self[MAX_PATH * 2] = {};
        const DWORD n = GetModuleFileNameW(nullptr, self,
                                           (DWORD)(sizeof(self) / sizeof(self[0])));
        if (n > 0 && n < sizeof(self) / sizeof(self[0])) {
            std::wstring dir(self, n);
            const size_t slash = dir.find_last_of(L"\\/");
            if (slash != std::wstring::npos) {
                dir.resize(slash);
                SetCurrentDirectoryW(dir.c_str());
            }
        }
    }

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    std::wstring arg1 = (argc > 1) ? argv[1] : L"";
    std::wstring arg2 = (argc > 2) ? argv[2] : L"";
    bool no_register = false;
    bool delete_data_arg = false;
    bool dev_unsigned = false;       // signature gates only (dev)
    bool restarted = false;          // relaunched by WER after a crash
    bool restored = false;           // relaunched by VIRULE Service
    std::wstring self_manifest_url;  // self-update manifest seam (dev)
    std::wstring admin_manifest_url; // Admin-manifest seam (dev)
    // The development seams this run carries, in the only form residency
    // ever forwards (loopback manifest urls only; residency.hpp).
    const std::wstring residency_seams = vclient::residency::forward_seams(argc, argv);
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--no-register") no_register = true;
        if (arg == L"--delete-data") delete_data_arg = true;
        if (arg == L"--dev-unsigned") dev_unsigned = true;
        if (arg == L"--restarted") restarted = true;
        if (arg == L"--restored") restored = true;
        if (arg.rfind(L"--self-manifest-url=", 0) == 0) {
            self_manifest_url = arg.substr(20);
        }
        if (arg.rfind(L"--admin-manifest-url=", 0) == 0) {
            admin_manifest_url = arg.substr(21);
        }
        if (arg.rfind(L"--evidence-test-endpoint=", 0) == 0) {
            g_evidence_test_endpoint = arg.substr(25);
        }
        // Staging-only harness seam (tools/account_live_staging_test.mjs):
        // the real staging service, the browser played by the harness.
        if (arg == L"--account-browser=capture") vclient::account::capture_browser() = true;
        // Development seam for the account service (tools/account_flow_test.mjs):
        // LOOPBACK ONLY, so no argument can point a real sign-in elsewhere.
        if (arg.rfind(L"--account-endpoint=", 0) == 0) {
            const std::wstring v = arg.substr(19);
            if (v.rfind(L"http://127.0.0.1:", 0) == 0 || v.rfind(L"https://127.0.0.1:", 0) == 0) {
                vclient::account::set_endpoint_override(v);
            }
        }
    }
    LocalFree(argv);
    if (arg1 == L"--no-register" || arg1 == L"--dev-unsigned" ||
        arg1 == L"--restarted" || arg1 == L"--restored" ||
        arg1.rfind(L"--self-manifest-url=", 0) == 0 ||
        arg1.rfind(L"--admin-manifest-url=", 0) == 0 ||
        arg1.rfind(L"--evidence-test-endpoint=", 0) == 0 ||
        arg1.rfind(L"--account-endpoint=", 0) == 0 ||
        arg1 == L"--account-browser=capture") {
        arg1.clear();
    }

    // The command line Windows Error Reporting relaunches this process
    // with after a crash (serve() registers it): the marker, plus every
    // development seam this run carries, so a restarted client keeps the
    // posture it was started with.
    std::wstring restart_args = L"--restarted";
    if (no_register) restart_args += L" --no-register";
    if (dev_unsigned) restart_args += L" --dev-unsigned";
    if (!self_manifest_url.empty()) {
        restart_args += L" --self-manifest-url=" + self_manifest_url;
    }
    if (!admin_manifest_url.empty()) {
        restart_args += L" --admin-manifest-url=" + admin_manifest_url;
    }
    if (!g_evidence_test_endpoint.empty()) {
        restart_args += L" --evidence-test-endpoint=" + g_evidence_test_endpoint;
    }

    // Self-update run configuration. Self-update manages ONLY the managed
    // installation: it is enabled exactly when this process IS
    // %LOCALAPPDATA%\Programs\VIRULE\virule-client.exe (a development tree
    // never self-updates). The %TEMP% helper mode below reads the same
    // configuration.
    vclient::self_update::g_dev_unsigned = dev_unsigned;
    vclient::self_update::g_manifest_override = self_manifest_url;
    vclient::self_update::g_no_register = no_register;
    // ONE UPDATE ACTION CONVERGES BOTH (owner spec 2026-09-16): a
    // user-initiated Admin install / update / launch handoff forces the
    // client's own self-update check now (its own thread; the download
    // never delays the Admin work). The staged client swaps at the safe
    // takeover point once the Admin operation is over, exactly as a timer
    // check would.
    vclient::admin_install::g_on_user_operation = [] {
        if (HANDLE t = CreateThread(nullptr, 0,
                [](LPVOID) -> DWORD {
                    vclient::self_update::refresh_check(0);
                    return 0;
                },
                nullptr, 0, nullptr)) {
            CloseHandle(t);
        }
    };
    // THE ADMIN UPDATE RESUMES AFTER THE CLIENT'S OWN SWAP (0.9.15;
    // admin_install.hpp): the approved Admin needs a newer client, the
    // request is recorded, and this client stages its update NOW
    // (synchronously, on the operation's own thread; a check already in
    // flight from g_on_user_operation is the same staging) and swaps at
    // the first safe moment instead of its 15-second cadence.
    vclient::admin_install::g_on_client_update_required = [] {
        vclient::self_update::refresh_check(0);
        g_swap_asap.store(true); // the serve loop ticks every second
    };
    // The managed-Admin pipeline's own two dev seams (same posture:
    // --dev-unsigned relaxes only Authenticode gates, the manifest
    // override relaxes only host + repository pin).
    vclient::admin_install::g_dev_unsigned = dev_unsigned;
    vclient::admin_install::g_manifest_override = admin_manifest_url;
    {
        wchar_t self[MAX_PATH * 2] = {};
        const DWORD n = GetModuleFileNameW(nullptr, self,
                                           (DWORD)(sizeof(self) / sizeof(self[0])));
        std::wstring self_path = (n > 0 && n < sizeof(self) / sizeof(self[0]))
            ? std::wstring(self, n) : std::wstring();
        std::wstring installed = vclient::paths::installed_client_exe().wstring();
        for (wchar_t& c : self_path) c = (wchar_t)towlower(c);
        for (wchar_t& c : installed) c = (wchar_t)towlower(c);
        vclient::self_update::g_enabled.store(
            !installed.empty() && self_path == installed);
    }
    // VIRULE Service distribution and residency follow the same rule: the
    // managed install only, the same two seams.
    vclient::service_install::g_enabled.store(vclient::self_update::g_enabled.load());
    vclient::service_install::g_dev_unsigned = dev_unsigned;
    vclient::service_install::g_manifest_seam = !self_manifest_url.empty();
    vclient::service_install::g_seams = residency_seams;

    // ---- helper mode (a %TEMP% copy finishing an uninstall) ----
    if (arg1 == L"--finish-uninstall") {
        unsigned long pid = 0;
        try { pid = std::stoul(arg2); } catch (...) {}
        return run_finish_uninstall(pid, delete_data_arg);
    }

    // ---- helper mode (a %TEMP% copy finishing a client self-update) ----
    // Handles the uninstall-intent latch itself (a latched machine gets
    // its staged update discarded and NO client started - uninstall wins).
    if (arg1 == L"--finish-self-update") {
        unsigned long pid = 0;
        try { pid = std::stoul(arg2); } catch (...) {}
        return vclient::self_update::run_finish_self_update(pid);
    }

    // ---- Windows-initiated uninstall (Apps & Features / command line) ----
    if (arg1 == L"--uninstall") {
        // The native confirmation mirrors the site's uninstall modal: the
        // DEFAULT preserves the user's local VIRULE data, and only the
        // explicit Delete local data option (with its own warning) makes
        // the removal destructive.
        bool delete_data = false;
        if (!vclient::uninstall_dialog::run(delete_data)) return 0;
        // ONE ordered teardown owns the flow: a serving instance runs the
        // whole sequence itself (intent latch, update cancellation,
        // Admin-close-first, helper). This short-lived launcher only
        // forwards the confirmed decision.
        const std::string msg = std::string("{\"type\":\"uninstall_local\",") +
            "\"delete_data\":" + (delete_data ? "true" : "false") + "}";
        if (forward_to_running_instance(msg)) return 0;
        // No serving instance: this process runs the pre-teardown steps
        // itself. Intent FIRST, then Admin-close-first, then the helper.
        if (!vclient::lifecycle::set_uninstall_intent()) return 1;
        vclient::residency::request_service_stop();
        vclient::result_card::show_working("Removing VIRULE\xE2\x80\xA6", "");
        vclient::uninstall::reconcile_admin_update_residue();
        if (vclient::admin_install::admin_running()) {
            if (!vclient::admin_install::close_running_admin(30000)) {
                // Nothing was destroyed; the latch stays (self-heal keeps
                // standing down) and Apps & Features remains the retry.
                vclient::uninstall::temp_log(
                    "uninstall: the Admin did not close; nothing removed");
                vclient::result_card::update("Something went wrong.",
                                             "Close VIRULE and try again.");
                vclient::result_card::wait_closed(12000);
                return 1;
            }
        }
        if (!vclient::uninstall::spawn_uninstall_helper(delete_data)) {
            vclient::result_card::update("Something went wrong.",
                                         "Try again in a moment.");
            vclient::result_card::wait_closed(12000);
            return 1;
        }
        return 0;
    }

    if (arg1 == L"--version") {
        if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            DWORD written = 0;
            const std::string line = std::string("virule-client ") +
                VIRULE_CLIENT_VERSION_STRING + "\n";
            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line.data(),
                      (DWORD)line.size(), &written, nullptr);
        }
        return 0;
    }

    // ---- the uninstall-intent gate ----
    // EXPLICIT UNINSTALL WINS: while the durable intent latch is set, a
    // freshly started client refuses to serve, register virule:// or do
    // anything else that would fight the removal (a client started during
    // the teardown would hold the very files the helper is removing). The
    // helper mode and the --uninstall retry path were dispatched above;
    // recovery from a stranded latch is an explicit gesture: retrying the
    // uninstall, or a fresh Virule-Setup install (which clears the latch).
    if (vclient::lifecycle::uninstall_intent_active()) {
        vclient::uninstall::temp_log(
            "client: uninstall intent active; refusing to start");
        return 0;
    }

    // ---- protocol launch or plain start ----
    std::string protocol_url;
    if (arg1.rfind(L"virule://", 0) == 0) protocol_url = narrow(arg1);

    // DETERMINISTIC ROUTING (the same order the VIRULE Admin uses). The
    // grammar decides and nothing else: a generic wake is decided FIRST and
    // can never fall into QA, and only a URL inside the QA namespace may
    // reach QA verification.
    std::string qa_token;
    if (!protocol_url.empty()) {
        if (vclient::protocol_reg::is_wake_url(protocol_url)) {
            // Generic wake: start (or keep) serving, carry no task. The
            // browser owns whatever the user actually came for.
        } else if (vclient::protocol_reg::is_qa_url(protocol_url)) {
            const auto token = vclient::protocol_reg::parse_qa_verify_token(protocol_url);
            if (!token) {
                // Inside the QA namespace but malformed: rejected. Never
                // trusted, never partially interpreted, no UI (the browser
                // side owns messaging; a crafted URL earns nothing).
                vclient::log::client("rejected virule:// input");
                return 0;
            }
            qa_token = *token;
        } else {
            // Unknown grammar: rejected with no action and no UI.
            vclient::log::client("rejected virule:// input");
            return 0;
        }
    }

    // ---- single instance ----
    HANDLE mutex = CreateMutexW(nullptr, TRUE, vclient::residency::kClientSingleton);
    const bool already_running =
        (mutex != nullptr && GetLastError() == ERROR_ALREADY_EXISTS) ||
        (mutex == nullptr);
    if (already_running) {
        // Clean second-launch behavior: hand the work to the running
        // instance and leave. No duplicate client, no duplicate listener.
        if (!qa_token.empty()) {
            const std::string msg =
                "{\"type\":\"qa_verify_url\",\"token\":\"" + qa_token + "\"}";
            if (!forward_to_running_instance(msg)) {
                // The instance is mid-exit or wedged: run the flow in this
                // process without a listener (the /qa/link polling and the
                // Admin-bridge report still deliver the outcome).
                vclient::qa_flow::run(qa_token);
            }
        } else {
            (void)forward_to_running_instance("{\"type\":\"wake\"}");
        }
        if (mutex) CloseHandle(mutex);
        return 0;
    }

    if (restarted) {
        vclient::log::client("residency: restarted by Windows after an unexpected exit");
    }
    if (restored) {
        vclient::log::client("residency: restored by VIRULE Service after an unexpected exit");
    }
    serve(qa_token, !no_register, restart_args, residency_seams);

    ReleaseMutex(mutex);
    CloseHandle(mutex);
    return 0;
}
