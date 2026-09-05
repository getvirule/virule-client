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
//   Draining      idle timeout reached or shutdown requested; the
//                 listener closes and the process exits cleanly
//   Uninstalling  a verified uninstall began; the %TEMP% helper takes
//                 over after this process exits
//
// SINGLE INSTANCE: one named mutex; a second launch forwards its work
// (a virule:// URL, or a plain wake) to the running instance over the
// loopback bridge and exits immediately. Two launches can never produce
// two active clients or two listeners.
//
// ON DEMAND: no service, no login task. The client runs when Setup, a
// virule:// launch, or the user starts it, and exits on its own after
// kIdleExitMs with no bridge connection and no work. The browser's
// deterministic wake path (the protocol preflight) covers every later
// visit.

#include <atomic>
#include <string>
#include <vector>

#include "client/admin_install.hpp"
#include "client/bridge.hpp"
#include "client/qa_flow.hpp"
#include "client/result_card.hpp"
#include "client/self_update.hpp"
#include "client/takeover.hpp"
#include "client/uninstall_dialog.hpp"
#include "shared/client_state.hpp"
#include "shared/lifecycle_intent.hpp"
#include "shared/logging.hpp"
#include "shared/paths.hpp"
#include "shared/protocol_reg.hpp"
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

// Idle-exit policy: with no open bridge connection and no activity for
// this long, the process leaves. virule:// wakes it again deterministically.
constexpr unsigned long long kIdleExitMs = 20ull * 60ull * 1000ull;

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
//   5. exit and hand the removal to the visible %TEMP% helper, which
//      removes files, removes registrations LAST, verifies, clears the
//      intent latch LAST and shows the terminal outcome.
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

    // 5. Helper handoff. The listener closes so the freed port and the
    // dying socket read as removal in progress; the helper (a %TEMP% copy
    // of this exe) owns the visible surface from here.
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
                    rc::update("VIRULE has been uninstalled.",
                               delete_data ? "" : "Your local data was kept.");
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

void serve(const std::string& initial_qa_token, bool register_protocol) {
    // Self-heal the pieces an installed client owns. Registration mirrors
    // the Admin's behavior: whichever VIRULE component ran last holds
    // virule://, and both handle qa/verify identically. (--no-register is
    // a development seam so a directly-run build does not take over a
    // machine's real registration.)
    if (register_protocol) vclient::protocol_reg::register_protocol();

    vclient::bridge::Callbacks callbacks;
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
        // "VIRULE is ready" card must close, never stand beside it).
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
    callbacks.admin_update_status_json = []() {
        return vclient::admin_install::update_status_json();
    };
    callbacks.on_uninstall = [](bool delete_data) {
        begin_uninstall_async(delete_data);
    };
    callbacks.on_shutdown = []() {
        vclient::log::client("shutdown requested (local)");
        g_exit_requested.store(true);
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

    // Update-residue reconciliation: an interrupted update (crash, power
    // loss, a cancelled uninstall) must not strand Admin.previous /
    // Admin.staging / admin-download.zip in an ambiguous state. A stranded
    // known-good Admin.previous with no live Admin\ is restored.
    vclient::admin_install::reconcile_startup_residue();

    // Version recovery (the false-"up to date" fix): if a managed Admin
    // exists, its ACTUAL installed version is reconciled from the
    // authoritative in-install metadata immediately, so a reinstalled or
    // reset client never serves stale/empty version knowledge.
    vclient::admin_install::reconcile_installed_version();

    // CLIENT SELF-UPDATE housekeeping (managed installs only): bring any
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

    // The silent Admin update check (AUTOMATIC CHECKING, USER-INITIATED
    // INSTALLING): one check at startup, then a quiet periodic recheck
    // while this process happens to be serving. Both no-op instantly when
    // no managed Admin install exists, so machines without one create no
    // background traffic. The thread is detached and dies with the process.
    // The client's OWN self-update check rides the same quiet cadence
    // (startup, then the 6-hour recheck) and never blocks the bridge: the
    // listener is already up before this thread runs its first fetch.
    // Checking (and even staging) is automatic and silent; the SWAP waits
    // for the safe takeover point in the serve loop below.
    if (HANDLE h = CreateThread(nullptr, 0,
            [](LPVOID) -> DWORD {
                vclient::admin_install::refresh_update_check(
                    vclient::admin_install::kUpdateCheckFreshMs);
                vclient::self_update::refresh_check(
                    vclient::self_update::kCheckFreshMs);
                for (;;) {
                    Sleep(60000);
                    vclient::admin_install::refresh_update_check(
                        vclient::admin_install::kUpdateCheckPeriodMs);
                    vclient::self_update::refresh_check(
                        vclient::self_update::kCheckPeriodMs);
                }
            },
            nullptr, 0, nullptr)) {
        CloseHandle(h);
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
    for (;;) {
        Sleep(1000);
        if (g_exit_requested.load()) break;

        // THE SELF-UPDATE SWAP MONITOR: a verified staged client waits
        // here for the safe takeover point. UNINSTALL ALWAYS WINS: a
        // standing uninstall intent discards the staged update instead of
        // applying it. The drain flag closes the tiny race between the
        // safety check and the exit: nothing new starts in a process that
        // is about to hand its binary to the replacement helper.
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
        if (vclient::bridge::g_open_connections.load() == 0 &&
            !vclient::admin_install::g_busy.load()) {
            const unsigned long long last = vclient::bridge::g_last_activity_tick.load();
            if (last != 0 && GetTickCount64() - last > kIdleExitMs) {
                vclient::log::client("idle; exiting");
                break;
            }
        }
    }
    g_state.store(RunState::Draining);
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
    bool dev_unsigned = false;      // self-update signature gates only (dev)
    std::wstring self_manifest_url; // self-update manifest seam (dev)
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--no-register") no_register = true;
        if (arg == L"--delete-data") delete_data_arg = true;
        if (arg == L"--dev-unsigned") dev_unsigned = true;
        if (arg.rfind(L"--self-manifest-url=", 0) == 0) {
            self_manifest_url = arg.substr(20);
        }
    }
    LocalFree(argv);
    if (arg1 == L"--no-register" || arg1 == L"--dev-unsigned" ||
        arg1.rfind(L"--self-manifest-url=", 0) == 0) {
        arg1.clear();
    }

    // Self-update run configuration. Self-update manages ONLY the managed
    // installation: it is enabled exactly when this process IS
    // %LOCALAPPDATA%\Programs\VIRULE\virule-client.exe (a development tree
    // never self-updates). The %TEMP% helper mode below reads the same
    // configuration.
    vclient::self_update::g_dev_unsigned = dev_unsigned;
    vclient::self_update::g_manifest_override = self_manifest_url;
    vclient::self_update::g_no_register = no_register;
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
    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Local\\ViruleClient.Singleton");
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

    serve(qa_token, !no_register);

    ReleaseMutex(mutex);
    CloseHandle(mutex);
    return 0;
}
