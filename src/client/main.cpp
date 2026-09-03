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
#include "shared/client_state.hpp"
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

// The minimal native removal confirmation (Windows Apps & Features entry
// point; the browser owns this confirmation whenever the flow starts
// there). Sparse by rule: title, one sentence, Cancel / Remove VIRULE.
bool confirm_uninstall_native() {
    // MessageBox keeps this dependency-free; the button labels are the
    // standard system pair and the text carries the owner's exact copy.
    const int r = MessageBoxW(nullptr,
        L"This removes VIRULE and its local data from this computer.",
        L"Remove VIRULE?",
        MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND);
    return r == IDOK;
}

// A verified uninstall: leave Serving, free the port, hand the removal to
// the %TEMP% helper and exit. Never deletes anything in-process.
void begin_uninstall_and_exit() {
    g_state.store(RunState::Uninstalling);
    vclient::log::client("uninstall: starting (helper handoff)");
    vclient::bridge::stop_listening();
    if (!vclient::uninstall::spawn_uninstall_helper()) {
        vclient::log::client("uninstall: helper could not be started; nothing removed");
        g_state.store(RunState::Serving);
        return;
    }
    ExitProcess(0);
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
    callbacks.on_admin_install = [](bool shortcut) {
        // The verified staged pipeline runs off the connection thread. Once
        // accepted it finishes even if every page closes (g_busy keeps the
        // idle-exit policy from ending the process mid-operation), and a
        // fresh install still launches the Admin at the end.
        struct Arg { bool shortcut; };
        auto* arg = new Arg{ shortcut };
        HANDLE h = CreateThread(nullptr, 0,
            [](LPVOID p) -> DWORD {
                Arg* a = (Arg*)p;
                vclient::admin_install::run(a->shortcut);
                delete a;
                return 0;
            },
            arg, 0, nullptr);
        if (h) CloseHandle(h); else delete arg;
    };
    callbacks.on_admin_open = []() {
        return vclient::admin_install::open_installed_admin();
    };
    callbacks.admin_status_json = []() {
        return vclient::admin_install::status_json();
    };
    callbacks.on_uninstall = []() { begin_uninstall_and_exit(); };
    callbacks.on_shutdown = []() {
        vclient::log::client("shutdown requested (local)");
        g_exit_requested.store(true);
    };
    vclient::bridge::start(callbacks);
    g_state.store(RunState::Serving);
    vclient::log::client(std::string("serving, version ") + VIRULE_CLIENT_VERSION_STRING);

    // A virule:// launch that made this process the instance carries its
    // work in. The grace window lets the invitation page reconnect to
    // this fresh listener before the ownership decision.
    if (!initial_qa_token.empty()) {
        vclient::qa_flow::run(initial_qa_token);
    }

    for (;;) {
        Sleep(1000);
        if (g_exit_requested.load()) break;
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
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    std::wstring arg1 = (argc > 1) ? argv[1] : L"";
    std::wstring arg2 = (argc > 2) ? argv[2] : L"";
    bool no_register = false;
    for (int i = 1; i < argc; ++i) {
        if (std::wstring(argv[i]) == L"--no-register") no_register = true;
    }
    LocalFree(argv);
    if (arg1 == L"--no-register") arg1.clear();

    // ---- helper mode (a %TEMP% copy finishing an uninstall) ----
    if (arg1 == L"--finish-uninstall") {
        unsigned long pid = 0;
        try { pid = std::stoul(arg2); } catch (...) {}
        return vclient::uninstall::finish_uninstall(pid);
    }

    // ---- Windows-initiated uninstall (Apps & Features / command line) ----
    if (arg1 == L"--uninstall") {
        if (!confirm_uninstall_native()) return 0;
        // May be the installed exe itself: single instance must not block
        // the removal. Ask a running instance to leave first.
        (void)forward_to_running_instance("{\"type\":\"shutdown\"}");
        Sleep(300);
        if (!vclient::uninstall::spawn_uninstall_helper()) return 1;
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
