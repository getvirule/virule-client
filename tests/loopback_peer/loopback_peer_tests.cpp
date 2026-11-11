// Loopback peer identity (shared/loopback_peer.hpp; audit H-3, 2026-11-11).
// Built and run by tests\loopback_peer\run_tests.bat. Starts NO client and
// never touches port 47612: every socket here is an ephemeral 127.0.0.1 port
// owned by this test process.
//
//   1. The pure tuple match (find_peer_pid) over hand-made rows: the
//      mirrored row is found, a row with a wrong port or address, a
//      non-ESTABLISHED row and an ambiguous pair are not.
//   2. A real loopback connection inside this process, resolved from BOTH
//      directions: the accepted side resolves the connector (the bridge's
//      case) and the connecting side resolves the listener (VIRULE
//      Desktop's case); both must name this process and this user.
//   3. Processes Windows runs under other accounts (System, dwm.exe,
//      winlogon.exe, ...) are never reported as this user.
//   4. A platform probe for the listener's bind options (audit L-24,
//      SO_EXCLUSIVEADDRUSE): can a listener re-bind its port right after
//      connections it accepted were closed (the Client's self-update
//      relaunch, restart_listening after a failed uninstall helper)? The
//      probe prints what Windows does; it is information, not a pass/fail.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "shared/loopback_peer.hpp"

#include <tlhelp32.h>

namespace lp = vclient::loopback_peer;

static int g_pass = 0, g_fail = 0;
static void check(const char* what, bool ok) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    (ok ? g_pass : g_fail)++;
}

static lp::TcpRow row(std::uint32_t la, std::uint16_t lport, std::uint32_t ra, std::uint16_t rport,
                      std::uint32_t state, std::uint32_t pid) {
    lp::TcpRow r;
    r.local_addr = la; r.local_port = lport; r.remote_addr = ra; r.remote_port = rport;
    r.state = state; r.pid = pid;
    return r;
}

static void pure_cases() {
    const std::uint32_t L = 0x7F000001; // 127.0.0.1
    const lp::Endpoint mine{ L, 47612 };   // the bridge's accepted socket
    const lp::Endpoint theirs{ L, 50123 }; // the caller's ephemeral port
    const std::uint32_t E = lp::kStateEstablished;
    {
        std::vector<lp::TcpRow> rows = {
            row(L, 47612, L, 50123, E, 100), // our own accepted row
            row(L, 50123, L, 47612, E, 200), // the caller's row
        };
        check("pure: the mirrored row names the caller's PID", lp::find_peer_pid(rows, mine, theirs) == 200);
        check("pure: from the caller's side the mirror names the listener", lp::find_peer_pid(rows, theirs, mine) == 100);
    }
    {
        std::vector<lp::TcpRow> rows = { row(L, 50124, L, 47612, E, 200) };
        check("pure: a different caller port is no match", lp::find_peer_pid(rows, mine, theirs) == 0);
    }
    {
        std::vector<lp::TcpRow> rows = { row(L, 50123, L, 47611, E, 200) };
        check("pure: a different listener port is no match", lp::find_peer_pid(rows, mine, theirs) == 0);
    }
    {
        std::vector<lp::TcpRow> rows = { row(0x7F000002, 50123, L, 47612, E, 200) };
        check("pure: a different caller address is no match", lp::find_peer_pid(rows, mine, theirs) == 0);
    }
    {
        std::vector<lp::TcpRow> rows = { row(L, 50123, L, 47612, 11 /* TIME_WAIT */, 0) };
        check("pure: a non-ESTABLISHED row is ignored", lp::find_peer_pid(rows, mine, theirs) == 0);
    }
    {
        std::vector<lp::TcpRow> rows = { row(L, 50123, L, 47612, E, 200), row(L, 50123, L, 47612, E, 300) };
        check("pure: two candidate rows are refused, never guessed", lp::find_peer_pid(rows, mine, theirs) == 0);
    }
    check("pure: an empty table is no match", lp::find_peer_pid({}, mine, theirs) == 0);
}

static SOCKET listen_ephemeral(unsigned short& port, bool exclusive) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    if (exclusive) {
        BOOL on = TRUE;
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&on, sizeof(on));
    }
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    int len = sizeof(a);
    if (bind(s, (sockaddr*)&a, sizeof(a)) != 0 || listen(s, 4) != 0 ||
        getsockname(s, (sockaddr*)&a, &len) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    port = ntohs(a.sin_port);
    return s;
}

static SOCKET connect_to(unsigned short port) {
    SOCKET c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET) return c;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (connect(c, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(c); return INVALID_SOCKET; }
    return c;
}

static void real_connection() {
    unsigned short port = 0;
    SOCKET l = listen_ephemeral(port, false);
    check("real: an ephemeral loopback listener opens", l != INVALID_SOCKET);
    if (l == INVALID_SOCKET) return;
    SOCKET c = connect_to(port);
    SOCKET a = c != INVALID_SOCKET ? accept(l, nullptr, nullptr) : INVALID_SOCKET;
    check("real: a loopback connection is made and accepted", c != INVALID_SOCKET && a != INVALID_SOCKET);
    if (a != INVALID_SOCKET) {
        const lp::Result from_listener = lp::check_peer(a);
        std::printf("  accepted side: pid %u (this process %lu), %s\n", from_listener.pid, GetCurrentProcessId(), from_listener.why);
        check("real: the accepted side resolves the connector to THIS process", from_listener.pid == GetCurrentProcessId());
        check("real: the accepted side reads the connector as the same user", from_listener.verdict == lp::Verdict::same_user);
        check("real: peer_is_same_user passes it", lp::peer_is_same_user(a));
    }
    if (c != INVALID_SOCKET) {
        const lp::Result from_caller = lp::check_peer(c);
        std::printf("  connecting side: pid %u, %s\n", from_caller.pid, from_caller.why);
        check("real: the connecting side resolves the listener to THIS process", from_caller.pid == GetCurrentProcessId());
        check("real: the connecting side reads the listener as the same user", from_caller.verdict == lp::Verdict::same_user);
    }
    if (a != INVALID_SOCKET) closesocket(a);
    if (c != INVALID_SOCKET) closesocket(c);
    closesocket(l);

    // A socket that is not connected has no peer: refused, never "same user".
    SOCKET lone = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    check("real: an unconnected socket is not a same-user peer", !lp::peer_is_same_user(lone));
    closesocket(lone);
}

static void other_users() {
    const lp::Result system = lp::check_pid(4);
    std::printf("  System (pid 4): %s\n", system.why);
    check("other users: System is never this user", system.verdict != lp::Verdict::same_user);
    check("other users: no PID is never this user", lp::check_pid(0).verdict != lp::Verdict::same_user);

    // Processes Windows always runs under ANOTHER account, several of them
    // inside this user's own session (dwm.exe as Window Manager\DWM-n,
    // fontdrvhost.exe as Font Driver Host\UMFD-n, winlogon.exe and csrss.exe
    // as SYSTEM): the same-session, other-user case a session comparison
    // would miss.
    static const wchar_t* kOtherAccounts[] = {
        L"dwm.exe", L"fontdrvhost.exe", L"winlogon.exe", L"csrss.exe",
        L"services.exe", L"lsass.exe", L"wininit.exe", L"smss.exe",
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    int seen = 0, other = 0, unknown = 0, wrongly_same = 0;
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
            bool listed = false;
            for (const wchar_t* name : kOtherAccounts) listed = listed || _wcsicmp(pe.szExeFile, name) == 0;
            if (!listed) continue;
            ++seen;
            const lp::Result r = lp::check_pid(pe.th32ProcessID);
            if (r.verdict == lp::Verdict::other_user) ++other;
            else if (r.verdict == lp::Verdict::unknown) ++unknown;
            else ++wrongly_same;
        }
        CloseHandle(snap);
    }
    std::printf("  system-account processes: %d (another user %d, unreadable %d, read as this user %d)\n",
                seen, other, unknown, wrongly_same);
    check("other users: system-account processes exist to test against", seen > 0);
    // A standard user normally cannot open another account's token at all,
    // so most of these read as "unreadable": that is why the check FAILS
    // CLOSED. Either verdict refuses; only same_user passes.
    check("other users: none is read as this user (every one refused)", wrongly_same == 0);
}

// Information only (see the header): does Windows let a listener re-bind its
// port at once after the connections it accepted were closed?
static void bind_probe(bool exclusive, bool server_closes_first, bool keep_accepted_open) {
    unsigned short port = 0;
    SOCKET l = listen_ephemeral(port, exclusive);
    if (l == INVALID_SOCKET) { std::printf("  probe: listener failed\n"); return; }
    SOCKET c = connect_to(port);
    SOCKET a = accept(l, nullptr, nullptr);
    char byte = 'x';
    send(c, &byte, 1, 0);
    recv(a, &byte, 1, 0);
    if (!keep_accepted_open) {
        if (server_closes_first) { shutdown(a, SD_BOTH); closesocket(a); Sleep(50); closesocket(c); }
        else { shutdown(c, SD_BOTH); closesocket(c); Sleep(50); closesocket(a); }
        a = INVALID_SOCKET; c = INVALID_SOCKET;
    }
    closesocket(l);
    Sleep(50);
    unsigned short again = port;
    SOCKET l2 = listen_ephemeral(again, exclusive);
    const int err = l2 == INVALID_SOCKET ? WSAGetLastError() : 0;
    std::printf("  probe: %s listener, %s: re-bind of port %u %s (WSA %d)\n",
                exclusive ? "SO_EXCLUSIVEADDRUSE" : "default",
                keep_accepted_open ? "accepted connection still open" :
                    (server_closes_first ? "listener side closed first (its TIME_WAIT)" : "caller closed first"),
                port, l2 != INVALID_SOCKET ? "SUCCEEDED" : "FAILED", err);
    if (l2 != INVALID_SOCKET) closesocket(l2);
    if (a != INVALID_SOCKET) closesocket(a);
    if (c != INVALID_SOCKET) closesocket(c);
}

// The self-update shape: ANOTHER process (the old client) listened with
// SO_EXCLUSIVEADDRUSE, served a connection it closed first (its TIME_WAIT
// stays behind) and exited; this process (the new client) binds the port.
static int child_serve_once(unsigned short port) {
    SOCKET l = listen_ephemeral(port, true);
    if (l == INVALID_SOCKET) return 2;
    std::printf("%u\n", port);
    std::fflush(stdout);
    SOCKET a = accept(l, nullptr, nullptr);
    char byte = 0;
    recv(a, &byte, 1, 0);
    send(a, &byte, 1, 0);
    shutdown(a, SD_BOTH);
    closesocket(a); // the listener side closes first
    Sleep(100);
    closesocket(l);
    return 0;
}

static void cross_process_probe() {
    wchar_t self[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, self, (DWORD)(sizeof(self) / sizeof(self[0])));
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    std::wstring cmd = L"\"" + std::wstring(self) + L"\" --serve-once";
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(self, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        std::printf("  probe: child could not start\n");
        return;
    }
    CloseHandle(wr);
    char line[32] = {};
    DWORD got = 0;
    ReadFile(rd, line, sizeof(line) - 1, &got, nullptr);
    const unsigned short port = (unsigned short)std::atoi(line);
    SOCKET c = connect_to(port);
    char byte = 'x';
    send(c, &byte, 1, 0);
    recv(c, &byte, 1, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    closesocket(c);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(rd);
    unsigned short again = port;
    SOCKET l2 = listen_ephemeral(again, true);
    const int err = l2 == INVALID_SOCKET ? WSAGetLastError() : 0;
    std::printf("  probe: SO_EXCLUSIVEADDRUSE, another process listened, served, closed first and exited: re-bind of port %u %s (WSA %d)\n",
                port, l2 != INVALID_SOCKET ? "SUCCEEDED" : "FAILED", err);
    if (l2 != INVALID_SOCKET) closesocket(l2);
}

int main(int argc, char** argv) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { std::printf("FAIL WSAStartup\n"); return 1; }
    if (argc > 1 && std::string(argv[1]) == "--serve-once") return child_serve_once(0);
    pure_cases();
    real_connection();
    other_users();
    std::printf("bind probe (information only):\n");
    for (int ex = 0; ex < 2; ++ex) {
        bind_probe(ex == 1, true, false);
        bind_probe(ex == 1, false, false);
        bind_probe(ex == 1, false, true);
    }
    cross_process_probe();
    WSACleanup();
    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
