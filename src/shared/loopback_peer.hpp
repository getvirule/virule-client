#pragma once
// WHO IS ON THE OTHER END OF A LOOPBACK TCP CONNECTION (audit H-3,
// 2026-11-11).
//
// The VIRULE Client's bridge (127.0.0.1:47612) is reachable by every process
// on the computer, including processes of OTHER Windows users (another
// interactive session, Fast User Switching, a "run as" process). The
// account session and device key are DPAPI user-scope protected
// (VIRULE/docs/specs/evaluation-security.md decision 23); a bridge that
// answered another user's process would hand that user this user's powers
// and authorization. So every accepted connection is mapped to the process
// that owns its other end, and that process's token user SID must equal this
// process's own. Same-user callers (the website in this user's browser,
// VIRULE Desktop, the evaluation wrapper, Setup, a second Client instance,
// the self-update helper) all pass: a browser's sandboxed network process
// or a restricted or AppContainer token keeps the same TokenUser. NOT
// VERIFIED: whether this (medium integrity) client can read the token of an
// ELEVATED process of the same user; no VIRULE component requests
// elevation, and if it cannot, such a peer is refused (fail closed).
// Hostile code running as THIS user is out of
// scope (evaluation-security.md, the same-user limit); this closes the
// cross-user path only and takes no position on whether two Windows users
// may each run VIRULE.
//
// Windows-supported mechanisms only: GetExtendedTcpTable
// (TCP_TABLE_OWNER_PID_CONNECTIONS) finds the row whose endpoints are the
// MIRROR of this socket's (its local endpoint is our remote one and the
// reverse); OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) +
// OpenProcessToken(TOKEN_QUERY) + GetTokenInformation(TokenUser) reads that
// process's user. FAIL CLOSED: a peer whose row, process or token cannot be
// read is refused. That is load-bearing, not a corner: a standard user
// normally cannot open ANOTHER account's token at all, so in practice a
// cross-user peer reads as "unreadable" rather than as a different SID
// (tests\loopback_peer shows it on dwm.exe, winlogon.exe and the rest). The
// other usual cause is a peer that already went away, whose connection is
// dead anyway.
//
// The tuple matching is a pure function (find_peer_pid) so it is unit
// tested without sockets: tests\loopback_peer\run_tests.bat.

#include <cstdint>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#endif

namespace vclient::loopback_peer {

// One IPv4 TCP connection row, every field in HOST byte order.
struct TcpRow {
    std::uint32_t local_addr = 0;
    std::uint16_t local_port = 0;
    std::uint32_t remote_addr = 0;
    std::uint16_t remote_port = 0;
    std::uint32_t state = 0;
    std::uint32_t pid = 0;
};

// One endpoint, host byte order.
struct Endpoint {
    std::uint32_t addr = 0;
    std::uint16_t port = 0;
};

// MIB_TCP_STATE_ESTAB.
inline constexpr std::uint32_t kStateEstablished = 5;

// The PID owning the OTHER end of the connection whose own endpoints are
// `mine` (this socket's local endpoint) and `theirs` (its remote endpoint):
// the one ESTABLISHED row whose local endpoint is `theirs` and whose remote
// endpoint is `mine`. 0 when there is no such row, or more than one (an
// ambiguity is never resolved by guessing).
inline std::uint32_t find_peer_pid(const std::vector<TcpRow>& rows,
                                   Endpoint mine, Endpoint theirs) {
    std::uint32_t found = 0;
    int matches = 0;
    for (const TcpRow& r : rows) {
        if (r.state != kStateEstablished) continue;
        if (r.local_addr != theirs.addr || r.local_port != theirs.port) continue;
        if (r.remote_addr != mine.addr || r.remote_port != mine.port) continue;
        ++matches;
        found = r.pid;
    }
    return matches == 1 ? found : 0;
}

#if defined(_WIN32)

enum class Verdict { same_user, other_user, unknown };

struct Result {
    Verdict verdict = Verdict::unknown;
    std::uint32_t pid = 0;
    const char* why = "";
};

// Every IPv4 TCP connection on this computer (listeners excluded).
inline bool read_tcp_table(std::vector<TcpRow>& out) {
    out.clear();
    std::vector<unsigned char> buf;
    DWORD size = 0;
    DWORD rc = ERROR_INSUFFICIENT_BUFFER;
    for (int attempt = 0; attempt < 8 && rc == ERROR_INSUFFICIENT_BUFFER; ++attempt) {
        buf.resize((size_t)size + 32 * sizeof(MIB_TCPROW_OWNER_PID) + sizeof(DWORD));
        size = (DWORD)buf.size();
        rc = GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    }
    if (rc != NO_ERROR) return false;
    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
    out.reserve(table->dwNumEntries);
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_TCPROW_OWNER_PID& r = table->table[i];
        TcpRow row;
        row.local_addr = ntohl(r.dwLocalAddr);
        row.local_port = ntohs((u_short)(r.dwLocalPort & 0xFFFF));
        row.remote_addr = ntohl(r.dwRemoteAddr);
        row.remote_port = ntohs((u_short)(r.dwRemotePort & 0xFFFF));
        row.state = r.dwState;
        row.pid = r.dwOwningPid;
        out.push_back(row);
    }
    return true;
}

// This socket's own (local) and remote endpoints; IPv4 only.
inline bool endpoints_of(SOCKET s, Endpoint& mine, Endpoint& theirs) {
    sockaddr_in a{};
    int len = sizeof(a);
    if (getsockname(s, (sockaddr*)&a, &len) != 0 || a.sin_family != AF_INET) return false;
    mine.addr = ntohl(a.sin_addr.s_addr);
    mine.port = ntohs(a.sin_port);
    sockaddr_in b{};
    len = sizeof(b);
    if (getpeername(s, (sockaddr*)&b, &len) != 0 || b.sin_family != AF_INET) return false;
    theirs.addr = ntohl(b.sin_addr.s_addr);
    theirs.port = ntohs(b.sin_port);
    return true;
}

// The PID owning the other end of this connected socket, or 0.
inline std::uint32_t peer_pid(SOCKET s) {
    Endpoint mine, theirs;
    if (!endpoints_of(s, mine, theirs)) return 0;
    std::vector<TcpRow> rows;
    // Both halves of a loopback connection exist once connect() returned on
    // one side and accept() on the other; the second read only absorbs a
    // table snapshot taken mid-update.
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (attempt) Sleep(20);
        if (!read_tcp_table(rows)) continue;
        const std::uint32_t pid = find_peer_pid(rows, mine, theirs);
        if (pid) return pid;
    }
    return 0;
}

// The token user SID of a process (a copy of its bytes).
inline bool token_user_sid(HANDLE process, std::vector<unsigned char>& sid_out) {
    sid_out.clear();
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return false;
    DWORD need = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &need);
    bool ok = false;
    if (need > 0) {
        std::vector<unsigned char> buf(need);
        if (GetTokenInformation(token, TokenUser, buf.data(), need, &need)) {
            const auto* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
            if (tu->User.Sid && IsValidSid(tu->User.Sid)) {
                const DWORD n = GetLengthSid(tu->User.Sid);
                const auto* p = reinterpret_cast<const unsigned char*>(tu->User.Sid);
                sid_out.assign(p, p + n);
                ok = true;
            }
        }
    }
    CloseHandle(token);
    return ok;
}

inline bool process_user_sid(std::uint32_t pid, std::vector<unsigned char>& sid_out) {
    sid_out.clear();
    if (pid == 0) return false;
    if (pid == GetCurrentProcessId()) return token_user_sid(GetCurrentProcess(), sid_out);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return false;
    const bool ok = token_user_sid(h, sid_out);
    CloseHandle(h);
    return ok;
}

// This process's own token user SID, read once.
inline const std::vector<unsigned char>& own_user_sid() {
    static const std::vector<unsigned char> sid = [] {
        std::vector<unsigned char> s;
        (void)token_user_sid(GetCurrentProcess(), s);
        return s;
    }();
    return sid;
}

inline Result check_pid(std::uint32_t pid) {
    Result r;
    r.pid = pid;
    if (pid == 0) { r.why = "no connection row for the peer"; return r; }
    const std::vector<unsigned char>& mine = own_user_sid();
    if (mine.empty()) { r.why = "own user unreadable"; return r; }
    std::vector<unsigned char> theirs;
    if (!process_user_sid(pid, theirs)) { r.why = "peer process or token unreadable"; return r; }
    const bool same = theirs.size() == mine.size() &&
        EqualSid((PSID)theirs.data(), (PSID)const_cast<unsigned char*>(mine.data()));
    r.verdict = same ? Verdict::same_user : Verdict::other_user;
    r.why = same ? "same user" : "another Windows user";
    return r;
}

// The whole check for a connected socket: who is on the other end, and is
// it this process's own Windows user.
inline Result check_peer(SOCKET s) { return check_pid(peer_pid(s)); }

// FAIL CLOSED: only a positively identified same-user peer passes.
inline bool peer_is_same_user(SOCKET s) {
    return check_peer(s).verdict == Verdict::same_user;
}

#endif

} // namespace vclient::loopback_peer
