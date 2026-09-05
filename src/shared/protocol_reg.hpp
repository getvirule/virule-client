#pragma once
// virule:// protocol registration, per-user (HKCU\Software\Classes\virule),
// no elevation. The registry shape is EXACTLY the one the VIRULE Admin
// writes (qa_protocol::register_protocol in the VIRULE repository), so the
// two products can hold the registration interchangeably: whichever ran
// last owns it, and both handle virule://qa/verify/<token> identically.
//
// Uninstall removes the registration ONLY when its command still points at
// this executable: a registration the VIRULE Admin has since taken over is
// left exactly as it is.

#include <optional>
#include <string>

#include "shared/paths.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace vclient::protocol_reg {

inline void set_reg_string(const wchar_t* subkey, const wchar_t* name,
                           const std::wstring& value) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, subkey, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return;
    }
    RegSetValueExW(key, name, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(value.c_str()),
                   (DWORD)((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
}

// Register virule:// to launch `exe_path` (defaults to this executable).
inline void register_protocol(const std::wstring& exe_path_in = L"") {
    // Same machine-registration guard as the Apps & Features entry: HKCU
    // is the real hive even under a redirected (test-sandbox) filesystem
    // world, so a sandboxed run never rewrites the real virule:// handler.
    if (paths::environment_redirected()) return;
    std::wstring exe_path = exe_path_in;
    if (exe_path.empty()) {
        wchar_t exe[MAX_PATH] = {};
        if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return;
        exe_path = exe;
    }
    set_reg_string(L"Software\\Classes\\virule", nullptr, L"URL:VIRULE Protocol");
    set_reg_string(L"Software\\Classes\\virule", L"URL Protocol", L"");
    set_reg_string(L"Software\\Classes\\virule\\DefaultIcon", nullptr,
                   L"\"" + exe_path + L"\",0");
    set_reg_string(L"Software\\Classes\\virule\\shell\\open\\command", nullptr,
                   L"\"" + exe_path + L"\" \"%1\"");
}

// The currently registered open command, or empty.
inline std::wstring registered_command() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Classes\\virule\\shell\\open\\command", 0,
                      KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return L"";
    }
    wchar_t buf[1024] = {};
    DWORD size = sizeof(buf) - sizeof(wchar_t);
    DWORD type = 0;
    std::wstring out;
    if (RegQueryValueExW(key, nullptr, nullptr, &type,
                         reinterpret_cast<BYTE*>(buf), &size) == ERROR_SUCCESS &&
        type == REG_SZ) {
        out = buf;
    }
    RegCloseKey(key);
    return out;
}

// Case-insensitive: does the registered command name this exe?
inline bool registered_to(const std::wstring& exe_path) {
    std::wstring cmd = registered_command();
    if (cmd.empty()) return false;
    auto lower = [](std::wstring s) {
        for (auto& c : s) c = static_cast<wchar_t>(towlower(c));
        return s;
    };
    return lower(cmd).find(lower(exe_path)) != std::wstring::npos;
}

// Remove the registration entirely (only call after registered_to()).
inline void unregister_protocol() {
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\virule");
}

// ---- the virule:// grammar (ONE grammar, implemented in two components) ----
//
// The scheme carries exactly two shapes and they are never confused:
//
//   virule://qa/...    the QA namespace (qa/verify/<token> is the invitation
//                      page's ACCEPT fallback);
//   virule://open      a GENERIC WAKE. It carries no task, it is NEVER a QA
//                      event, and it must never produce a QA surface.
//
// Anything else is rejected without action. The VIRULE Admin implements the
// identical functions (src/cli/main.cpp, namespace qa_protocol) and
// tools/protocol_routing_test.mjs fails if the two ever diverge.

inline std::string lowered(const std::string& url) {
    std::string lower;
    lower.reserve(url.size());
    for (const char c : url) {
        lower += (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    return lower;
}

// The QA namespace. Only a URL inside it may ever reach QA verification, so
// a malformed invite still gets the QA answer while nothing outside qa/ can
// produce a QA surface.
inline bool is_qa_url(const std::string& url) {
    return lowered(url).rfind("virule://qa/", 0) == 0;
}

// The plain wake URL: virule://open (a trailing slash or a query/fragment
// suffix is tolerated). The browser's install flow uses it to start local
// VIRULE without commanding anything.
inline bool is_wake_url(const std::string& url) {
    const std::string lower = lowered(url);
    if (lower.rfind("virule://open", 0) != 0) return false;
    const std::string rest = lower.substr(13);
    return rest.empty() || rest[0] == '/' || rest[0] == '?' || rest[0] == '#';
}

// An invitation token, exactly as the service mints them: the CURRENT
// 32-character Base64URL form (192-bit, no padding, case-SENSITIVE) or the
// LEGACY 64-lowercase-hex form (accepted until those invites expire).
inline bool is_invite_token(const std::string& s) {
    if (s.size() == 64) {
        return s.find_first_not_of("0123456789abcdef") == std::string::npos;
    }
    if (s.size() == 32) {
        return s.find_first_not_of(
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "abcdefghijklmnopqrstuvwxyz0123456789-_") ==
               std::string::npos;
    }
    return false;
}

// virule://qa/verify/<token> (a trailing slash or a query/fragment suffix
// is tolerated; anything else is not a QA verification URL). The prefix
// matches case-insensitively but the token is taken from the ORIGINAL
// string: Base64URL tokens are case-sensitive and must never be lowercased.
inline std::optional<std::string> parse_qa_verify_token(const std::string& url) {
    const std::string lower = lowered(url);
    const std::string prefix = "virule://qa/verify/";
    if (lower.rfind(prefix, 0) != 0) return std::nullopt;
    std::string rest = url.substr(prefix.size());
    const size_t end = rest.find_first_of("/?#");
    if (end != std::string::npos) rest = rest.substr(0, end);
    if (!is_invite_token(rest)) return std::nullopt;
    return rest;
}

} // namespace vclient::protocol_reg
