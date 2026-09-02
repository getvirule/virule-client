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

// virule://qa/verify/<64 lowercase hex> (a trailing slash or a
// query/fragment suffix is tolerated; anything else is not a QA
// verification URL). The Admin's parser, ported.
inline std::optional<std::string> parse_qa_verify_token(const std::string& url) {
    std::string lower;
    lower.reserve(url.size());
    for (const char c : url) {
        lower += (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    const std::string prefix = "virule://qa/verify/";
    if (lower.rfind(prefix, 0) != 0) return std::nullopt;
    std::string rest = lower.substr(prefix.size());
    const size_t end = rest.find_first_of("/?#");
    if (end != std::string::npos) rest = rest.substr(0, end);
    if (rest.size() != 64 ||
        rest.find_first_not_of("0123456789abcdef") != std::string::npos) {
        return std::nullopt;
    }
    return rest;
}

// A plain wake URL: virule://open (optionally with a trailing slash or
// suffix). The browser's install flow uses it to start the client without
// commanding anything.
inline bool is_wake_url(const std::string& url) {
    std::string lower;
    lower.reserve(url.size());
    for (const char c : url) {
        lower += (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    if (lower.rfind("virule://open", 0) != 0) return false;
    const std::string rest = lower.substr(13);
    return rest.empty() || rest[0] == '/' || rest[0] == '?' || rest[0] == '#';
}

} // namespace vclient::protocol_reg
