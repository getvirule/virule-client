#pragma once
// THE GAME'S LAUNCH FILE NAME, checked where the Client takes it in (audit
// L-25, 2026-11-11; defense in depth).
//
// The VIRULE service already constrains `launch_exe` to one bare .exe file
// name (VIRULE_BACKEND src/evaluations/distribution.ts EXE_NAME: no
// separators, no colon, no Windows-reserved characters or control
// characters). The Client joins it to the install folder and starts it, so
// it re-checks the same shape itself instead of trusting the answer: a name
// that could leave the install folder (a separator, `..`, a drive or UNC
// root, an alternate data stream) is refused. Length is bounded in bytes
// only (the service counts characters), so no name the service accepts is
// refused here.
//
// Pure; tests\launch_name\run_tests.bat.

#include <string>

namespace vclient::launch_name {

inline bool is_safe(const std::string& name) {
    if (name.empty() || name.size() > 1024) return false;
    if (name == "." || name == "..") return false;
    for (const char ch : name) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c < 0x20) return false;
        switch (c) {
            case '\\': case '/': case ':': case '*': case '?':
            case '"': case '<': case '>': case '|':
                return false;
            default:
                break;
        }
    }
    // One .exe file with a name before the extension.
    if (name.size() < 5) return false;
    const std::string ext = name.substr(name.size() - 4);
    std::string lower;
    for (const char ch : ext) lower += (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : ch;
    return lower == ".exe";
}

} // namespace vclient::launch_name
