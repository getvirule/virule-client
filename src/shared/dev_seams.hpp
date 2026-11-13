#pragma once
// THE DEVELOPMENT COMMAND-LINE SEAMS (audit L-24, 2026-11-12).
//
// The client's test harnesses drive it with a few command-line seams that a
// production run must never act on:
//
//   --dev-unsigned            waives ONLY the signature gates (never the hash)
//   --self-manifest-url=<u>   the client release manifest from a local server
//   --admin-manifest-url=<u>  the approved Admin manifest from a local server
//   --account-endpoint=<u>    the account service at a local test server
//
// They are honored ONLY where dev_seams::allowed() answers true: a
// staging build, or a sandboxed run whose LOCALAPPDATA is redirected
// (paths::environment_redirected), the gate --evidence-test-endpoint has
// always had. A production build on a real profile, which is every launch a
// browser, the protocol handler, Windows or VIRULE Desktop makes (they all
// inherit the real environment and pass no seam), ignores them exactly as it
// ignores any unknown argument. The manifest urls must also be loopback
// (is_loopback_url) and the account endpoint 127.0.0.1, in every build.
//
// RESIDUAL, inside the documented same-user trust model (ARCHITECTURE.md,
// "The origin check defends against the WEB, not against local code"): a
// process already running as this Windows user that starts the client with a
// redirected LOCALAPPDATA can still reach them.
//
// SETUP'S TWO SEAMS (--dev-unsigned, --manifest-url=; owner brief 2026-11-12
// section 7) follow a STRICTER rule, setup_permitted() below: a sandboxed run
// ONLY, never merely a staging build. Setup is the signed executable a user
// downloads and runs on a real profile, and the staging Setup is signed too
// while verifying no Authenticode (kRequireAuthenticode is false there), so a
// staging exemption would let one argument install any payload from any host.
// --manifest-url= must also be loopback (is_loopback_url). The canonical
// signed Setups (release/setup/) were re-cut with this rule from ee930ec on
// 2026-11-12; the production one reaches users at the next production
// Client publish.
//
// --no-register is NOT gated: it relaxes no gate (it only skips the machine
// registrations) and every harness, including the unsandboxed bridge_test,
// relies on it to keep the machine's virule:// untouched.

#include <string>

#include "shared/environment.hpp"
#include "shared/paths.hpp"

namespace vclient::dev_seams {

// THE ONE PREDICATE for every development test seam of the client: the
// command-line seams below (also what VIRULE Service forwards) and the
// evidence test transport (shared/evidence_queue.hpp). True in a staging
// build, or in a run whose LOCALAPPDATA is redirected away from the real
// profile (paths::environment_redirected, which fails to false). This is a
// RUN-TIME rule, unlike the compile-time origin rule in environment.hpp: any
// web page can present any Origin, but a launch from a browser, the protocol
// handler, Windows or VIRULE Desktop inherits the real environment, so extra
// arguments on it can never switch a seam on, while the sandboxed harnesses
// keep running the production build they test.
inline constexpr bool permitted(bool staging_build, bool redirected) {
    return staging_build || redirected;
}
inline bool allowed() {
    return permitted(env::kStaging, paths::environment_redirected());
}

// A loopback http(s) url: exactly 127.0.0.1 or localhost (lowercase), then an
// explicit decimal port 1..65535, then the end of the url or a '/'. The
// authority is therefore the loopback host itself: no userinfo
// (http://127.0.0.1:1@evil.example/), no longer host
// (http://127.0.0.1.evil.example/), no other 127.x address, no IPv6 literal.
// No whitespace or quotes anywhere (the value becomes one argv element when
// forwarded).
inline bool is_loopback_url(const std::wstring& url) {
    for (const wchar_t* p : { L"http://127.0.0.1:", L"http://localhost:",
                              L"https://127.0.0.1:", L"https://localhost:" }) {
        if (url.rfind(p, 0) != 0) continue;
        for (const wchar_t c : url) {
            if (c == L' ' || c == L'"' || c == L'\t') return false;
        }
        size_t i = std::wstring(p).size();
        const size_t digits_from = i;
        unsigned long port = 0;
        while (i < url.size() && url[i] >= L'0' && url[i] <= L'9' && i - digits_from < 5) {
            port = port * 10 + (unsigned long)(url[i] - L'0');
            ++i;
        }
        if (i == digits_from || port == 0 || port > 65535) return false;
        return i == url.size() || url[i] == L'/';
    }
    return false;
}

// The account service seam's own rule (unchanged): 127.0.0.1 only.
inline bool is_account_endpoint(const std::wstring& v) {
    return v.rfind(L"http://127.0.0.1:", 0) == 0 || v.rfind(L"https://127.0.0.1:", 0) == 0;
}

struct Seams {
    bool dev_unsigned = false;
    std::wstring self_manifest_url;
    std::wstring admin_manifest_url;
    std::wstring account_endpoint;
    int ignored = 0; // seams present on the command line and not honored
};

inline constexpr size_t kSelfLen = 20;    // --self-manifest-url=
inline constexpr size_t kAdminLen = 21;   // --admin-manifest-url=
inline constexpr size_t kAccountLen = 19; // --account-endpoint=

// The seams this run honors. `honored` is dev_seams::allowed() at the call
// sites; a parameter so the rule is testable in either build.
inline Seams parse(int argc, wchar_t** argv, bool honored) {
    Seams s;
    for (int i = 1; i < argc; ++i) {
        const std::wstring a = argv[i];
        if (a == L"--dev-unsigned") {
            if (honored) s.dev_unsigned = true; else ++s.ignored;
        } else if (a.rfind(L"--self-manifest-url=", 0) == 0) {
            const std::wstring v = a.substr(kSelfLen);
            if (honored && is_loopback_url(v)) s.self_manifest_url = v; else ++s.ignored;
        } else if (a.rfind(L"--admin-manifest-url=", 0) == 0) {
            const std::wstring v = a.substr(kAdminLen);
            if (honored && is_loopback_url(v)) s.admin_manifest_url = v; else ++s.ignored;
        } else if (a.rfind(L"--account-endpoint=", 0) == 0) {
            const std::wstring v = a.substr(kAccountLen);
            if (honored && is_account_endpoint(v)) s.account_endpoint = v; else ++s.ignored;
        }
    }
    return s;
}

// The seams a residency launch carries (client <-> VIRULE Service):
// --no-register always, the others only where they are honored.
inline std::wstring forward(int argc, wchar_t** argv, bool honored) {
    std::wstring out;
    for (int i = 1; i < argc; ++i) {
        const std::wstring a = argv[i];
        if (a == L"--no-register") {
            out += L" " + a;
        } else if (!honored) {
            continue;
        } else if (a == L"--dev-unsigned") {
            out += L" " + a;
        } else if (a.rfind(L"--self-manifest-url=", 0) == 0 && is_loopback_url(a.substr(kSelfLen))) {
            out += L" " + a;
        } else if (a.rfind(L"--admin-manifest-url=", 0) == 0 && is_loopback_url(a.substr(kAdminLen))) {
            out += L" " + a;
        }
    }
    return out;
}

// ---- SETUP'S SEAMS (setup/main.cpp) ----
//
//   --dev-unsigned       waives ONLY the client and service signature gates
//                        (never the size and SHA-256 gate)
//   --manifest-url=<u>   the client release manifest from a local server;
//                        relaxes only the repository pin
//
// THE ONE PREDICATE for Setup: a run whose LOCALAPPDATA is redirected away
// from the real profile, in EVERY build. It deliberately takes no staging
// flag (header comment): every launch a user makes, from a browser download
// or Explorer, inherits the real environment, so no argument on it can switch
// a Setup seam on. A redirected run also writes nothing outside the sandbox:
// Setup's machine registrations refuse on their own there.
inline constexpr bool setup_permitted(bool redirected) {
    return redirected;
}
inline bool setup_allowed() {
    return setup_permitted(paths::environment_redirected());
}

struct SetupSeams {
    bool dev_unsigned = false;
    std::wstring manifest_url; // empty = the compiled-in manifest
    int ignored = 0;           // seams present on the command line and not honored
};

inline constexpr size_t kSetupManifestLen = 15; // --manifest-url=

// The seams this Setup run honors. `honored` is setup_allowed() at the call
// site; a parameter so the rule is testable in either build. A refused seam
// is ignored (the normal verified install proceeds) and counted.
inline SetupSeams parse_setup(int argc, wchar_t** argv, bool honored) {
    SetupSeams s;
    for (int i = 1; i < argc; ++i) {
        const std::wstring a = argv[i];
        if (a == L"--dev-unsigned") {
            if (honored) s.dev_unsigned = true; else ++s.ignored;
        } else if (a.rfind(L"--manifest-url=", 0) == 0) {
            const std::wstring v = a.substr(kSetupManifestLen);
            if (honored && is_loopback_url(v)) s.manifest_url = v; else ++s.ignored;
        }
    }
    return s;
}

} // namespace vclient::dev_seams
