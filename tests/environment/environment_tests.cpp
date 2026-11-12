// The browser origins the loopback listeners accept (shared/environment.hpp
// origin_allowed; audit M-6, 2026-11-12). Built TWICE and run by
// tests\environment\run_tests.bat: once as a production build (no define)
// and once with VIRULE_ENV_STAGING, so each half of the seam is proven by
// the build it belongs to.
//
//   A production build answers its own site's origins and nothing else.
//   The LOCAL DEVELOPMENT origins (the vite dev server on 5173/5174,
//   wrangler dev on 8788) are accepted ONLY by a staging build. The client
//   bridge (client/bridge.hpp) and Setup's handoff listener
//   (setup/handoff_listener.hpp) both answer through this one function.
//
//   The DEVELOPMENT COMMAND-LINE SEAMS (shared/dev_seams.hpp; audit L-24,
//   2026-11-12): --dev-unsigned, --self-manifest-url=, --admin-manifest-url=
//   and --account-endpoint= are honored, and forwarded by the residency
//   layer, only in a staging build or a sandboxed run (LOCALAPPDATA
//   redirected). A production build on a real profile ignores every one.
//   --no-register is honored and forwarded in every build.
//
// Starts no client and touches no port. The process's own LOCALAPPDATA is
// set (to the real known folder, then to a sandbox path) and restored.

#include <cstdio>
#include <initializer_list>
#include <string>
#include <vector>

#include "shared/dev_seams.hpp"
#include "shared/environment.hpp"
#include "shared/paths.hpp"
#include "shared/residency.hpp"

namespace env = vclient::env;
namespace ds = vclient::dev_seams;

static int g_pass = 0, g_fail = 0;
static void check(const std::string& what, bool ok) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what.c_str());
    (ok ? g_pass : g_fail)++;
}

static const char* const kDev[] = {
    "http://localhost:5173",  "http://127.0.0.1:5173",  "http://localhost:5174",
    "http://127.0.0.1:5174",  "https://localhost:8788", "https://127.0.0.1:8788",
};

static std::wstring known_local_appdata() {
    PWSTR known = nullptr;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &known)) && known) out = known;
    if (known) CoTaskMemFree(known);
    return out;
}

// argv as the Windows command line hands it over.
static std::vector<wchar_t*> argv_of(std::vector<std::wstring>& keep) {
    std::vector<wchar_t*> argv;
    for (auto& a : keep) argv.push_back(a.data());
    return argv;
}
static ds::Seams parse(std::vector<std::wstring> keep, bool honored) {
    std::vector<wchar_t*> argv = argv_of(keep);
    return ds::parse((int)argv.size(), argv.data(), honored);
}
// The residency layer's own entry point (what VIRULE Service calls).
static std::wstring forward_seams(std::vector<std::wstring> keep) {
    std::vector<wchar_t*> argv = argv_of(keep);
    return vclient::residency::forward_seams((int)argv.size(), argv.data());
}

int main() {
    const bool staging = env::kStaging;
    std::printf("build: %s\n", staging ? "STAGING (VIRULE_ENV_STAGING)" : "PRODUCTION");

    for (const char* o : kDev) {
        check(std::string("development origin ") + o +
                  (staging ? " accepted (staging build)" : " refused (production build)"),
              env::origin_allowed(o) == staging);
    }
    check("https://virule.app accepted only by production",
          env::origin_allowed("https://virule.app") == !staging);
    check("https://www.virule.app accepted only by production",
          env::origin_allowed("https://www.virule.app") == !staging);
    check("the staging site accepted only by staging",
          env::origin_allowed("https://virule-api-staging.heath-michaels9441.workers.dev") == staging);
    check("a foreign origin refused", !env::origin_allowed("https://evil.example"));
    check("the literal null origin refused", !env::origin_allowed("null"));
    check("a wildcard refused", !env::origin_allowed("*"));
    check("an empty origin is not an allowed page origin", !env::origin_allowed(""));
    check("a development origin with a trailing slash refused", !env::origin_allowed("http://localhost:5173/"));
    check("a localhost port outside the list refused", !env::origin_allowed("http://localhost:5175"));
    check("plain http on the wrangler port refused", !env::origin_allowed("http://localhost:8788"));
    check("the site origin with a trailing slash refused", !env::origin_allowed("https://virule.app/"));

    // ---- the development command-line seams ----
    check("predicate: production build on a real profile honors no seam", !ds::permitted(false, false));
    check("predicate: a sandboxed production run honors the seams", ds::permitted(false, true));
    check("predicate: a staging build honors the seams", ds::permitted(true, false) && ds::permitted(true, true));

    const std::vector<std::wstring> all_seams = {
        L"virule-client.exe", L"--no-register", L"--dev-unsigned",
        L"--self-manifest-url=http://127.0.0.1:1/m.json",
        L"--admin-manifest-url=http://localhost:2/a.json",
        L"--account-endpoint=http://127.0.0.1:3",
    };
    const std::wstring all_forwarded =
        L" --no-register --dev-unsigned --self-manifest-url=http://127.0.0.1:1/m.json"
        L" --admin-manifest-url=http://localhost:2/a.json";

    wchar_t saved[MAX_PATH * 4] = {};
    const DWORD saved_n = GetEnvironmentVariableW(L"LOCALAPPDATA", saved, MAX_PATH * 4);
    const std::wstring real = known_local_appdata();
    check("(setup) the real LocalAppData known folder is readable", !real.empty());

    // A real profile: what every browser, protocol, Windows and Desktop launch sees.
    SetEnvironmentVariableW(L"LOCALAPPDATA", real.c_str());
    check("real profile: the run is not redirected", !vclient::paths::environment_redirected());
    check(staging ? "real profile, staging build: seams honored" : "real profile, production build: seams refused",
          ds::allowed() == staging);
    {
        const ds::Seams s = parse(all_seams, ds::allowed());
        if (staging) {
            check("real profile, staging build: --dev-unsigned honored", s.dev_unsigned);
            check("real profile, staging build: --self-manifest-url= honored", s.self_manifest_url == L"http://127.0.0.1:1/m.json");
            check("real profile, staging build: --admin-manifest-url= honored", s.admin_manifest_url == L"http://localhost:2/a.json");
            check("real profile, staging build: --account-endpoint= honored", s.account_endpoint == L"http://127.0.0.1:3");
            check("real profile, staging build: nothing ignored", s.ignored == 0);
        } else {
            check("real profile, production build: --dev-unsigned ignored", !s.dev_unsigned);
            check("real profile, production build: --self-manifest-url= ignored", s.self_manifest_url.empty());
            check("real profile, production build: --admin-manifest-url= ignored", s.admin_manifest_url.empty());
            check("real profile, production build: --account-endpoint= ignored", s.account_endpoint.empty());
            check("real profile, production build: all four counted as ignored", s.ignored == 4);
        }
        const std::wstring fwd = forward_seams(all_seams);
        check(staging ? "real profile, staging build: residency forwards every loopback seam"
                      : "real profile, production build: residency forwards only --no-register",
              fwd == (staging ? all_forwarded : std::wstring(L" --no-register")));
    }

    // A sandboxed harness run (LOCALAPPDATA redirected): both builds honor the seams.
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    const std::wstring sandbox = std::wstring(temp) + L"virule-environment-test-sandbox";
    SetEnvironmentVariableW(L"LOCALAPPDATA", sandbox.c_str());
    check("sandbox: the run is redirected", vclient::paths::environment_redirected());
    check("sandbox: seams honored in either build", ds::allowed());
    {
        const ds::Seams s = parse(all_seams, ds::allowed());
        check("sandbox: every seam honored",
              s.dev_unsigned && s.self_manifest_url == L"http://127.0.0.1:1/m.json" &&
                  s.admin_manifest_url == L"http://localhost:2/a.json" &&
                  s.account_endpoint == L"http://127.0.0.1:3" && s.ignored == 0);
        check("sandbox: residency forwards every loopback seam", forward_seams(all_seams) == all_forwarded);
    }

    // Where honored, the values must still be loopback.
    {
        const ds::Seams s = parse({ L"exe", L"--self-manifest-url=https://evil.example/m.json",
                                    L"--admin-manifest-url=http://example.com/a.json",
                                    L"--account-endpoint=http://localhost:3",
                                    L"--self-manifest-url=http://127.0.0.1:1/m json" }, true);
        check("a non-loopback manifest url is refused even where seams are honored",
              s.self_manifest_url.empty() && s.admin_manifest_url.empty());
        check("the account endpoint stays 127.0.0.1 only", s.account_endpoint.empty());
        check("every refused value is counted as ignored", s.ignored == 4);
        check("a non-loopback manifest url is never forwarded",
              forward_seams({ L"exe", L"--self-manifest-url=https://evil.example/m.json",
                              L"--admin-manifest-url=http://example.com/a.json" }).empty());
    }
    check("--no-register is never an ignored seam", parse({ L"exe", L"--no-register" }, false).ignored == 0);

    SetEnvironmentVariableW(L"LOCALAPPDATA", saved_n ? saved : nullptr);

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
