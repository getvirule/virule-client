// Developer key custody (shared/developer_custody.hpp; owner brief
// 2026-11-12 section 6): the signed message bytes, the request body, the
// once-per-(account, machine key) record, the gates (sandboxed run, signed
// out, no developer role, no credential) and the answers (registered, held,
// 409 held elsewhere, failures on the retry ladder). The signing and the
// sending are injected fakes: no credential, no network, no bridge port.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "shared/developer_custody.hpp"

namespace dc = vclient::developer_custody;
namespace fs = std::filesystem;

static int g_pass = 0, g_fail = 0;
static void check(const std::string& name, bool ok) {
    if (ok) { ++g_pass; std::printf("ok   %s\n", name.c_str()); }
    else { ++g_fail; std::printf("FAIL %s\n", name.c_str()); }
}

static const std::string HINT_A = "0123456789abcdef0123456789abcdef";
static const std::string HINT_B = "fedcba9876543210fedcba9876543210";
static const std::string DEVICE = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb";
static const std::string KEY_1 = std::string(64, 'a');
static const std::string KEY_2 = std::string(64, 'b');
static const std::string SIG = std::string(128, 'c');
static const std::string HOST = "virule-api-staging.example.dev";

struct Fake {
    std::string key = KEY_1;
    bool sign_ok = true;
    dc::Reply answer{ 200, "{\"custody\":\"registered\"}" };
    int key_reads = 0, signs = 0, sends = 0;
    std::string signed_message, sent_body;
};

static dc::Inputs developer(const std::string& hint = HINT_A) {
    dc::Inputs in;
    in.signed_in = true;
    in.account_status = "active";
    in.cap_developer = "active";
    in.account_hint = hint;
    in.device_id = DEVICE;
    return in;
}

static dc::Deps deps(Fake& f, const fs::path& file, std::int64_t now) {
    dc::Deps d;
    d.file = file;
    d.machine_key = [&f] { ++f.key_reads; return f.key; };
    d.sign_hex = [&f](const std::string& m) { ++f.signs; f.signed_message = m; return f.sign_ok ? SIG : std::string(); };
    d.send = [&f](const std::string& b) { ++f.sends; f.sent_body = b; return f.answer; };
    d.host = HOST;
    d.now = now;
    return d;
}

int main() {
    const fs::path dir = fs::temp_directory_path() / ("virule-custody-test-" + std::to_string((long long)time(nullptr)));
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);
    int n = 0;
    auto fresh_file = [&] { return dir / ("custody_" + std::to_string(++n) + ".json"); };
    const std::int64_t T = 1794500000; // 2026-11-12T...

    // ---- the wire: exactly the service's grammar (oauth.ts developerCustodyMessage)
    check("the signed message bytes",
        dc::message(HOST, DEVICE, KEY_1, "2026-11-12T10:00:00Z") ==
        "virule-developer-custody.v1|" + HOST + "|" + DEVICE + "|" + KEY_1 + "|2026-11-12T10:00:00Z");
    check("the body carries the binding fields the service reads (readBindProof)",
        dc::body(KEY_1, "2026-11-12T10:00:00Z", SIG) ==
        "{\"machine_key\":\"" + KEY_1 + "\",\"timestamp\":\"2026-11-12T10:00:00Z\",\"machine_signature\":\"" + SIG + "\"}");
    check("the timestamp is the canonical UTC instant", dc::canonical_utc(0) == "1970-01-01T00:00:00Z");
    check("the route", std::string(dc::kRoute) == "/v1/account/developer-custody");

    // ---- one pass: what is signed is what is sent
    {
        Fake f;
        const fs::path file = fresh_file();
        dc::Deps d = deps(f, file, T);
        const auto r = dc::run(developer(), d);
        const std::string ts = dc::canonical_utc((std::time_t)T);
        check("a signed-in developer with a credential sends", r == dc::Decision::send && f.sends == 1);
        check("the machine key signs the custody message for this host, device, key and instant",
            f.signed_message == dc::message(HOST, DEVICE, KEY_1, ts));
        check("the body sent is that key, instant and signature", f.sent_body == dc::body(KEY_1, ts, SIG));
        const dc::Record rec = dc::load(file);
        const dc::Entry* e = dc::find(rec, HINT_A, KEY_1, DEVICE);
        check("success is remembered locally", e && e->outcome == "registered");
        std::ifstream in(file, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        check("the record holds no signature (no secret)", text.find(SIG) == std::string::npos);

        // ---- ONCE PER (account, machine key)
        Fake g;
        dc::Deps d2 = deps(g, file, T + 5);
        check("the same account and key is never sent again", dc::run(developer(), d2) == dc::Decision::settled && g.sends == 0 && g.signs == 0);
        Fake h;
        h.key = KEY_2;
        dc::Deps d3 = deps(h, file, T + 6);
        check("a new machine key for the same account is sent", dc::run(developer(), d3) == dc::Decision::send && h.sends == 1);
        Fake k;
        dc::Deps d4 = deps(k, file, T + 7);
        check("another account on the same key is sent (its own pair)", dc::run(developer(HINT_B), d4) == dc::Decision::send && k.sends == 1);
        Fake m;
        m.answer = { 200, "{\"custody\":\"held\"}" };
        const fs::path f2 = fresh_file();
        dc::Deps d5 = deps(m, f2, T);
        (void)dc::run(developer(), d5);
        const dc::Record r2 = dc::load(f2);
        check("`held` (already registered, e.g. after a reinstall) is remembered too",
            dc::find(r2, HINT_A, KEY_1, DEVICE) && dc::find(r2, HINT_A, KEY_1, DEVICE)->outcome == "held");
    }

    // ---- the gates: none of them signs, reads the credential or calls
    {
        auto none = [](const Fake& f) { return f.sends == 0 && f.signs == 0 && f.key_reads == 0; };
        {
            Fake f;
            const fs::path file = fresh_file();
            dc::Deps d = deps(f, file, T);
            dc::Inputs in = developer();
            in.suppressed = true;
            check("a sandboxed (redirected) run makes no network call", dc::run(in, d) == dc::Decision::suppressed && none(f) && !fs::exists(file));
        }
        {
            Fake f;
            dc::Deps d = deps(f, fresh_file(), T);
            dc::Inputs in = developer();
            in.signed_in = false;
            check("signed out: no call", dc::run(in, d) == dc::Decision::signed_out && none(f));
        }
        for (const char* cap : { "none", "pending", "revoked", "" }) {
            Fake f;
            dc::Deps d = deps(f, fresh_file(), T);
            dc::Inputs in = developer();
            in.cap_developer = cap;
            check(std::string("no developer role (") + (*cap ? cap : "unknown") + "): no call", dc::run(in, d) == dc::Decision::not_developer && none(f));
        }
        {
            Fake f;
            dc::Deps d = deps(f, fresh_file(), T);
            dc::Inputs in = developer();
            in.account_status = "restricted";
            check("an account that is not active: no call", dc::run(in, d) == dc::Decision::not_developer && none(f));
        }
        {
            Fake f;
            dc::Deps d = deps(f, fresh_file(), T);
            dc::Inputs in = developer();
            in.account_hint.clear();
            check("a snapshot without the account hint: no call", dc::run(in, d) == dc::Decision::no_context && none(f));
        }
        {
            Fake f;
            f.key = "";
            const fs::path file = fresh_file();
            dc::Deps d = deps(f, file, T);
            check("no usable credential: no call, nothing signed, nothing recorded",
                dc::run(developer(), d) == dc::Decision::no_credential && f.sends == 0 && f.signs == 0 && !fs::exists(file));
        }
        {
            Fake f;
            f.sign_ok = false;
            dc::Deps d = deps(f, fresh_file(), T);
            check("a signature that cannot be made: no call", dc::run(developer(), d) == dc::Decision::no_credential && f.sends == 0);
        }
    }

    // ---- 409: recorded, never retried
    {
        Fake f;
        f.answer = { 409, "{\"error\":{\"code\":\"custody_held_elsewhere\",\"message\":\"x\"}}" };
        const fs::path file = fresh_file();
        dc::Deps d = deps(f, file, T);
        (void)dc::run(developer(), d);
        const dc::Record rec = dc::load(file);
        check("a 409 custody_held_elsewhere is recorded (so the Desktop could show it)",
            dc::find(rec, HINT_A, KEY_1, DEVICE) && dc::find(rec, HINT_A, KEY_1, DEVICE)->outcome == "held_elsewhere");
        Fake g;
        dc::Deps d2 = deps(g, file, T + 100000);
        check("...and stops the retries for good", dc::run(developer(), d2) == dc::Decision::settled && g.sends == 0);
        Fake h;
        h.answer = { 409, "{\"error\":{\"code\":\"conflict\",\"message\":\"x\"}}" };
        const fs::path f2 = fresh_file();
        dc::Deps d3 = deps(h, f2, T);
        (void)dc::run(developer(), d3);
        check("a 409 that is not custody_held_elsewhere is not settled", !dc::settled(*dc::find(dc::load(f2), HINT_A, KEY_1, DEVICE)));
    }

    // ---- failures: the retry ladder
    {
        Fake f;
        f.answer = { 0, "" };
        const fs::path file = fresh_file();
        dc::Deps d = deps(f, file, T);
        (void)dc::run(developer(), d);
        const dc::Entry e1 = *dc::find(dc::load(file), HINT_A, KEY_1, DEVICE);
        check("no answer (offline) is not settled; next attempt after the first step", e1.outcome.empty() && e1.failures == 1 && e1.next_attempt == T + 10);
        Fake g;
        dc::Deps d2 = deps(g, file, T + 5);
        check("before the step: waits, no call", dc::run(developer(), d2) == dc::Decision::waiting && g.sends == 0);
        Fake h;
        h.answer = { 503, "" };
        dc::Deps d3 = deps(h, file, T + 10);
        check("at the step: tries again", dc::run(developer(), d3) == dc::Decision::send && h.sends == 1);
        const dc::Entry e2 = *dc::find(dc::load(file), HINT_A, KEY_1, DEVICE);
        check("a 5xx is the next step (60 s)", e2.failures == 2 && e2.next_attempt == T + 10 + 60);
        Fake c;
        c.answer = { 401, "{\"error\":{\"code\":\"clock_skew\",\"message\":\"x\"}}" };
        dc::Deps d4 = deps(c, file, T + 70);
        (void)dc::run(developer(), d4);
        const dc::Entry e3 = *dc::find(dc::load(file), HINT_A, KEY_1, DEVICE);
        check("a clock_skew refusal is the next step too", e3.failures == 3 && e3.next_attempt == T + 70 + 300);
        check("the ladder's last step repeats", dc::backoff_seconds(50) == 1800);
        Fake z;
        dc::Deps d5 = deps(z, file, T - 100000);
        check("a clock moved back far past the cap does not strand it", dc::run(developer(), d5) == dc::Decision::send && z.sends == 1);
        Fake ok;
        dc::Deps d6 = deps(ok, file, T + 100000);
        (void)dc::run(developer(), d6);
        const dc::Entry e4 = *dc::find(dc::load(file), HINT_A, KEY_1, DEVICE);
        check("a later success settles it and clears the ladder", e4.outcome == "registered" && e4.failures == 0);
    }

    // ---- the record file
    {
        const fs::path file = fresh_file();
        { std::ofstream o(file, std::ios::binary); o << "garbage {"; }
        check("an unreadable record is empty", dc::load(file).entries.empty());
        dc::Record r;
        r.entries.push_back(dc::Entry{ HINT_A, KEY_1, DEVICE, "registered", 0, 0, T });
        r.entries.push_back(dc::Entry{ HINT_B, KEY_2, DEVICE, "", 2, T + 60, T });
        r.entries.push_back(dc::Entry{ "nothex", KEY_2, DEVICE, "registered", 0, 0, T });
        check("the record saves", dc::save(file, r));
        const dc::Record back = dc::load(file);
        check("it reads back, malformed entries dropped", back.entries.size() == 2 &&
            back.entries[0].outcome == "registered" && back.entries[1].failures == 2 && back.entries[1].next_attempt == T + 60);
        check("a missing file is empty", dc::load(dir / "absent.json").entries.empty());
        check("the device authorization reads back", back.entries[0].device == DEVICE);
    }

    // ---- a NEW sign-in (a new device authorization) proves custody again,
    //      so the service records a proof fresh for the account's current
    //      security state (recovery after a password change); the same
    //      sign-in never repeats a settled answer.
    {
        dc::Record r;
        r.entries.push_back(dc::Entry{ HINT_A, KEY_1, DEVICE, "held", 0, 0, T });
        check("same device authorization, settled: not sent again",
            dc::decide(developer(), KEY_1, r, T) == dc::Decision::settled);
        dc::Inputs again = developer();
        again.device_id = "ccccccccccccccccdddddddddddddddd";
        check("a new device authorization: sent again",
            dc::decide(again, KEY_1, r, T) == dc::Decision::send);
    }

    fs::remove_all(dir, ec);
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
