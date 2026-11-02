// THIS COMPUTER'S READINESS TO BUY AN EVALUATION: the Client's ONE rule
// (owner decision 2026-11-02; shared/evaluation_purchase_readiness.hpp),
// moved here from the Admin host, which no longer decides it.
//
// The pure decision over every state the purchase must tell apart, fed the
// Windows version (shared/os_support.hpp, the one Windows rule) and the
// scanning law's own answer (malware_scan::Availability, what
// scanning_availability() returns), so no antivirus is changed and no
// malware file is used: this is availability, not a scan. The AMSI cases use
// the provider policy the AMSI path itself decides with (amsi_scan.hpp
// decide_before_scan, what availability() consults). Then the staging test
// seam (it can only refuse), then this computer, read for real.
//
// THE SENTENCES are the owner's (Windows 2026-10-31; the three antivirus
// sentences approved 2026-11-02): compared verbatim so a change is made
// deliberately, in the header and its authority (evaluation-security.md)
// together.
//
// Build + run: tests\purchase_readiness\run_tests.bat (cl, x64). Exit 0 ==
// every check passed.

#include <cstdio>
#include <string>

#include "shared/evaluation_purchase_readiness.hpp"

namespace er = vclient::purchase_readiness;
namespace osv = vclient::os_support;
namespace ms = virule::core::malware_scan;
namespace as = virule::core::amsi_scan;

static int g_pass = 0, g_fail = 0;
static void check(const char* name, bool ok) {
    if (ok) { ++g_pass; std::printf("PASS %s\n", name); }
    else { ++g_fail; std::printf("FAIL %s\n", name); }
}

static osv::WindowsVersion win(unsigned long major, unsigned long minor, unsigned long build) {
    osv::WindowsVersion v;
    v.known = true;
    v.major = major;
    v.minor = minor;
    v.build = build;
    return v;
}

static ms::Availability usable() {
    ms::Availability a;
    a.usable = true;
    a.why = ms::Unavailable::none;
    return a;
}

static ms::Availability unusable(ms::Unavailable why, const char* reason) {
    ms::Availability a;
    a.usable = false;
    a.why = why;
    a.reason = reason;
    return a;
}

static bool no_em_dash(const std::string& s) { return s.find("\xE2\x80\x94") == std::string::npos; }

int main() {
    const osv::WindowsVersion win10 = win(10, 0, 19045), win11 = win(10, 0, 26100);

    // ---- Windows -------------------------------------------------------
    for (const auto& v : { win(6, 1, 7601), win(6, 2, 9200), win(6, 3, 9600), win(5, 1, 2600) }) {
        const er::Readiness r = er::decide(v, usable());
        check("Windows 8.1 and earlier: the purchase cannot complete, even with a usable scanner",
              !r.ready() && r.blocker == er::Blocker::unsupported_windows);
        check("...with the owner's sentence", r.message == "VIRULE requires Windows 10 or later.");
    }
    check("Windows 10: proceeds to the scanner's answer", er::decide(win10, usable()).ready());
    check("Windows 11: proceeds to the scanner's answer", er::decide(win11, usable()).ready());
    check("Windows 10 still needs the scanner: no scanner, no purchase",
          !er::decide(win10, unusable(ms::Unavailable::off, "No antivirus is active.")).ready());
    {
        osv::WindowsVersion unknown;   // known = false
        check("an unreadable version is not taken for an old Windows (the scanner decides)",
              er::decide(unknown, usable()).ready() &&
                  er::decide(unknown, unusable(ms::Unavailable::off, "x")).blocker == er::Blocker::defender_off);
    }

    // ---- Defender ------------------------------------------------------
    {
        const er::Readiness r = er::decide(win10, usable());
        check("healthy Defender: the purchase may proceed", r.ready() && r.message.empty());
    }
    {
        const er::Readiness r = er::decide(win10, unusable(ms::Unavailable::off, "No antivirus is active."));
        check("Defender off (no antivirus on): blocked as defender_off", !r.ready() && r.blocker == er::Blocker::defender_off);
        check("...turn it on in Windows Security",
              r.message == "This computer can't verify games because Microsoft Defender Antivirus is off. Turn it on in Windows Security.");
    }
    for (const char* reason : { "Windows Security Center is not available.",
                                "The Microsoft Defender Antivirus service is not running.",
                                "The Microsoft Defender Antivirus scanner was not found." }) {
        check("Defender unavailable (security center, service or scanner missing): blocked as defender_off",
              er::decide(win10, unusable(ms::Unavailable::off, reason)).blocker == er::Blocker::defender_off);
    }
    {
        const er::Readiness r = er::decide(win10, unusable(ms::Unavailable::out_of_date,
                                                          "Microsoft Defender Antivirus security intelligence is out of date."));
        check("Defender out of date: blocked as defender_out_of_date", !r.ready() && r.blocker == er::Blocker::defender_out_of_date);
        check("...update it in Windows Security",
              r.message == "This computer can't verify games because Microsoft Defender Antivirus needs an update. Update it in Windows Security.");
    }
    {
        const er::Readiness r = er::decide(win10, unusable(ms::Unavailable::other_antivirus, "Microsoft Defender Antivirus is in passive mode."));
        check("Defender passive: blocked as an unsupported configuration", !r.ready() && r.blocker == er::Blocker::antivirus_unsupported);
    }

    // ---- Another antivirus ---------------------------------------------
    {
        // What scanning_availability() answers when another antivirus is on
        // and the AMSI path is not usable (no, several, unsigned, unknown or
        // denied providers): Defender's own other_antivirus, unchanged.
        const er::Readiness r = er::decide(win10, unusable(ms::Unavailable::other_antivirus,
                                                          "Another antivirus is active; Microsoft Defender Antivirus is not."));
        check("another antivirus, no approved AMSI provider: blocked", !r.ready() && r.blocker == er::Blocker::antivirus_unsupported);
        check("...recommends Microsoft Defender and never asks to disable anything",
              r.message == "This computer can't verify games with the current antivirus configuration. Microsoft Defender Antivirus is recommended." &&
                  r.message.find("isable") == std::string::npos);
    }
    {
        // The AMSI path's own verdicts, as availability() decides them.
        as::Identity id;
        id.clsid = "{11111111-2222-3333-4444-555555555555}";
        id.signer = "Example Antivirus Vendor";
        id.signature_valid = true;
        id.version_known = true;
        id.file_version.part[0] = 5;
        const as::Policy shipped = as::shipped_policy();
        check("the shipped allowlist is empty: no real third-party provider is claimed supported",
              shipped.allow.empty() && shipped.deny.empty());
        check("an unknown provider is not usable (unknown = unsupported)",
              as::decide_before_scan(shipped, id) == as::Verdict::unknown);
        as::Policy approved;
        as::PolicyEntry e;
        e.clsid = id.clsid;
        e.signer = id.signer;
        e.display_name = "Example Antivirus";
        e.min_version.part[0] = 5;
        e.evidence = "test record";
        approved.allow.push_back(e);
        check("an explicitly approved provider in its qualified range is allowed",
              as::decide_before_scan(approved, id) == as::Verdict::allowed);
        as::Policy denied = approved;
        denied.deny.push_back(e);
        check("a denied provider is refused even when also allowlisted (the denylist wins)",
              as::decide_before_scan(denied, id) == as::Verdict::denied);
        as::Identity unsigned_id = id;
        unsigned_id.signature_valid = false;
        check("an unsigned provider is never allowed", as::decide_before_scan(approved, unsigned_id) != as::Verdict::allowed);
        as::Identity old_id = id;
        old_id.file_version.part[0] = 4;
        check("a version outside the qualified range is not allowed", as::decide_before_scan(approved, old_id) == as::Verdict::unknown);
        // An allowed, usable AMSI provider is what scanning_availability()
        // turns into usable (why none): the preflight accepts it.
        check("an approved, usable AMSI provider: accepted by the preflight", er::decide(win10, usable()).ready());
    }
    {
        ms::Availability odd = unusable(static_cast<ms::Unavailable>(99), "unrecognized");
        check("an unrecognized reason fails closed", er::decide(win10, odd).blocker == er::Blocker::antivirus_unsupported);
    }

    // ---- The sentences and the bridge answer ---------------------------
    for (const auto b : { er::Blocker::unsupported_windows, er::Blocker::defender_off, er::Blocker::defender_out_of_date,
                          er::Blocker::antivirus_unsupported }) {
        check("every blocked sentence is present and has no em dash", !er::sentence(b).empty() && no_em_dash(er::sentence(b)));
    }
    {
        const er::Readiness r = er::decide(win10, unusable(ms::Unavailable::other_antivirus, "Active: Example Antivirus."));
        const std::string j = er::to_json(r);
        check("the bridge answer names the reason and the sentence",
              j == "{\"type\":\"evaluation_purchase_readiness\",\"ready\":false,\"reason\":\"antivirus_unsupported\",\"message\":\"" + r.message + "\"}");
        check("...and no product name or technical detail", j.find("Example") == std::string::npos);
        check("a ready answer", er::to_json(er::decide(win11, usable())) == "{\"type\":\"evaluation_purchase_readiness\",\"ready\":true,\"reason\":\"supported\",\"message\":\"\"}");
    }

    // ---- The staging test seam: it can only refuse ---------------------
    {
        check("the seam's names are the reason codes", er::blocker_of("defender_off") == er::Blocker::defender_off &&
              er::blocker_of("unsupported_windows") == er::Blocker::unsupported_windows &&
              er::blocker_of("defender_out_of_date") == er::Blocker::defender_out_of_date &&
              er::blocker_of("antivirus_unsupported") == er::Blocker::antivirus_unsupported);
        check("the seam cannot name ready", er::blocker_of("supported") == er::Blocker::none && er::blocker_of("") == er::Blocker::none);
        const er::Readiness live = er::current();
        er::forced_blocker() = er::Blocker::defender_out_of_date;
        const er::Readiness forced = er::current();
        er::forced_blocker() = er::Blocker::none;
        check("a forced blocker refuses with its own sentence",
              !forced.ready() && (live.ready() ? forced.blocker == er::Blocker::defender_out_of_date &&
                                                     forced.message == er::sentence(er::Blocker::defender_out_of_date)
                                               : forced.blocker == live.blocker));
        check("with no forced blocker the live answer is untouched", er::current().blocker == live.blocker);
    }

    // ---- This computer -------------------------------------------------
    {
        const osv::WindowsVersion v = osv::current_windows();
        std::printf("this computer: Windows %lu.%lu.%lu (known %d)\n", v.major, v.minor, v.build, v.known ? 1 : 0);
        check("this computer's real version is read (not the manifest's 6.2)", v.known && v.major >= 10);
        const ms::Availability a = ms::scanning_availability();
        const er::Readiness r = er::current();
        std::printf("this computer: scanning usable %d (%s); readiness %s %s\n", a.usable ? 1 : 0, a.reason.c_str(),
                    er::blocker_name(r.blocker), er::to_json(r).c_str());
        check("this computer: the live answer is the decision over the live scanning law",
              r.blocker == er::decide(v, a).blocker);
    }

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
