#pragma once
// THIS COMPUTER'S READINESS TO BUY AN EVALUATION: THE ONE RULE (owner
// decision 2026-11-02, VIRULE/docs/specs/evaluation-security.md "Purchase
// preflight"; decision 15 of 2026-10-31). The VIRULE Client is the single
// local authority for it: the Admin asks the Client (bridge message
// `evaluation_purchase_readiness`) and only shows the answer, and the
// Client decides it again itself, immediately before it would authorize
// and send a purchase (client/account.hpp api_call). There is no second
// implementation anywhere.
//
// A purchase needs, NOW,
//
//   1. Windows 10 or later: the ONE Windows rule, shared/os_support.hpp
//      (the rule Setup enforces), read the same way (RtlGetVersion), and
//   2. a trusted scan that can run here: EXACTLY the scanning law the scan
//      itself uses, malware_scan::scanning_availability() (Defender active
//      and current with its service and tool, or, where another antivirus
//      replaces Defender, an explicitly validated AMSI provider). No second
//      detector: an antivirus Windows reports installed is not a supported
//      one, and the shipped AMSI allowlist is empty.
//
// LOCAL ONLY. Nothing here is sent to the service; the service has no proof
// of this computer's state (no attestation in this MVP). The answer carries
// a reason code and a sentence; the technical detail stays in the Client
// log.
//
// decide() is pure (tests/purchase_readiness); current() reads this
// computer.

#include <string>

#include "shared/os_support.hpp"
#include "virule/core/malware_scan.hpp"

namespace vclient::purchase_readiness {

namespace ms = virule::core::malware_scan;
namespace os = vclient::os_support;

enum class Blocker {
    none,
    unsupported_windows,     // Windows 8.1 or earlier
    defender_off,            // no antivirus on, or Defender's service or scanner missing
    defender_out_of_date,    // Defender on, its security intelligence out of date
    antivirus_unsupported,   // another antivirus replaces Defender (or Defender passive) and no validated AMSI provider
};

inline const char* blocker_name(Blocker b) {
    switch (b) {
        case Blocker::none: return "supported";
        case Blocker::unsupported_windows: return "unsupported_windows";
        case Blocker::defender_off: return "defender_off";
        case Blocker::defender_out_of_date: return "defender_out_of_date";
        case Blocker::antivirus_unsupported: return "antivirus_unsupported";
    }
    return "antivirus_unsupported";
}

/** The one sentence a blocked purchase states (no em dash). All four are
 *  the owner's: Windows (os_support.hpp, brief 2026-10-31), the three
 *  antivirus sentences approved 2026-11-02. */
inline std::string sentence(Blocker b) {
    switch (b) {
        case Blocker::none: return {};
        case Blocker::unsupported_windows: {
            std::string s;   // os_support's sentence is ASCII
            for (const wchar_t* p = os::kUnsupportedSentence; *p; ++p) s += static_cast<char>(*p);
            return s;
        }
        case Blocker::defender_off: return "This computer can't verify games because Microsoft Defender Antivirus is off. Turn it on in Windows Security.";
        case Blocker::defender_out_of_date: return "This computer can't verify games because Microsoft Defender Antivirus needs an update. Update it in Windows Security.";
        case Blocker::antivirus_unsupported: break;
    }
    return "This computer can't verify games with the current antivirus configuration. Microsoft Defender Antivirus is recommended.";
}

struct Readiness {
    Blocker blocker = Blocker::antivirus_unsupported;
    std::string message;
    std::string detail;   // technical, for the Client log only; never answered
    bool ready() const { return blocker == Blocker::none; }
};

/**
 * THE DECISION (pure; tested). `scanning` is what scanning_availability()
 * answered on this computer. Usable means a trusted scan can run: ready.
 * Otherwise its reason names the blocker; anything not recognized fails
 * closed as an unsupported configuration.
 */
inline Readiness decide(const os::WindowsVersion& v, const ms::Availability& scanning) {
    Readiness r;
    if (!os::is_supported(v)) {
        r.blocker = Blocker::unsupported_windows;
        r.detail = "Windows " + std::to_string(v.major) + "." + std::to_string(v.minor) + "." + std::to_string(v.build);
    } else if (scanning.usable) {
        r.blocker = Blocker::none;
    } else {
        switch (scanning.why) {
            case ms::Unavailable::off: r.blocker = Blocker::defender_off; break;
            case ms::Unavailable::out_of_date: r.blocker = Blocker::defender_out_of_date; break;
            default: r.blocker = Blocker::antivirus_unsupported; break;
        }
        r.detail = scanning.reason;
    }
    r.message = sentence(r.blocker);
    return r;
}

/** STAGING-BUILD-ONLY test seam (--test-purchase-blocker=<reason>,
 *  client/main.cpp; tools/purchase_enforcement_test.mjs): a blocker this
 *  run reports on top of the real answer. It can only REFUSE: it never
 *  makes a computer ready that is not, so it cannot weaken the rule.
 *  Ignored in production. */
inline Blocker& forced_blocker() {
    static Blocker b = Blocker::none;
    return b;
}

/** This computer, now (header). An unsupported Windows asks no scanner. */
inline Readiness current() {
    const os::WindowsVersion v = os::current_windows();
    Readiness r = os::is_supported(v) ? decide(v, ms::scanning_availability()) : decide(v, ms::Availability{});
    if (r.ready() && forced_blocker() != Blocker::none) {
        r.blocker = forced_blocker();
        r.message = sentence(r.blocker);
        r.detail = "test seam";
    }
    return r;
}

/** The seam's reason code, as blocker_name() spells it; none otherwise. */
inline Blocker blocker_of(const std::string& name) {
    for (const Blocker b : { Blocker::unsupported_windows, Blocker::defender_off, Blocker::defender_out_of_date,
                             Blocker::antivirus_unsupported }) {
        if (name == blocker_name(b)) return b;
    }
    return Blocker::none;
}

/** The bridge answer: {"type","ready","reason","message"}. No product
 *  names, paths, versions or technical detail leave the Client. */
inline std::string to_json(const Readiness& r) {
    return std::string("{\"type\":\"evaluation_purchase_readiness\",\"ready\":") + (r.ready() ? "true" : "false") +
           ",\"reason\":" + ms::json_quote(blocker_name(r.blocker)) + ",\"message\":" + ms::json_quote(r.message) + "}";
}

} // namespace vclient::purchase_readiness
