#pragma once
// THE ONE DESKTOP UPDATE RULE: when an approved VIRULE Desktop (Admin)
// release is an update for the installed one. Pure (no IO, no globals), so
// tests/admin_version exercises exactly what the Client runs. Every Desktop
// update decision in the Client goes through `update_wanted`
// (admin_install.hpp: update_claim, the launch handoff's re-check;
// takeover.hpp: the "already current" short-circuit); the website applies the
// same rule to the same manifest (v1_mvp_site src/client/semver.ts
// updateWanted).
//
// SEMANTIC VERSION ORDERING (owner correction 2026-09-04, mirroring the
// site's fix): the approved version is offered and installed when it is a
// genuine UPGRADE over the installed one. An installed Desktop NEWER than the
// approved manifest is never moved to it by that ordering alone: no arbitrary
// downgrade.
//
// THE OPERATOR ROLLBACK (owner ruling 2026-11-13,
// VIRULE/docs/scratchpads/OWNER_ROLLBACK_PULLBACK_RULING_2026-11-13.md): an
// operator-initiated rollback also updates Desktops that ALREADY installed the
// withdrawn version, through the ordinary update paths (application restart,
// Settings, the website) and looking exactly like a normal update. The signal
// is the manifest's `withdrawn` list, written ONLY by the operator rollback
// (v2_mvp/helpers/release_rollback.ps1) and absent from every forward release:
// an installed version EXACTLY listed there takes the approved release as its
// update. Nothing else moves an installed Desktop to an older version, and
// nothing about the install itself changes: the package must still pass the
// pinned release url prefix, the exact size, the exact SHA-256 and the VIRULE
// Authenticode identity (admin_install.hpp run_pipeline).
//
// Grammar: MAJOR.MINOR.PATCH with an optional pre-release suffix
// ("0.1.1-alpha.17"). Standard SemVer precedence: the numeric triple, then
// no-pre-release outranks pre-release, then pre-release identifiers field by
// field (numeric identifiers numerically, and lower than alphanumeric ones).

#include <string>
#include <vector>

namespace vclient::admin_install {

inline bool is_version_grammar(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    for (const char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

inline int compare_prerelease(const std::string& a, const std::string& b) {
    if (a.empty() && b.empty()) return 0;
    if (a.empty()) return 1;  // a release outranks any pre-release
    if (b.empty()) return -1;
    size_t pa = 0, pb = 0;
    for (;;) {
        const bool more_a = pa < a.size();
        const bool more_b = pb < b.size();
        if (!more_a && !more_b) return 0;
        if (!more_a) return -1; // fewer identifiers ranks lower
        if (!more_b) return 1;
        const size_t ea = a.find('.', pa);
        const size_t eb = b.find('.', pb);
        const std::string ia = a.substr(pa, (ea == std::string::npos ? a.size() : ea) - pa);
        const std::string ib = b.substr(pb, (eb == std::string::npos ? b.size() : eb) - pb);
        const bool na = !ia.empty() &&
            ia.find_first_not_of("0123456789") == std::string::npos;
        const bool nb = !ib.empty() &&
            ib.find_first_not_of("0123456789") == std::string::npos;
        if (na && nb) {
            // Numerically, without converting: a 60-digit identifier (the
            // grammar allows it) must order, never throw (std::stoll would).
            const size_t za = ia.find_first_not_of('0');
            const size_t zb = ib.find_first_not_of('0');
            const std::string da = za == std::string::npos ? std::string() : ia.substr(za);
            const std::string db = zb == std::string::npos ? std::string() : ib.substr(zb);
            if (da.size() != db.size()) return da.size() < db.size() ? -1 : 1;
            if (da != db) return da < db ? -1 : 1;
        } else if (na != nb) {
            return na ? -1 : 1; // numeric identifiers rank lower
        } else if (ia != ib) {
            return ia < ib ? -1 : 1;
        }
        pa = (ea == std::string::npos) ? a.size() : ea + 1;
        pb = (eb == std::string::npos) ? b.size() : eb + 1;
    }
}

// "x.y.z..." -> the leading numeric triple (pre-release suffixes ignored).
inline bool parse_version_triple(const std::string& s, long long out[3]) {
    size_t p = 0;
    for (int i = 0; i < 3; ++i) {
        bool any = false;
        long long v = 0;
        while (p < s.size() && s[p] >= '0' && s[p] <= '9') {
            if (v > 100000000000LL) return false; // no overflow, no claim
            v = v * 10 + (s[p] - '0');
            ++p;
            any = true;
        }
        if (!any) return false;
        out[i] = v;
        if (i < 2) {
            if (p >= s.size() || s[p] != '.') return false;
            ++p;
        }
    }
    return true;
}

// True only when `approved` is a genuine upgrade over `installed`. An
// unparseable version never wins a comparison (no claim either way).
inline bool version_is_upgrade(const std::string& approved,
                               const std::string& installed) {
    long long ta[3] = {};
    long long tb[3] = {};
    if (!parse_version_triple(approved, ta)) return false;
    if (!parse_version_triple(installed, tb)) return false;
    for (int i = 0; i < 3; ++i) {
        if (ta[i] != tb[i]) return ta[i] > tb[i];
    }
    auto prerelease_of = [](const std::string& v) -> std::string {
        // The suffix after the numeric triple's '-', up to any '+' build
        // metadata; "" = a plain release.
        size_t p = 0;
        for (int i = 0; i < 3; ++i) {
            while (p < v.size() && v[p] >= '0' && v[p] <= '9') ++p;
            if (i < 2) { if (p >= v.size() || v[p] != '.') return ""; ++p; }
        }
        if (p >= v.size() || v[p] != '-') return "";
        std::string rest = v.substr(p + 1);
        const size_t plus = rest.find('+');
        if (plus != std::string::npos) rest.resize(plus);
        return rest;
    };
    return compare_prerelease(prerelease_of(approved), prerelease_of(installed)) > 0;
}

// The most versions one manifest may withdraw. A rollback writes the version
// it withdraws plus the earlier withdrawals and the approved releases between
// it and its target, which is a handful; the bound keeps a hostile or broken
// manifest from costing anything.
constexpr size_t kMaxWithdrawn = 32;

// The manifest's `withdrawn` list, read STRICTLY: `"withdrawn":[` then zero
// or more JSON strings, each in the version grammar, separated by commas,
// then `]` (whitespace allowed between tokens). Anything else (an escape, a
// non-string, a malformed version, more than kMaxWithdrawn entries, a missing
// bracket) makes the whole list EMPTY: a manifest that cannot be read exactly
// withdraws nothing, so it can only fall back to the ordinary upgrade rule.
// No field = empty (every forward release).
inline std::vector<std::string> parse_withdrawn(const std::string& body) {
    std::vector<std::string> out;
    static const std::string kMarker = "\"withdrawn\":";
    const size_t at = body.find(kMarker);
    if (at == std::string::npos) return out;
    // A second occurrence is ambiguous: withdraw nothing.
    if (body.find(kMarker, at + kMarker.size()) != std::string::npos) return {};
    size_t p = at + kMarker.size();
    auto skip_ws = [&]() {
        while (p < body.size() && (body[p] == ' ' || body[p] == '\t' ||
                                   body[p] == '\r' || body[p] == '\n')) ++p;
    };
    skip_ws();
    if (p >= body.size() || body[p] != '[') return {};
    ++p;
    skip_ws();
    if (p < body.size() && body[p] == ']') return out; // []
    for (;;) {
        skip_ws();
        if (p >= body.size() || body[p] != '"') return {};
        ++p;
        const size_t e = body.find('"', p);
        if (e == std::string::npos) return {};
        const std::string v = body.substr(p, e - p);
        if (!is_version_grammar(v)) return {}; // also refuses any backslash escape
        if (out.size() >= kMaxWithdrawn) return {};
        out.push_back(v);
        p = e + 1;
        skip_ws();
        if (p >= body.size()) return {};
        if (body[p] == ']') return out;
        if (body[p] != ',') return {};
        ++p;
    }
}

// THE RULE. The approved release is an update for the installed one when it
// is a genuine upgrade, or when the installed version is EXACTLY one the
// manifest withdrew (an operator rollback) and is not the approved version
// itself. Unknown or ungrammatical versions never make a claim.
inline bool update_wanted(const std::string& approved, const std::string& installed,
                          const std::vector<std::string>& withdrawn) {
    if (approved.empty() || installed.empty()) return false;
    if (!is_version_grammar(approved) || !is_version_grammar(installed)) return false;
    if (version_is_upgrade(approved, installed)) return true;
    if (installed == approved) return false;
    for (const auto& w : withdrawn) {
        if (w == installed) return true;
    }
    return false;
}

} // namespace vclient::admin_install
