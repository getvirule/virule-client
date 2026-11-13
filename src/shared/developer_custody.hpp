#pragma once
// DEVELOPER KEY CUSTODY (owner brief 2026-11-12, "Owner-Directed Completion
// Assignment", section 6: the PRESERVE half of optional account-based
// recovery; the service's half is VIRULE_BACKEND src/auth/oauth.ts
// developerCustody, migration 0037, docs/ACCOUNTS.md "Developer key
// custody"; docs/ARCHITECTURE.md "VIRULE account").
//
// While a developer is signed in here, this Client proves this computer's
// Developer Machine key (dev_machine.cred, machine_identity.hpp) to the
// service ONCE per (account, machine key), so the account holds a proven
// record of it made BEFORE the computer can be lost:
//
//   POST /v1/account/developer-custody   (this installation's DPoP authorization)
//   {machine_key, timestamp, machine_signature} over
//   virule-developer-custody.v1|<API host>|<device id>|<machine key>|<timestamp>
//
// the developer machine binding's grammar (machine_proof.hpp): the API host
// the request goes to and this installation's device authorization.
//
// WHEN: signed in, the account ACTIVE with the ACTIVE developer capability
// (the service's last confirmed snapshot; the service re-checks), the
// snapshot names the device and the account hint, and a USABLE credential
// already exists. Never creates a credential for this (machine_identity
// sign_hex/public_key_hex only read one). A sandboxed Client (LOCALAPPDATA
// redirected, no --account-endpoint test service) never calls the real
// service: the check-in's rule (admin_install.hpp checkin_suppressed).
//
// THE RECORD (%LOCALAPPDATA%\VIRULE\client\developer_custody.json, no
// secret: the opaque account hint, the public key, the outcome):
//   registered | held      the service holds this key for this account; never sent again
//   held_elsewhere         409 custody_held_elsewhere: another account holds the
//                          key; recorded, never retried (whether VIRULE Desktop
//                          shows it is PENDING OWNER DECISION)
//   (no outcome)           not settled yet: `failures` and `next_attempt` place it on
//                          the retry ladder (the evidence delivery's steps,
//                          evidence_queue.hpp kBackoffLadder)
// Removed with the client state directory by every uninstall; a later
// registration is then answered `held` (idempotent at the service).
//
// IT AUTHORIZES NOTHING, here or at the service. Pure apart from the record
// file: the signing and the sending are injected (client/account.hpp
// deliver_custody_locked), which is what lets the whole exchange be tested
// without a credential, a network or the bridge port.

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#include "shared/json_scan.hpp"

namespace vclient::developer_custody {

inline constexpr const char* kRoute = "/v1/account/developer-custody";
inline constexpr const char* kFileName = "developer_custody.json";
// The retry ladder (seconds; the last step repeats), the evidence delivery's.
inline constexpr std::int64_t kLadder[] = { 10, 60, 300, 900, 1800 };
inline constexpr std::int64_t kLadderCap = 1800;
inline constexpr size_t kMaxEntries = 32;

inline bool is_hex(const std::string& s, size_t n) {
    if (s.size() != n) return false;
    for (const char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

inline std::string message(const std::string& host, const std::string& device_id,
                           const std::string& machine_key, const std::string& timestamp) {
    return "virule-developer-custody.v1|" + host + "|" + device_id + "|" + machine_key + "|" + timestamp;
}

inline std::string body(const std::string& machine_key, const std::string& timestamp, const std::string& signature) {
    return "{\"machine_key\":\"" + machine_key + "\",\"timestamp\":\"" + timestamp + "\",\"machine_signature\":\"" + signature + "\"}";
}

/** The service's canonical UTC instant: YYYY-MM-DDTHH:MM:SSZ. */
inline std::string canonical_utc(std::time_t t) {
    std::tm g{};
#if defined(_WIN32)
    gmtime_s(&g, &t);
#else
    gmtime_r(&t, &g);
#endif
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &g);
    return ts;
}

inline std::int64_t backoff_seconds(std::int64_t failures) {
    const std::int64_t steps = (std::int64_t)(sizeof(kLadder) / sizeof(kLadder[0]));
    if (failures <= 0) return kLadder[0];
    return kLadder[std::min<std::int64_t>(failures - 1, steps - 1)];
}

// ------------------------------------------------------------- the record --

struct Entry {
    std::string account;      // the service's opaque account hint (32 hex)
    std::string machine_key;  // 64 hex
    std::string outcome;      // "registered" | "held" | "held_elsewhere" | "" (unsettled)
    std::int64_t failures = 0;
    std::int64_t next_attempt = 0; // epoch seconds
    std::int64_t updated = 0;      // epoch seconds
};

struct Record {
    std::vector<Entry> entries;
};

inline bool settled(const Entry& e) {
    return e.outcome == "registered" || e.outcome == "held" || e.outcome == "held_elsewhere";
}

inline Entry* find(Record& r, const std::string& account, const std::string& key) {
    for (auto& e : r.entries) if (e.account == account && e.machine_key == key) return &e;
    return nullptr;
}
inline const Entry* find(const Record& r, const std::string& account, const std::string& key) {
    for (const auto& e : r.entries) if (e.account == account && e.machine_key == key) return &e;
    return nullptr;
}

inline std::mutex& file_mutex() {
    static std::mutex m;
    return m;
}

inline Record parse(const std::string& t) {
    Record r;
    const size_t list = t.find("\"entries\":[");
    if (list == std::string::npos) return r;
    size_t i = list;
    while (r.entries.size() < kMaxEntries) {
        const size_t b = t.find('{', i);
        if (b == std::string::npos) break;
        const size_t e = t.find('}', b);
        if (e == std::string::npos) break;
        Entry x;
        long long n = 0;
        (void)json_scan::find_string_in(t, b, e, "account", x.account);
        (void)json_scan::find_string_in(t, b, e, "machine_key", x.machine_key);
        (void)json_scan::find_string_in(t, b, e, "outcome", x.outcome);
        if (json_scan::find_number_in(t, b, e, "failures", n)) x.failures = n;
        if (json_scan::find_number_in(t, b, e, "next_attempt", n)) x.next_attempt = n;
        if (json_scan::find_number_in(t, b, e, "updated", n)) x.updated = n;
        if (is_hex(x.account, 32) && is_hex(x.machine_key, 64) &&
            (x.outcome.empty() || settled(x))) {
            r.entries.push_back(x);
        }
        i = e + 1;
    }
    return r;
}

inline std::string serialize(const Record& r) {
    std::string s = "{\"version\":1,\"entries\":[";
    for (size_t i = 0; i < r.entries.size(); ++i) {
        const Entry& e = r.entries[i];
        if (i) s += ",";
        s += "{\"account\":\"" + e.account + "\",\"machine_key\":\"" + e.machine_key + "\",\"outcome\":\"" + e.outcome +
             "\",\"failures\":" + std::to_string(e.failures) + ",\"next_attempt\":" + std::to_string(e.next_attempt) +
             ",\"updated\":" + std::to_string(e.updated) + "}";
    }
    return s + "]}";
}

inline Record load(const std::filesystem::path& f) {
    if (f.empty()) return {};
    std::ifstream in(f, std::ios::binary);
    if (!in) return {};
    const std::string t((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return parse(t);
}

inline bool save(const std::filesystem::path& f, Record r) {
    if (f.empty()) return false;
    // Bounded: the oldest entries go first (settled or not, they are
    // re-learned from the service's idempotent answer).
    if (r.entries.size() > kMaxEntries) {
        std::stable_sort(r.entries.begin(), r.entries.end(),
                         [](const Entry& a, const Entry& b) { return a.updated > b.updated; });
        r.entries.resize(kMaxEntries);
    }
    std::error_code ec;
    std::filesystem::create_directories(f.parent_path(), ec);
    const auto tmp = f.parent_path() / (f.filename().wstring() + L".tmp");
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        const std::string body = serialize(r);
        out.write(body.data(), (std::streamsize)body.size());
        if (!out.good()) return false;
    }
    ec.clear();
    std::filesystem::rename(tmp, f, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
}

// ----------------------------------------------------------- the decision --

struct Inputs {
    bool suppressed = false;      // sandboxed (redirected) without a test service
    bool signed_in = false;
    std::string account_status;   // the snapshot's: must be "active"
    std::string cap_developer;    // the snapshot's: must be "active"
    std::string account_hint;     // 32 hex
    std::string device_id;        // 32 hex
};

enum class Decision {
    send,           // an attempt goes now
    suppressed,     // a sandboxed run: never the real service
    signed_out,
    not_developer,  // account not active, or no active developer capability
    no_context,     // the snapshot does not name the device or the account yet
    no_credential,  // no usable dev_machine.cred (never created for this)
    settled,        // this (account, key) is already answered for good
    waiting,        // on the retry ladder
};

inline const char* name(Decision d) {
    switch (d) {
    case Decision::send: return "send";
    case Decision::suppressed: return "suppressed";
    case Decision::signed_out: return "signed_out";
    case Decision::not_developer: return "not_developer";
    case Decision::no_context: return "no_context";
    case Decision::no_credential: return "no_credential";
    case Decision::settled: return "settled";
    case Decision::waiting: return "waiting";
    }
    return "?";
}

/** Whether an attempt goes now for `machine_key` (64 hex, "" = no usable
 *  credential). */
inline Decision decide(const Inputs& in, const std::string& machine_key, const Record& r, std::int64_t now) {
    if (in.suppressed) return Decision::suppressed;
    if (!in.signed_in) return Decision::signed_out;
    if (in.account_status != "active" || in.cap_developer != "active") return Decision::not_developer;
    if (!is_hex(in.account_hint, 32) || in.device_id.empty()) return Decision::no_context;
    if (!is_hex(machine_key, 64)) return Decision::no_credential;
    const Entry* e = find(r, in.account_hint, machine_key);
    if (e && settled(*e)) return Decision::settled;
    // A clock moved back far past the ladder's cap does not strand it.
    if (e && e->next_attempt > now && e->next_attempt - now <= kLadderCap) return Decision::waiting;
    return Decision::send;
}

/** Record the service's answer. 200 {custody:"registered"|"held"}: settled.
 *  409 custody_held_elsewhere: settled as held_elsewhere, never retried.
 *  Anything else (no answer, 5xx, 429, a refusal such as clock_skew or a
 *  capability the service no longer confirms): the next ladder step. */
inline void apply_answer(Record& r, const std::string& account, const std::string& key,
                         unsigned long status, const std::string& reply, std::int64_t now) {
    Entry* e = find(r, account, key);
    if (!e) {
        r.entries.push_back(Entry{ account, key, "", 0, 0, now });
        e = &r.entries.back();
    }
    e->updated = now;
    std::string custody;
    if (status == 200 && json_scan::find_string_in(reply, 0, reply.size(), "custody", custody) &&
        (custody == "registered" || custody == "held")) {
        e->outcome = custody;
        e->failures = 0;
        e->next_attempt = 0;
        return;
    }
    if (status == 409 && reply.find("\"custody_held_elsewhere\"") != std::string::npos) {
        e->outcome = "held_elsewhere";
        e->failures = 0;
        e->next_attempt = 0;
        return;
    }
    e->failures += 1;
    e->next_attempt = now + backoff_seconds(e->failures);
}

// -------------------------------------------------------------- one pass --

struct Reply {
    unsigned long status = 0; // 0 = no HTTP answer
    std::string body;
};

struct Deps {
    std::filesystem::path file;                                   // the record
    std::function<std::string()> machine_key;                     // "" = no usable credential (never creates one)
    std::function<std::string(const std::string&)> sign_hex;      // by the machine key; "" = failed
    std::function<Reply(const std::string& body)> send;           // POST kRoute under the DPoP authorization
    std::string host;                                             // the API host the request goes to
    std::int64_t now = 0;                                         // epoch seconds
    std::function<void(const std::string&)> log;
};

/** One delivery pass: decide, sign, send, record. Returns the decision
 *  (send = an attempt was made). Never touches the network unless send. */
inline Decision run(const Inputs& in, Deps& d) {
    // The gates that need no file or credential first: a sandboxed,
    // signed-out or non-developer run reads nothing.
    if (in.suppressed) return Decision::suppressed;
    if (!in.signed_in) return Decision::signed_out;
    if (in.account_status != "active" || in.cap_developer != "active") return Decision::not_developer;
    if (!is_hex(in.account_hint, 32) || in.device_id.empty()) return Decision::no_context;
    const std::string key = d.machine_key ? d.machine_key() : std::string();
    std::lock_guard<std::mutex> lock(file_mutex());
    Record r = load(d.file);
    const Decision dec = decide(in, key, r, d.now);
    if (dec != Decision::send) return dec;
    const std::string ts = canonical_utc((std::time_t)d.now);
    const std::string sig = d.sign_hex ? d.sign_hex(message(d.host, in.device_id, key, ts)) : std::string();
    if (!is_hex(sig, 128)) return Decision::no_credential;
    const Reply reply = d.send ? d.send(body(key, ts, sig)) : Reply{};
    apply_answer(r, in.account_hint, key, reply.status, reply.body, d.now);
    const Entry* e = find(r, in.account_hint, key);
    if (d.log) {
        d.log(std::string("account: developer key custody: ") +
              (e && !e->outcome.empty() ? e->outcome : "retry later (" + std::to_string(reply.status) + ")"));
    }
    if (!save(d.file, r) && d.log) d.log("account: developer key custody: could not persist the record");
    return dec;
}

} // namespace vclient::developer_custody
