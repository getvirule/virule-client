#pragma once
// EVALUATION EVIDENCE DELIVERY: the Client-owned queue that carries every
// evidence package the evaluator wrapper handed off to a receipt
// (v2_mvp/docs/EVALUATION_VIRULE.md section 6; docs/ARCHITECTURE.md,
// "Evaluation evidence delivery").
//
// OWNERSHIP. The package format, the layout, the handoff, the receipt and
// the atomic writer are virule/core/evaluation_evidence.hpp (vendored
// byte-identical from v2_mvp); this file never redefines them. The wrapper
// owns evidence\.incoming\<id> until its one rename into evidence\outbox\<id>;
// from that rename the Client owns the package. .incoming is never touched
// here. The Client writes exactly two things: its own delivery state,
// evidence\delivery\<id>.json, and the receipt.
//
// GUARANTEES (each one has a test in tests/evidence):
//   - oldest package first (outbox directory creation time, then id);
//   - delivery state is written atomically after every attempt
//     {attempts, failures, next_attempt_utc, last_error, damaged, acked};
//   - the receipt is written atomically BEFORE the payload is removed
//     (evaluation_evidence::acknowledge), and the payload goes only after a
//     COMPLETE acknowledgment that covers every file;
//   - a package that already has a receipt is never delivered or reported
//     again: a pass only finishes removing its payload (the crash between
//     the two steps);
//   - a duplicate acknowledgment changes nothing; a partial one is kept and
//     only the unacknowledged files are offered again;
//   - retry NEVER gives up and NEVER expires: 10 s, 1 min, 5 min, 15 min,
//     30 min, then 30 min forever. An acknowledgment that grew the acked
//     set is progress and restarts the ladder;
//   - a damaged package (unreadable package.json, a missing file, a size or
//     hash mismatch) is NEVER deleted: it is reported `damaged`, kept, and
//     checked again on the ladder in case it was a transient read failure;
//   - nothing is reported delivered without a receipt.
//
// TRANSPORTS. ProductionTransport is DEFERRED (no backend endpoint exists):
// it answers `unavailable` without any network call, so every package stays
// pending. TestTransport is loopback HTTP against --evidence-test-endpoint=,
// honored only in a staging build or a redirected-LOCALAPPDATA sandbox; its
// receipts carry simulated:true. Its wire protocol is documented above the
// class.
//
// DRIVER. run_driver() is the Client's dedicated evidence thread: one forced
// pass at startup (recovery after a crash or a Windows restart), then a
// blocked wait on the wake event Local\VIRULE.Evidence.Wake OR the earliest
// next_attempt, OR the stop event. Idle costs nothing.

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "shared/http_client.hpp"
#include "virule/core/evaluation_evidence.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace vclient::evidence {

namespace ee = virule::core::evaluation_evidence;
namespace fs = std::filesystem;

using Log = std::function<void(const std::string&)>;

// ---- the retry ladder (seconds). The last step repeats forever.
inline constexpr std::int64_t kBackoffLadder[] = { 10, 60, 300, 900, 1800 };
inline constexpr std::int64_t kBackoffCap = 1800;
inline constexpr size_t kLadderSteps = sizeof(kBackoffLadder) / sizeof(kBackoffLadder[0]);

inline std::int64_t backoff_seconds(std::int64_t failures) {
    if (failures <= 0) return kBackoffLadder[0];
    const size_t i = static_cast<size_t>(std::min<std::int64_t>(failures - 1, (std::int64_t)kLadderSteps - 1));
    return kBackoffLadder[i];
}

// ---- delivery state: evidence\delivery\<id>.json (Client-written only)

inline fs::path delivery_dir(const ee::Root& r) { return r.dir / L"delivery"; }
inline fs::path delivery_path(const ee::Root& r, const std::string& id) {
    return delivery_dir(r) / fs::path(id + ".json");
}

struct State {
    std::string package_id, assignment_id;
    std::int64_t attempts = 0;          // every delivery attempt, ever
    std::int64_t failures = 0;          // consecutive attempts without progress (the ladder)
    std::int64_t next_attempt_utc = 0;  // 0 = due now
    std::string last_error;
    bool damaged = false;
    std::vector<std::string> acked;     // files the service acknowledged, sorted
};

inline std::string state_json(const State& s) {
    using ee::json::quote;
    std::string out = "{\"package_id\":" + quote(s.package_id) +
        ",\"assignment_id\":" + quote(s.assignment_id) +
        ",\"attempts\":" + std::to_string(s.attempts) +
        ",\"failures\":" + std::to_string(s.failures) +
        ",\"next_attempt_utc\":" + std::to_string(s.next_attempt_utc) +
        ",\"last_error\":" + quote(s.last_error) +
        ",\"damaged\":" + (s.damaged ? "true" : "false") + ",\"acked\":[";
    for (size_t i = 0; i < s.acked.size(); ++i) {
        if (i) out += ",";
        out += quote(s.acked[i]);
    }
    return out + "]}\n";
}

inline bool parse_state(std::string_view text, State& s) {
    s = State{};
    namespace j = ee::json;
    if (!j::get_string(text, "package_id", s.package_id) || !ee::is_hex32(s.package_id)) return false;
    s.assignment_id = j::opt_string(text, "assignment_id");
    s.attempts = j::opt_int(text, "attempts");
    s.failures = j::opt_int(text, "failures");
    s.next_attempt_utc = j::opt_int(text, "next_attempt_utc");
    s.last_error = j::opt_string(text, "last_error");
    (void)j::get_bool(text, "damaged", s.damaged);
    std::string_view raw;
    if (j::member(text, "acked", raw)) {
        std::vector<std::string_view> list;
        if (j::items(raw, list)) {
            for (const auto& item : list) {
                std::string f;
                if (j::as_string(item, f) && !f.empty()) s.acked.push_back(f);
            }
        }
    }
    std::sort(s.acked.begin(), s.acked.end());
    s.acked.erase(std::unique(s.acked.begin(), s.acked.end()), s.acked.end());
    return true;
}

inline State load_state(const ee::Root& r, const std::string& id) {
    State s;
    const std::string text = ee::read_document(delivery_path(r, id));
    if (text.empty() || !parse_state(text, s) || s.package_id != id) {
        s = State{};
        s.package_id = id;
    }
    return s;
}

inline bool save_state(const ee::Root& r, const State& s) {
    return ee::write_file_atomic(delivery_path(r, s.package_id), state_json(s));
}

inline void remove_state(const ee::Root& r, const std::string& id) {
    std::error_code ec;
    fs::remove(delivery_path(r, id), ec);
}

inline bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

// ---- transport interface

// One file the package carries. package.json itself is the first file, so
// the service receives the session record and the frames the same way.
struct OfferFile {
    std::string file, sha256;
    std::int64_t bytes = 0;
    fs::path path;
};

struct Offer {
    std::string package_id, assignment_id;
    std::vector<OfferFile> files;          // every file of the package
    std::vector<std::string> already_acked; // never sent again
};

struct Answer {
    enum class Kind { Answered, Unavailable, Failed };
    Kind kind = Kind::Failed;
    std::vector<std::string> acked;  // the service's acknowledged set (may repeat old names)
    bool complete = false;
    std::string receipt_id;
    std::string error;
};

class Transport {
public:
    virtual ~Transport() = default;
    virtual const char* name() const = 0;
    virtual bool simulated() const = 0;
    virtual Answer deliver(const Offer& offer) = 0;
};

// DEFERRED: no evidence endpoint exists in virule-api (contract section 9,
// item 2). No network call is made; every package stays pending.
class ProductionTransport final : public Transport {
public:
    const char* name() const override { return "production"; }
    bool simulated() const override { return false; }
    Answer deliver(const Offer&) override {
        Answer a;
        a.kind = Answer::Kind::Unavailable;
        a.error = "evidence upload is not available yet";
        return a;
    }
};

// ---- base64 (the test wire carries file bodies as JSON strings)
inline std::string base64(const unsigned char* data, size_t n) {
    static const char* k = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((n + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        const unsigned v = (unsigned)data[i] << 16 | (unsigned)data[i + 1] << 8 | data[i + 2];
        out += k[(v >> 18) & 63]; out += k[(v >> 12) & 63]; out += k[(v >> 6) & 63]; out += k[v & 63];
    }
    if (i < n) {
        unsigned v = (unsigned)data[i] << 16;
        if (i + 1 < n) v |= (unsigned)data[i + 1] << 8;
        out += k[(v >> 18) & 63];
        out += k[(v >> 12) & 63];
        out += (i + 1 < n) ? k[(v >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

// Parse a service answer {acked:[...], complete, receipt_id}.
inline bool parse_answer(std::string_view text, Answer& a) {
    namespace j = ee::json;
    std::string_view raw;
    if (!j::member(text, "acked", raw)) return false;
    std::vector<std::string_view> list;
    if (!j::items(raw, list)) return false;
    a.acked.clear();
    for (const auto& item : list) {
        std::string f;
        if (!j::as_string(item, f)) return false;
        a.acked.push_back(f);
    }
    a.complete = false;
    if (j::member(text, "complete", raw) && !j::as_bool(raw, a.complete)) return false;
    a.receipt_id = j::opt_string(text, "receipt_id");
    a.kind = Answer::Kind::Answered;
    return true;
}

// THE TEST TRANSPORT (staging builds and redirected sandboxes only).
//
// Wire protocol, JSON over loopback HTTP, every answer the same shape
//   200 {"acked":["package.json","000001.jpg",...],"complete":bool,"receipt_id":"..."}
// (acked = everything the service holds verified for the package; complete
// = the package is whole; receipt_id required when complete):
//
//   1. POST <endpoint>/packages/<package_id>
//      {"v":1,"package_id","assignment_id",
//       "files":[{"file","sha256","bytes"},...]}           registration
//   2. for each file not in acked (local or answered), in chunks of at most
//      kTestChunkBytes raw:
//      POST <endpoint>/packages/<package_id>/files/<file>
//      {"package_id","file","sha256","bytes","offset","last":bool,
//       "data":"<base64>"}                                  the service
//      verifies the sha256 at the last chunk and only then acks the file.
//
// Any non-200, an unparsable answer, or no answer at all is a failure; the
// acked set gathered so far is still kept.
inline constexpr size_t kTestChunkBytes = 192 * 1024;
inline constexpr size_t kTestAnswerMaxBytes = 64 * 1024;

class TestTransport final : public Transport {
public:
    explicit TestTransport(http::Url endpoint) : url_(std::move(endpoint)) {
        while (!url_.path.empty() && url_.path.back() == L'/') url_.path.pop_back();
    }
    const char* name() const override { return "test"; }
    bool simulated() const override { return true; }

    Answer deliver(const Offer& offer) override {
        Answer result;
        std::set<std::string> acked(offer.already_acked.begin(), offer.already_acked.end());
        const auto finish = [&](Answer a) {
            a.acked.assign(acked.begin(), acked.end());
            return a;
        };
        std::string body = "{\"v\":1,\"package_id\":" + ee::json::quote(offer.package_id) +
            ",\"assignment_id\":" + ee::json::quote(offer.assignment_id) + ",\"files\":[";
        for (size_t i = 0; i < offer.files.size(); ++i) {
            if (i) body += ",";
            body += "{\"file\":" + ee::json::quote(offer.files[i].file) +
                    ",\"sha256\":" + ee::json::quote(offer.files[i].sha256) +
                    ",\"bytes\":" + std::to_string(offer.files[i].bytes) + "}";
        }
        body += "]}";
        Answer last;
        if (!post(L"/packages/" + widen(offer.package_id), body, last)) return finish(last);
        acked.insert(last.acked.begin(), last.acked.end());
        if (last.complete) return finish(last);

        for (const auto& f : offer.files) {
            if (acked.count(f.file)) continue;
            std::ifstream in(f.path, std::ios::binary);
            if (!in) {
                Answer a;
                a.kind = Answer::Kind::Failed;
                a.error = "could not read " + f.file;
                return finish(a);
            }
            std::vector<unsigned char> buf(kTestChunkBytes);
            std::int64_t offset = 0;
            for (;;) {
                in.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
                const std::int64_t n = (std::int64_t)in.gcount();
                const bool is_last = offset + n >= f.bytes || n <= 0;
                const std::string chunk = "{\"package_id\":" + ee::json::quote(offer.package_id) +
                    ",\"file\":" + ee::json::quote(f.file) +
                    ",\"sha256\":" + ee::json::quote(f.sha256) +
                    ",\"bytes\":" + std::to_string(f.bytes) +
                    ",\"offset\":" + std::to_string(offset) +
                    ",\"last\":" + (is_last ? "true" : "false") +
                    ",\"data\":\"" + base64(buf.data(), (size_t)std::max<std::int64_t>(n, 0)) + "\"}";
                if (!post(L"/packages/" + widen(offer.package_id) + L"/files/" + widen(f.file), chunk, last)) {
                    return finish(last);
                }
                acked.insert(last.acked.begin(), last.acked.end());
                offset += n;
                if (is_last) break;
            }
            if (last.complete) return finish(last);
        }
        return finish(last);
    }

private:
    static std::wstring widen(const std::string& s) { return std::wstring(s.begin(), s.end()); }

    bool post(const std::wstring& suffix, const std::string& body, Answer& out) {
        out = Answer{};
        unsigned long status = 0;
        std::string text;
        http::Timeouts t;
        t.resolve_ms = 5000;
        t.connect_ms = 5000;
        t.send_ms = 10000;
        t.receive_ms = 10000;
        const std::wstring path = url_.path + suffix;
        const bool got = http::http_post_json(url_.host.c_str(), url_.port, url_.secure,
                                              path.c_str(), body, kTestAnswerMaxBytes,
                                              status, text, t);
        if (!got || status == 0) {
            out.kind = Answer::Kind::Failed;
            out.error = "no answer from the test endpoint";
            return false;
        }
        if (status != 200) {
            out.kind = Answer::Kind::Failed;
            out.error = "test endpoint answered " + std::to_string(status);
            return false;
        }
        if (!parse_answer(text, out)) {
            out = Answer{};
            out.kind = Answer::Kind::Failed;
            out.error = "unreadable answer from the test endpoint";
            return false;
        }
        return true;
    }

    http::Url url_;
};

// ---- transport selection (the --evidence-test-endpoint= seam)

// The test endpoint is honored ONLY in a staging build or a sandbox whose
// LOCALAPPDATA is redirected (paths::environment_redirected). A production
// build on a real profile ignores it.
inline bool test_endpoint_permitted(bool staging_build, bool redirected) {
    return staging_build || redirected;
}

// A loopback http(s) url: 127.0.0.1 or localhost, nothing else.
inline bool parse_test_endpoint(const std::wstring& s, http::Url& out) {
    if (!http::parse_url(s, out)) return false;
    std::wstring host = out.host;
    for (wchar_t& c : host) c = (wchar_t)towlower(c);
    return host == L"127.0.0.1" || host == L"localhost";
}

inline std::unique_ptr<Transport> select_transport(const std::wstring& test_endpoint,
                                                   bool staging_build, bool redirected,
                                                   const Log& log) {
    if (!test_endpoint.empty()) {
        http::Url u;
        if (!test_endpoint_permitted(staging_build, redirected)) {
            if (log) log("evidence: --evidence-test-endpoint ignored (production build on a real profile)");
        } else if (!parse_test_endpoint(test_endpoint, u)) {
            if (log) log("evidence: --evidence-test-endpoint ignored (not a loopback http url)");
        } else {
            if (log) log("evidence: test transport active (simulated receipts)");
            return std::make_unique<TestTransport>(u);
        }
    }
    return std::make_unique<ProductionTransport>();
}

// ---- the engine

inline std::string utc_text(std::int64_t t) {
    const std::time_t tt = (std::time_t)t;
    std::tm tm{};
    gmtime_s(&tm, &tt);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// The outbox package ids, oldest first.
inline std::vector<std::string> outbox_ids(const ee::Root& r) {
    struct Entry { std::uint64_t created; std::string id; };
    std::vector<Entry> v;
    std::error_code ec;
    for (fs::directory_iterator it(ee::outbox_dir(r), ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code dec;
        if (!it->is_directory(dec)) continue;
        const std::string id = it->path().filename().string();
        if (!ee::is_hex32(id)) continue;
        std::uint64_t created = 0;
        WIN32_FILE_ATTRIBUTE_DATA a{};
        if (GetFileAttributesExW(it->path().c_str(), GetFileExInfoStandard, &a)) {
            created = ((std::uint64_t)a.ftCreationTime.dwHighDateTime << 32) | a.ftCreationTime.dwLowDateTime;
        }
        v.push_back({ created, id });
    }
    std::sort(v.begin(), v.end(), [](const Entry& a, const Entry& b) {
        return a.created != b.created ? a.created < b.created : a.id < b.id;
    });
    std::vector<std::string> out;
    for (auto& e : v) out.push_back(std::move(e.id));
    return out;
}

// Verify an outbox package against its own package.json. Empty = whole.
inline std::string verify_package(const ee::Root& r, const std::string& id,
                                  ee::Package& pkg, std::vector<OfferFile>& files) {
    files.clear();
    const fs::path dir = ee::outbox_dir(r, id);
    const fs::path pj = dir / ee::kPackageFileName;
    const std::string text = ee::read_document(pj);
    if (text.empty()) return "package.json is missing or unreadable";
    if (!ee::parse_package(text, pkg)) return "package.json is not a valid evidence package";
    if (pkg.package_id != id) return "package.json names a different package";
    OfferFile head;
    head.file = ee::kPackageFileName;
    head.path = pj;
    if (!ee::sha256_file(pj, head.sha256, head.bytes)) return "package.json could not be read";
    files.push_back(head);
    for (const auto& pf : ee::package_files(pkg)) {
        OfferFile f;
        f.file = pf.file;
        f.path = dir / fs::path(pf.file);
        std::string sha;
        std::int64_t bytes = 0;
        if (!ee::sha256_file(f.path, sha, bytes)) return "missing file " + pf.file;
        if (bytes != pf.bytes) return "size mismatch in " + pf.file;
        if (sha != pf.sha256) return "hash mismatch in " + pf.file;
        f.sha256 = sha;
        f.bytes = bytes;
        files.push_back(std::move(f));
    }
    return {};
}

struct PassResult {
    int delivered = 0;        // receipts written this pass
    int cleaned = 0;          // payloads removed under an existing receipt
    int pending = 0;          // still waiting
    int damaged = 0;
    int skipped_not_due = 0;
    int transport_calls = 0;
    std::int64_t next_due_utc = 0;  // earliest next attempt, 0 = nothing pending
};

// Remembered per process so a quiet state is logged once, not every pass.
struct LogOnce {
    std::set<std::string> seen;
    bool first(const std::string& key) { return seen.insert(key).second; }
};

// ONE PASS over the outbox. `force` ignores next_attempt (the startup
// recovery pass). `now` is UTC seconds (injected for the tests).
inline PassResult run_pass(const ee::Root& r, Transport& transport, std::int64_t now,
                           bool force, const Log& log, LogOnce* once = nullptr) {
    PassResult res;
    if (r.dir.empty()) return res;
    const auto say = [&](const std::string& key, const std::string& text) {
        if (!log) return;
        if (once && !once->first(key)) return;
        log(text);
    };
    const auto ids = outbox_ids(r);
    for (const auto& id : ids) {
        // A receipt is the fact: never deliver or report again, only finish
        // removing the payload (a crash between receipt and removal).
        ee::Receipt existing;
        if (ee::read_receipt(r, id, existing)) {
            std::error_code ec;
            fs::remove_all(ee::outbox_dir(r, id), ec);
            remove_state(r, id);
            ++res.cleaned;
            if (log) log("evidence: " + id + " already acknowledged; payload removed");
            continue;
        }

        State st = load_state(r, id);
        const bool clock_moved_back = st.next_attempt_utc > now + kBackoffCap;
        if (!force && st.next_attempt_utc > now && !clock_moved_back) {
            ++res.skipped_not_due;
            if (st.damaged) ++res.damaged; else ++res.pending;
            if (res.next_due_utc == 0 || st.next_attempt_utc < res.next_due_utc) res.next_due_utc = st.next_attempt_utc;
            continue;
        }

        ee::Package pkg;
        std::vector<OfferFile> files;
        const std::string damage = verify_package(r, id, pkg, files);
        if (!pkg.assignment_id.empty()) st.assignment_id = pkg.assignment_id;
        if (!damage.empty()) {
            // KEPT, NEVER DELETED. Re-checked on the ladder.
            const bool newly = !st.damaged || st.last_error != damage;
            st.damaged = true;
            st.last_error = damage;
            ++st.failures;
            st.next_attempt_utc = now + backoff_seconds(st.failures);
            (void)save_state(r, st);
            ++res.damaged;
            if (newly) say("damaged:" + id + damage, "evidence: " + id + " damaged (" + damage + "); kept");
            if (res.next_due_utc == 0 || st.next_attempt_utc < res.next_due_utc) res.next_due_utc = st.next_attempt_utc;
            continue;
        }
        st.damaged = false;

        // Acked names that are not files of this package mean nothing.
        std::vector<std::string> known;
        for (const auto& f : files) known.push_back(f.file);
        std::vector<std::string> acked_before;
        for (const auto& a : st.acked) if (contains(known, a)) acked_before.push_back(a);

        Offer offer;
        offer.package_id = id;
        offer.assignment_id = pkg.assignment_id;
        offer.files = files;
        offer.already_acked = acked_before;

        ++st.attempts;
        ++res.transport_calls;
        const Answer ans = transport.deliver(offer);

        std::set<std::string> merged(acked_before.begin(), acked_before.end());
        for (const auto& a : ans.acked) if (contains(known, a)) merged.insert(a);
        const bool progress = merged.size() > acked_before.size();
        st.acked.assign(merged.begin(), merged.end());

        const bool all_acked = merged.size() == known.size();
        if (ans.kind == Answer::Kind::Answered && ans.complete && all_acked && !ans.receipt_id.empty()) {
            ee::Receipt rc;
            rc.package_id = id;
            rc.assignment_id = pkg.assignment_id;
            rc.receipt_id = ans.receipt_id;
            rc.acknowledged_utc = utc_text(now);
            for (const auto& f : files) rc.files.push_back({ f.file, f.sha256, f.bytes });
            rc.simulated = transport.simulated();
            // The receipt first, durably; then the payload goes.
            if (ee::acknowledge(r, rc)) {
                remove_state(r, id);
                ++res.delivered;
                if (log) log("evidence: " + id + " acknowledged (receipt " + ans.receipt_id +
                             (rc.simulated ? ", simulated)" : ")"));
                continue;
            }
            st.last_error = "the receipt could not be written";
        } else if (ans.kind == Answer::Kind::Unavailable) {
            st.last_error = ans.error.empty() ? "transport unavailable" : ans.error;
            say("unavailable:" + id, "evidence: " + id + " pending (" + st.last_error + ")");
        } else if (ans.kind == Answer::Kind::Answered) {
            st.last_error = !ans.complete ? "partial acknowledgment"
                          : !all_acked     ? "the acknowledgment did not cover every file"
                                           : "the acknowledgment carried no receipt";
            if (log) log("evidence: " + id + " partially acknowledged (" +
                         std::to_string(merged.size()) + " of " + std::to_string(known.size()) + " files)");
        } else {
            st.last_error = ans.error.empty() ? "delivery failed" : ans.error;
            say("failed:" + id + st.last_error, "evidence: " + id + " delivery failed (" + st.last_error + ")");
        }
        st.failures = progress ? 1 : st.failures + 1;
        st.next_attempt_utc = now + backoff_seconds(st.failures);
        (void)save_state(r, st);
        ++res.pending;
        if (res.next_due_utc == 0 || st.next_attempt_utc < res.next_due_utc) res.next_due_utc = st.next_attempt_utc;
    }

    // Delivery state whose package left the outbox (acknowledged, or removed
    // by hand) is stale.
    std::error_code ec;
    for (fs::directory_iterator it(delivery_dir(r), ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (name.size() != 37 || name.compare(32, 5, ".json") != 0) continue;
        const std::string id = name.substr(0, 32);
        if (!ee::exists_quiet(ee::outbox_dir(r, id))) remove_state(r, id);
    }
    return res;
}

// ---- status (the bridge's local evidence_status query)

inline constexpr size_t kStatusMaxBytes = 3800; // inside bridge::kMaxFrameBytes (4096)
inline constexpr size_t kStatusErrorChars = 80;

// {"type":"evidence_status","assignment_id","counts":{pending,acknowledged,
//  damaged},"packages":[{"id","state","simulated","attempts","last_error"}],
//  "truncated":bool}. Damaged first, then pending, then acknowledged; the
// counts are always complete even when the list is truncated.
inline std::string status_json(const ee::Root& r, const std::string& assignment_id) {
    using ee::json::quote;
    struct Row { int order; std::string id, state; bool simulated; std::int64_t attempts; std::string error; };
    std::vector<Row> rows;
    std::set<std::string> receipted;
    std::error_code ec;
    for (fs::directory_iterator it(ee::receipts_dir(r), ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (name.size() != 37 || name.compare(32, 5, ".json") != 0) continue;
        ee::Receipt rc;
        if (!ee::read_receipt(r, name.substr(0, 32), rc)) continue;
        if (rc.assignment_id != assignment_id) continue;
        receipted.insert(rc.package_id);
        rows.push_back({ 2, rc.package_id, "acknowledged", rc.simulated, 0, "" });
    }
    for (const auto& id : outbox_ids(r)) {
        if (receipted.count(id)) continue;
        const State st = load_state(r, id);
        std::string owner = st.assignment_id;
        ee::Package pkg;
        if (ee::read_outbox_package(r, id, pkg)) owner = pkg.assignment_id;
        if (owner != assignment_id) continue;
        std::string err = st.last_error.substr(0, kStatusErrorChars);
        rows.push_back({ st.damaged ? 0 : 1, id, st.damaged ? "damaged" : "pending", false, st.attempts, err });
    }
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        return a.order != b.order ? a.order < b.order : a.id < b.id;
    });
    int counts[3] = { 0, 0, 0 };
    for (const auto& row : rows) ++counts[row.order];
    std::string out = "{\"type\":\"evidence_status\",\"assignment_id\":" + quote(assignment_id) +
        ",\"counts\":{\"pending\":" + std::to_string(counts[1]) +
        ",\"acknowledged\":" + std::to_string(counts[2]) +
        ",\"damaged\":" + std::to_string(counts[0]) + "},\"packages\":[";
    bool truncated = false;
    bool first = true;
    for (const auto& row : rows) {
        const std::string item = "{\"id\":" + quote(row.id) + ",\"state\":" + quote(row.state) +
            ",\"simulated\":" + (row.simulated ? "true" : "false") +
            ",\"attempts\":" + std::to_string(row.attempts) +
            ",\"last_error\":" + quote(row.error) + "}";
        if (out.size() + item.size() + 32 > kStatusMaxBytes) { truncated = true; break; }
        if (!first) out += ",";
        out += item;
        first = false;
    }
    out += std::string("],\"truncated\":") + (truncated ? "true" : "false") + "}";
    return out;
}

// ---- the wake event and the driver

// Create (or open) the wake event. Same parameters as the wrapper's
// evaluation_evidence::open_wake_event (auto-reset, initially clear), plus
// an explicit descriptor so the object is reachable by every process of
// this user whichever integrity level created it first: full access for
// this user's SID and SYSTEM, medium mandatory label (no-write-up), so an
// elevated wrapper of the same user can signal it and a low-integrity
// process cannot. Null on failure (the driver then polls).
inline HANDLE create_wake_event(const wchar_t* name) {
    std::wstring sid_text;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD len = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &len);
        std::vector<unsigned char> buf(len ? len : 1);
        if (len && GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
            LPWSTR s = nullptr;
            if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &s)) {
                sid_text = s;
                LocalFree(s);
            }
        }
        CloseHandle(token);
    }
    HANDLE h = nullptr;
    if (!sid_text.empty()) {
        const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + sid_text + L")S:(ML;;NW;;;ME)";
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
            SECURITY_ATTRIBUTES sa{ sizeof(sa), sd, FALSE };
            h = CreateEventW(&sa, FALSE, FALSE, name);
            LocalFree(sd);
        }
    }
    if (!h) h = CreateEventW(nullptr, FALSE, FALSE, name);
    if (!h) h = OpenEventW(SYNCHRONIZE, FALSE, name);
    return h;
}

inline constexpr DWORD kPollWithoutWakeMs = 60000;   // no wake event at all
inline constexpr DWORD kPausedPollMs = 60000;        // uninstall in progress

struct DriverConfig {
    ee::Root root;
    Transport* transport = nullptr;
    std::wstring wake_name = ee::kWakeEventName;
    HANDLE stop_event = nullptr;              // set = leave
    std::function<bool()> paused;             // true = an uninstall is running
    Log log;
    std::function<std::int64_t()> now;        // UTC seconds; default time()
};

// The evidence thread's whole life. Returns when stop_event is set.
inline void run_driver(const DriverConfig& cfg) {
    if (!cfg.transport || !cfg.stop_event) return;
    const auto now = [&]() -> std::int64_t {
        return cfg.now ? cfg.now() : (std::int64_t)std::time(nullptr);
    };
    HANDLE wake = create_wake_event(cfg.wake_name.c_str());
    if (!wake && cfg.log) cfg.log("evidence: wake event unavailable; polling every minute");
    LogOnce once;
    bool force = true; // the startup pass: recovery after a crash or a restart
    for (;;) {
        if (cfg.paused && cfg.paused()) {
            if (WaitForSingleObject(cfg.stop_event, kPausedPollMs) == WAIT_OBJECT_0) break;
            continue;
        }
        const std::int64_t t = now();
        const PassResult r = run_pass(cfg.root, *cfg.transport, t, force, cfg.log, &once);
        force = false;
        DWORD wait_ms = INFINITE;
        if (r.next_due_utc > 0) {
            const std::int64_t s = std::clamp<std::int64_t>(r.next_due_utc - t, 1, kBackoffCap);
            wait_ms = (DWORD)(s * 1000);
        }
        if (!wake) wait_ms = std::min<DWORD>(wait_ms, kPollWithoutWakeMs);
        HANDLE hs[2] = { cfg.stop_event, wake };
        const DWORD w = WaitForMultipleObjects(wake ? 2 : 1, hs, FALSE, wait_ms);
        if (w == WAIT_OBJECT_0) break;
        if (w == WAIT_FAILED) Sleep(1000);
    }
    if (wake) CloseHandle(wake);
}

} // namespace vclient::evidence
