#pragma once
// THE CHECK-IN THAT RIDES THE UPDATE CHECK (owner spec 2026-10-01): capture
// richly locally, transmit sparsely.
//
// The client's ordinary Admin manifest check is sent as a POST that does two
// things in the one request:
//
//   1. IDENTIFIES THIS INSTALLATION, always: the machine's VIRULE identity,
//      its install id, the client version and the installed Admin version
//      ('' when none). A client whose Admin was never opened, or never
//      installed, is therefore still on record (first seen, last seen).
//   2. CARRIES THE ADMIN'S PENDING BATCHES, when there are any. The VIRULE
//      Admin spools what it records to disk (virule/core/usage_spool.hpp,
//      the one file both products share); the answer's `ack` names the
//      batch ids the service stored. ONLY those are deleted; everything else
//      stays on disk for the next check. The service de-duplicates by event
//      id, so a batch delivered twice (a lost acknowledgement) is stored
//      once.
//
// Body: {"developer_public_key","timestamp","developer_signature",
//        "n":"<install id>","cv":"<client version>","a":"<Admin version>",
//        "pk":"<previous machine key>",            (only while unlinked)
//        "b":[{"id":"<batch id>","l":["<spooled line>",...]}]}  (if any)
// signed by this machine's existing VIRULE identity over
//   virule-checkin.v1|<install id>|<batch ids, comma-joined>|<timestamp>
//
// THE PREVIOUS-KEY LINK. The Admin issues its own machine key on its first
// run when the credential it finds was created by this client. Without a
// link the same installation would appear twice, once as "client only" and
// once as "Admin user". The client therefore remembers the key its last
// accepted check-in used (`checkin.json`), and while the current key
// differs it names the old one as `pk`; the service's `seen` answer is what
// advances the remembered key, so the link is sent until it has landed.
// Each spooled line travels as a JSON STRING, so a torn line (a crash while
// the Admin was writing) can never make the request unparseable.
//
// Nothing here touches the network or the identity file: the caller hands
// in the key, the id and a signing function, which is what lets the whole
// exchange be tested without a machine credential.

#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <system_error>
#include <vector>

#include "shared/json_scan.hpp"
#include "virule/core/usage_spool.hpp"

namespace vclient::usage_checkin {

// One check carries at most this much: far below the service's 64 KiB body
// bound even after string escaping, so a long offline backlog drains over
// several checks instead of one large request.
constexpr size_t kMaxBatches = 8;
constexpr size_t kMaxSpoolBytes = 40 * 1024;

struct Identity {
    std::string public_key_hex; // 64 hex
    std::string install_id;     // 32 hex
    std::function<std::string(const std::string& message)> sign_hex;
};

// Minimal installation state the check-in reports beside the identity.
struct Install {
    std::string client_version;
    std::string admin_version;  // "" = no managed Admin installed
    std::string previous_key;   // "" = the key never changed (or is linked)
};

struct Pending {
    std::vector<virule::usage_spool::Batch> batches;
    // "" = this machine cannot identify itself (no usable VIRULE identity):
    // the check stays the plain GET and any batches wait.
    std::string body;
    std::string public_key_hex; // the key `body` was signed with
};

inline std::string signed_message(const std::string& install_id,
                                  const std::vector<virule::usage_spool::Batch>& batches,
                                  const std::string& timestamp) {
    std::string ids;
    for (const auto& b : batches) {
        if (!ids.empty()) ids += ",";
        ids += b.id;
    }
    return "virule-checkin.v1|" + install_id + "|" + ids + "|" + timestamp;
}

// Build the check-in: the identity always, plus the oldest sealed batches
// when there are any. An identity that cannot sign means nothing is sent
// and nothing is lost.
inline Pending prepare(const std::filesystem::path& spool_dir, bool staging,
                       const Identity& id, const std::string& timestamp,
                       const Install& install) {
    namespace us = virule::usage_spool;
    Pending out;
    if (!us::is_hex(id.public_key_hex, 64) || !us::is_hex(id.install_id, 32) || !id.sign_hex) {
        return out;
    }
    out.batches = us::load_sealed(spool_dir, staging, kMaxBatches, kMaxSpoolBytes);
    const std::string signature =
        id.sign_hex(signed_message(id.install_id, out.batches, timestamp));
    if (!us::is_hex(signature, 128)) {
        out.batches.clear();
        return out;
    }

    std::string body = "{\"developer_public_key\":\"" + id.public_key_hex +
        "\",\"timestamp\":\"" + timestamp +
        "\",\"developer_signature\":\"" + signature +
        "\",\"n\":\"" + id.install_id +
        "\",\"cv\":\"" + json_scan::json_escape(install.client_version) +
        "\",\"a\":\"" + json_scan::json_escape(install.admin_version) + "\"";
    if (us::is_hex(install.previous_key, 64) && install.previous_key != id.public_key_hex) {
        body += ",\"pk\":\"" + install.previous_key + "\"";
    }
    if (!out.batches.empty()) {
        body += ",\"b\":[";
        for (size_t i = 0; i < out.batches.size(); ++i) {
            if (i > 0) body += ",";
            body += "{\"id\":\"" + out.batches[i].id + "\",\"l\":[";
            for (size_t j = 0; j < out.batches[i].lines.size(); ++j) {
                if (j > 0) body += ",";
                body += "\"" + json_scan::json_escape(out.batches[i].lines[j]) + "\"";
            }
            body += "]}";
        }
        body += "]";
    }
    body += "}";
    out.body = std::move(body);
    out.public_key_hex = id.public_key_hex;
    return out;
}

// Did the service put this installation on record? (`"seen":1`)
inline bool seen(const std::string& response) {
    return response.find("\"seen\":1") != std::string::npos;
}

// ---- the remembered key (the previous-key link) ----
// <client state dir>\checkin.json: {"key":"<64 hex>"}, the machine key the
// last ACCEPTED check-in was signed with. Fail-soft in both directions: an
// unreadable file means "nothing to link".

inline std::string load_checked_key(const std::filesystem::path& file) {
    if (file.empty()) return {};
    std::ifstream f(file, std::ios::binary);
    if (!f) return {};
    const std::string text((std::istreambuf_iterator<char>(f)),
                           std::istreambuf_iterator<char>());
    std::string key;
    if (!json_scan::find_string_in(text, 0, text.size(), "key", key)) return {};
    return virule::usage_spool::is_hex(key, 64) ? key : std::string();
}

inline bool save_checked_key(const std::filesystem::path& file, const std::string& key) {
    if (file.empty() || !virule::usage_spool::is_hex(key, 64)) return false;
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    const auto tmp = file.parent_path() / (file.filename().string() + ".tmp");
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f << "{\"key\":\"" << key << "\"}\n";
        if (!f) return false;
    }
    std::filesystem::rename(tmp, file, ec);
    if (ec) {
        std::error_code ec2;
        std::filesystem::remove(tmp, ec2);
        return false;
    }
    return true;
}

// After a check-in the service accepted: remember the key it used, which is
// what stops the previous-key link from being sent again.
inline void note_seen(const std::filesystem::path& file, const Pending& pending) {
    if (pending.public_key_hex.empty()) return;
    if (load_checked_key(file) == pending.public_key_hex) return;
    (void)save_checked_key(file, pending.public_key_hex);
}

// Delete exactly the batches the answer acknowledges. Returns how many.
inline size_t apply_ack(const std::string& response, const Pending& pending) {
    std::string ack;
    if (!json_scan::find_string_in(response, 0, response.size(), "ack", ack)) return 0;
    size_t removed = 0;
    for (const auto& b : pending.batches) {
        // Ids are fixed-width hex joined by commas, so a substring match at
        // a 33-character stride is an exact membership test.
        bool named = false;
        for (size_t at = 0; at + 32 <= ack.size(); at += 33) {
            if (ack.compare(at, 32, b.id) == 0) { named = true; break; }
        }
        if (named && virule::usage_spool::remove_batch(b)) ++removed;
    }
    return removed;
}

} // namespace vclient::usage_checkin
