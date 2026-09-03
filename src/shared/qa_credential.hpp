#pragma once
// The native local QA tester credential store, EXACTLY as the VIRULE
// product defines it (qa_tester_credential in the VIRULE repository's
// qa_access_service.hpp; the save routine below is that code, ported with
// only the scanner/escape helpers renamed to this repository's shared
// modules). One file, one format, one consumer contract:
//
//   <user data>\security\qa_tester.cred, JSON:
//   { "version": 1, "credentials": [ { "organization_id", "tester_id",
//     "machine_key", "bound_utc", "signature", "organization_name" } ] }
//
// The wrapper runtime (qa_runtime_client.hpp) reads this file at launch
// and requires the service signature over
// `virule-qa-tester.v2|org|tester|machine_key|bound_utc` to verify against
// the embedded VIRULE service key, and the local machine identity
// (dev_machine.cred) to reproduce machine_key. Do not invent a second
// store and do not change a byte of this shape.

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "shared/json_scan.hpp"
#include "virule/core/embargo_signing.hpp"

namespace vclient::qa_credential {

inline constexpr const char* kFileName = "qa_tester.cred";
// SUPER ADMIN QA TEST MODE writes here instead: an isolated namespace so a
// test redemption never replaces or contaminates the real tester
// credential store.
inline constexpr const char* kTestFileName = "qa_tester_test.cred";

struct Entry {
    std::string organization_id;
    std::string tester_id;
    std::string machine_key;
    std::string bound_utc;
    std::string signature;
    std::string organization_name; // display label for future diagnostics
};

// The credential grammar the service signed at redemption
// (virule-qa-tester.v2 in VIRULE_BACKEND src/v1/qa.ts).
inline std::string credential_message(const Entry& e) {
    return std::string("virule-qa-tester.v2|") + e.organization_id + "|" +
        e.tester_id + "|" + e.machine_key + "|" + e.bound_utc;
}

// The client verifies what it writes: the service's signature over the
// credential must check out against the embedded VIRULE public key before
// the file is touched (the wrapper re-verifies at every launch; a
// credential that fails here would be dead weight anyway).
inline bool signature_valid(const Entry& e) {
    return virule::core::embargo_signing::verify_virule_signature(
        credential_message(e), e.signature);
}

// Save one verified credential, replacing any earlier entry for the same
// relationship. Best-effort atomic: temp file + rename. Byte-compatible
// with the Admin's writer.
inline bool save(const std::filesystem::path& security_dir, const Entry& entry,
                 const char* file_name = kFileName) {
    namespace fs = std::filesystem;
    namespace js = vclient::json_scan;
    std::error_code ec;
    fs::create_directories(security_dir, ec);
    const fs::path file = security_dir / file_name;

    // Existing entries, minus the one being replaced.
    std::vector<Entry> kept;
    {
        std::ifstream in(file, std::ios::binary);
        if (in) {
            std::string text((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
            size_t p = text.find('[');
            const size_t end = text.rfind(']');
            while (p != std::string::npos && end != std::string::npos && p < end) {
                const size_t ob = text.find('{', p);
                if (ob == std::string::npos || ob >= end) break;
                const size_t oe = text.find('}', ob);
                if (oe == std::string::npos || oe > end) break;
                Entry e;
                if (js::find_string_in(text, ob, oe, "organization_id", e.organization_id) &&
                    js::find_string_in(text, ob, oe, "tester_id", e.tester_id)) {
                    (void)js::find_string_in(text, ob, oe, "machine_key", e.machine_key);
                    (void)js::find_string_in(text, ob, oe, "bound_utc", e.bound_utc);
                    (void)js::find_string_in(text, ob, oe, "signature", e.signature);
                    (void)js::find_string_in(text, ob, oe, "organization_name", e.organization_name);
                    if (e.organization_id != entry.organization_id ||
                        e.tester_id != entry.tester_id) {
                        kept.push_back(std::move(e));
                    }
                }
                p = oe + 1;
            }
        }
    }
    kept.push_back(entry);

    std::string body = "{\"version\":1,\"credentials\":[";
    bool first = true;
    for (const auto& e : kept) {
        if (!first) body += ",";
        first = false;
        body += "{\"organization_id\":\"" + e.organization_id +
            "\",\"tester_id\":\"" + e.tester_id +
            "\",\"machine_key\":\"" + e.machine_key +
            "\",\"bound_utc\":\"" + e.bound_utc +
            "\",\"signature\":\"" + e.signature +
            "\",\"organization_name\":\"" +
            js::json_escape(e.organization_name) +
            "\"}";
    }
    body += "]}";

    const fs::path tmp = file.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(body.data(), (std::streamsize)body.size());
        if (!out.good()) return false;
    }
    fs::rename(tmp, file, ec);
    if (ec) {
        // Rename over an open target can fail; fall back to a direct write.
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(body.data(), (std::streamsize)body.size());
        fs::remove(tmp, ec);
        return out.good();
    }
    return true;
}

} // namespace vclient::qa_credential
