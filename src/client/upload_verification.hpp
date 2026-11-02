#pragma once
// THE CLIENT'S DEVELOPER VERIFICATION AND ITS OWN SECURITY INCIDENTS (owner
// brief 2026-11-02, "Client Security Authority Phase 2" sections 4 to 9 and
// 11; docs/ARCHITECTURE.md "Developer verification and the upload gate").
//
// THE VERIFICATION RECORD. Before an upload job sends a byte, this Client
// verifies the exact package itself (client/transfers.hpp verify_package:
// its own SHA-256, its own extraction and its own malware scan) and keeps
// what it verified here, SEALED (client/client_seal.hpp), at
// client\upload_verification\<job id>.json:
//   the job, game and build it belongs to; the package's path, size, last
//   write time and SHA-256 as this Client read them; the SHA-256 of every
//   32 MiB part (evaluation_distribution kPartBytes); the content size, file
//   count and launch file it found inside; the scanner and its versions.
// The upload trusts nothing else: not the job's `scan_outcome`, `package_*`
// or `state`, which the Admin host writes. A record that is absent, unsealed,
// for another job, build or path, or whose package no longer has the size
// and write time it had means VERIFY AGAIN; a part whose bytes differ from
// the recorded part means the package changed and the upload stops.
//
// THE CLIENT'S INCIDENTS. A security incident the Client reports to the
// service is one it produced itself (its own scan, or Defender's own record
// it read), kept sealed at client\incidents\<job id>.json until the service
// recorded it. A job file's `incident` is never sent.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "client/client_seal.hpp"
#include "virule/core/evaluation_distribution.hpp"
#include "virule/core/evaluation_evidence.hpp"

#if defined(_WIN32)
#include <bcrypt.h>
#endif

namespace vclient::upload_verification {

namespace fs = std::filesystem;
namespace ed = virule::core::evaluation_distribution;
namespace ee = virule::core::evaluation_evidence;
namespace seal = vclient::client_seal;

inline constexpr const char* kFormat = "virule-upload-verification.v1";

inline fs::path record_path(const fs::path& root, const std::string& job_id) {
    return seal::client_dir(root) / L"upload_verification" / fs::path(job_id + ".json");
}
inline fs::path incident_path(const fs::path& root, const std::string& job_id) {
    return seal::client_dir(root) / L"incidents" / fs::path(job_id + ".json");
}

inline fs::path path_of(const std::string& utf8) { return fs::path(std::u8string(utf8.begin(), utf8.end())); }

// ------------------------------------------------------------ identity ----

struct Identity {
    std::uint64_t bytes = 0;
    std::int64_t mtime = 0;   // last write time, file-clock ticks
};

inline bool identity_of(const fs::path& p, Identity& out) {
    std::error_code ec;
    const auto sz = fs::file_size(p, ec);
    if (ec) return false;
    const auto t = fs::last_write_time(p, ec);
    if (ec) return false;
    out.bytes = static_cast<std::uint64_t>(sz);
    out.mtime = static_cast<std::int64_t>(t.time_since_epoch().count());
    return true;
}

struct Digests {
    std::string sha256;
    std::vector<std::string> parts;   // one per kPartBytes part, in order
};

#if defined(_WIN32)
/** One read of the file: the whole SHA-256 and every part's. */
inline bool digest_package(const fs::path& p, std::uint64_t bytes, Digests& out, const std::function<bool()>& keep_going) {
    out = Digests{};
    FILE* f = nullptr;
    if (_wfopen_s(&f, p.wstring().c_str(), L"rb") != 0 || !f) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) { fclose(f); return false; }
    BCRYPT_HASH_HANDLE whole = nullptr, part = nullptr;
    const auto finish = [](BCRYPT_HASH_HANDLE h, std::string& hex_out) {
        unsigned char d[32];
        const bool okd = BCryptFinishHash(h, d, sizeof(d), 0) == 0;
        BCryptDestroyHash(h);
        if (okd) hex_out = seal::detail::hex(d, sizeof(d));
        return okd;
    };
    bool okd = BCryptCreateHash(alg, &whole, nullptr, 0, nullptr, 0, 0) == 0 &&
               BCryptCreateHash(alg, &part, nullptr, 0, nullptr, 0, 0) == 0;
    std::vector<unsigned char> buf(1024 * 1024);
    std::uint64_t done = 0, in_part = 0;
    while (okd) {
        const size_t want = static_cast<size_t>(std::min<std::uint64_t>(buf.size(), ed::kPartBytes - in_part));
        const size_t n = fread(buf.data(), 1, want, f);
        if (n == 0) break;
        if (BCryptHashData(whole, buf.data(), static_cast<ULONG>(n), 0) != 0 ||
            BCryptHashData(part, buf.data(), static_cast<ULONG>(n), 0) != 0) { okd = false; break; }
        done += n;
        in_part += n;
        if (in_part == ed::kPartBytes) {
            std::string h;
            okd = finish(part, h);
            part = nullptr;
            if (!okd) break;
            out.parts.push_back(h);
            in_part = 0;
            okd = BCryptCreateHash(alg, &part, nullptr, 0, nullptr, 0, 0) == 0;
        }
        if (keep_going && !keep_going()) okd = false;
    }
    if (ferror(f)) okd = false;
    fclose(f);
    if (okd && (in_part > 0 || done == 0)) {
        std::string h;
        okd = finish(part, h);
        part = nullptr;
        if (okd) out.parts.push_back(h);
    }
    if (part) BCryptDestroyHash(part);
    std::string w;
    if (whole) { if (!finish(whole, w)) okd = false; }
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!okd || done != bytes || out.parts.size() != ed::parts_total(bytes)) return false;
    out.sha256 = w;
    return true;
}
#endif

// -------------------------------------------------------------- record ----

struct Record {
    std::string job_id, game_uuid, build_uuid, package_path;
    Identity package;
    std::string package_sha256;
    std::vector<std::string> part_sha256;
    std::uint64_t content_bytes = 0, file_count = 0;
    std::string launch_exe;
    std::string scanner, scan_path, engine_version, signature_version, verified_utc;
};

inline bool write_record(const fs::path& root, const Record& r) {
    using ee::json::quote;
    std::string b = "\"format\":" + quote(kFormat);
    b += ",\"job_id\":" + quote(r.job_id) + ",\"game_uuid\":" + quote(r.game_uuid) + ",\"build_uuid\":" + quote(r.build_uuid);
    b += ",\"package_path\":" + quote(r.package_path) + ",\"package_bytes\":" + std::to_string(r.package.bytes);
    b += ",\"package_mtime\":" + std::to_string(r.package.mtime) + ",\"package_sha256\":" + quote(r.package_sha256);
    b += ",\"content_bytes\":" + std::to_string(r.content_bytes) + ",\"file_count\":" + std::to_string(r.file_count);
    b += ",\"launch_exe\":" + quote(r.launch_exe) + ",\"scanner\":" + quote(r.scanner) + ",\"scan_path\":" + quote(r.scan_path);
    b += ",\"engine_version\":" + quote(r.engine_version) + ",\"signature_version\":" + quote(r.signature_version);
    b += ",\"verified_utc\":" + quote(r.verified_utc) + ",\"part_sha256\":[";
    for (size_t i = 0; i < r.part_sha256.size(); ++i) b += (i ? "," : "") + quote(r.part_sha256[i]);
    b += "]";
    return seal::write_sealed(root, record_path(root, r.job_id), b);
}

/** The sealed record of `job_id`; false when absent or not this Client's. */
inline bool read_record(const fs::path& root, const std::string& job_id, Record& r) {
    r = Record{};
    std::string t;
    if (!seal::read_sealed(root, record_path(root, job_id), t)) return false;
    std::string format;
    if (!ee::json::get_string(t, "format", format) || format != kFormat) return false;
    r.job_id = ee::json::opt_string(t, "job_id");
    r.game_uuid = ee::json::opt_string(t, "game_uuid");
    r.build_uuid = ee::json::opt_string(t, "build_uuid");
    r.package_path = ee::json::opt_string(t, "package_path");
    r.package.bytes = static_cast<std::uint64_t>(ee::json::opt_int(t, "package_bytes"));
    r.package.mtime = ee::json::opt_int(t, "package_mtime");
    r.package_sha256 = ee::json::opt_string(t, "package_sha256");
    r.content_bytes = static_cast<std::uint64_t>(ee::json::opt_int(t, "content_bytes"));
    r.file_count = static_cast<std::uint64_t>(ee::json::opt_int(t, "file_count"));
    r.launch_exe = ee::json::opt_string(t, "launch_exe");
    r.scanner = ee::json::opt_string(t, "scanner");
    r.scan_path = ee::json::opt_string(t, "scan_path");
    r.engine_version = ee::json::opt_string(t, "engine_version");
    r.signature_version = ee::json::opt_string(t, "signature_version");
    r.verified_utc = ee::json::opt_string(t, "verified_utc");
    std::string_view raw;
    std::vector<std::string_view> items;
    if (!ee::json::member(t, "part_sha256", raw) || !ee::json::items(raw, items)) return false;
    for (const auto& it : items) {
        std::string h;
        if (!ee::json::as_string(it, h) || !ee::is_sha256_hex(h)) return false;
        r.part_sha256.push_back(h);
    }
    return r.job_id == job_id && ee::is_sha256_hex(r.package_sha256) &&
           r.part_sha256.size() == ed::parts_total(r.package.bytes);
}

inline void remove_record(const fs::path& root, const std::string& job_id) {
    std::error_code ec;
    fs::remove(record_path(root, job_id), ec);
}

/** Does this Client's record vouch for the package the job names, as it
 *  stands on disk now? `why` says why not. Bytes are bound part by part as
 *  they are sent (transfers.hpp send_parts); this is the cheap gate. */
inline bool vouches(const fs::path& root, const ed::Job& j, Record& r, std::string& why) {
    if (!read_record(root, j.id, r)) { why = "no verification by this Client"; return false; }
    if (r.game_uuid != j.game_uuid || r.build_uuid != j.build_uuid || r.package_path != j.package_path) {
        why = "the verification is of another build or package";
        return false;
    }
    Identity now;
    if (!identity_of(path_of(j.package_path), now)) { why = "the package cannot be read"; return false; }
    if (now.bytes != r.package.bytes || now.mtime != r.package.mtime) { why = "the package changed since it was verified"; return false; }
    return true;
}

// ----------------------------------------------------------- incidents ----

struct Incident {
    std::string incident;        // the service body (malware_scan incident_json)
    std::string route;           // where it is reported
    bool examined = false;       // an Admin-claimed detection was looked into
    bool reported = false;
};

inline bool write_incident(const fs::path& root, const std::string& job_id, const Incident& i) {
    using ee::json::quote;
    const std::string b = "\"job_id\":" + quote(job_id) + ",\"route\":" + quote(i.route) + ",\"incident\":" + quote(i.incident) +
        ",\"examined\":" + (i.examined ? "true" : "false") + ",\"reported\":" + (i.reported ? "true" : "false");
    return seal::write_sealed(root, incident_path(root, job_id), b);
}

inline bool read_incident(const fs::path& root, const std::string& job_id, Incident& i) {
    i = Incident{};
    std::string t;
    if (!seal::read_sealed(root, incident_path(root, job_id), t)) return false;
    if (ee::json::opt_string(t, "job_id") != job_id) return false;
    i.route = ee::json::opt_string(t, "route");
    i.incident = ee::json::opt_string(t, "incident");
    bool b = false;
    i.examined = ee::json::get_bool(t, "examined", b) && b;
    b = false;
    i.reported = ee::json::get_bool(t, "reported", b) && b;
    return true;
}

} // namespace vclient::upload_verification
