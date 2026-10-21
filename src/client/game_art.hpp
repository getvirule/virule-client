#pragma once
// GAME ART (2026-10-21; docs/ARCHITECTURE.md "Game art"; the service side is
// VIRULE_BACKEND src/evaluations/art.ts): the box art of an evaluation game,
// carried between the Admin and the service by this installation, like every
// other authorized transfer. LOCAL ONLY bridge message `game_art`:
//
//   {"type":"game_art","action":"upload","game_uuid":"<32 hex>","path":"<image file>"}
//       The developer's Admin hands over its Game's local art. The file is
//       read here (an image of at most 16 MiB: PNG, JPEG, WebP, BMP or ICO,
//       recognized by its bytes), its SHA-256 computed, and it is stored as
//       the game's art (PUT /v1/evaluations/games/<uuid>/art). The service
//       keeps one image per game; the same image again changes nothing.
//       Answers {"type":"game_art","ok":true,"sha256":"...","path":"<cached copy>"}.
//
//   {"type":"game_art","action":"fetch","game_uuid":"<32 hex>","sha256":"<64 hex>"
//    [,"assignment_id":"<32 hex>"]}
//       The art the service names by its digest, as a local file the Admin
//       can show: from the cache when it is there, otherwise downloaded (the
//       developer's own game, or with `assignment_id` the evaluator's
//       accepted assignment), its SHA-256 verified, then cached.
//       Answers {"type":"game_art","ok":true,"path":"..."}.
//
// Every failure answers {"type":"game_art","ok":false,"message":"..."}; the
// Admin then keeps the placeholder it already shows.
//
// THE CACHE is %LOCALAPPDATA%\VIRULE\art\<sha256>.<ext>, content-addressed:
// a changed image is another file, so a cached copy is never stale, and it
// survives a sign-out (the bytes are the image, nothing of the account).

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "client/transfers.hpp"

namespace vclient::game_art {

namespace fs = std::filesystem;
namespace tr = vclient::transfers;
namespace ev = virule::core::evaluation_evidence;
namespace js = vclient::json_scan;

inline constexpr std::uint64_t kMaxArtBytes = 16ull * 1024 * 1024;   // art.ts ART_MAX_BYTES

inline fs::path cache_dir(const fs::path& root) { return root / L"art"; }

/** The file extension of the image the bytes ARE (art.ts sniffImageType), or "". */
inline const wchar_t* image_ext(const unsigned char* b, size_t n) {
    if (n >= 8 && b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4e && b[3] == 0x47 && b[4] == 0x0d && b[5] == 0x0a && b[6] == 0x1a && b[7] == 0x0a) return L".png";
    if (n >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff) return L".jpg";
    if (n >= 12 && b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F' && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') return L".webp";
    if (n >= 26 && b[0] == 'B' && b[1] == 'M') return L".bmp";
    if (n >= 6 && b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == 0 && (b[4] | (b[5] << 8)) > 0) return L".ico";
    return L"";
}

inline bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

/** A cached image of this digest, or an empty path. */
inline fs::path cached(const fs::path& root, const std::string& sha256) {
    static const wchar_t* kExts[] = { L".png", L".jpg", L".webp", L".bmp", L".ico" };
    std::error_code ec;
    for (const wchar_t* e : kExts) {
        const fs::path p = cache_dir(root) / fs::path(std::wstring(sha256.begin(), sha256.end()) + e);
        if (fs::is_regular_file(p, ec) && !ec && fs::file_size(p, ec) > 0 && !ec) return p;
    }
    return {};
}

inline std::string utf8_of(const fs::path& p) {
    const std::u8string u = p.u8string();
    return std::string(u.begin(), u.end());
}

inline std::string failure(const std::string& message) {
    return "{\"type\":\"game_art\",\"ok\":false,\"message\":" + ev::json::quote(message) + "}";
}

inline bool read_all(const fs::path& p, std::string& out, std::uint64_t max) {
    out.clear();
    std::error_code ec;
    const auto size = fs::file_size(p, ec);
    if (ec || size == 0 || size > max) return false;
    FILE* f = nullptr;
    if (_wfopen_s(&f, p.wstring().c_str(), L"rb") != 0 || !f) return false;
    out.resize(static_cast<size_t>(size));
    const size_t got = fread(out.data(), 1, out.size(), f);
    fclose(f);
    return got == out.size();
}

/** Place verified bytes in the cache under their digest; the cached path. */
inline fs::path store(const fs::path& root, const std::string& sha256, const std::string& bytes) {
    const wchar_t* ext = image_ext(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    if (!*ext) return {};
    std::error_code ec;
    fs::create_directories(cache_dir(root), ec);
    const fs::path dst = cache_dir(root) / fs::path(std::wstring(sha256.begin(), sha256.end()) + ext);
    if (!ev::write_file_atomic(dst, bytes)) return {};
    return dst;
}

inline std::string upload(const std::string& payload, const fs::path& root, tr::Service& svc) {
    std::string game_uuid, path;
    (void)js::find_string_in(payload, 0, payload.size(), "game_uuid", game_uuid);
    (void)js::find_string_in(payload, 0, payload.size(), "path", path);
    if (!ev::is_hex32(game_uuid) || path.empty()) return "{\"type\":\"error\"}";
    std::string bytes;
    if (!read_all(tr::path_of(path), bytes, kMaxArtBytes)) return failure("The art file could not be read.");
    if (!*image_ext(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size())) {
        return failure("The art file is not a PNG, JPEG, WebP, BMP or ICO image.");
    }
    const std::string sha = tr::sha256_hex(bytes);
    std::string email;
    if (!svc.signed_in(email)) return failure("Sign in to VIRULE first.");
    const tr::Reply r = svc.call("PUT", "/v1/evaluations/games/" + game_uuid + "/art", bytes,
                                 "application/octet-stream", { { "x-virule-art-sha256", sha } });
    if (r.status != 200) {
        return failure(r.status == 0 ? "Couldn't reach our servers right now." : tr::detail::body_message(r.body));
    }
    const fs::path cached_copy = store(root, sha, bytes);
    return "{\"type\":\"game_art\",\"ok\":true,\"sha256\":\"" + sha + "\",\"path\":" + ev::json::quote(utf8_of(cached_copy)) + "}";
}

inline std::string fetch(const std::string& payload, const fs::path& root, tr::Service& svc) {
    std::string game_uuid, sha, assignment;
    (void)js::find_string_in(payload, 0, payload.size(), "game_uuid", game_uuid);
    (void)js::find_string_in(payload, 0, payload.size(), "sha256", sha);
    (void)js::find_string_in(payload, 0, payload.size(), "assignment_id", assignment);
    if (!ev::is_hex32(game_uuid) || !is_hex64(sha) || (!assignment.empty() && !ev::is_hex32(assignment))) {
        return "{\"type\":\"error\"}";
    }
    if (const fs::path hit = cached(root, sha); !hit.empty()) {
        return "{\"type\":\"game_art\",\"ok\":true,\"path\":" + ev::json::quote(utf8_of(hit)) + "}";
    }
    std::string email;
    if (!svc.signed_in(email)) return failure("Sign in to VIRULE first.");
    const std::string route = assignment.empty() ? "/v1/evaluations/games/" + game_uuid + "/art"
                                                 : "/v1/assignments/" + assignment + "/art";
    std::error_code ec;
    fs::create_directories(cache_dir(root), ec);
    const fs::path part = cache_dir(root) / fs::path(std::wstring(sha.begin(), sha.end()) + L".part");
    FILE* out = nullptr;
    if (_wfopen_s(&out, part.wstring().c_str(), L"wb") != 0 || !out) return failure("The art could not be saved.");
    std::uint64_t got = 0;
    unsigned long status = 0;
    const bool ok = svc.get_range_to_file(route, 0, kMaxArtBytes - 1, out, got, status, {});
    fclose(out);
    std::string bytes;
    const bool read = ok && got > 0 && read_all(part, bytes, kMaxArtBytes);
    fs::remove(part, ec);
    if (!ok || !read) {
        return failure(status == 0 ? "Couldn't reach our servers right now." : "The art could not be downloaded.");
    }
    if (tr::sha256_hex(bytes) != sha) return failure("The downloaded art does not match its digest.");
    const fs::path dst = store(root, sha, bytes);
    if (dst.empty()) return failure("The art could not be saved.");
    return "{\"type\":\"game_art\",\"ok\":true,\"path\":" + ev::json::quote(utf8_of(dst)) + "}";
}

/** The bridge's `game_art`. `svc` null = no service here (answers ok:false). */
inline std::string handle(const std::string& payload, const fs::path& root, tr::Service* svc) {
    std::string action;
    (void)js::find_string_in(payload, 0, payload.size(), "action", action);
    if (action != "upload" && action != "fetch") return "{\"type\":\"error\"}";
    if (!svc) return failure("No service here.");
    return action == "upload" ? upload(payload, root, *svc) : fetch(payload, root, *svc);
}

} // namespace vclient::game_art
