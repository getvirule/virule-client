#pragma once
// THE CLIENT'S VIEW OF THE ENVIRONMENT SEAM.
//
// THIS FILE NAMES NO ENVIRONMENT. Every host, site URL, release repository
// and signature rule lives in exactly one place for every C++ component,
// `virule/core/launch_policy.hpp` (vendored into this repo under
// third_party/), and this header only re-exports those constants under the
// names the client's call sites use, plus the ONE thing that is genuinely
// client-specific: the local development origins.
//
// It exists so that a client call site reads `env::kAdminManifestHost`
// rather than reaching into launch_policy for a value that means something
// slightly different to the Admin. It is a view, not a second source of
// truth: change a URL in launch_policy.hpp and every component in both
// repositories moves together, which is the property that stops the Admin's
// self-heal and the client's own updater from ever disagreeing about which
// client release is the right one.

#include <string>

#include "virule/core/launch_policy.hpp"

namespace vclient::env {

namespace lp = virule::core::launch_policy;

// True only in a build that defined VIRULE_ENV_STAGING.
inline constexpr bool kStaging = lp::kIsStagingBuild;

// The site this build belongs to.
inline constexpr const wchar_t* kSiteUrl = lp::kSiteUrlW;
inline constexpr const char* kSiteDisplayName = lp::kSiteDisplayName;

// The approved Admin manifest, and the prefix every manifest package url
// must carry: a DIRECT versioned release-asset URL of this environment's
// Admin release repository, nothing else.
inline constexpr const wchar_t* kAdminManifestHost = lp::kAdminManifestHostW;
inline constexpr const wchar_t* kAdminManifestPath = lp::kAdminManifestPathW;
inline constexpr const char* kAdminPackageUrlPrefix = lp::kAdminPackageUrlPrefix;

// The client's own release manifest and the url pin that goes with it.
// Setup and the client self-update read the same pair, so an installed
// client can only ever replace itself from its own environment.
inline constexpr const wchar_t* kClientManifestHost = lp::kClientManifestHostW;
inline constexpr const wchar_t* kClientManifestPath = lp::kClientManifestPathW;
inline constexpr const wchar_t* kClientManifestUrl  = lp::kClientManifestUrlW;
inline constexpr const char* kClientUrlPrefix = lp::kClientUrlPrefix;

// Whether a downloaded artifact must carry a valid VIRULE Authenticode
// signature. TRUE in every build that is not an explicit staging build; the
// exact-size and exact-SHA-256 gates are NOT relaxed in either environment.
inline constexpr bool kRequireAuthenticode = lp::kRequireAuthenticode;
inline constexpr const wchar_t* kExpectedSigner = lp::kExpectedSignerW;

// ACCEPTED BROWSER ORIGINS.
//
// This environment's site comes from the seam (lp::is_site_origin, the same
// check the Admin's QA bridge uses, so the two loopback listeners can never
// disagree about which pages they answer). The LOCAL DEVELOPMENT origins
// below are the one genuinely client-specific entry: the vite dev server for
// the site and wrangler dev for the QA page both talk to a locally built
// client, and neither exists for the Admin.
//
// The site origins are deliberately NOT repeated here. Never '*', never a
// wildcard. The two environments' site lists do not overlap, so a production
// client does not answer the staging site and a staging client does not
// answer virule.app.
inline constexpr const char* kDevOrigins[] = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "https://localhost:8788",
    "https://127.0.0.1:8788",
};

inline bool origin_allowed(const std::string& origin) {
    if (lp::is_site_origin(origin)) return true;
    for (const char* dev : kDevOrigins) {
        if (origin == dev) return true;
    }
    return false;
}

} // namespace vclient::env
