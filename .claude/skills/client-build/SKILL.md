---
name: client-build
description: Build virule-client.exe and Virule-Setup.exe (production or staging), run the client test harnesses, and know how each artifact is signed and published.
---

# Client build

Authority: `helpers\build.ps1`, `publish.ps1`, `publish_staging_client.ps1`
headers; `docs\ARCHITECTURE.md`. Nothing in this repo signs; signing is
`VIRULE_SECURITY\artifact-signing` (`sign_client.bat`, `sign_client_setup.bat`).

## Build

```
powershell -ExecutionPolicy Bypass -File helpers\build.ps1 [-Stage all|client|setup] [-Environment Production|Staging]
```

Output `build\Release\x64\{virule-client.exe, Virule-Setup.exe}`;
`-Environment Staging` writes to `build\Release\x64\staging\` with
`VIRULE_ENV_STAGING` defined (the staging half of `src\shared\environment.hpp`
and the vendored `launch_policy.hpp`). The two executables are INDEPENDENT
signed artifacts with no build coupling: Setup embeds nothing and
downloads the approved client at install time. Dropbox holds fresh files
briefly (MSB6003 / C1041); the script retries those, so a retried
transient is not a failure.

## Test (no client needed unless stated)

```
node tools\protocol_routing_test.mjs      # virule:// grammar of BOTH components; fails on divergence
build\Release\x64\virule-client.exe --no-register   # dev run without touching the machine's virule://
node tools\bridge_test.mjs                # bridge protocol/security matrix
```

Never run the harnesses against the owner's installed client unless the
task says so; site suites need the real client evicted first.

## Publish

- Production: after `sign_client` / `sign_client_setup`,
  `helpers\publish.ps1` (`-Validate` first). It refuses unsigned
  artifacts and refuses to rewrite a published version's client bytes:
  bump `src\shared\version.h` instead. The release tag is `v<version>`;
  the latest release IS the approved release. Normally driven by the
  promotion (Skill `release-production` in v2_mvp).
- Staging: `helpers\publish_staging_client.ps1` publishes the UNSIGNED
  staging build to the fixed `client-staging` tag on
  `getvirule/virule-staging-releases` and refuses a production-configured
  binary. Normally driven by `release_staging.ps1` (Skill `release-staging`).
- Core headers under `third_party\virule_core` are vendored byte-identical
  from `VIRULE\v2_mvp`; re-vendor when the originals change.
