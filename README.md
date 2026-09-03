# virule-client

The persistent local VIRULE component and its one-shot installer.

**virule.app is the interface. This software is plumbing.** The browser
owns every normal flow; these processes exist to answer it over a loopback
bridge, to handle `virule://` launches, to perform authenticated local
actions, and to remove VIRULE completely when asked.

Two Windows executables, one repository:

| Executable | Role |
|---|---|
| `virule-client.exe` | Persistent per-user client: loopback bridge (`ws://127.0.0.1:47612/v1`), `virule://` handler, QA tester credential writer, full VIRULE uninstall. Single-instance, on-demand (no service, no login task), idle-exits after 20 minutes with no connections. |
| `Virule-Setup.exe` | Disposable installer: fetches `https://downloads.virule.app/client/manifest.json`, downloads the approved SIGNED client release and verifies it (manifest SHA-256 + Authenticode + the VIRULE signing identity), installs to `%LOCALAPPDATA%\Programs\VIRULE`, registers `virule://` and the uninstall entry per-user (HKCU, no elevation), starts the client, hands the browser back, exits. ONE small native card ("Setting up VIRULE..." / "Setup is complete."); no wizard, no pages, no choices. Embeds NO client payload. |

Full design: `docs/ARCHITECTURE.md`.

## Build

Development (unsigned, one pass):

```
powershell -ExecutionPolicy Bypass -File helpers\build.ps1
```

virule-client.exe and Virule-Setup.exe are INDEPENDENT signed artifacts:
Setup embeds nothing and downloads the approved client release at install
time, so there is no build coupling and no required order. Nothing in this
repo signs; signing is centralized in `VIRULE_SECURITY\artifact-signing`
(the existing VIRULE Microsoft Artifact Signing workflow):

```
client: helpers\build.ps1 -Stage client  ->  sign_client.bat
setup : helpers\build.ps1 -Stage setup   ->  sign_client_setup.bat
```

Output: `build\Release\x64\{virule-client.exe, Virule-Setup.exe}`.

## Distribution (downloads.virule.app, Cloudflare R2)

The R2 bucket `virule-downloads` behind `https://downloads.virule.app`
serves exactly three things:

```
/Virule-Setup.exe                       the installer (stable URL)
/client/manifest.json                   the ONE mutable pointer to the
                                        approved client release (no-cache)
/client/<version>/virule-client.exe     immutable versioned client binaries
```

`helpers\publish.ps1` is the deterministic publisher: it refuses unsigned
artifacts, uploads the client to its immutable versioned path (an existing
version with different bytes is a hard failure, never an overwrite),
regenerates the manifest (`version`/`url`/`sha256`/`size`), uploads Setup
only when its bytes changed, and re-downloads everything to verify. It uses
the established `CLOUDFLARE_VIRULE_API_TOKEN` credential convention. The
client version comes from `src\shared\version.h`; bump it before publishing
a changed client.

At install time Setup enforces: manifest structure, the declared size, the
manifest SHA-256 (never waived), Authenticode, and the VIRULE signer
identity. `--dev-unsigned` (development only) waives only the signature
gates; `--manifest-url=` points Setup at a local test manifest and relaxes
only the downloads.virule.app host pin.

## Test

```
node tools\protocol_routing_test.mjs                  # virule:// routing (no client needed)
build\Release\x64\virule-client.exe --no-register     # dev: keep the machine's virule:// as-is
node tools\bridge_test.mjs                            # bridge protocol/security matrix
```

`protocol_routing_test.mjs` is the regression for the homepage-to-QA
misroute: it reads the routing source of BOTH components and fails if a
generic `virule://open` could reach QA, or if the two implementations of
the grammar ever drift apart.

## Boundaries

- No SidecarK, no CEF, no wrapper, no VIRULE Admin code in this repo.
- The QA credential formats (`dev_machine.cred`, `qa_tester.cred`) and the
  `/v1/qa/redeem` wire contract are the EXISTING VIRULE product contracts,
  vendored byte-identical under `third_party/virule_core/` (source of
  truth: the `VIRULE/v2_mvp` tree). Never fork their behavior here.
- Command dispatch is a closed, versioned message set. Future authenticated
  actions (install/update package, install/launch/remove game, report
  managed installs) extend it; nothing generic is ever exposed.
