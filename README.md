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
| `Virule-Setup.exe` | Disposable installer: fetches the latest GitHub Release's `manifest.json`, downloads the approved SIGNED client release and verifies it (manifest SHA-256 + Authenticode + the VIRULE signing identity), installs to `%LOCALAPPDATA%\Programs\VIRULE`, registers `virule://` and the uninstall entry per-user (HKCU, no elevation), starts the client, hands the browser back, exits. ONE small native card ("Setting up VIRULE..." / "Setup is complete."); no wizard, no pages, no choices. Embeds NO client payload. |

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

## Distribution (GitHub Releases on getvirule/virule-client)

GitHub Releases are the MVP binary distribution source. Each release tag
`v<version>` carries exactly three assets:

```
Virule-Setup.exe        the installer
virule-client.exe       the immutable versioned client binary
manifest.json           describes THAT release's client
                        (version / direct asset url / sha256 / size)
```

The LATEST release is the approved release: Setup fetches
`https://github.com/getvirule/virule-client/releases/latest/download/manifest.json`
and the site links
`.../releases/latest/download/Virule-Setup.exe`; publishing a new release
is what moves the pointer. Direct asset URLs only, never the release page.

`helpers\publish.ps1` is the deterministic publisher: it refuses unsigned
artifacts, refuses to replace a published version's virule-client.exe with
different bytes (bump `src\shared\version.h` instead), regenerates the
manifest, uploads Setup only when its bytes changed, and re-downloads
every public asset URL to verify. It uses the machine's existing `gh`
login.

At install time Setup enforces: manifest structure, an HTTPS
`releases/download/` url pinned to this repository, the declared size, the
manifest SHA-256 (never waived), Authenticode, and the VIRULE signer
identity. GitHub is a host, not a trust anchor. `--dev-unsigned`
(development only) waives only the signature gates; `--manifest-url=`
points Setup at a local test manifest and relaxes only the repository pin.

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
