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
| `Virule-Setup.exe` | Disposable installer: verifies its embedded SIGNED client payload (baked SHA-256 + Authenticode), installs to `%LOCALAPPDATA%\Programs\VIRULE`, registers `virule://` and the uninstall entry per-user (HKCU, no elevation), starts the client, exits. No wizard, no pages, no windows on success. |

Full design: `docs/ARCHITECTURE.md`.

## Build

```
powershell -ExecutionPolicy Bypass -File helpers\build.ps1          # development (unsigned)
powershell -ExecutionPolicy Bypass -File helpers\build.ps1 -Sign    # release (signed)
```

Release order is fixed and enforced by the script: build client, sign
client, embed the signed client + its hash into Setup, build Setup, sign
Setup. Signing rides the existing VIRULE Microsoft Artifact Signing
workflow (`VIRULE_SECURITY\artifact-signing`: same signtool, dlib,
metadata, timestamp service; no new Azure configuration).

Output: `build\Release\x64\{virule-client.exe, Virule-Setup.exe}`.

An unsigned development Setup installs only with `--dev-unsigned` (the
payload hash gate always holds; only the Authenticode gate is waived).

## Test

```
build\Release\x64\virule-client.exe --no-register    # dev: keep the machine's virule:// as-is
node tools\bridge_test.mjs                            # bridge protocol/security matrix
```

## Boundaries

- No SidecarK, no CEF, no wrapper, no VIRULE Admin code in this repo.
- The QA credential formats (`dev_machine.cred`, `qa_tester.cred`) and the
  `/v1/qa/redeem` wire contract are the EXISTING VIRULE product contracts,
  vendored byte-identical under `third_party/virule_core/` (source of
  truth: the `VIRULE/v2_mvp` tree). Never fork their behavior here.
- Command dispatch is a closed, versioned message set. Future authenticated
  actions (install/update package, install/launch/remove game, report
  managed installs) extend it; nothing generic is ever exposed.
