# VIRULE Client architecture (Phase 1)

Current state only. When a change makes something here untrue, REPLACE it.

## The bridge (transport + discovery)

ONE loopback WebSocket listener: `ws://127.0.0.1:47612`, handshake path
`/v1` (the API version; unknown paths are refused). Discovery is fixed and
documented: the browser opens the socket and waits for the hello
`{"virule_client":1,"v":1,"version":"x.y.z"}`; a refused or silent socket
means no client. The VIRULE Admin's QA bridge keeps its own listener on
47611; the two coexist and the invitation page probes both.

The port binds 127.0.0.1 ONLY. If 47612 is held by a foreign process the
client logs it and exits; there is no fallback port and no remote exposure
of any kind.

LOCAL NETWORK ACCESS (verified in Edge, 2026-09-02): current Chromium
gates a public https origin's loopback sockets behind the
`local-network-access` permission - the first attempt shows a browser
permission prompt in headed browsing and fails with
ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS when denied. The virule.app
pages therefore probe quietly only while the permission is already
granted (Permissions API query), attempt ungated only after an explicit
user action (ACCEPT), and never depend on the bridge to complete QA
verification (virule:// + /qa/link polling is the bridge-free path). Do
not paper over a denial with flags or lesser transports; the permission
prompt IS the standards path, and local origins (wrangler dev, vite) are
exempt, which is why development never sees it.

Origin policy: browser connections must present one of the explicit
allowed origins (`https://virule.app`, `https://www.virule.app`, plus the
listed local development origins in `src/client/bridge.hpp`); anything
else is dropped at handshake. A connection with NO Origin header is a
local control connection (second-instance forwarding, Setup's shutdown
request); local processes already run with the user's full power, so the
origin check defends against the web, not against local code.

### Message set (closed, versioned)

| From | Message | Effect |
|---|---|---|
| page | `{"type":"status"}` | version, capability list, connected-page count |
| page | `{"type":"qa_accept","token":"<64 hex>"}` | asynchronous QA redemption (below) |
| page | `{"type":"uninstall","nonce","timestamp","signature"}` | full VIRULE uninstall after verification |
| local | `{"type":"qa_verify_url","token"}` | a second instance forwarding a `virule://` launch |
| local | `{"type":"wake"}` / `{"type":"shutdown"}` | keep-alive no-op / clean exit (Setup replacing the exe) |

Client pushes: `{"type":"qa_result","token","state"}` to every connected
page (each page filters by token). Everything else answers
`{"type":"error"}`. Frames over 4 KB, unmasked client frames, and
malformed handshakes drop the connection.

`status` carries `"pages"`, the number of connected virule.app PAGES.
Local control connections are never counted, which is what makes it
usable by Setup: Setup asks over its own local connection whether a
browser page reached the freshly installed client, and so whether the
browser is still driving the flow (see "Setup's browser handoff").

## Security model

- **No generic surface.** No filesystem endpoint, no process-launch
  endpoint, no eval. The message set above is everything.
- **QA credential writes** are authorized by the service-minted,
  24-hour, single-use invitation token: the client redeems it at
  `POST https://api.virule.app/v1/qa/redeem` with this machine's Ed25519
  proof, the SERVICE decides (issuer check, binding, sibling
  invalidation), and the returned credential's service signature is
  verified against the embedded VIRULE public key
  (`launch_policy::kViruleEmbargoPublicKeyHex`) before anything is
  written. A malformed `virule://` URL or token is rejected with no
  action; query-string data is never trusted.
- **Uninstall** requires a fresh signed authorization from the VIRULE
  service (`POST virule.app/client/uninstall-auth` fetched same-origin by
  the page): message `virule-client-uninstall.v1|<nonce>|<timestamp>`,
  verified against the same embedded public key, timestamp within 600 s,
  nonce single-use per process lifetime. Reaching localhost is never by
  itself authority to remove software.
- Only PUBLIC verification material is embedded. No server private key
  exists outside the Worker.

## Machine identity and the QA credential (existing product contracts)

`%LOCALAPPDATA%\VIRULE\security\dev_machine.cred` is the machine's VIRULE
identity (Ed25519 seed under DPAPI, entropy = the file's own install_id),
exactly as the Admin creates it and the wrapper consumes it. The client
uses a valid existing file AS-IS (so Admin machines keep ONE identity) and
creates one (random install id) only when nothing usable exists,
recording `created_dev_machine_cred` provenance in
`%LOCALAPPDATA%\VIRULE\client\state.json`.

`security\qa_tester.cred` is written after a `verified` redemption, in the
exact `qa_tester_credential` JSON shape the wrapper's
`qa_runtime_client.hpp` reads. SUPER ADMIN QA TEST MODE (the Admin's
`%LOCALAPPDATA%\VIRULE\qa_test_mode` flag file) is honored: ephemeral
throwaway identity + the isolated `qa_tester_test.cred`.

Browser/native ownership of the QA outcome mirrors the Admin: result is
pushed to pages on this bridge; with none, a running Admin GUI session's
47611 bridge is asked to deliver it to its pages; only with no page
anywhere does the minimal native result card appear.

## virule://

ONE protocol, TWO components, DETERMINISTIC routing. The scheme carries
exactly two grammars and they are never confused:

| URL | Meaning |
|---|---|
| `virule://qa/...` | the QA namespace (`qa/verify/<64 hex>` is the invitation page's ACCEPT fallback) |
| `virule://open` | a GENERIC WAKE: no task, NEVER a QA event, never a QA surface |

Anything else is rejected with no action and no UI. Both components decide
the wake FIRST and only then the QA namespace, so a wake can never fall
into QA. The grammar functions are implemented identically in
`src/shared/protocol_reg.hpp` and the Admin's `src/cli/main.cpp`
(`qa_protocol`); `tools/protocol_routing_test.mjs` fails if they diverge.

REGRESSION THIS ENCODES (2026-09-02): a homepage `virule://open` was caught
by VIRULE Admin, which treated every `virule://` launch as QA and, with
Super Admin QA TEST MODE on, showed an expired QA invitation. A generic
wake must never produce a QA surface in either component.

OWNERSHIP: registration is per-user (`HKCU\Software\Classes\virule`), the
same registry shape in both components. When the client is INSTALLED it is
the canonical handler, because it is the process the browser's bridge is
waiting for. The client self-heals its registration on every run
(`--no-register` skips this for development). The Admin no longer takes
the scheme back on every GUI launch: it prefers the installed client, heals
a registration that names neither, and registers itself only when no client
is installed. Both still handle `qa/verify` identically, so QA works
whoever holds it.

A generic wake reaching the Admin is a no-op that heals the registration
and, if the client is installed, launches it with `virule://open` so the
browser's bridge finds it. It reads no QA state at all, test mode included.

Single instance: `Local\ViruleClient.Singleton` mutex; a second launch
forwards its URL (or a wake) to the running instance over the bridge and
exits.

## Distribution (GitHub Releases, getvirule/virule-client)

Setup and the client are INDEPENDENT signed artifacts published as GitHub
Release assets on `getvirule/virule-client` (a public repository; release
assets are only publicly downloadable from public repositories):

| Asset (per release tag `v<version>`) | Mutability |
|---|---|
| `Virule-Setup.exe` | replaced when Setup changes |
| `virule-client.exe` | IMMUTABLE; a published version is never rewritten |
| `manifest.json` | describes THAT release's client |

The LATEST release is the approved release. Setup follows
`releases/latest/download/manifest.json`; the site links
`releases/latest/download/Virule-Setup.exe`; publishing a new release is
the act that moves the pointer. Direct asset URLs only (they redirect
https to https onto GitHub's CDN; WinHTTP follows that by default), never
the human release page.

The manifest is minimal and secret-free:
`{"version","url","sha256","size"}` in COMPACT JSON (the marker scanner
takes no whitespace). `helpers/publish.ps1` is the only writer: it refuses
unsigned artifacts, refuses to overwrite a published version with
different bytes, and verifies every public asset URL by re-downloading it.
GitHub is a HOST, not a trust anchor: everything a user runs is still
gated by the manifest hash plus the VIRULE Authenticode identity below.

## Install / uninstall

Setup fetches the manifest, validates it structurally (version grammar, an
HTTPS `github.com/getvirule/virule-client/releases/download/` url, 64-hex
sha256, bounded size), downloads the approved client capped at the
declared size, and
enforces IN ORDER: exact size, manifest SHA-256 (never waived),
Authenticode validity, and the VIRULE signer identity
(`CN=Heath Michaels`) on the staged file. Any failure refuses the install
with one short human line; the technical reason goes to the log.

It then installs to `%LOCALAPPDATA%\Programs\VIRULE\virule-client.exe`,
registers `virule://` + the `ViruleClient` HKCU uninstall entry
(DisplayName "VIRULE", `--uninstall`), records the INSTALLED CLIENT's
version (the manifest's) in state.json, starts the client, hands the
browser back, exits. Development seams: `--dev-unsigned` waives only the
signature gates; `--manifest-url=` fetches the manifest elsewhere and
relaxes only the repository pin.

### Setup's one native surface

Setup used to run and vanish with no window: technically correct (the
browser owns the flow) and, in practice, untrustworthy. It now shows ONE
small card in VIRULE's native visual language (the Admin splash grammar:
rounded card, yellow V mark, spaced wordmark, one muted line), and nothing
more. NOT A WIZARD: no pages, no Next/Back, no destination picker, no
component list, no license page, no user choice of any kind.

| State | Copy |
|---|---|
| Working | `Setting up VIRULE...` + a subtle indeterminate bar |
| Complete | `Setup is complete.` briefly, then it closes itself |
| Failed | one short human sentence; the technical reason goes to the log only |

The status line sits at the same coordinates in every state. The copy never
says "return to your browser": by then the browser may be closed, and
recovering it is Setup's job. Setup never sits open indefinitely (a failure
surface is dismissible and leaves on its own after 60 s).

### Setup's browser handoff

Setup has ONE job: install, register and start the client. It does not
decide whether the user wanted Admin, QA or anything else. THE BROWSER OWNS
THAT INTENT (see "Browser-owned pending intent").

After starting the client, Setup allows a short grace period (12 s) for a
virule.app page to reach the client's bridge, asking over its own local
connection (`status` -> `pages`). That is the NORMAL first-install outcome:
the page that sent the user here is still open and picks the flow back up.
When it happens Setup opens NOTHING; a duplicate tab would be a bug.

Only when no page appears does Setup reopen the resume URL
(`https://virule.app/?resume=setup`; `--resume-url=` is the development
seam). The browser choice is a hierarchy, so a flow begun in Brave comes
back in Brave even when Edge is the machine default:

1. the ORIGINATING browser process is still alive -> open the URL through
   that browser's executable, so it lands in that same running instance;
2. that process is gone but its executable was captured -> launch that same
   browser application with the URL;
3. the originating browser cannot be determined -> the Windows default
   browser, and only then.

### Originating-browser capture

`src/setup/origin_browser.hpp`, run FIRST at Setup startup, before any
install work, because that is the only moment the browser is certain to
still exist. It walks the process ANCESTRY upward (up to 8 levels): a
downloaded-file launch may arrive through a shell hop or Explorer, so the
immediate parent is never assumed to be the browser. Recognized names:
Brave, Edge, Chrome, Firefox, Opera, Opera GX, Vivaldi. It records the
image name, the full executable path, the PID, and a LIVE HANDLE, so
liveness can never be fooled by PID reuse (a parent whose creation time is
later than its child's is rejected as a recycled PID). The whole ancestry
chain goes to the Setup log.

NOT A SECURITY INPUT. Browser identity authorizes nothing, is never sent
anywhere and is never written into installed state; it only decides which
application shows a URL that is a compile-time constant. A wrong guess
costs the user one tab.

## Browser-owned pending intent

The browser remembers WHY the user started, because that is where the user
said it: "Get VIRULE" on the homepage is `INSTALL_ADMIN`, ACCEPT on an
invitation is `QA_ACCEPT`. The record is persistent (localStorage, key
`virule.pending`, 24 h expiry) on the virule.app origin, so it survives the
browser closing during setup; sessionStorage would be gone exactly when it
is needed. Shape and expiry are implemented twice, in the site's
`src/client/pendingIntent.ts` and inline in the Worker's QA page
(`VIRULE_BACKEND/src/qa_page.ts`); change one, change both.

UX STATE, NEVER AUTHORIZATION. QA remains authorized end to end by the
existing signed flow (service-minted invitation token, redemption with this
machine's proof, credential signature verified against the embedded VIRULE
key). A forged record can at most reopen a page. It is cleared at every
terminal state.

`INSTALL_ADMIN` also carries the desktop-shortcut preference asked at the
protocol preflight. Nothing acts on it yet: installing VIRULE Admin is
Phase 2, and a connected client with `INSTALL_ADMIN` pending says only
"Ready to install VIRULE" and never claims the Admin is installed.

Full VIRULE uninstall removes an EXPLICIT ownership inventory and nothing
else (see `src/shared/uninstall.hpp`): the install dir, the client state
dir, `qa_tester*.cred`, `dev_machine.cred` ONLY when client-created AND no
`virule.db` exists, `virule://` ONLY while it points at this client, the
uninstall entry, and the shared `VIRULE\` folders only if left empty. The
running exe hands removal to a `%TEMP%` copy (`--finish-uninstall <pid>`)
so no broken executable is left behind. A full VIRULE uninstall and
removing an individual future game are SEPARATE actions forever; this
inventory must never grow a recursive game-library delete.

## Phase 2 integration point

The browser's `status` message and the versioned message set are the seam:
Phase 2 adds an authenticated "what VIRULE Admin version is installed"
answer plus install/update commands driven by the remote manifest, behind
the same bridge, the same origin policy, and the same
server-issued-authorization pattern. Nothing in Phase 1 fakes any of it.
