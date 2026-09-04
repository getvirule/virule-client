# VIRULE Client architecture (Phase 2)

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

An invite token is either the CURRENT 32-character Base64URL mint
(192-bit, case-sensitive) or the LEGACY 64-lowercase-hex mint, accepted
until those invites expire (`protocol_reg::is_invite_token`, one grammar
in both components).

| From | Message | Effect |
|---|---|---|
| page | `{"type":"status"}` | version, capability list, connected-page count, the Admin status block |
| page | `{"type":"qa_accept","token":"<invite token>"}` | asynchronous QA redemption (below) |
| page/local | `{"type":"admin_install","shortcut":true\|false}` | the verified staged Admin install/update (below); a LOCAL sender is the Admin's own Settings Update through its host, shortcut always false there |
| page | `{"type":"admin_open"}` | launch the managed Admin installation, and nothing else |
| page | `{"type":"surface_ack"}` | the page states its next feedback view is rendered and active (the Setup takeover's browser acknowledgement) |
| page | `{"type":"uninstall","nonce","timestamp","signature","delete_data"}` | VIRULE uninstall after verification; `delete_data` (default false) is the explicit destructive option |
| local | `{"type":"qa_verify_url","token"}` | a second instance forwarding a `virule://` launch |
| local | `{"type":"wake"}` / `{"type":"shutdown"}` | keep-alive no-op / clean exit (Setup replacing the exe) |
| local | `{"type":"admin_update_check"}` | answers `admin_update_status` (installed/approved versions + `update`); refreshes the cached manifest check when stale |
| local | `{"type":"setup_takeover",...}` | Virule-Setup transferring the pending-operation envelope, or its explicit absence (see "The Setup takeover") |
| local | `{"type":"setup_wait"}` | answers `{"released":bool}`: whether the takeover's next feedback surface is ready, so Setup's card may close |

Client pushes: `{"type":"qa_result","token","state"}` and
`{"type":"admin_result","state","version"}` to every connected page.
The status answer's `"admin"` block is
`{"installed":bool,"version":"...","running":bool}` - the managed
installation only (below); a development tree is never reported, and an
EMPTY version with installed:true means genuinely unknown (never to be
rendered as a currency claim).
Everything else answers `{"type":"error"}`. Frames over 4 KB, unmasked
client frames, and malformed handshakes drop the connection.

`status` carries `"pages"`, the number of connected virule.app PAGES.
Local control connections are never counted.

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
| `virule://qa/...` | the QA namespace (`qa/verify/<invite token>` is the invitation page's ACCEPT fallback; token = 32 Base64URL or legacy 64 hex) |
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
version (the manifest's) in state.json, starts the client, transfers the
takeover, and waits for the client's release (see "The Setup takeover").
Development seams: `--dev-unsigned` waives only the signature gates;
`--manifest-url=` fetches the manifest elsewhere and relaxes only the
repository pin.

### Setup's one native surface

Setup used to run and vanish with no window: technically correct (the
browser owns the flow) and, in practice, untrustworthy. It now shows ONE
small card in VIRULE's native visual language (the Admin splash grammar:
rounded card, yellow V mark, spaced wordmark, one muted line), and nothing
more. NOT A WIZARD: no pages, no Next/Back, no destination picker, no
component list, no license page and no user choice of any kind.

| State | Copy |
|---|---|
| Working | `Setting up VIRULE...` + a subtle indeterminate bar, held until the client releases Setup |
| Complete | `Setup is complete.` briefly, then it closes itself |
| Failed | one short human sentence; the technical reason goes to the log only |

The status line sits at the same coordinates in every state. The
completion state carries no instruction on purpose: by the time it shows,
the client has confirmed the next feedback surface is already visible, and
"return to your browser" would be wrong when no browser was involved.
Setup never sits open indefinitely (the release wait is bounded, and a
failure surface is dismissible and leaves on its own after 60 s).

### The browser -> Setup handoff channel (2026-09-03)

The retired design guessed the originating browser (process ancestry,
browser families, default-browser fallback) to reopen a resume URL. ALL OF
THAT IS GONE: Setup never opens a browser, and intent is handed over
explicitly or it does not exist.

While Setup runs, it listens on ONE small temporary loopback channel,
`ws://127.0.0.1:47613`, path `/handoff` (`src/setup/handoff_listener.hpp`),
opened FIRST at startup so a still-open virule.app page can hand its
pending operation over while the install runs. CLOSED and versioned:

- browser pages ONLY (an allowed Origin is REQUIRED; local no-Origin
  connections are dropped);
- hello `{"virule_setup":1,"v":1}`;
- exactly one envelope is kept (first valid wins):
  `{"type":"handoff","v":1,"op":"QA_ACCEPT","token","game"}` or
  `{"type":"handoff","v":1,"op":"INSTALL_ADMIN","shortcut"}`; anything
  else answers `{"type":"error"}`;
- no URL, no path, no executable, no filesystem capability of any kind;
- Setup treats it as opaque and the client revalidates all authorization
  (a QA token still has to survive service redemption; an Admin install
  still runs the verified manifest/signature pipeline);
- tokens are never logged.

### The Setup takeover (ownership transition)

The hard UX invariant: a VIRULE surface must never disappear until the
next VIRULE surface is ready to give immediate feedback. After starting
the client, Setup:

1. transfers the envelope - or its explicit absence - over a local bridge
   connection (`setup_takeover`), retrying until the fresh client
   acknowledges (a late envelope is forwarded as an upgrade);
2. polls `setup_wait` until the client answers `released:true`, keeping
   its card visible the whole time;
3. only then completes and closes. Bounded backstops (a client that stops
   answering, an overall timeout) exist so a wedged client can never hold
   a window open forever; they are failure handling, never the path.

The client releases Setup (`src/client/takeover.hpp`) only once the next
feedback surface is demonstrably in place (lifecycle continuity pass,
2026-09-03, v0.6.0):

- QA_ACCEPT: the branded native continuation card "Finishing up…" ALWAYS
  shows before Setup may close (the user watching the native flow never
  has to hunt for the browser), then resolves to "You're all set." and
  closes itself; a live page still receives the result push and reaches
  its own success state in parallel.
- INSTALL_ADMIN: a live page owns the install UX (Setup releases on its
  acknowledgement); with the browser gone the client runs the install
  behind a branded "Installing…"/"Updating…" card and launches the Admin
  at completion.
- no envelope: the standalone completion card.

A Setup run with NO envelope (standalone / stale download) has no
recoverable intent and none is invented: after a short watch for a live
page or native QA progress, the client shows the branded "VIRULE is
ready" card with the ONE explicit `[ Continue ]` action. Only that click
opens a browser (virule.app, in the Windows default). The homepage's
continuous detection then resolves the machine's real state.

`result_card.hpp` is the ONE client lifecycle surface: the bare Result
mode is the unchanged QA-doctrine card (no brand mark), while Working /
Ready / resolved lifecycle Results wear the Setup card's branded grammar
(V mark, spaced wordmark, indeterminate bar or action button). It is
reusable across the persistent client process, and both executables embed
the official VIRULE application icon (`assets/ViruleAppIcon.ico`).

The same lifecycle grammar carries the Admin update: a Settings-initiated
update shows the Admin's "Shutting down VIRULE" overlay, the client closes
it gracefully and IMMEDIATELY owns the feedback with the native "Updating…"
card through download / verify / stage / replace, then relaunches the new
Admin (a failed update relaunches the untouched known-good Admin). A
user-initiated launch of an out-of-date managed Admin is handed over by
virule.exe as the local-only `admin_launch` bridge message: the client
updates first (same card) and launches only the new Admin; a failed update
never blocks the launch.

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
protocol preflight. The moment a client is connected with `INSTALL_ADMIN`
pending, the page hands the install over (`admin_install`, the shortcut
preference riding along) and shows only "Installing VIRULE..." - there is
no stopping point and no second install button. An already-installed
Admin means the work is done (the client finished it after the page
closed); the intent is cleared and the page settles.

VIRULE uninstall has TWO EXPLICIT MODES (owner spec 2026-09-03; see
`src/shared/uninstall.hpp`), both driven by an explicit ownership
inventory. The DEFAULT preserves user data: it removes the install dir
(the managed `Admin\` installation included), the client state dir,
`virule://` ONLY while it points at this client, the uninstall entry, and
the desktop `VIRULE.lnk` ONLY when the client created it (state.json
provenance); `virule.db`, `workspace\`, `logs\`, `backup.json` and the
whole `security\` credential store (dev_machine.cred AND qa_tester*.cred)
all stay, and the shared `VIRULE\` folder goes only if left empty. The
explicit DELETE LOCAL DATA mode (the `delete_data` flag behind the site
modal's toggle / the native dialog's checkbox, each with its "cannot be
undone" warning) additionally removes the entire `%LOCALAPPDATA%\VIRULE\`
user-data root. Both surfaces say "Uninstall VIRULE" (never "Remove").
The running exe hands removal to a `%TEMP%` copy
(`--finish-uninstall <pid> [--delete-data]`) so no broken executable is
left behind. Development trees (the VIRULE repository, its
`virule\publish\Virule` folder) and the user's chosen build root are
outside every inventory root and can never be touched. A full VIRULE
uninstall and removing an individual future game are SEPARATE actions
forever; this inventory must never grow a recursive game-library delete.

## The managed VIRULE Admin installation (Phase 2)

The client owns exactly one Admin install location:
`%LOCALAPPDATA%\Programs\VIRULE\Admin\` (`virule.exe` + `.resources\`).
ONLY that location counts as "Admin installed"; the development publish
folder or a manually extracted copy elsewhere is never reported, updated,
or launched. `src/client/admin_install.hpp` is the whole implementation.

THE APPROVED MANIFEST lives at
`https://virule.app/client/admin-manifest.json` (no-store; the
VIRULE_BACKEND Worker serves it):
`{version, channel, url, sha256, size, minimumClientVersion}`. virule.app
decides which Admin release is approved; the package bytes live on the
`getvirule/virule-overlay-releases` GitHub Release
(`Virule-v<version>.zip`, the folder contents at the zip root, generated
and verified by `helpers/publish_admin.ps1`). The manifest url is pinned
to that repository's `releases/download/` prefix.

THE VERIFIED STAGED PIPELINE (install and update are the same path; an
update never touches the live install file-by-file): fetch manifest ->
validate structurally -> streamed download capped at the declared size,
hashed on the way through -> exact size -> exact SHA-256 (never waived) ->
zip-slip-guarded extraction into `Admin.staging\` -> Authenticode + the
VIRULE signer identity (`CN=Heath Michaels`) on every VIRULE-owned binary
(virule.exe, ViruleAdminHost.exe, SidecarK32/64.dll, both
SidecarKHost.exe) -> atomic placement. A fresh install is ONE directory
rename; an update renames live -> `Admin.previous`, staging -> `Admin`,
and a failed swap renames the previous install straight back, so a
known-good install always survives.

THE INSTALLED VERSION IS AUTHORITATIVE IN-INSTALL METADATA (the
false-"up to date" fix, 2026-09-03): the pipeline writes
`Admin\installed-release.json` (`{"version":...}`) into the STAGING tree
before the atomic placement, so version and binaries can never disagree.
`state.json` (`admin_version`) is only a mirror; at every startup the
client reconciles the two (metadata wins; a pre-metadata install with
surviving state gets the file written). A managed Admin whose version is
genuinely unknown reports an EMPTY version, and nothing anywhere turns
unknown into "up to date" or "update available": both claims require a
real comparison of two known versions. The Admin binaries are never
probed for a version.

THE CLIENT OWNS THE UPDATE LIFECYCLE (owner spec 2026-09-03). An update
that finds the Admin running no longer refuses: after a ~4 s grace (the
initiating surface shows the approved "Shutting down VIRULE" / "One
moment..." messaging), the client closes the Admin GRACEFULLY (WM_CLOSE to
its top-level window; never TerminateProcess, never any unrelated
process), waits bounded for every managed-directory process to exit, runs
the verified staged pipeline, and RELAUNCHES the Admin it closed. An
Admin that refuses to close still answers `admin_running` and changes
nothing (the safe fallback, no longer the normal path); an already-closed
Admin skips the grace entirely and is not relaunched.

THE SILENT UPDATE CHECK: the client caches the approved manifest's
version (client startup, a quiet 6-hour recheck while serving, and a
15-minute-fresh refetch on the local `admin_update_check` ask), only ever
while a managed install exists. Checking is automatic; INSTALLING is
always user-initiated (Admin Settings > GENERAL > Update, or virule.app's
Update VIRULE). The Admin host owns no manifest logic: it asks over a
local control connection, starting the on-demand client when needed.

Once accepted, the operation finishes even if every page closes
(`g_busy` also holds off the idle-exit policy), and a FRESH install
launches the installed Admin automatically at the end. The desktop
shortcut (`VIRULE.lnk`, target = the managed `virule.exe`) is created
when the browser's intent asked for one, and its provenance is recorded
so uninstall removes exactly what the client created.

`admin_install`/`admin_open` are page messages behind the same origin
policy, but they are CLOSED operations, not a filesystem or
process-launch surface: install runs only the pipeline above against the
approved manifest (package SHA-256 + Authenticode + signer identity are
the trust decision, exactly Virule-Setup's), and open launches only the
managed installation the client itself placed.
