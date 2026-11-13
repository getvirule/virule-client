# VIRULE Client architecture (Phase 2)

Current state only. When a change makes something here untrue, REPLACE it,
and advance the last-verified stamp.

Last verified 2026-09-10, against client v0.8.3; the usage check-in and
update-health sections were written against v0.8.6 (2026-10-01); residency
(VIRULE Service), the manifest's service fields and Setup's service
placement against v0.9.0 (2026-10-06); evaluation evidence delivery
against the 2026-10-14 tree; the VIRULE account against v0.9.4 (2026-10-15);
installed capabilities, the message table, the handoff envelope and the
takeover against v0.9.9 (2026-10-16); account roles, the QA link offer,
the sign-in answer page's favicon and the shutdown drain against 0.9.12
(2026-10-20); evidence delivery to the service, the requests, the
developer's evaluation inbox, the game update and removal, and
`evaluation_changes` against 0.9.17 (2026-10-21).
The compiled constant in
`src/shared/version.h` is the version authority; a version tag below marks
when a contract was introduced, never the current release.

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

LOCAL NETWORK ACCESS (verified in Edge, 2026-09-02; browser facts
re-verified HEADED with fresh profiles in Edge 152 and Firefox 154,
2026-09-11): browsers gate a public https origin's loopback sockets
behind a permission prompt, "Access other apps and services on this
device" in both; a denied request fails (Chromium:
ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS). The Permissions API name is
`loopback-network`: both browsers answer it, it turns `granted` on Allow
and `denied` on Block, and it persists across reloads and browser
restarts (Firefox: when "Remember my choice for this site" was ticked; a
one-time Allow lasts the session). Chromium still answers the older
`local-network-access` in step with it; Firefox REJECTS that name.
Chromium raises its prompt for the attempt itself, even with nothing
listening on the port; Firefox raises it only once a connection reaches
a LISTENING port (a refused port fails in ~2 s with no prompt). The
virule.app pages therefore probe quietly ONLY while the permission
positively answers `granted` (`loopback-network`, or
`local-network-access` where only that name is known): a rejected
query, a missing Permissions API, `prompt` and `denied` are all NOT
granted. Reading a rejected name as "no gate" is exactly what prompted
every Firefox visitor on page load before 2026-09-11. Ungated attempts
happen only after an explicit user action (Get VIRULE, ACCEPT), and the
pages never depend on the bridge to complete QA verification (virule://
+ /qa/link polling is the bridge-free path). Do not paper over a denial
with flags or lesser transports; the permission prompt IS the standards
path, and local origins (wrangler dev, vite) are exempt, which is why
development never sees it.

DENIED IS A STATE, NOT AN ABSENCE (site, 2026-09-10). A denied permission
blocks the bridge (47612) AND the Setup handoff channel (47613) alike, so
an INSTALL_ADMIN intent has no delivery route and re-offering the
installer only loops (Setup -> "Finish installing from the site" -> Get VIRULE -> Download
-> Setup, with Admin never installed). The homepage keeps the ONE
PermissionStatus from its query, treats `denied` as its own connection
state (`blocked`: once the user has clicked Get VIRULE, a recovery view
replaces the whole install path; before the click a denied browser sees
Get VIRULE like every browser that has not granted access), and
reconnects the instant `onchange` reports `granted`,
so allowing the site in site settings resumes the pending intent with no
reload and no reinstall. A denied origin is never re-prompted by
Chromium, and a failed socket carries no reason, so the Permissions API
is the only observer of this state.

PROMPT IS A STATE TOO, AND IT COMES FIRST (site, owner spec 2026-09-10).
With the permission unanswered (`prompt`), Get VIRULE records the intent,
makes the ONE loopback attempt that raises the browser's prompt (the
socket stays parked behind it) and waits on the pending copy, "Your
browser will ask you for permission." with its one recovery line ("Accept
to continue setup. If you don't see a prompt, refresh your browser and
try again."; the intent survives the refresh in localStorage and Get
VIRULE re-raises the ask): no `virule://open`, no timer toward
Download, no Setup, no "absent" conclusion, for as long as the answer is
`prompt` (a dismissed prompt is asked again on a slow cadence; the
browser turns repeated dismissals into a denial by itself). Allow -> the
bridge is tried at once; a client answering proceeds from its real
status; no client -> only now does `virule://open` wake one and the
bounded wake wait run, and only its expiry offers Download. The order is
therefore always permission resolution -> client detection -> fallback
wake -> installer offer, so a fresh install can no longer reach Setup
(and the standalone card) merely because the user has
not answered the browser yet. Firefox exception, from its prompt model:
a Get VIRULE attempt REFUSED within 4 s while the answer is still
`prompt` means nothing is listening and Firefox will not ask yet, so the
flow continues to the wake, the bounded wait and the installer offer, and
Firefox asks once Setup (47613) or the client (47612) listens; an attempt
that parks (a listener, so the prompt is up) keeps the wait. A browser
that answers neither name takes the direct path on the click (Checking
this PC + wake). Proof: `v1_mvp_site/tools/permission_state_test.mjs` and
`probe_gate_test.mjs` (browser models emulated; the prompt itself is
verified only headed).

Origin policy: browser connections must present one of the explicit
allowed origins of this build's environment (production `https://virule.app`
and `https://www.virule.app`; staging its own site), and a STAGING build
also accepts the listed local development origins (`kDevOrigins` in
`src/shared/environment.hpp`; a production build accepts none of them since
audit M-6, 2026-11-12); anything else is dropped at handshake. A connection with NO Origin header is a
local control connection (second-instance forwarding, Setup's shutdown
request). The origin check defends against the WEB, not against local
code: any local program running as this Windows user can reach the control
messages.

User policy (audit H-3, 2026-11-11; Client 0.9.29, staging): every
accepted connection is mapped to
the process on its other end (`GetExtendedTcpTable`, the mirrored 4-tuple)
and refused before a byte is read unless that process's token user SID is
this client's own (`src/shared/loopback_peer.hpp`). It fails closed: an
owner that cannot be read is refused, which is also how another account's
process normally reads to a standard user. The site in this user's browser,
VIRULE Desktop, the evaluation wrapper, Setup and a second client instance
all run as this user and pass; a process of another Windows user on the
same computer cannot use the bridge. `loopback_roundtrip` checks the
listener it reaches the same way before sending anything. The listener is
bound with `SO_EXCLUSIVEADDRUSE` and serves at most 128 connections at once
(beyond that a connection is closed at once). This takes no position on
whether two Windows users may each run VIRULE on one computer.

DLL SEARCH ORDER (audit L-24, Client 0.9.29, staging): `virule-client.exe`
and `ViruleService.exe` call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`
first thing at entry, and the Client delay-loads its system imports that are
not KnownDLLs (bcrypt, crypt32, wintrust, version, wevtapi, winhttp,
iphlpapi; `client/virule_client.vcxproj`), so a DLL planted beside the exe
(the Downloads folder, the `%TEMP%` helper copies) is never loaded. The
`%TEMP%` uninstall helper starts `cmd.exe` and `ping.exe` by their full
System32 paths. The permanent signed Setup is unchanged; manifest signing and
a downgrade floor remain open (owner).

LOCAL CALLERS VERSUS OPERATION AUTHORIZATION (owner decision 2026-11-02,
`VIRULE/docs/specs/evaluation-security.md` decision 16). Reaching the
bridge is never permission to skip a VIRULE rule. A privileged VIRULE
operation enforces its own invariants at the component that owns its
credential or action, whoever asked: there is no "trusted Admin" caller,
since the Admin reaches this bridge exactly as any local program of this
user does and
its screen checks are presentation only. Being a local caller suffices only
for what such a program could already do itself (open virule://, run Setup
or an update). Examples: an evaluation purchase is refused by the Client
before it uses its authorization when this computer cannot verify games;
the relay admits only the Admin's own requests, never the routes of the
Client's own drivers. LIMIT: the account session and device key are
DPAPI user-scope protected, which stops copying and other Windows users
(who also cannot reach the bridge, User policy above) but
is NOT a hardware boundary against hostile code already running as this
user; VIRULE claims no protection from such code, only that it offers no
supported path around its own rules (stronger endpoint isolation: open
items).

### Message set (closed, versioned)

An invite token is either the CURRENT 32-character Base64URL mint
(192-bit, case-sensitive) or the LEGACY 64-lowercase-hex mint, accepted
until those invites expire (`protocol_reg::is_invite_token`, one grammar
in both components).

| From | Message | Effect |
|---|---|---|
| page | `{"type":"status"}` | version, protocol feature list (`capabilities`), connected-page count, the Admin status block, and `enabled` `{"dev_tools":bool,"evaluator":bool}`, the installed capabilities (v0.9.9, see "Installed capabilities") |
| page | `{"type":"qa_accept","token":"<invite token>"}` | asynchronous QA redemption (below) |
| page/local | `{"type":"admin_install","shortcut":true\|false,"capability":"dev_tools"\|"evaluator"}` | the verified staged Admin install/update (below). From a PAGE the entry point's `capability` (absent or unrecognized = `dev_tools`) is RECORDED as the request is accepted, before the pipeline runs (v0.9.9). A LOCAL sender is the Admin's own Settings Update through its host: shortcut always false, and it records no capability |
| page/local | `{"type":"capability_enable","capability":"dev_tools"\|"evaluator"}` | adds one installed capability to an existing installation, never removing another and never reinstalling (v0.9.9); answers `{"type":"capability_enabled","capability","enabled":{"dev_tools","evaluator"}}`, an unknown or missing capability answers `error`; refused while uninstalling and during the self-update drain; a change pushes `status` to pages at once |
| page | `{"type":"admin_open"}` | launch the managed Admin installation, and nothing else |
| page | `{"type":"surface_ack"}` | the page states its next feedback view is rendered and active (the Setup takeover's browser acknowledgement) |
| page | `{"type":"uninstall","nonce","timestamp","signature","delete_data"}` | VIRULE uninstall after verification; `delete_data` (default false) is the explicit destructive option |
| local | `{"type":"qa_verify_url","token"}` | a second instance forwarding a `virule://` launch |
| local | `{"type":"wake"}` / `{"type":"shutdown"}` | keep-alive no-op / clean exit (Setup replacing the exe; since 0.9.12 an event wakes the serve loop so draining starts at once, not at its next 1 s poll, narrowing the race with Setup's fixed 2 s wait before it replaces the exe) |
| local | `{"type":"admin_update_check"}` | answers `admin_update_status` (installed/approved versions + `update`); refreshes the cached manifest check when stale; a caller declaring `{"context":"launch"}` gets the launch-retry hold semantics below |
| local | `{"type":"update_health"}` | answers `{"type":"update_health","blocked":bool}` from the persisted update-connectivity record (see "Update connectivity health"); a read only, it never makes a request (v0.8.6) |
| local | `{"type":"admin_launch"}` | virule.exe handing over a user-initiated launch of an out-of-date managed Admin: the client updates first (native "Updating…" card) and launches only the new Admin; a failed update launches the current Admin, never blocking the launch. THE FALLBACK (owner ruling 2026-10-22, for evaluation games built before `assignment_open`, whose "Quit and Open VIRULE" sends `admin_launch`): the update claim is asked first, showing nothing (`admin_install::approved_update_available`, the same claim `admin_update_check` answers, launch context); with NO approved update the Admin is opened or focused as `admin_open` does, with no card (an update in flight is joined; a running Admin is focused at once and, if it was a handing-off virule.exe that exits within 10 s, launched); with a real approved update the behavior is exactly the update-on-launch handoff above |
| local | `{"type":"assignment_open","assignment_id":"<32 hex>"}` | THE EVALUATION WRAPPER'S Write Evaluation (owner ruling 2026-10-22, `client/assignment_open.hpp`): records an in-memory OPEN INTENT (latest wins; expires after 10 minutes; survives an Admin update relaunch because the Client process stays), bumps the change counter, then opens or focuses the Admin through the `admin_open` path (an update in flight is joined; a running Admin is focused; else it is launched); never the "Updating…" card (virule.exe itself may still run a real approved update-on-launch). Answers `{"type":"assignment_open_started"}`, or `error` (malformed id, Admin not installed or not started); refused while uninstalling and during the self-update drain |
| local | `{"type":"assignment_open_take"}` | the Admin host taking the open intent (2026-10-22): answers `{"type":"assignment_open_intent","assignment_id":"<32 hex or empty>"}` and clears it |
| local | `{"type":"uninstall_local"}` | the Apps & Features `--uninstall` launcher forwarding removal to the serving instance, so there is one teardown owner |
| local | `{"type":"setup_takeover",...}` | Virule-Setup transferring the pending-operation envelope, or its explicit absence (see "The Setup takeover") |
| local | `{"type":"evidence_status","assignment_id":"<32 hex>"}` | answers `{"type":"evidence_status","assignment_id","counts":{"pending","acknowledged","damaged"},"packages":[{"id","state","simulated","attempts","last_error"}],"truncated":bool}` for one evaluation assignment (see "Evaluation evidence delivery"); a read only, it never delivers; a malformed id answers `error` |
| local | `{"type":"evaluation_changes"}` | answers `{"type":"evaluation_changes","generation":"<boot>:<n>"}` (0.9.17): a counter this process bumps on every evidence receipt, request answer and fetched developer package, and (0.9.18) on every launch, exit and install job state change and every kept progress document; the Admin reads it to learn locally that its own Client changed something, never by asking the service (see "Evaluation evidence delivery", "The launcher") |
| local | `{"type":"game_launch","assignment_id":"<32 hex>","required_revision_id"?:"<32 hex>"}` | THE LAUNCHER (0.9.18): the one launch of an installed game. Answers `{"type":"game_launch","ok":true,"pid":n}` or `ok:false` with `code` (`running`, `updating`, `not_installed`, `update_required`, `missing`, `failed`) and a plain `message` (see "The launcher") |
| local | `{"type":"launcher_state"}` | answers `{"type":"launcher_state","assignments":[{"assignment_id","running","launching"}]}` (0.9.18): for every install job here, whether its game is up in any form, read from the system at the moment of asking |
| local | `{"type":"setup_wait"}` | answers `{"released":bool}`: whether the takeover's next feedback surface is ready, so Setup's card may close |
| local | `{"type":"account_status"}` | answers the account snapshot (see "VIRULE account"): `signed_in`, `phase` (idle / browser / exchanging), `offline`, `error`, and when signed in `account{email,display_name,status}`, `capabilities{developer,evaluator,qa_tester}`, `effective{developer,evaluator}`, `checked`, `qa_link_available`, `appearance` (v0.9.4); ALWAYS, signed in or out, `enabled{dev_tools,evaluator}`, the installed capabilities (v0.9.9), and `remembered{developer,evaluator}`, the roles last confirmed for an account here (0.9.12; absent until an account was confirmed on this installation). Never a token |
| local | `{"type":"account_sign_in"}` / `{"type":"account_sign_in_cancel"}` | start (idempotent) / cancel the browser sign-in |
| local | `{"type":"account_sign_out"}` | revoke at the service (bounded), then forget locally |
| local | `{"type":"account_refresh"}` | re-confirm the account and capabilities with the service (asynchronous) |
| local | `{"type":"account_link_qa"}` | the explicit QA identity link (the person chose it in the Admin) |
| local | `{"type":"account_set_appearance","appearance":"dark"}` (or "light") | an explicit account appearance choice (v0.9.4; refused signed out) |
| local | `{"type":"account_open_settings"}` | open the website account page for THIS account in the person's browser (v0.9.5; the single-use link is minted and opened here, never returned) |
| local | `{"type":"account_api","method":"GET"\|"POST","path":"/v1/evaluations...","body":{...}}` | THE EVALUATION RELAY (v0.9.7): one call to `/v1/evaluations` or `/v1/assignments` made here under this installation's DPoP authorization; since 2026-11-02 ONLY the Admin's own requests (`account_relay.hpp` `admin_route_ok`, see "Desktop account"), anything else is `bad_request`; the body is the message's LAST field, raw JSON. A purchase (POST `/v1/evaluations/purchases`) on a computer that is not ready answers `{"status":0,"error":"not_ready","reason","message"}` and nothing is sent. Answers `{"type":"account_api","status","body"}` (the service's JSON object, else `null`) or `{"status":0,"error":"signed_out"\|"offline"\|"bad_request"\|"too_large"\|"not_ready"}`. Never a token. Local frames for it are bounded at 60,000 bytes (`kMaxLocalFrameBytes`); page frames stay 4,096 |
| local | `{"type":"evaluation_purchase_readiness"}` | (2026-11-02) can THIS computer buy an evaluation now: THE CLIENT'S ANSWER, which the Admin only shows (`src/shared/evaluation_purchase_readiness.hpp`, the one rule). Answers `{"type":"evaluation_purchase_readiness","ready":bool,"reason":"supported"\|"unsupported_windows"\|"defender_off"\|"defender_out_of_date"\|"antivirus_unsupported","message":"<the owner's sentence, empty when ready>"}`; no product name, path or version leaves the Client (the detail is in its log). Refused to pages |
| local | `{"type":"transfer_control","assignment_id":"<32 hex>","action":"pause"\|"resume"\|"retry"\|"verify"}` | GAME DISTRIBUTION (v0.9.14): pause, resume or re-queue the evaluator's install job for that assignment; `verify` (0.9.15) makes an INSTALLED assignment's launch chain current before the Admin launches its wrapper (see "Game distribution"); answers `{"type":"transfer_control","ok":bool}` (`verify` adds `"message"`); a malformed id or action answers `error` |
| local | `{"type":"transfer_wake"}` | signal the transfer driver to run a pass now (the Admin host wrote or changed a job record); answers `{"type":"transfer_wake","ok":true}` |
| local | `{"type":"transfer_status"}` | answers `{"type":"transfer_status","jobs":[...],"truncated":bool}`: every job record under `%LOCALAPPDATA%\VIRULE\transfers` as it stands (bounded); a read only |

Client pushes to every connected page: `{"type":"qa_result","token","state"}`,
`{"type":"admin_result","state","version"}`,
`{"type":"uninstall_state","state":"removing"|"failed"|"complete"}` (the
ordered teardown's transitions; `complete` (v0.8.2) is the POSITIVE
terminal signal sent once the removal is committed, see "Uninstall"), and,
the P1 lifecycle
status push (v0.6.3), UNSOLICITED `status` frames whenever the lifecycle
core changes (the admin block, the `uninstalling` flag or, v0.9.9, the
`enabled` installed capabilities): a 1 s watcher
while pages are connected plus immediate pushes at operation boundaries
(update start/end, Admin launch, teardown start), so open virule.app tabs
converge in about a second instead of their 15 s poll, which stays as the
convergence backstop. Local control connections never receive pushes.
The status answer carries `"uninstalling":bool` and the `"admin"` block
`{"installed":bool,"version":"...","running":bool,"updating":bool}` - the
managed installation only (below); a development tree is never reported,
and an EMPTY version with installed:true means genuinely unknown (never
to be rendered as a currency claim).
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
`%LOCALAPPDATA%\VIRULE\client\state.json` (informational: nothing reads it
today; a default uninstall preserves `security\` (`dev_machine.cred` and
the QA credentials), and Uninstall & Delete Data removes it with the rest of
the data root; `uninstall.hpp`, `evidence_keep.hpp`). VIRULE Desktop now keeps a
Client-created credential too (owner brief 2026-11-12, "Owner-Directed
Completion Assignment", section 4; v2_mvp `dev_machine_license.hpp` "KEPT OR
REPLACED", in source, not yet in a released Desktop): a Desktop older than
that fix replaced it on its first run, because it required the file's
install id to equal its own workspace id, which also orphaned a QA tester
credential bound to the Client's key.

`security\qa_tester.cred` is written after a `verified` redemption, in the
exact `qa_tester_credential` JSON shape the wrapper's
`qa_runtime_client.hpp` reads. SUPER ADMIN QA TEST MODE (the Admin's
`%LOCALAPPDATA%\VIRULE\qa_test_mode` flag file) is honored: ephemeral
throwaway identity + the isolated `qa_tester_test.cred`.

Browser/native ownership of the QA outcome mirrors the Admin: result is
pushed to pages on this bridge; with none, a running Admin GUI session's
47611 bridge is asked to deliver it to its pages; only with no page
anywhere does the minimal native result card appear.

## VIRULE account (2026-10-15, staging; `src/client/account.hpp`, `src/shared/account_store.hpp`)

The Client is the ONE owner of persistent desktop authentication; the Admin
presents it through the account_* LOCAL messages above (a page, even an
allowed origin, gets `error`). Service side: `VIRULE_BACKEND/docs/ACCOUNTS.md`.

- Sign-in: OAuth 2.0 authorization code + PKCE S256 + PAR + DPoP. The Client
  opens a one-shot listener on `127.0.0.1:<ephemeral>` (only `GET
  /callback`, only its own state, constant-time; the issuer must equal this
  build's site), pushes the request to `/v1/oauth/par` under a DPoP proof,
  and opens the person's default browser on `<site>/authorize/`. The answer
  page the listener serves is Smoky Blue with the canonical mark, light or
  dark: the authorize page appends `ui=light|dark` (its own resolved theme)
  to the redirect, and without it the browser's preference decides; `ui` is
  presentation only. The page carries the VIRULE favicon inline (a `data:`
  URI of the website's `favicon.svg`; its CSP adds `img-src data:`), because
  the one-shot listener closes right after answering (0.9.12). Ten-minute bound; Cancel ends it. ONE PENDING
  SIGN-IN, REOPENABLE (0.9.11): another `account_sign_in` while the browser
  step waits starts nothing new; it opens the SAME authorize page again (the
  same request_uri, listener and PKCE pair; answer `{started: true,
  reopened: true}`), so a closed tab or a browser that opened behind VIRULE
  is never a dead end and two clicks never make two authorizations. While
  the request is being prepared, or the code exchanged, it opens nothing.
  A cancelled sign-in is never reopened. The Admin host lets the browser
  take the foreground (AllowSetForegroundWindow from the window the person
  clicked) before it asks; the Client itself never forces a window.
- Device key: `security\account_device.cred` (Ed25519, DPAPI user scope,
  entropy `virule-account-device.v1`). NOT dev_machine.cred, which the Admin
  may replace; the machine public key is sent as information only. THE KEY
  BELONGS TO ONE AUTHORIZATION (v0.9.4): every sign-out (the person's, the
  service's refusal on refresh, uninstall) deletes it and the next sign-in
  makes a new one, so a second person signing in here never shares a key or
  an authorization with the first, and an authorization an offline sign-out
  could not revoke is left bound to a key that no longer exists. A device
  key is never created while signed out.
- Session: `client\account.dat` (DPAPI, entropy `virule-account-session.v1`):
  the rotating refresh token plus the last snapshot. The access token lives
  in memory only. Staging builds use `.staging` file names.
- Every token operation is serialized (a racing refresh would present one
  refresh token twice, which the service treats as theft). A refresh the
  service refuses signs the installation out (`signed_out_by_service`);
  network failure keeps the snapshot and reports `offline`. A snapshot older
  than 5 minutes is re-confirmed in the background on the next status read.
- Uninstall signs the installation out at the service (bounded, step 4b of
  the teardown), which deletes the session and the device key. Sign-out
  never touches local records: games, QA credentials, the machine identity
  and evaluation files stay.
- ACCOUNT APPEARANCE (v0.9.4): the session snapshot carries the account's
  explicit appearance and its version (`/v1/account/me`), and the status
  reports `appearance` ("light" | "dark", "" = never chosen).
  `{"type":"account_set_appearance","appearance":...}` (local only; refused
  signed out) records an explicit choice at once (persisted with the version
  it was made on) and delivers it in the background as the live choice. If
  the service is unreachable it stays pending, survives restarts, and is
  replayed with `base_version` on the next contact (status reads retry it at
  most every 30 s); a 409 means the account changed elsewhere since, and the
  installation adopts the preference in force. `account_refresh` re-confirms
  at most every 20 s (the Admin asks at start, on every activation and every
  30 s while in the foreground).
- ACCOUNT SETTINGS (v0.9.5): `account_open_settings` mints a single-use web
  link (`POST /v1/account/web-link`, DPoP) and opens
  `<site>/account/?for=<account hint>#h=<link>` itself (ShellExecute); no
  bridge answer carries the link. Signed out or offline it opens the plain
  page (with the hint when known). The snapshot keeps the service's
  `account_hint`. Staging test seam: `test_settings_url` in the status.
- EVALUATION RELAY (v0.9.7, `account_api`, grammar
  `src/shared/account_relay.hpp`, unit tests `tests/account_relay`): the
  Admin's Evaluations and Assignments reach the service's evaluation records
  only through this, so the access token and the device key never leave the
  Client. A 401 refreshes once (a refused refresh signs out, as anywhere);
  no answer marks the snapshot offline. VIRULE_BACKEND
  `docs/EVALUATIONS.md` is the contract.
  - ONLY THE ADMIN'S REQUESTS (owner decision 2026-11-02, `admin_route_ok`):
    GET `/v1/evaluations` and `/v1/assignments`; POST `purchases`, `seen`,
    `games/<id>`, `games/<id>/build`, `<id>/rating`; POST `preferences`,
    `support`, `offers/open`, `offers/<id>/{close,accept,reject,decline}`
    (ids 32 lowercase hex); and THE EVALUATOR'S CONTRACTOR PAYMENTS (owner
    brief 2026-11-06, VIRULE_BACKEND `docs/PAYMENTS.md`; `payments_route_ok`,
    Client 0.9.28; on staging, not in production): GET `payments`,
    `payments/older/<id>`, `payments/invoices/<id>`, `payments/invoices/<id>/document`,
    `payments/invoices/<id>/<line offset 1..9999>`, and POST
    `payments/invoices/<id>/submit`, nothing else (no route of the service
    takes an amount). VIRULE Desktop's Payments needs a Client with it.
    SINCE 0.9.28 (owner brief 2026-11-10, VIRULE_BACKEND `docs/FINANCE.md`;
    on staging, not in production): the developer's STRIPE CHECKOUT, POST `checkouts`,
    GET `checkouts/<id>`, POST `checkouts/<id>/cancel` (`is_purchase` counts
    the Checkout's creation as a purchase, so the same purchase readiness
    decides it before anything is sent; no Stripe secret or key ever reaches
    the Client, which only relays the service's answer with the hosted page's
    address), and the evaluator's acknowledgement of a financial end, POST
    `<a>/ended/seen`. VIRULE Desktop requires 0.9.28 (its minimum Client). The routes of the Client's own drivers
    (`credential`, `<a>/runtime`, both `security/incident`, `<a>/download`
    and its `complete`/`failed`, `games/<id>/uploads`, `uploads/*`,
    `<a>/evidence/*`, `<a>/progress`, `early-completion`, `report`, `art`,
    `<a>/ticket`) are refused before a token is touched: they are made only
    by `transfers.hpp`, `runtime_report.hpp` and the evidence delivery,
    where their scan, verification and machine binding happen. Since the
    Phase 2 brief (2026-11-02) the service also requires a MACHINE PROOF on
    the state-changing ones ("Machine proofs" below), so a lower-level
    caller holding the account's authorization cannot make them either.
  - PURCHASE ENFORCEMENT (owner decision 2026-11-02): `api_call` recognizes
    POST `/v1/evaluations/purchases` on the parsed request it would send
    (`account_relay::is_purchase`) and decides this computer's readiness
    (`src/shared/evaluation_purchase_readiness.hpp`, the ONE rule: the
    `os_support.hpp` Windows rule and `malware_scan::scanning_availability()`)
    BEFORE it loads the device key, has or refreshes a token, makes the
    DPoP proof or sends anything. Not ready: `{"status":0,"error":
    "not_ready","reason","message"}`, nothing reaches the service, the
    idempotency key is unspent, and the same request succeeds once the
    computer is fixed. The caller does not matter; there is no simulation
    exception. The Admin's readiness display is this rule's answer
    (`evaluation_purchase_readiness`), never its own.
  - STAGING-ONLY TEST SEAM `--test-purchase-blocker=<reason>` (ignored in
    production): a blocker reported on top of the real answer. It can only
    refuse, never make a computer ready. Proof against the real binary:
    `tools/purchase_enforcement_test.mjs` (a direct local caller and the
    Admin host's exact translation refused for each reason with nothing
    reaching the real service routes; fixed, the same key buys once; the
    drivers' routes refused). Units: `tests/purchase_readiness`,
    `tests/account_relay`.
- QA link: reads `qa_tester.cred`, proves the credential's machine key
  (dev_machine.cred), sends both under the DPoP authorization. The QA
  credential is never changed; QA keeps working without any account.
  `qa_link_available` (0.9.12) is true when this installation holds a QA
  tester credential bound to THIS machine whose tester id is not among the
  account's `qa_linked_testers` (parsed from `/v1/account/me` and kept in
  the session), even when the account already holds `qa_tester`; a session
  saved before the list was kept falls back to the capability alone until
  `/me` answers. It is a menu-offer flag only: confirmed participation is
  the account's `qa_tester` capability and `qa_linked_testers`.
- DEVELOPER KEY CUSTODY (owner briefs 2026-11-12, optional account-based
  recovery; Client 0.9.31 as published to staging from the commit after ee930ec (Setup 0.9.31, cut from ee930ec, contains no custody code); `src/shared/developer_custody.hpp`, `account.hpp`
  `deliver_custody_locked`; service half VIRULE_BACKEND `docs/ACCOUNTS.md`
  "Developer key custody"). AUTOMATIC while signed in: right after a sign-in
  reads `/v1/account/me`, and after every re-confirmation (`confirm_now`),
  when the confirmed snapshot says the account is ACTIVE with the ACTIVE
  `developer` capability, names the device and the account hint, and a
  USABLE dev_machine.cred already exists (never created for this), the
  Client sends `POST /v1/account/developer-custody` under the DPoP
  authorization: `{machine_key, timestamp, machine_signature}`, the machine
  key signing `virule-developer-custody.v1|<API host>|<device id>|<machine key>|<timestamp>`
  (the developer machine binding's convention, "Machine proofs"). ONCE PER
  (account hint, machine key, device authorization), remembered in
  `client\developer_custody.json` (no secret: the hint, the public key, the
  device id, the outcome): 200 `registered` or `held` is not sent again under
  the same sign-in; a NEW sign-in (a new device authorization, which a
  password change or an account recovery forces) proves custody again, so
  the service records the key's proof as fresh for the account's current
  security state; 409 `custody_held_elsewhere` (another account holds this
  key) is recorded as `held_elsewhere` and not retried under that sign-in
  (shown nowhere: the computer keeps managing its own builds with its own
  key, unchanged); anything else
  (offline, 5xx, 429, `clock_skew`, a refusal) waits on the evidence
  delivery's ladder (10 s, 60 s, 5 min, 15 min, then every 30 min) for a
  later confirmation. A 401 other than `clock_skew` refreshes once and sends
  the same proof again. It never blocks anything: it runs after the sign-in
  is reported and after the snapshot is saved. A SANDBOXED Client
  (LOCALAPPDATA redirected, `paths::environment_redirected`) never sends to
  the real service, the check-in's rule (`admin_install.hpp`
  `checkin_suppressed`); with `--account-endpoint` it sends to that test
  service. Removed with the client state directory at uninstall; a later
  registration is answered `held`. RECOVERY: the service lets a key act for
  every other key in the same account's custody (builds, press access,
  Press and QA Activity, QA testers) while the account is an active
  developer without a financial hold, this key's proof is fresh, and this
  computer's sign-in (the device authorization behind its latest proof) is
  live now (VIRULE_BACKEND `src/developer_authority.ts`, `docs/ACCOUNTS.md`,
  the full rule); a key
  never placed in custody, or anonymous use, keeps exactly its own
  authority.
  Units: `tests/developer_custody` (message bytes, body, the record, every
  gate, 409, the ladder).
- Development seam: `--account-endpoint=http(s)://127.0.0.1:<port>` (loopback
  only; honored only in a staging build or a sandboxed run, Development
  command-line seams) points the service and site at a test server and replaces opening the
  browser with a `test_authorize_url` in the status. Proof:
  `tools/account_flow_test.mjs` (the real binary, sandboxed, against the real
  service routes). A second seam, `--account-browser=capture`, exists ONLY in
  staging builds (ignored in production): the real staging service, with the
  authorize URL surfaced instead of the browser opened. Proof against live
  staging with the published binary: `tools/account_live_staging_test.mjs`.
- Nothing here logs a token, code, verifier or key.

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
(`--no-register` skips this for development), with ONE guard: every
machine-registration WRITE (protocol registration, Setup's install-time
registration, self-update's ARP healing) refuses while
`paths::environment_redirected()` answers true, i.e. while the
env-resolved `%LOCALAPPDATA%` is not the OS-known per-user folder, so a
sandboxed harness run can never capture the real machine's registration.
The check fails open on a shell API failure (a real install never loses
its registration to a hiccup) and removal paths are deliberately
unguarded. The Admin no longer takes
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

RESIDENT (v0.8.0, 2026-09-10; replaces the original 20-minute idle exit):
an installed client stays running, so `127.0.0.1:47612` is normally
always available to the browser and an installed VIRULE is discoverable
from a cold boot with no click. Idle costs nothing: every background
thread sleeps, no connected page means no status pushes, and the update
checks are one manifest fetch per 6 hours (client self-update and the
managed-Admin check ride the same cadence). Three small PER-USER mechanisms
give the residency (no Windows SCM service, no scheduled task, no
elevation): the two below, and VIRULE Service (next section).

- the login start, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  value `VIRULE` = the managed `virule-client.exe`
  (`src/shared/login_start.hpp`): written by Virule-Setup at install time
  and healed by the client on every run, managed installs only, under the
  machine-registration guard; removed by the uninstall inventory with the
  other registrations, LAST, and only while it points into the removed
  tree;
- Windows Error Reporting's application restart
  (`RegisterApplicationRestart`, armed in `serve()` for managed installs):
  a client that dies on an unhandled exception (or that WER judges hung)
  after running at least 60 s is relaunched with `--restarted` plus its
  development seams; only patch/reboot relaunches are opted out. A clean
  exit is never restarted, so Setup's shutdown, the self-update swap and
  an uninstall are unaffected, and the uninstall-intent gate at the top of
  `wWinMain` still wins over a restart that races a removal.

The client leaves only on request: Setup's `shutdown`, the self-update
swap, an uninstall, or a port it can never own. Anything else (End task, a
kill) is restored by VIRULE Service. `virule://open` remains a FALLBACK
wake, never the normal path to discovery, and the Admin's `client_health`
monitor remains an in-session watchdog. The single-instance mutex makes a
login start racing a `virule://` launch harmless (the second forwards and
exits).

## Core Services residency: VIRULE Service (v0.9.0, 2026-10-06)

Windows names (the process identity table and the PascalCase naming law
live in `v2_mvp/docs/ADMIN_ARCHITECTURE.md`): `virule-client.exe` presents
as **VIRULE Core Services** (the file keeps its grandfathered name),
`ViruleService.exe` as **VIRULE Service**, `Virule-Setup.exe` as **VIRULE
Setup**.

THE HOLE IT CLOSES: before v0.9.0 a client ended deliberately or cleanly
while the Admin was closed stayed gone until the next login (WER restarts
only crashes after 60 s; `client_health` exists only while the Admin runs).
`ViruleService.exe` closes it. It is a normal per-user background process
(`src/service/main.cpp`): NOT a Windows SCM service, no elevation, no window,
no tray, no network, no telemetry, no CEF; about 400 KB, static CRT. Its one
job is to wait on the Core Services process handle and restore it.

ONE CONTRACT, `src/shared/residency.hpp`, shared by the client, the service
and Setup. A healthy installed machine runs exactly one of each, and they
protect one another:

- the service blocks in `WaitForMultipleObjects` on {stop event, wake event,
  every `virule-client.exe` process in the session}; the client runs one
  watch thread (`src/client/service_watch.hpp`) that blocks the same way on
  {its wake event, every `ViruleService.exe`}. Idle is a blocked wait: a
  timed wait exists only while a backoff, hold-off or grace window runs.
  Discovery (a toolhelp snapshot) happens only at a re-evaluation.
- Each restores ONLY the exact managed executable under
  `%LOCALAPPDATA%\Programs\VIRULE\` (`launch_managed` refuses any other
  path), with the client's own fixed development seams and nothing else
  (`--no-register`, and, only where the seams are honored (a staging build
  or a sandboxed run, Development command-line seams), `--dev-unsigned` and
  manifest overrides that point at the loopback interface). No path, executable or command line is
  accepted from anywhere; there is no new IPC surface.
- Both run only AS the managed install (a copy elsewhere exits at once) and
  never under the uninstall latch.

SINGLE INSTANCE, never two survivors: `Local\ViruleClient.Singleton` (the
existing name, unchanged; a second client forwards its work and exits) and
`Local\VIRULE.Service.Singleton` (a second service leaves quietly). A race
(login, `virule://`, Setup, the Admin, both peers at once) may START a
process; the singletons guarantee one of each SURVIVES. A start that loses
the race is not counted as a failure.

INTENTIONAL EXITS WIN. On every wake a watcher decides, in order:

1. the uninstall latch (`HKCU\Software\VIRULE\Lifecycle`) is set: stand
   down for good (the service exits; the client's watch thread ends). Every
   uninstall entry point also sets `Local\VIRULE.Service.Stop` right after
   writing the latch, so the helper finds the install directory free;
2. the peer is running: wait on it;
3. `Local\VIRULE.Residency.Maintenance` is HELD: wait for it, then give the
   maintainer's own restart a 10 s grace (`kPostMaintenanceGraceMs`; the
   replacement wakes the watcher the moment it serves). Holders: Setup
   (from stopping the old client until the new one is started), the client
   self-update helper (`--finish-self-update`, for the whole swap or
   rollback), and the client's own service replacement. A mutex follows its
   holder's lifetime: a crashed holder abandons it and residency resumes, so
   nothing durable can be stranded;
4. Core Services announced its exit (`Local\VIRULE.CoreServices.ExitIntent`,
   set right before Setup's `shutdown` or the self-update swap exit): the
   service holds off up to 60 s for the replacement (`kIntentHoldoffMs`).
   This is what keeps an OLDER Setup, which knows nothing of maintenance,
   from being fought;
5. otherwise the exit was unexpected: restore.

The service never announces an intentional exit of its own: it leaves on
purpose only on the stop event, which is set only under maintenance or with
the latch already written, and both are seen first.

CRASH-LOOP PROTECTION (`kSustainMs`, `kBackoffLadderMs`): an exit after a
run of at least 60 s (the same bar WER uses) is restored after 1 s;
consecutive short runs climb 5 s, 30 s, 2 min, 10 min, then stay at 30 min
for good: at most two launches an hour, no process storm, one log line per
attempt. One sustained run resets the ladder. A session that is ending
(`SM_SHUTTINGDOWN`) restores nothing.

LOGIN START IS THE CLIENT'S ALONE: the existing Run value `VIRULE` (unchanged)
starts Core Services, which starts the service when it begins serving.
Deliberately not a second Run entry: one Startup item in Task Manager, and a
user who disables it disables both, instead of the service resurrecting a
client the user turned off. WER application restart stays armed for the
client.

DISTRIBUTION (see "Distribution" and "VIRULE Service distribution" below):
the service ships in every client release; Setup places it, the client
installs it when missing and replaces it when it is not the one its own
release ships. Old installations converge on their own: an older client
self-updates to 0.9.0 (reading only the four fields it knows), and the new
client finds no service and installs it from the same manifest.

Logs: `client\logs\virule-service.log` (the service) and
`virule-client.log` (`service watch:` and `service:` lines). Proof:
`tools/residency_test.mjs` (17 sandboxed scenarios: mutual restore,
duplicates, start races, the latch, a real self-update swap and rollback, a
real service update, real Setup over a running pair, fresh install and
repair, both crash-loop ladders, full uninstall).

## Environments (production and staging)

VIRULE has exactly TWO environments. There is ONE implementation of the
client: an environment is a set of constants, never a second code path.
The install pipeline, the download caps, the exact-size and exact-SHA-256
gates, the zip-slip guards, the atomic placement and the whole bridge
protocol are byte-identical in both.

**`virule/core/launch_policy.hpp` is THE seam** (vendored byte-identical
under `third_party/`, shared with the Admin). It is the only place in any
C++ component where either environment is named:

| Constant | Production | Staging |
|---|---|---|
| `kEmbargoApiHost` | `api.virule.app` | the staging Worker host |
| `kSiteUrlW` | `https://virule.app/` | `https://virule-api-staging.heath-michaels9441.workers.dev/` |
| `kSiteOrigins` | `virule.app` + `www.virule.app` | the staging site |
| `kAdminManifestHostW` | `virule.app` | the staging Worker host |
| `kAdminPackageUrlPrefix` | `getvirule/virule-overlay-releases` | `getvirule/virule-staging-releases` |
| `kClientManifestPathW` | `getvirule/virule-client` `releases/latest/download/manifest.json` | `getvirule/virule-staging-releases` `releases/download/client-staging/manifest.json` |
| `kClientUrlPrefix` | `getvirule/virule-client` | `getvirule/virule-staging-releases` |
| `kRequireAuthenticode` | `true` | `false` |
| `kViruleEmbargoPublicKeyHex` | the production key | a SEPARATE staging key |

Staging has its OWN embargo keypair, so the staging Worker's
`uninstall-auth` and QA credential signatures verify in staging and
nowhere else.

`src/shared/environment.hpp` is a VIEW over that seam, not a second source
of truth: it re-exports those constants under the names the client's call
sites use and adds the one genuinely client-specific value, the LOCAL
DEVELOPMENT origins (the vite dev server for the site and `wrangler dev`
for the QA page, neither of which exists for the Admin). Its
`origin_allowed()` defers to `launch_policy::is_site_origin()` rather than
repeating a site URL, so the client's bridge and the Admin's QA bridge can
never disagree about which pages they answer. The development origins are
accepted by a STAGING build only (audit M-6; the owner brief
`VIRULE/docs/scratchpads/FINISH_HARDENING_BRIEF_2026-11-12.md` item 3
directs their removal from production unless a legitimate production
dependency exists, and none was found in code or authority), because any
page served on one of those localhost ports would otherwise be treated as virule.app by a production
client. The gate is compile-time on purpose (any web page can present any
Origin, so nothing known at run time may widen it). Local site or QA page
development therefore pairs with a client built with `-Environment
Staging`; `v1_mvp_site`'s `npm run dev` page still carries production
constants: the bridge protocol does not depend on them, but that page's
install flow offers the production Setup and reads the production approved
Admin version (`src/install/useInstallFlow.tsx`, `src/config.ts`). Proof:
`tests/environment/run_tests.bat` (the same test compiled as both builds).
Setup's handoff listener (`src/setup/handoff_listener.hpp`) answers through
the same function, so the rule is in Setup's SOURCE, but the permanent
signed Setups (`release/setup`, The canonical Setup) were cut before it and
keep accepting the development origins on 47613 until the owner re-cuts
them.

That sharing is the point rather than tidiness: the Admin host's client
self-heal (`admin_host.cpp`, `client_health`) reads the SAME client-release
constants this client's Setup and self-update read. When each carried its
own copy, a staging Admin could have silently repaired itself back to the
production client.

**Production is the default and cannot be reached by accident.** With no
macro defined every constant is exactly what it has always been.
`VIRULE_ENV_STAGING` is added only by an explicit staging build:

```
helpers\build.ps1 -Stage all -Environment Staging
```

which `Directory.Build.props` / `.targets` turn into the macro plus a
separate `build\Release\x64\staging\` output leaf, so a staging binary and
a production binary are never the same file and a staging build can never
overwrite a signed production artifact.

**Why staging may run unsigned.** Staging exists to exercise the product
end to end without consuming manual Microsoft Artifact Signing capacity.
THE ONE EXCEPTION is Setup, the file a person downloads and runs: the
staging `Virule-Setup.exe` is a permanent binary signed with the VIRULE
identity (The canonical Setup, below), because Windows 11 SmartScreen,
Smart App Control and Defender's cloud heuristics treat an unsigned
downloaded installer as untrusted. What stays unsigned is what that signed
Setup downloads: the staging client and service. The relaxation is
deliberately narrow and structural:

- it lives in ONE constant, `kRequireAuthenticode`;
- that constant is `true` in every build that does not define
  `VIRULE_ENV_STAGING`, so a production binary's environment never skips
  the signature gates. The `--dev-unsigned` development seam waives them
  only where every development seam is honored: a staging build, or a
  sandboxed run whose `LOCALAPPDATA` is redirected (Development
  command-line seams, below). Setup is STRICTER in source: its own
  `--dev-unsigned` and `--manifest-url=` are honored only in a sandboxed
  run, never merely in a staging build (Setup's development seams, below).
  The canonical signed Setups were re-cut with it (0.9.31, source ee930ec,
  2026-11-12; "The canonical Setup" below);
- a staging build only ever downloads from the staging release repository
  and the staging Worker, neither of which holds a production artifact;
- the exact-size and exact-SHA-256 gates are NOT relaxed. A staging
  package is still pinned byte for byte by its manifest.

The origin allowlists are environment-scoped rather than merged, and they
do not overlap: a staging client does not answer virule.app, and a
production client does not answer the staging site (nor, since audit M-6,
the local development origins, which only a staging build accepts).
That is what stops a page in one environment from ever driving an
install in the other.

**Development command-line seams** (audit L-24, 2026-11-12; owner brief
`VIRULE/docs/scratchpads/FINISH_HARDENING_BRIEF_2026-11-12.md` item 2,
"implement only changes consistent with established authority").
`src/shared/dev_seams.hpp` is the one rule for the client's test seams:
`--dev-unsigned`, `--self-manifest-url=`, `--admin-manifest-url=` and
`--account-endpoint=` are honored, and forwarded by the residency layer
(`residency::forward_seams`, which is all VIRULE Service parses), ONLY
where `dev_seams::allowed()` answers true: a staging build, or a run whose
`LOCALAPPDATA` is redirected away from the real profile
(`paths::environment_redirected`, which fails to false). The evidence test
transport (`--evidence-test-endpoint=`) uses the same predicate, and the
two staging-only harness seams (`--account-browser=capture`,
`--test-purchase-blocker=`) stay stricter (staging builds only). A
production build on a real profile ignores every one of them, as it
ignores any unknown argument; for the four command-line seams it notes the
count in `virule-client.log` (the evidence transport logs its own line).
Every production launch of the client (Setup's start, the Run value, the
`virule://` handler, Apps & Features `--uninstall`, VIRULE Desktop's
starts, the helpers and the residency restores) inherits the real
environment and passes no such seam, while every sandboxed harness
redirects `LOCALAPPDATA` and so keeps driving the production build it
tests. The manifest urls must be loopback (`dev_seams::is_loopback_url`:
exactly `127.0.0.1` or `localhost`, lowercase, an explicit port 1..65535,
then the end of the url or `/`, so no userinfo, longer host, other 127.x
address or IPv6 literal) and the account endpoint `127.0.0.1`, in every
build.
`--no-register` is not gated: it relaxes nothing (it only skips the
machine registrations) and every harness relies on it. This is a RUN-TIME
rule on purpose, unlike the compile-time origin rule: a browser or protocol
launch can carry extra arguments but cannot redirect the environment.
RESIDUAL, inside the same-user trust model (Origin policy above: the
bridge defends against the web, not against local code): a process already
running as this Windows user that starts the client with a redirected
`LOCALAPPDATA` can still reach the seams. Proof:
`tests/environment/run_tests.bat`.

**Setup's development seams** (owner brief
`VIRULE/docs/scratchpads/OWNER_DIRECTED_COMPLETION_BRIEF_2026-11-12.md`
section 7: development-only overrides must not let production-trusted
Setup install untrusted or unsigned software). In source,
`src/setup/main.cpp` takes its two seams, `--dev-unsigned` and
`--manifest-url=`, from `dev_seams::parse_setup`, which honors them ONLY
where `dev_seams::setup_permitted(redirected)` answers true: a run whose
`LOCALAPPDATA` is redirected away from the real profile, in BOTH builds.
Setup deliberately does not get the client's staging exemption: Setup is
the signed executable a user downloads and runs on a real profile, and the
staging Setup is signed too while verifying no Authenticode
(`kRequireAuthenticode` is false there), so a staging exemption would let
one `--manifest-url=` install any payload from any host. `--manifest-url=`
must also pass `is_loopback_url` (above). A seam that is present but not
honored is ignored, the normal verified install proceeds against the
compiled-in manifest (repository pin, https, Authenticode and the VIRULE
signer where the build requires them, exact size and SHA-256), and Setup
writes one line to its log with the count, as the client does. Every
harness that drives Setup's seams (`tools/takeover_test.mjs`,
`residency_test.mjs`, `uninstall_lifecycle_test.mjs`,
`arp_isolation_test.mjs`) redirects `LOCALAPPDATA` and serves its
manifest from `http://127.0.0.1:<port>/manifest.json`, and a redirected
Setup writes no machine registration (its registrations refuse on their own
there). RESIDUAL, inside the same-user trust model: a process already
running as this Windows user can start Setup with a redirected
`LOCALAPPDATA` and its own loopback server; that installs into the
redirected tree only. Proof: `tests/environment/run_tests.bat`.
THE CANONICAL SETUPS CARRY THE FIX: both permanent signed Setups
(`release/setup/{production,staging}/Virule-Setup.exe`,
`release/setup/canonical_setup.json`) were re-cut TOGETHER from ee930ec on
2026-11-12 under the owner's finish brief of that day ("prepare the
corrected signed installers using established release procedures. Do
not independently replace production installers"): built, signed with
the VIRULE identity, approved and pinned. The STAGING Setup is published
by the next staging release; the PRODUCTION Setup is published only by a
production Client publish (`publish.ps1`), which the owner authorizes:
until then the Setup people download from production is the 3454b27 one
and still honors both seams ungated.

**Staging distribution** uses FIXED tags on `getvirule/virule-staging-releases`
rather than a `latest` pointer, because that repository also carries the
staging Admin packages and "latest" there would mean whichever release was
cut last:

| Tag | Assets |
|---|---|
| `client-staging` | `Virule-Setup.exe`, `virule-client.exe`, `ViruleService.exe`, `manifest.json` |
| `admin-staging` | `Virule-v<version>-staging.zip` |

`helpers/publish_staging_client.ps1` is the only writer of the first, and
it is the mirror image of `publish.ps1`: where the production publisher
refuses anything unsigned, the staging publisher refuses anything that is
not a STAGING build (it reads the compiled-in staging host out of the
bytes) and refuses to touch a production repository or tag. The client,
service and manifest are replaced with `--clobber`; `Virule-Setup.exe` is
the canonical SIGNED staging Setup, pinned by SHA-256 (The canonical
Setup), and nothing else is ever published in its place.

The whole staging environment is built and deployed by one script,
`v2_mvp\helpers\release_staging.ps1`, which also proves it did not touch a
signed production artifact and re-reads the production manifest afterwards.
`tools/staging_env_test.mjs` is the end-to-end proof.

## The canonical Setup (owner ruling 2026-10-19)

`Virule-Setup.exe` is a bootstrapper, not the application: it downloads and
verifies the approved client release of ITS environment. It is therefore a
STABLE, SIGNED binary reused unchanged across releases. No normal release,
staging or production, builds, signs or substitutes Setup; updating VIRULE
never requires a new Setup.

WINDOWS 10 AND LATER (owner decision 2026-10-30,
`VIRULE/docs/specs/evaluation-security.md` "Windows support"): Setup is the
authoritative enforcement point. FIRST in `wWinMain`, before its command
line is read and before anything is downloaded, listened for or written, it
reads the real version (`src/shared/os_support.hpp`, `RtlGetVersion`, never
the manifest-dependent `GetVersionEx` / VersionHelpers) and refuses a major
version below 10 on its card with `VIRULE requires Windows 10 or later.`
(the owner's brief 2026-10-31: "Known Windows major version below 10 must
show: VIRULE requires Windows 10 or later."); Windows 10 and 11 pass. Test:
`tests\os_support`. LIVE in both environments since 2026-10-31: both
canonical Setups were re-cut from 3454b27 (below). The Client itself adds no
refusal: an installation that exists keeps working.

Setup is environment-specific at compile time (the client manifest URL, the
download prefix and `kRequireAuthenticode` come from `launch_policy.hpp`): a
production Setup fetches only the production manifest, accepts only
`getvirule/virule-client` downloads and requires a VIRULE signature on them,
so it cannot install staging; a staging Setup is the reverse. There are
therefore exactly TWO canonical binaries, both signed with the VIRULE
identity and timestamped, committed in this repository:

| File | Pinned in `release/setup/canonical_setup.json` |
|---|---|
| `release/setup/production/Virule-Setup.exe` | Setup 0.9.31, source ee930ec, signed 2026-11-12 (not yet published to production) |
| `release/setup/staging/Virule-Setup.exe` | Setup 0.9.31, source ee930ec, signed 2026-11-12 |

`helpers/canonical_setup.ps1` is the one check, and it fails closed: a
missing pin, a missing file, any byte or size difference, an invalid,
foreign or untimestamped signature, or the other environment's release
repository compiled in refuses the release. `publish.ps1` and
`publish_staging_client.ps1` publish ONLY the canonical file (never
`build\Release\x64\...\Virule-Setup.exe`), then re-download the public
asset and require the pinned SHA-256 and a valid signature again;
`release_promote.ps1`, `release_verify.ps1` and `release_staging.ps1` check
the same pin. `build.ps1 -Stage all` builds the client and the service only.

The client and the service still change freely; the staging client and
service stay unsigned (a staging Setup does not require their signatures).
The protocol between Setup and the client (the handoff envelope,
`setup_takeover` / `setup_wait`, the manifest wire form) is therefore a
compatibility contract: every client must keep serving the canonical Setups.

Both Setups are PERMANENT. A Setup re-cut happens only when the owner
explicitly authorizes a change to Setup itself, and then BOTH downloaders
receive it together, from ONE source commit, and are signed and verified
together: `build.ps1 -Stage setup -Environment Production` and
`-Environment Staging`, sign both exact files with the VIRULE identity, then
`helpers/approve_canonical_setup.ps1 -Production <file> -Staging <file>
-SourceCommit <sha> -Replace` (it refuses to replace one environment alone),
commit `release/setup/`, publish. Signing:
`VIRULE_SECURITY\artifact-signing\sign_client_setup.bat` signs the
production build; `-Environment Staging` signs the staging build in its own
`build\Release\x64\staging\` leaf (manifest group `clientSetupStaging`),
so neither binary is ever copied into the other's place. Publishing: the
staging Setup goes out with the next `release_staging.ps1`; the production
Setup goes onto the CURRENT latest client release with `publish.ps1`'s own
Setup step (`gh release upload <latest tag> Virule-Setup.exe --clobber`,
then `Assert-PublishedSetup`), because `publish.ps1` itself publishes the
`version.h` client and a Setup change never needs a client release (re-cut
2026-10-31: onto v0.9.0). The one single-environment approval ever
allowed was the first staging pin (2026-10-19), because no staging Setup
existed.

BOTH SETUPS SHARE ONE SOURCE (re-cut 2026-11-12 from ee930ec: the gated
development seams; before that the 2026-10-31 re-cut, 3454b27; owner
brief 2026-10-31): the production Setup gained what the staging one already
had (the evaluator entry point, 0.9.9; the "Continuing…" card, 0.9.10) and
both gained the Windows 10 refusal. Compatibility with the production 0.9.0
client was checked in source: 0.9.0 reads the takeover by key and ignores
the added `capability` field, and `state.json`'s added `enabled_*` fields
are ignored by its loader (independent verifier PASS).

Why: on 2026-10-19 every staging client release rebuilt and published an
UNSIGNED staging Setup, which Windows showed as "Publisher: Unknown" and
Defender's cloud heuristics flagged (`Contebrew.A!ml`). Review:
`VIRULE\docs\reviews\SETUP_SIGNING_2026-10-19.md`.

## Distribution (GitHub Releases, getvirule/virule-client)

Setup and the client are INDEPENDENT signed artifacts published as GitHub
Release assets on `getvirule/virule-client` (a public repository; release
assets are only publicly downloadable from public repositories):

| Asset (per release tag `v<version>`) | Mutability |
|---|---|
| `Virule-Setup.exe` | the CANONICAL production Setup, the same bytes on every tag (see The canonical Setup) |
| `virule-client.exe` | IMMUTABLE; a published version is never rewritten |
| `ViruleService.exe` | IMMUTABLE (since 0.9.0); same rule as the client |
| `manifest.json` | describes THAT release's client and service |

The LATEST release is the approved release. Setup follows
`releases/latest/download/manifest.json`; the site links
`releases/latest/download/Virule-Setup.exe`; publishing a new release is
the act that moves the pointer. Direct asset URLs only (they redirect
https to https onto GitHub's CDN; WinHTTP follows that by default), never
the human release page.

The manifest is minimal and secret-free:
`{"version","url","sha256","size","service_url","service_sha256","service_size"}`
in COMPACT JSON (the marker scanner takes no whitespace). The first four are
the client's and keep their names and their place; the three `service_*`
fields (0.9.0) are ADDITIVE: every scanner matches a field name with its
leading quote, so `"url"` never matches `"service_url"`, and every Setup and
client ever shipped (and v2_mvp's `client_health` repair) reads exactly what
it always read. `helpers/publish.ps1` is the only writer: it refuses
unsigned artifacts, refuses to overwrite a published client or service with
different bytes, uploads the service BEFORE the manifest that names it, and
verifies every public asset URL by re-downloading it.

### VIRULE Service distribution (0.9.0)

`src/client/service_install.hpp` is the whole implementation, and it is the
client's own trust model applied to a second file: url pinned to this
environment's client release repository, exact size, exact SHA-256 (never
waived), Authenticode + `CN=Heath Michaels` (staging skips only the two
signature gates; `--dev-unsigned` likewise). No second update system: the
client's ordinary update check (startup, the 6-hour recheck, the forced
check a user Admin operation triggers) parses the service fields and calls
`reconcile`:

- the installed service is MISSING: install the manifest's (the migration
  path for every machine whose client arrived through an older Setup or the
  self-update, and the repair path; the watch also forces one check the
  moment it finds the executable gone, then at most one per 30 min);
- it is present and the manifest is THIS client's release but the bytes
  differ: replace it (the service update rides the client release);
- a newer manifest leaves it alone (the client that self-updates to that
  release brings its own service); an older one never downgrades it;
- a malformed set of service fields refuses only the service, never the
  client's own update; a release without them (older releases) is not an
  error.

Replacement is a maintenance transaction: download to
`ViruleService.exe.update`, full gate, take the maintenance lock, stop the
running service (`Local\VIRULE.Service.Stop`), live -> `.old`, staged ->
live, start it and require residency within 10 s; any failure restores the
known-good binary, starts it, and holds that exact artifact against retry
for 6 hours. Startup restores a stranded `.old` and discards stale staging.
A sandboxed client never downloads without a manifest seam.

Setup (0.9.0) acquires the service through the same gates and places it
beside the client while it holds the maintenance lock; a service that
cannot be acquired never fails the install (the client repairs it).
Since 2026-09-11 it is driven by the product-wide promotion
(`v2_mvp\helpers\release-production.bat`, `release_promote.ps1`): the
client ships only when `src\shared\version.h` is above the live manifest
AND this repository's HEAD is clean, pushed, and the commit staging was
built from and QA approved; the promotion builds the Production client
and service, signs both, runs this publisher with the canonical Setup
(never rebuilt), then re-downloads the published Setup and checks it is
the pinned, signed binary. A commit or push here deploys nothing.
GitHub is a HOST, not a trust anchor: everything a user runs is still
gated by the manifest hash plus the VIRULE Authenticode identity below.

## Client self-update (v0.7.0)

The client is the persistent machine manager and manages ITS OWN updates:
a Client-only release reaches installed machines with no Setup rerun, no
GitHub visit, no reinstall, and no Admin release. Virule-Setup.exe remains
bootstrap/repair infrastructure (first install, missing/broken client).
`src/client/self_update.hpp` is the whole implementation; managed installs
only (a client running from anywhere but the installed path never
self-updates).

TRUST IS SETUP'S, REUSED EXACTLY: the LATEST getvirule/virule-client
release's `manifest.json`, url pinned to that repository's
`releases/download/` prefix, exact declared size, exact SHA-256 (never
waived), Authenticode + `CN=Heath Michaels` - re-verified IN FULL by the
helper immediately before the swap. Dev seams mirror Setup's:
`--self-manifest-url=` (loopback only) relaxes only the repository pin,
`--dev-unsigned` waives only the signature gates; both are honored only in a
staging build or a sandboxed run (Development command-line seams).

CADENCE: one asynchronous check shortly after startup (never blocking the
bridge) plus a quiet 6-hour recheck while serving; the freshness stamp is
written before the attempt so a failing network cannot hammer. SemVer
UPGRADE only: equal does nothing, an approved version lower than the
running build never auto-downgrades (rollback stays an explicit act).

DOWNLOAD FIRST, SWAP WHEN SAFE: the update is streamed to
`virule-client.exe.update`, verified, and recorded in the explicit
transaction `client\self_update.json` (`verified` -> `swapping` ->
cleared, or `failed` with a 6-hour retry hold; never "file exists
therefore maybe update"). The swap waits for a SAFE TAKEOVER POINT: no
uninstall, no Admin install/update/launch handoff, no fresh QA
redemption, no Setup takeover in flight, no native lifecycle card. Then
the bridge drains (new lifecycle operations are refused for the final
seconds), a %TEMP% copy of the signed client runs `--finish-self-update`,
the old process exits, the helper renames live -> `.old` and staged ->
live, starts the new client, and confirms the takeover by the bridge
answering with the NEW version. Success removes every trace; any failure
puts the known-good binary straight back, restarts it, and records the
failure. A fresh `swapping` record belongs to the helper (a starting
client leaves it alone for 10 minutes) so a rollback can never race a
re-staged copy of itself into a loop. The exiting client announces its exit
and the helper holds the residency maintenance lock for the whole swap or
rollback (0.9.0), so VIRULE Service never restores the binary mid-rename.

QUIET BY DESIGN: no card, no toast, no Admin modal - the restart fits
inside the browser's 5-second disconnect hysteresis and open virule.app
pages simply reconnect. EXPLICIT UNINSTALL ALWAYS WINS: under the durable
intent latch nothing checks, stages, swaps, or resurrects, staged residue
is discarded, and the helper stands down without starting anything.

VERSION AUTHORITY: the executable's compiled version constant is the one
truth. At startup a managed client heals the mirrors from it -
state.json's `installed_version` and the Apps & Features `DisplayVersion`
(only when the ViruleClient entry's own UninstallString names this
executable). Setup, for its part, clears self-update residue whenever it
installs (its install is the one client-acquisition transaction while it
runs). Targeted regression suite: `tools/self_update_test.mjs` (`pre` =
sandboxed lifecycle scenarios; `swap` = a real old->new binary swap).

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
version (the manifest's) in state.json, places the release's verified
`ViruleService.exe` beside it (0.9.0; never fatal), starts the client,
transfers the takeover, and waits for the client's release (see "The Setup
takeover"). From stopping the running client until the new one has been
started it holds the residency maintenance lock, so VIRULE Service never
restores the binary being replaced.
Development seams: `--dev-unsigned` waives only the signature gates;
`--manifest-url=` fetches the manifest from a loopback server and relaxes
only the repository pin; in source both are honored only in a sandboxed run
(Setup's development seams); the permanent signed Setups still honor them
ungated until their re-cut.

### Setup's one native surface

Setup used to run and vanish with no window: technically correct (the
browser owns the flow) and, in practice, untrustworthy. It now shows ONE
small card in VIRULE's native visual language (the Admin splash grammar:
square-cornered card, yellow V mark, spaced wordmark, one muted line), and nothing
more. NOT A WIZARD: no pages, no Next/Back, no destination picker, no
component list, no license page and no user choice of any kind.

| State | Copy |
|---|---|
| Working | `Setting up VIRULE...` + a subtle indeterminate bar, held until the client releases Setup |
| Complete | `Continuing…` briefly, then it closes itself (never a completion claim; 2026-10-19) |
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
  `{"type":"handoff","v":1,"op":"INSTALL_ADMIN","shortcut","capability"}`
  (v0.9.9: `capability` is the entry point, `dev_tools` or `evaluator`;
  absent or anything else is kept as `dev_tools`); anything else answers
  `{"type":"error"}`;
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
feedback surface is demonstrably in place. THE SINGLE AUTHORITATIVE
DECISION (v0.6.5, superseding the earlier page-alive step-aside
branches): every Setup takeover terminates in exactly ONE of two native
surfaces, and Setup is never released into neither.

- PENDING INTENT EXISTS -> the branded native continuation card
  "Finishing up…", UNCONDITIONALLY; a live page renders its own progress
  IN PARALLEL, never instead. A QA_ACCEPT continuation resolves to
  "You're all set." and closes itself while a live page still receives
  the result push. An INSTALL_ADMIN takeover holds the card through
  "Installing…"/"Updating…" until the installation completes and the
  launched Admin is VISIBLE; envelope-driven and page-driven installs
  converge on the ONE `g_busy` operation whichever starts first, and an
  already-current installed Admin short-circuits to a watched open (never
  re-downloads the package). The takeover's INSTALL_ADMIN carries the
  envelope's `capability` (validated like the page's: absent or unknown =
  `dev_tools`), and the client RECORDS it first, before either the
  watched open or the install (v0.9.9). QA_ACCEPT and the standalone
  takeover record nothing.

THE LAST HOP IS PROVEN LIKE EVERY OTHER, BY WHAT THE USER SEES (v0.8.0
dead-air fix, corrected v0.8.3, 2026-09-10): every card that ends in an
Admin launch (the takeover continuations, the Settings/launch-handoff
"Updating…" card) retires through ONE helper,
`admin_install::retire_card_into_admin_surface`, and nowhere else. The
rule it enforces: A VIRULE SURFACE MUST NOT RETIRE MERELY BECAUSE ITS
SUCCESSOR HWND HAS `WS_VISIBLE`. The successor must actually be presented
to the user at the retiring surface's position, or the current surface
stays until a later successor genuinely is. In order:

1. `wait_for_admin_window` (unchanged, 90 s bound) proves the next
   surface EXISTS: a visible, unowned top-level window of a
   managed-directory process, virule.exe's startup splash or the Admin
   window, whichever paints first. `WS_VISIBLE` proves existence only.
2. While the card still exists and still owns the foreground, the client
   hands the foreground to that surface (`SetForegroundWindow`; the
   client is the foreground process, so Windows permits it).
3. The handoff is confirmed by presentation, not by the flag:
   `GetForegroundWindow()` is a managed-directory window, or the root of
   `WindowFromPoint(card centre)` belongs to a managed-directory process.
   A short bounded confirmation (1.5 s ceiling), never a fixed delay: it
   returns the instant either holds.
4. Only then does the card close. Destroying a window that is no longer
   active transfers activation to nothing, so the splash stays on top.
5. If the handoff is refused, the card does NOT close: "Finishing up…"
   holds until the REAL Admin window is visible (title "VIRULE Admin",
   image ViruleAdminHost.exe in the managed directory, never a dialog),
   hands the foreground to it the same way, then closes. That path is
   Finishing up -> Admin with the splash skipped, never Finishing up ->
   browser -> Admin. The 90 s bound runs from the helper's entry; a
   managed process that dies still releases the card to the recovery.

Why the flag was never enough (audit
`SPLASH_HANDOFF_AND_PERMISSION_COPY_AUDIT_2026-09-10.md`): the card is
the FOREGROUND window and the splash is a non-activating tool window at
the same rectangle. Closing the active card made Windows activate the
previous window, the browser, which was raised above the splash; the
splash then sat "visible" behind the browser for the Admin's whole
first-run startup. v0.8.1/0.8.2 retired the card on the splash's flag
~0.5 s after launch and therefore showed exactly that. The act of
retiring changes the z-order, so no flag read before the close can be
sufficient unless the foreground has already moved to the successor.

It used to retire on process existence (CreateProcess returning, or the
8 s launch watch passing), which on a slow machine was the Admin's whole
startup of dead air. A concrete launch failure is still audit M15's 8 s
watch plus its recovery card, and a live process with no window after
the bound simply releases the card. The 8 s watch itself
(`launch_admin_watched`) ends early on the existence proof (2026-09-10):
it is a failure detector, and a visible managed-Admin window leaves
nothing to detect. A launch with no window still burns the full watch
exactly as before. virule.exe's splash is unchanged: it never steals
focus on a normal launch; the client, already holding the foreground,
gives it away. The takeover's `busy` hold and the site's
`adminInstalling` timeout are a MATCHED PAIR at 45 minutes (~1 Mbit/s
floor for the ~308 MiB package; the HTTP layer's 60 s per-read timeout
ends a dead transfer long before either fires); raise both together or
neither.
- NO PENDING INTENT (the bounded watch expires with no operation; a
  merely-connected idle page is NOT an operation and does not suppress
  this) -> the standalone branded card with the ONE explicit
  `[ Continue ]` action. Its line never claims completion before there is
  one (owner brief 2026-10-19): "Finish installing from the site" while
  VIRULE (the managed Admin) is not installed, whose site action reads
  Finish installing; "VIRULE is ready" only when it is. Only that click
  opens a browser: THIS BUILD'S site (`env::kSiteUrl`: virule.app in
  production, the staging origin in a staging build), in the Windows
  default; the homepage's continuous detection then resolves the
  machine's real state, and a browser intent the site still holds (an
  evaluator's, say) keeps its capability. A Setup of the OTHER
  environment cannot know about this one: a production Setup always
  continues to virule.app, so staging QA uses the Setup the staging site
  downloads (see Environments). The card is TERMINAL
  but REVOCABLE: a browser-owned operation arriving late (a
  closed/throttled tab delivering its durable intent) supersedes it, and
  a mid-watch arrival is instead converted live into the continuation so
  Ready never flashes first.

THE LATE-ENVELOPE UPGRADE KEEPS A LIVE WORKING CARD (v0.7.4 dead-air
fix): the standalone->operation upgrade closes only a non-Working card;
a visible "Finishing up…" card is ADOPTED, never destroyed and reshown,
and the next-surface-visible gate accepts only a genuinely visible
Working card (`is_working_visible`), so Setup can never be released
against a dying window.

`result_card.hpp` is the ONE client lifecycle surface: the bare Result
mode is the unchanged QA-doctrine card (no brand mark), while Working /
Ready / resolved lifecycle Results wear the branded grammar (V mark,
status line, indeterminate bar or action button; no wordmark). It is
reusable across the persistent client process, and both executables embed
the official VIRULE application icon (`assets/ViruleAppIcon.ico`).

THE TRANSITIONAL FAMILY IS ONE COMPONENT (owner law 2026-09-10,
`VIRULE/docs/specs/UIUX.md` product-wide law 2): Virule-Setup's card
(`setup_window.hpp`), every branded client card here and virule.exe's
"Loading…" startup splash (`v2_mvp/src/cli/main.cpp`) share one fixed
geometry: a 340 x 176 card, the 44 px V mark at y = 30, the status line
in the 94..118 band (13 px REGULAR weight, the word color; never
semibold/bold), and the 168 x 3 indeterminate bar at y = 136 BELOW the
status (mark, status, bar). Only the Ready / Action cards are taller
(192) for their button. A status change never moves anything; change one
surface and change all three.

The same lifecycle grammar carries the Admin update: a Settings-initiated
update shows the Admin's "Shutting down VIRULE" overlay, the client closes
it gracefully and IMMEDIATELY owns the feedback with the native "Updating…"
card through download / verify / stage / replace, then relaunches the new
Admin (a failed update relaunches the untouched known-good Admin). A
user-initiated launch of an out-of-date managed Admin is handed over by
virule.exe as the local-only `admin_launch` bridge message: the client
updates first (same card) and launches only the new Admin; a failed update
never blocks the launch.

LAUNCH-TIME LOOP BREAKER, PERSISTED (P2 hardening, v0.7.2): a failed
launch-time transaction records ONE hold in state.json
(`admin_hold_version`, `failed_utc`, `until_utc`) that survives client
restarts, read as TWO windows: 90 s of claim suppression for every
`admin_update_check` caller (the loop breaker), and a 6 h launch-retry
window for callers declaring `{"context":"launch"}` (the virule.exe
launch check), so a persistently failing package is never re-downloaded
on every launch while Settings and virule.app keep seeing the update.
The hold is cleared by any successful install/update and by startup
housekeeping (expired, moot, malformed, future-stamped). WATCHED
RELAUNCH (P2): every update-path Admin launch is watched (a
CreateProcess failure or an early exit with no managed process is a
concrete failure); one automatic retry after 2 s, then the client-owned
"Something went wrong." + Try again card. Try again retries ONLY the
launch; an intact installation is never re-downloaded for a launch
problem, and dismissal ends the recovery with everything preserved.

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
protocol preflight and, v0.9.9, the entry point's `capability` (see
"Installed capabilities"), on `admin_install` and on the Setup envelope
alike. The moment a client is connected with `INSTALL_ADMIN`
pending, the page hands the install over (`admin_install`, the shortcut
preference riding along) and shows only "Installing VIRULE..." - there is
no stopping point and no second install button. An already-installed
Admin means the work is done (the client finished it after the page
closed); the intent is cleared and the page settles.

VIRULE uninstall has TWO EXPLICIT MODES (owner spec 2026-09-03; see
`src/shared/uninstall.hpp`), both driven by an explicit ownership
inventory. The DEFAULT preserves user data: it removes the install dir
(`ViruleService.exe` and the managed `Admin\` installation included; the
service is told to stop the moment the latch is written), the client state dir,
`virule://` ONLY while it points at this client, the uninstall entry, and
the desktop `VIRULE.lnk` ONLY when the client created it (state.json
provenance); `virule.db`, `workspace\`, `logs\`, `backup.json` and the
whole `security\` credential store (dev_machine.cred AND qa_tester*.cred)
all stay, and the shared `VIRULE\` folder goes only if left empty. The
explicit DELETE LOCAL DATA mode (the `delete_data` flag behind the site
modal's toggle / the native dialog's checkbox, each with its "cannot be
undone" warning) additionally removes the `%LOCALAPPDATA%\VIRULE\`
user-data root, EXCEPT undelivered evaluation evidence and report drafts
(owner ruling 2026-10-22; the kept set, PENDING OWNER DECISION, is in
"Evaluation evidence delivery", "Uninstall and undelivered evidence"); with
nothing to keep the entire root goes, as before. Both surfaces say "Uninstall VIRULE" (never "Remove").
The running exe hands removal to a `%TEMP%` copy
(`--finish-uninstall <pid> [--delete-data]`) so no broken executable is
left behind. Development trees (the VIRULE repository, its
`virule\publish\Virule` folder) and the user's chosen build root are
outside every inventory root and can never be touched. A full VIRULE
uninstall and removing an individual future game are SEPARATE actions
forever; this inventory must never grow a recursive game-library delete.

### The durable intent latch and the ordered teardown (P0, 2026-09-04)

EXPLICIT USER UNINSTALL OUTRANKS EVERY AUTOMATIC RECOVERY (the locked
precedence): once removal begins VIRULE may not repair, reinstall,
re-register or relaunch itself. THE DURABLE INTENT LATCH is the registry
value `HKCU\Software\VIRULE\Lifecycle` / `UninstallInProgress`
(REG_DWORD 1, plus an `UninstallStartedUtc` inspection stamp;
`src/shared/lifecycle_intent.hpp`): written BEFORE any teardown,
surviving process exits and partial failure, cleared LAST after a fully
successful removal, or by an explicit Virule-Setup install (newer
explicit intent in the opposite direction; also the stale-latch recovery
path). The key path and value name are a CROSS-REPO CONTRACT: the VIRULE
Admin (admin_host `client_health`, virule.exe's launch cooperation)
reads the same location with its own copy of the check. Every
resurrection path on both sides honors it - self-heal, repair, on-demand
client start, protocol re-registration, update, managed launch - and
stands down while it is set; a freshly started client refuses to serve
at all while latched, and self-update discards staged residue under it.

THE ORDER IS THE CONTRACT: intent latch -> the bridge refuses new
lifecycle operations (status carries `"uninstalling":true`;
`uninstall_state` removing/failed pushed to pages) -> an in-flight Admin
update is CANCELLED back to known-good (stage-boundary checks plus an
abortable download; uninstall wins, never drained) -> update residue
reconciled -> the Admin closed GRACEFULLY (a refusal aborts with NOTHING
destroyed, failure push, latch kept) -> the signed-in evaluator's
undelivered evidence is delivered while files keep being acknowledged
(owner ruling 2026-10-22; ends on an empty outbox or a 60 s stall, PENDING
OWNER DECISION; "Uninstall and undelivered evidence") -> the installation
signs out -> the client exits -> the VISIBLE
`%TEMP%` helper (branded "Removing VIRULE…" card; log in
`%TEMP%\virule-uninstall.log`) waits for every install-dir process,
removes FILES (bounded retries per tree), then REGISTRATIONS LAST
(`virule://` only while it points into the removed tree, then the ARP
entry), verifies, clears the latch LAST, and shows "VIRULE has been
uninstalled." (plus "Your local data was kept." in the default mode) for
5 s (dismissible; the only result card with a shorter life than the 10 s
default, scoped through `result_card::update(..., life_ms)`).

THE SITE'S NORMAL SIGNAL IS POSITIVE (v0.8.2, 2026-09-10): between
starting the helper and exiting, the client pushes `uninstall_state
"complete"` to every connected page over the bridge connection it
already holds (the accept listener is closed by then; page connections
stay open). "Complete" means COMMITTED: every step that can run while
the client lives has run and the helper is running, so the only work
left is deleting the client executable itself and the helper's own
cleanup. The page leaves "Removing VIRULE…" for Get VIRULE at once and
closes its socket; the client waits for its page connections to go (that
close IS the delivery acknowledgement; no new message type) or 1.5 s,
whichever is first, then exits (`bridge::wait_pages_closed`). The site's
15 s bridge-absence window (`REMOVAL_ABSENCE_CONFIRM_MS`) remains ONLY as
the fallback for a client that died mid-teardown without sending it. A
failed removal keeps the latch AND the registrations
(Windows-recoverable) and offers Try again on the card.

## Installed capabilities (0.9.9) and account roles (0.9.12)

`src/shared/installed_capabilities.hpp`, persisted in `client\state.json`
(`enabled_recorded`, `enabled_dev_tools`, `enabled_evaluator`). VIRULE is
ONE installation (one Virule-Setup.exe, one managed Admin package) whose
ENTRY POINT record is acquired through ENTRY POINTS (owner ruling 2026-10-16):

- the homepage "Get VIRULE Dev Tools" entry enables `dev_tools`;
- an evaluator's "Install VIRULE" entry (the website account page) enables
  `evaluator`.

The record decides the Admin's workspaces only for an installation no
account was ever confirmed on (ADMIN NAVIGATION below).

The entry point determines the capability, and the existing handoff carries
it: a page's `admin_install` (recorded as the request is accepted), the
Setup envelope through the takeover (recorded at the start of the
INSTALL_ADMIN run), or `capability_enable` for an installation that already
exists (no reinstall). Capabilities are ADDITIVE: receiving one never
removes another. The Admin reads the record from `account_status`, the
website from `status`, both as `enabled{dev_tools,evaluator}`.

ROLES ARE THE ACCOUNT'S (owner ruling 2026-10-20, replacing "the
installation and the account together" of 2026-10-16). The service grants
`developer` only through Install Dev Tools and `evaluator` only through the
evaluator approval and accepted invitation; signing up grants nothing
(VIRULE_BACKEND `docs/ACCOUNTS.md`). `src/shared/account_roles.hpp` keeps
the two local facts this needs in `client\account_roles.json` (its own
file, because the pinned Setup rewrites state.json with its own field
list):

- `pending_developer`, the INSTALL DEV TOOLS INTENT, recorded ONLY for the
  person's explicit Get VIRULE Dev Tools / Install Dev Tools (EXPLICIT
  ENROLLMENT ONLY, owner rule 2026-10-20, 0.9.13; installed software is not
  enrollment): `capability_enable dev_tools` from a page (the homepage's
  Get VIRULE Dev Tools on an installation without Dev Tools) or the Admin's
  Settings > Install Dev Tools; a page's `admin_install` carrying
  `"enroll_developer":true` (the site sends it only for a pending Get
  VIRULE Dev Tools); and the Setup envelope's INSTALL_ADMIN `dev_tools`
  (the site hands Setup a `dev_tools` envelope only for Get VIRULE Dev
  Tools, and the pinned Setup normalizes the envelope, so this is the one
  fact it can carry). NEVER recorded by a page `admin_install` without
  `enroll_developer` (the homepage's Update and Finish installing), a local
  `admin_install` (Settings Update), the launch update, the one-time
  capability migration, a sign-in, or Dev Tools already recorded on the
  installation. Recording `dev_tools` in the capability record
  (`installed_capabilities.hpp`) is presentation and never an intent. The
  Client delivers it (`POST /v1/account/developer/enable`) to the signed-in
  account at once (confirm), or, when it was made SIGNED OUT, right after
  the next sign-in before `/me` is read; one made SIGNED IN is bound to
  that account (`pending_bound`) and dropped at sign-out, so it never
  reaches another account. Cleared once the service answers 200 or 403,
  kept while it is unreachable. While signed out the request also adds Dev
  Tools to the remembered layout. The record is version 2; a version 1
  record (0.9.12, which recorded an intent on every homepage Update and
  delivered it as a developer grant) is read with NO intent, because a
  real one cannot be told apart from an Update's.
- REMEMBERED ROLES: every successful `/v1/account/me` records the account's
  effective `developer` / `evaluator`, kept through sign-out, reported as
  `account_status.remembered`.

ADMIN NAVIGATION (`ui/account.ts` `workspacesFor`). Signed in, the
account's service-confirmed roles decide: developer only = GAMES,
EVALUATIONS, CAMPAIGNS; evaluator only = ASSIGNMENTS; both = all four; an
account with neither role sees the local Dev Tools. Signed out: the
remembered roles of the last account confirmed here, else the entry point
record (`evaluator` alone = Assignments; `dev_tools` or nothing recorded =
Dev Tools). EVALUATIONS is part of every Dev Tools layout, signed out too,
where MY EVALUATIONS asks the person to sign in and holds no record.

LOCAL PRESENTATION ONLY, NEVER AUTHORIZATION. Neither record grants
anything at the VIRULE service, which enforces the account's capabilities
on every call.

MIGRATION, one time, at client startup (after the installed-version
reconciliation): an installation with no record gains `dev_tools` when the
managed Admin is installed (every Admin installed before 0.9.9 came
through the Dev Tools entry point) and never `evaluator`. The migration
only adds, so a capability recorded in the moments before it ran is kept.

Every uninstall removes both records with the client state directory, so a reinstall
starts fresh. QA is untouched: a QA invitation keeps its per-game QA
credential flow and records nothing here (QA credentials are not
capabilities of this record).

Every in-process state.json read-modify-write goes through
`state::update()` under one mutex, and `State` carries every field, so no
writer can drop another's fields. Proof: `tools/takeover_test.mjs`
scenarios 8 and 9 (`--staging --only=8,9`).

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
to that repository's `releases/download/` prefix. Dev seams mirror
Setup's: `--admin-manifest-url=` points the approved-manifest fetch
at a loopback server and relaxes only the repository pin; `--dev-unsigned`
waives only the signature gates; both are honored only in a staging build
or a sandboxed run (Development command-line seams).

THE VERIFIED STAGED PIPELINE (install and update are the same path; an
update never touches the live install file-by-file): fetch manifest ->
validate structurally -> streamed download capped at the declared size,
hashed on the way through -> exact size -> exact SHA-256 (never waived) ->
zip-slip-guarded extraction into `Admin.staging\` (THE ZIP ENTRY NAME GUARD,
in "Local malware scanning") -> Authenticode + the
VIRULE signer identity (`CN=Heath Michaels`) on every VIRULE-owned binary
(virule.exe, ViruleAdminHost.exe, SidecarK32/64.dll, both
SidecarKHost.exe, and ViruleUIHelper.exe WHEN PRESENT: newer packages carry
it, older approved packages do not, and both stay installable) -> atomic
placement. A fresh install is ONE directory
rename; an update renames live -> `Admin.previous`, staging -> `Admin`,
and a failed swap renames the previous install straight back, so a
known-good install always survives.

STARTUP RESIDUE RECONCILIATION (uninstall corrective pass, hardened by
the P2 pass): once at client startup, before any operation can be in
flight, an interrupted update cannot strand the managed tree. A missing
live `Admin\` with a surviving `Admin.previous` is restored locally ONLY
when the previous tree passes the pipeline's own bar (well-formed
install metadata plus a valid VIRULE signature on every required
component; `--dev-unsigned` relaxes only the signature half); a tree
that fails validation is never promoted and never deleted here. Stale
staging and stale downloads are always debris. The uninstall-path
restore stays unvalidated on purpose: everything it touches is about to
be removed.

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

THE PACKAGE CARRIES THE OUTREACH PROVIDER CONFIGURATION (2026-09-16):
`outreach_providers.json` at the package root is the owner's registered
Google and Microsoft application configuration, the reason Connect in the
Admin is a sign-in and nothing more. `publish_admin.ps1` refuses to
package or publish a tree without it, the staged tree is refused without
it (`kRequiredFiles`, existence only: it is data, not a signed binary),
and every update re-places it with the rest of the tree.

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
15-minute-fresh refetch on the local `admin_update_check` ask). The two
SCHEDULED checks run whether or not a managed Admin exists, because they are
also this installation's check-in (below, v0.8.6); without an Admin the
manifest answer is simply unused. An ask from the Admin never runs without a
managed install. Checking is automatic; INSTALLING is
always user-initiated (Admin Settings > GENERAL > Update, or virule.app's
Update VIRULE). The Admin host owns no manifest logic: it asks over a
local control connection, starting the (resident) client if it is not
serving, which is the in-session recovery for a client ended by hand.

THE CHECK-IN RIDES THE UPDATE CHECK (owner spec 2026-10-01, v0.8.6;
product law `VIRULE/docs/specs/usage-tracking.md`). Every manifest check is
sent as a `POST` to the same path (`src/shared/manifest_request.hpp`,
`src/shared/usage_checkin.hpp`) and does two things in the one request:

1. IDENTIFIES THIS INSTALLATION, always: the machine's VIRULE identity, its
   install id, the client version and the installed Admin version (empty
   when none). A client whose Admin was never opened, or never installed, is
   therefore still on record with the service.
2. CARRIES THE ADMIN'S PENDING USAGE BATCHES, when there are any. The VIRULE
   Admin records its usage events to an on-disk spool and sends nothing
   itself; the answer is the same manifest plus `ack`, the batch ids the
   service stored.

The identity is the existing shared `dev_machine.cred`. When none exists yet
the client creates it exactly as QA redemption does (same provenance record
in `state.json`). THE PREVIOUS-KEY LINK: a Desktop older than the
2026-11-12 fix issues its own machine key on its first run when the
credential it finds was created by this client (and any Desktop replaces a
credential this Windows user cannot open), so the client remembers the key its last accepted check-in used
(`client\checkin.json`) and, while the current key differs, names the old
one as `pk` until the service answers `seen`. That is what keeps "client
only" and "Admin user" one installation.

A SANDBOXED CLIENT NEVER CHECKS IN TO THE REAL SERVICE: while
`paths::environment_redirected()` answers true (a harness run with
`LOCALAPPDATA` redirected) and no `--admin-manifest-url=` is given, the
client creates no identity, sends no check-in, and without a managed Admin
makes no manifest request at all (`admin_install::checkin_suppressed`).

- ONE request per check. A second (the plain `GET`) is made only when the
  `POST` was answered with something other than 200, which is how a service
  that predates the check-in is handled. A `POST` that got no answer at all
  is not retried as a `GET`.
- Only acknowledged batches are deleted. Everything else stays for the next
  check; the service de-duplicates by event id, so a batch delivered twice
  is stored once.
- At most 8 batches and 40 KiB of spool per check, so an offline backlog
  drains over several checks rather than one large request.
- The request is signed with the machine's VIRULE identity
  (`virule-checkin.v1|<install id>|<batch ids>|<timestamp>`, the id list
  empty when there is no batch). Only when the identity can be neither read
  nor created is the check the plain `GET`, and any batches wait.
- The update check never depends on the batches: any spool, identity or
  service problem on that side leaves the manifest answer exactly as before.
- THE SPOOL IS THE ONE HAND-OFF across the ownership boundary:
  `%LOCALAPPDATA%\VIRULE\usage\` is Admin-owned and Admin-written
  (`virule/core/usage_spool.hpp`, vendored byte-identical from v2_mvp); the
  client reads sealed batches and deletes acknowledged ones, nothing else.
  A staging build reads `s-*.jsonl`, production `b-*.jsonl`, so neither
  environment can deliver the other's records.

UPDATE CONNECTIVITY HEALTH (owner spec 2026-10-01, v0.8.6;
`src/shared/update_health.hpp`). Every manifest request records whether the
update service was REACHED, in `client\update_health.json`
(`{last_contact_utc, failed_attempts}`):

- Reached = any HTTP response arrived, whatever its status. A 500, a 404 or
  a manifest this client refuses is contact, never evidence that the user's
  network blocks VIRULE. Only no response at all (DNS failure, timeout,
  refused connection, TLS failure) is a failed attempt.
- Every request updates the last-contact instant when it reaches the
  service; only SCHEDULED checks (startup and the 6-hour recheck) add to the
  failure count, so a Settings ask or a retried install cannot fast-forward
  the notice.
- `blocked` = more than 48 hours since the last contact AND at least 3 failed
  scheduled attempts since then. On a machine that has never reached the
  service the 48 hours run from its first attempt. One contact clears it.
- The Admin asks with the local `update_health` message and shows its
  passive notice only on `blocked:true` (`v2_mvp/docs/STYLE_GUIDE.md` 14.1).
- The record is its own file, not `state.json`, so no other writer's
  load-modify-save can drop it. A default uninstall removes it with
  `client\`.

ONE UPDATE ACTION CONVERGES BOTH (owner spec 2026-09-16, v0.8.5): every
user-initiated Admin install, update or launch handoff also forces the
client's OWN self-update check at once (`admin_install::g_on_user_operation`,
installed by `main.cpp`, running `self_update::refresh_check(0)` on its own
thread), so the client never waits for its 6-hour timer while the Admin
moves. The staged client still swaps only at the safe takeover point after
the Admin operation, so the Admin update's timing and feedback are
unchanged. One check runs at a time (`g_check_in_flight`).

ADMIN AND CLIENT UPDATES CONVERGE (0.9.15; defect correction 2026-10-21:
staging alpha.59 needed Client 0.9.14 and nothing made an older Client
update before the Admin did, so the two ran as an incompatible pair until
the Client's six-hour timer). The approved Admin manifest names the Client
it needs (`minimumClientVersion`, published from the Admin's one
definition `v2_mvp/include/virule/core/client_requirement.hpp`). When this
client is OLDER than that:

- `fetch_manifest` still READS the manifest (the approved Admin version is
  known and Settings offers the update as usual) and records the
  requirement (`Manifest.minimum_client`, `client_too_old`;
  `admin_update_status` carries `client_required` and `client_version`,
  additive). The first time a requirement this client fails is seen, its
  own self-update check runs at once (`note_client_requirement` through
  `g_on_user_operation`), so the staged client swaps at the next safe
  point, seconds on an idle machine. No six-hour wait, no Windows restart.
- an Admin install or update the person asks for meanwhile (Settings
  Update, virule.app, update-on-launch) NEVER installs an Admin this
  client cannot serve. `run()` decides it BEFORE any Admin is closed: the
  request is RECORDED (`client\pending_admin_update.json`: the shortcut
  choice, the native-feedback choice, whether the Admin is to be launched
  afterwards, when, and which client version recorded it), the self-update
  is staged now and the swap asked for at the first safe moment
  (`g_on_client_update_required` → `self_update::refresh_check(0)`, the
  serve loop's cadence dropped to every second for two minutes), and the
  operation answers `client_update`. The Admin, if open, stays open.
  `status` reports `updating:true` while the record stands, so the
  Admin's Settings overlay keeps waiting through the swap.
- the NEW client, at startup after its own reconciliation
  (`resume_pending_update`), runs the Admin update from the record: the
  Admin is closed gracefully, the native "Updating…" card shows, the
  verified pipeline runs, the Admin relaunches (`launch_after` for the
  update-on-launch handoff). A record is honored once and only while fresh
  (30 minutes); a client that finds ITS OWN version in the record (the
  swap failed or rolled back) discards it and the update fails visibly and
  stays offered: never a loop. The Admin host's own gate (an older Client
  refuses Build for Evaluation's delivery and an evaluator's Install, and
  asks the Client to update) is `v2_mvp/docs/ADMIN_ARCHITECTURE.md`.
- an older Client (before 0.9.15) does not know any of this: it refuses
  the manifest outright, its forced self-update check (above) stages the
  new client, and the swap at the next safe point brings this behavior.
  Proof: `tools/client_requirement_test.mjs`.

Once accepted, the operation finishes even if every page closes
(`g_busy` also holds off the client self-update swap), and a FRESH install
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

## Game distribution (2026-10-20, client 0.9.14)

Product contract: `v2_mvp/docs/EVALUATION_VIRULE.md` sections 3 and 9a
(and `VIRULE_BACKEND/docs/EVALUATIONS.md`, "Hosted evaluation builds"). The
job record, its states and the figures (the 20 GB cap on contents, 32 MiB
parts, 64 MiB ranges, the wake event, the `transfers\` folder) are
`virule/core/evaluation_distribution.hpp`, vendored byte-identical from
v2_mvp. Engine and driver: `src/client/transfers.hpp`; wiring:
`start_transfers()` and `AccountTransferService` in `src/client/main.cpp`.

THE DRIVER is a dedicated thread started in `serve()` on every client. One
forced pass at startup (the recovery after a crash, a kill or a Windows
restart), then a blocked wait on `Local\VIRULE.Transfers.Wake` (the Admin
host signals it after packaging a build or writing an install), the
earliest retry, or its stop event. An uninstall pauses it. It moves every
job under `%LOCALAPPDATA%\VIRULE\transfers\<job id>\job.json` whose stage is
the Client's, one at a time:

- `upload` (Build for Evaluation; the Admin host hands it over as
  `packaged`): FIRST THE CLIENT'S OWN VERIFICATION (`verifying`; owner brief
  2026-11-02, "Developer verification and the upload gate" below), then
  open or resume the service's upload session for the build
  (`POST /v1/evaluations/games/<uuid>/uploads`; the same build always
  answers the same session), READ BACK which parts the service holds
  (`GET /uploads/<session>`), send every missing 32 MiB part with its
  SHA-256 and MD5 (`PUT /uploads/<session>/parts/<n>`; 409 `integrity` =
  send again; 410 = renew the storage upload under the same session and
  send everything again; 404 = open the session again), complete it
  (`POST .../complete`; 409 `incomplete` = read back and continue), then
  `done`: the service holds the hosted build. Every part must be the part
  this Client verified (its SHA-256), else the job fails (`The package
  changed since it was built. Build it again.`).
- A HELD upload (0.9.20; owner brief 2026-10-22, UPLOAD ELIGIBILITY in
  `VIRULE_BACKEND/docs/EVALUATIONS.md`): the service refuses an upload for a
  game with no purchased evaluation still owed, or never bought for (409
  `no_pending_evaluation`, at opening or at completion; another account's
  game stays a 404 failure). The job goes to `held`, never `failed`: the
  package and the session stay and nothing is sent. It is asked again (one
  opening, which resumes the same session; each refused ask keeps the
  service's session alive) every 30 minutes and AT ONCE when the
  developer's Evaluations view read through this Client (`account_api` GET
  `/v1/evaluations`) answers something new, as a purchase makes it
  (`release_held_uploads` beside the inbox wake in `main.cpp`); once taken
  it continues where it stood. A session left unasked for two days (the
  computer off) is abandoned by the service, and the released job then
  fails with its sentence (`Build it again.`). A held job whose game has a
  NEWER upload job (a new Build for Evaluation) is retired by this driver
  (`failed`, `Replaced by a newer build.`) before anything is asked, so the
  driver stays the held job's only writer; the newer build's packaging has
  already removed the held package. An older Client fails such a job with
  the service's sentence instead.
- `install` (the Admin's Install writes it `queued` with the installs
  location, the game folder and the partial file's path): ask for the
  download (`POST /v1/assignments/<id>/download`: the revision, its size
  and SHA-256; a revision other than the job's starts the download over),
  fetch 64 MiB ranges appended to the partial file (a restart resumes from
  its length), verify the whole package's SHA-256 (a mismatch removes the
  file, reports `failed` to the service and fails the job with its reason),
  extract into `<installs>\.virule-staging\<game>` and swap it into
  `<installs>\<game uuid>` by one rename (a previous revision's folder goes
  only then), write the assignment ticket (`GET /v1/assignments/<id>/ticket`,
  plus `install_path` and `launch_exe`) and the evaluator credential
  (`POST /v1/assignments/credential {machine_key}`, this installation's
  dev_machine identity) the wrapper verifies at launch, report the
  verified completion (`POST .../complete {sha256, bytes}`), then
  `installed`.
- THE UPDATE (0.9.17; the service requires the newer build): the Admin
  host moves the same job back to `queued` for the new revision. The
  download and verification run as above while the installed game stays on
  disk and playable; the swap NEVER runs while the wrapper's presence is
  held (`Local\VIRULE.Evaluation.Running.<assignment>`), looking again every
  15 s. Every file of the installed folder the new package does not carry
  (saves, settings) is carried into the staged one first; then the
  installed folder steps aside, the staged one moves in, and only then is
  the previous one deleted; if the move in fails, the previous folder is
  put back and the job fails with its reason.
- `removing` (0.9.17): once the service acknowledged the evaluator's
  report, the job of that assignment is moved to `removing`: when no
  session of it is running, its own game folder (and only that) is
  deleted, then `removed`, a terminal state.
- A job still `building` or `packaging` is the Admin host's. When its
  process is gone and no Admin is running (`Local\VIRULE.AdminHost.Singleton`
  absent), the driver starts the host headless
  (`ViruleAdminHost.exe --data-root=<dir> --resume-delivery=<job id>`,
  from the paths the job records, with `<dir>\.resources\bin\x64` as the
  working directory: the host's CEF import resolves from it, exactly as
  virule.exe starts it; corrected 2026-10-21), at most every five minutes
  per job. A CLOSING Admin starts the same host for the stage it owns
  itself (v2_mvp ADMIN_ARCHITECTURE.md "Closing the Admin while a build
  runs"), so a stage rarely has to wait for this driver.

GUARANTEES (`tests	ransfers`, `tools	ransfer_test.mjs`): the record is
written atomically after every step; a part the service holds is never
sent again; one session per build; retry never gives up (10 s, 1 min,
5 min, 15 min, 30 min, then 30 min forever; a 409/410/404 is handled, not
backed off); a job belongs to the account that started it (`account_email`,
bound at the first attempt when the host did not know it) and waits
untouched under another account or signed out; nothing is reported
installed or done without the service's own acknowledgement; an install
never touches anything but its own folder.

AUTHORIZATION: every service call is this installation's DPoP proof
(`account::transfer_headers`, a fresh proof per request, the access token
refreshed on 401), never the relay. Part uploads carry the raw bytes
(`http::request`); ranged downloads stream to the file (`http::request_to_file`).

LOCAL MESSAGES (control connections only): `transfer_control`
(`{"assignment_id","action":"pause"|"resume"|"retry"|"verify"}`: a pause is
recorded on the job and honored at the next range, a resume clears it, a
retry re-queues a failed install; answers `{"type":"transfer_control","ok":true}`),
`transfer_wake` (signal the driver), `transfer_status` (every job, bounded).

THE LAUNCH CHAIN IS MADE CURRENT BEFORE A LAUNCH (0.9.15; defect correction
2026-10-21). `verify` runs the install's own chain step again for an
INSTALLED assignment (`ensure_launch_chain`, which the install also runs
before it places a build): the ticket is asked and written again, and the evaluator credential
is issued again when the machine key it is bound to is not this computer's
current one (a Desktop older than the 2026-11-12 fix re-issues
`dev_machine.cred` on its first run, and the credential must be bound to the key the wrapper will derive from that
file). The machine key is READ at every call, never remembered. It is
synchronous (the service is asked, the Admin host waits), never touches the
job record, and answers `ok:false` with a plain message when nothing can be
done (`This game isn't installed yet.`, `This computer has no VIRULE
identity.`, the service's refusal). The Admin host calls it from
`LaunchEvaluationGame` when the wrapper's own selection of the chain would
refuse, then selects again before launching. Proof: `tests/transfers`
(`test_launch_chain`).

THE REVISION ON DISK (0.9.18). An install job records
`installed_revision_id` when a revision is placed (`installed`), and keeps
it while an update moves the job's `revision_id` on to the next one; a job
written before the field reads it from its state (`installed_revision`).
It is this computer's fact: the Admin's Update compares it with the
revision the service requires, never with the account's download history.
A placed revision (before the job reads `installed`, so its first launch
already has it; and, once per process, every installed assignment) also
reads the service's progress for the assignment
(`GET /v1/assignments/<id>/progress`, kept forward only), so a fresh
installation knows the assignment's whole history (see "Evaluation
evidence delivery"). Every job STATE change (not a byte count) moves the
change counter. The driver never replaces or removes a game folder while
the launcher says the game is up (`DriverConfig::busy`).

GAME ART (0.9.16, `src/client/game_art.hpp`; the service side is
VIRULE_BACKEND `src/evaluations/art.ts`). A game's box art is held by the
service so every installation of its developer and the evaluator of an
accepted assignment show it without the game package. Local bridge message
`{"type":"game_art","action":"upload","game_uuid","path"}`: the Admin's
local art file, read here (at most 16 MiB; PNG, JPEG, WebP, BMP or ICO by
its bytes), hashed and stored (`PUT /v1/evaluations/games/<uuid>/art`,
`x-virule-art-sha256`); `{"type":"game_art","action":"fetch","game_uuid",
"sha256"[,"assignment_id"]}`: the image as a local file, from the cache or
downloaded (the developer's game route, or the evaluator's
`/v1/assignments/<id>/art`), its SHA-256 verified before it is kept. THE
CACHE is `%LOCALAPPDATA%\VIRULE\art\<sha256>.<ext>`, content-addressed,
so a cached image is never stale. Answers `{"type":"game_art","ok":true,
...}` or `ok:false` with a plain message; the Admin keeps its placeholder.
Proof: `tests/transfers` (`test_game_art`).

## Local malware scanning (owner briefs 2026-10-30, ON STAGING since 2026-10-31 in Client 0.9.22)

Product contract: `v2_mvp/docs/EVALUATION_VIRULE.md` section 9b; the
service half: `VIRULE_BACKEND/docs/EVALUATIONS.md` "Security incidents and
holds". The engine is `virule/core/malware_scan.hpp` and the record of what
was verified is `virule/core/verified_content.hpp`, both vendored
byte-identical from v2_mvp beside `evaluation_distribution.hpp` (whose job
record gains `scan_outcome`, `scan_revision_id`, `incident`,
`incident_reported`, `security_held` and the states `scanning_source`,
`scanning_package`, install `scanning`). The primary engine is Microsoft
Defender Antivirus in its ACTIVE state; when another antivirus replaces it,
the AMSI compatibility path (vendored `amsi_scan.hpp`) is tried and accepts
only an explicitly validated provider (none is validated yet: the shipped
allowlist is empty). Any other configuration, Defender disabled, passive or
in limited periodic scanning is `unavailable` and blocks (the evidence:
malware_scan.hpp "WHICH DEFENDER STATES SCAN"; the policy
`VIRULE/docs/specs/evaluation-security.md`).

THE ONE FOLDER WALK (Client 0.9.30; audit L-21; the vendored
`virule/core/folder_walk.hpp` from v2_mvp `5ee4b54`, which `malware_scan.hpp`, `amsi_scan.hpp` and
`verified_content.hpp` include; contract: `v2_mvp/docs/EVALUATION_VIRULE.md`
9b "ONE FOLDER WALK"). Every walk the Client makes over a game's files to
account for them goes through it: the scan's inventory and its search for
wrapped originals (`extract_wrapped_originals`), the AMSI path's file list
and the verified content record (`verified.txt`). Every regular file is
listed and every folder entered. A LINK (a reparse point whose tag is a
name surrogate: a symbolic link, a junction or mount point, a WSL link) is
never followed and never skipped: it FAILS the walk. Every other reparse
point is an ordinary file or folder, which is what a Dropbox, OneDrive or
other Cloud Files placeholder is (metadata only is read, so no placeholder
is hydrated by the walk). A folder that cannot be listed, or an entry whose
metadata cannot be read, fails the walk too; each caller then fails with its
own existing sentence (a scan is `incomplete`, nothing is vouched for).
Before 0.9.30 these walks skipped links, and with them a junction's
content. NOT CHANGED IN THIS PASS (lead's scope decision 2026-11-12; an
open L-21 remainder, not a design ruling): an update's carry-over of the
evaluator's own files (`transfers.hpp` `carry_over`) still skips links and
folders it may not read (`skip_permission_denied`), so an unreadable folder
of the evaluator's saves is silently not carried. Whether it should fail
instead (which would stop the update) is an open question.

THE ZIP ENTRY NAME GUARD (Client 0.9.30; audit L-24; the vendored
`virule/core/zip_entry.hpp` from v2_mvp `5ee4b54`, the rule VIRULE
Desktop's own extraction uses).
Both Client extractors pass every entry name through it before anything is
written: the evaluation package (`transfers.hpp` `safe_entry`, which fails
with `The package holds an unsafe file name.`) and the Desktop package
install (`admin_install.hpp` `extract_package`, `zip entry escapes the
destination`). A name is refused whole, never repaired, unless every
segment between '/' or '\' separators is non-empty (no leading separator,
so no absolute, UNC or device path; no doubled separator; one trailing
separator marks a folder), is not "." or "..", carries no ':' (drive,
drive-relative, alternate stream), control character or `< > " | ? *`, does
not end in '.' or ' ', and is not a device name (CON, PRN, AUX, NUL,
COM0-9, LPT0-9 and their superscript forms, CONIN$, CONOUT$, alone or
before an extension); at most 1024 bytes; and, in the Client, a name that
is not well-formed UTF-8 is refused too (the path conversion throws on it,
which uncaught would end the Client; `zip_entry::parse` itself does not yet
check UTF-8). The Desktop guard it replaced
checked only the first segment for a drive, so `a/D:x` reassembled onto
`D:`; segments are now read as UTF-8 on both paths. Proof:
`tests/zip_guard/run_tests.bat` (both real extractors; every entry name of
the staging alpha.77 Desktop package passes) and `tests/transfers`.

THE INSTALL (`src/client/transfers.hpp` `run_install`): after the
package's SHA-256 and extraction into `.virule-staging`, `scanning` copies
the wrapper's original executable out (never run) and scans it with every
extracted file; only `clean` goes on. THE LAUNCH FILE MUST BE THE WRAPPER
(the owner's audit remediation campaign of 2026-11-11, applying the audit's
H-2 fix "or when `launch_exe` does not parse as a wrapper",
`VIRULE/docs/reviews/COMPREHENSIVE_AUDIT_2026-11-11.md`; Client source after
0.9.28): every Client call of
`extract_wrapped_originals` (this scan, `verify_package` and both
extracting branches of `verify_installed`) names the job's `launch_exe`, so
a launch file that is not a wrapper the shared locator
(`virule/core/wrapper_payload.hpp`) reads fails the extraction before any
scan (outcome `error`: a refusal, never an incident or a hold). A MISSING
launch file at the install and at the developer's verification is the
earlier existence check (a failure, or the antivirus removal path when
Defender took it); only the pre-Play check reaches the extractor's own
"not found" refusal. An ordinary `.exe` beside the wrapper (a helper, a
redistributable) still scans as itself. For an update the evaluator's own
files are then carried over. BEFORE ANYTHING IS PLACED the launch chain is
asked for (`ensure_launch_chain`, the ticket GET): a 409 `security_hold`
fails the job for good with the service's sentence, the package and the
staging folder removed, the installed folder untouched. Once placed, the
VERIFIED CONTENT RECORD (`<root>\transfers\<job>\verified.txt`) lists every
delivered file as scanned (relative path, size, write time, the revision)
and the carried-over files the previous record vouched for; the scanned
revision is `scan_revision_id`. The antivirus refusing or taking the
package or a file at download, verify or extraction (a refused open, or
Defender's record naming the path; a file that merely went missing with no
such record is retried as before) is a security outcome, never `defer` and
never a re-download. A detection: the staging folder and the package go,
`security_held` (retry and Install again refuse that revision here),
`/download/<id>/failed` with reason `security`, and the incident is kept on
the job. The service's 409 `security_hold` at `/complete` also fails the job
for good. SINCE 0.9.28 a 409 `financial_hold` (owner brief 2026-11-10: the
game's developer is under a financial hold) is the SAME FINAL REFUSAL at
every one of these boundaries (`security_marks::is_hold_refusal`: the
download's authorize and `/complete`, the launch chain's ticket, the
pre-Play ticket): never retried, the service's sentence stated, the
installed folder and the evaluator's files untouched. A running game is
closed by the runtime answer's `security_hold`, which the service also sets
while a financial hold pauses the assignment (`financial_hold: true` beside
it). The Client records the CAUSE beside the shared hold marker
(`security_marks::kFinancial`, set from a `financial_hold` ticket refusal or
a runtime answer saying `financial_hold` with no `security_review`), so a
later local Play refusal states `This evaluation is paused.` (working
wording, PENDING OWNER REVIEW), never the security sentence. A job in `scanning` that was interrupted extracts and scans again.

THE INSTALLED CONTENT IS VERIFIED BEFORE EVERY PLAY (`verify_installed`):
the folder is compared with the record; new or changed files (the game's
saves, the wrapper's log, an executable it left behind) are scanned, and
ONLY those (`verified_content.hpp` `plan_scan`: a new folder of only new
files is one target; the wrapper's original is copied out only when the
launch file changed, and then the launch file must still be a wrapper:
a launch file replaced by a plain one is refused, never taken into the
record, and a job whose `launch_exe` is not one bare `.exe` name is never
verified); unchanged content is never scanned again, and the
whole folder only when no record of the installed revision exists (an
update, a replacement build, content installed before scanning existed)
(owner decisions 2026-10-30, "Scan cadence"); clean takes them into
the record (never a file that changed during the scan). It runs at once when
the launcher asks (Play found unverified files) and when a game's last
process exits (`on_stopped` in `main.cpp`), at the driver's first pass, and
for a game never scanned (installed before scanning existed) at most every
30 minutes; never while the game runs. A detection there holds the revision
here and reports an incident (with what is known of each flagged file:
"Finding identity" below). Size and write time are compared, not hashes:
any ordinary change is caught, a person deliberately restoring a file's
size and time on their own computer is not (reported, not solvable on an
evaluator-controlled computer).

INCIDENTS are reported by `run_pass` from any job, a failed one included,
until the service answers (developer: `/v1/evaluations/games/<uuid>/
security/incident`; evaluator: `/v1/assignments/<id>/security/incident`),
and ONLY INCIDENTS THIS CLIENT PRODUCED (2026-11-02): each is kept sealed in
Client-owned storage (`client\incidents\<job>.json`,
`src/client/upload_verification.hpp`), never in the job, whose `incident`
field (written by older builds) is never sent. When the Admin host's
precheck, build or packaging met the antivirus (the job failed with
`scan_outcome` `detected` or `removed`), the Client establishes it itself,
once (`establish_host_detection`): Defender's own record of acting on the
job's `source_path` or `build_path` since the job began, else its own scan
of the game's folder; found, its own incident (`scan_source`, or
`scan_package` once a build was packaged); not found, nothing is sent.

### Finding identity (0.9.27, owner brief 2026-11-06; `src/client/finding_identity.hpp`, `verified_digests.hpp`)

Every incident this Client keeps states, on EVERY threat entry (each named
detection and each `removed from disk` entry), what it established of the
flagged file (`malware_scan.hpp` `Identity`; the service's half:
`VIRULE_BACKEND/docs/EVALUATIONS.md` "Security incidents and holds", "The
security review"): `origin` (`package`, `wrapped_original`, `local`,
`unknown`; `local` is any file VIRULE cannot tie to the package: one it did
not deliver, or an installed file with no digest record), the package
`entry`, the wrapped original's `member`, the
content's `sha256` and `bytes`, and Defender's Threat ID when its event
states a valid one (supplementary, never the identity). THE DIGESTS ARE
COMPUTED WHILE THIS CLIENT HOLDS THE BYTES, never after the antivirus took
the file, and never with an extra read of content it already reads:

- THE EXTRACTOR (`extract_zip`, install and developer verification) hashes
  each entry in the same pass that writes it (after miniz's CRC check and the
  file's close), recording the exact entry name and the file's size and write
  time as written. An entry whose write did not complete is known by name,
  with no digest.
- THE WRAPPED ORIGINAL (`extract_wrapped_originals`, in the vendored
  `malware_scan.hpp`) is hashed block by block as it is copied out of the
  VRULPK1 archive into the scan folder.
- THE INDEX (`finding_identity.hpp`) is built right before each scan. A
  digest stands for a file still exactly as written (size and write time),
  or GONE: real-time protection took a file VIRULE wrote whole, before or
  during the scan (the usual quarantine path), so what it evaluated was the
  bytes VIRULE wrote. A file present but changed loses its digest, and so
  does one taken while it was being written (no complete digest exists) and
  a file more than one package entry wrote (a duplicate name, a case variant, or a name Windows maps onto the same file) has no digest (the extractor sees the file already there, and the index
  keys of VIRULE's own writes drop trailing dots and spaces, as Windows drops
  them from the names VIRULE opens, so the count holds even when the first
  file was taken before the alias was written; which entry's bytes were
  evaluated cannot be established). A REPORTED path is parsed STRICTLY:
  nothing is trimmed, `;` is part of a name except in Defender's exact
  container form (`containerfile:_X; file:_X->inner`, the two X the same
  text), and an inner name is looked up exactly; a path that does not parse,
  or has a literal trailing dot or space in any component (a file or folder
  the game created so), never takes an index digest and is never read. In VIRULE's own folders (the
  extraction, the scan copies) a path the index does not know is never hashed
  after the fact.
- THE INCIDENT BODY IS BOUNDED: every field is cut as the service keeps it
  (`malware_scan.hpp` `bounded`: name 200, path 1024, action 100, entry and
  member 1024 UTF-8 bytes, control characters as spaces), so 50 entries stay
  far inside the service's 512 KiB limit and an incident is never refused for
  its size. Content INSIDE any container, the package zip included
  (`containerfile:_...->inner`), gets no digest: only the package entry's
  name is stated (the extracted copy of that entry is flagged with its own
  digest; a name inside the zip identifies its bytes only if the whole
  package was read). A bare entry name (a refused launch file) gets no digest
  (which bytes were refused is not known).
- INSTALLED CONTENT: at placement the VERIFIED DIGESTS RECORD
  (`<root>\transfers\<job>\verified_digests.txt`, `verified_digests.hpp`)
  keeps each delivered file's digest with its size and write time as the
  scan of the delivered build began, its exact entry, and the revision. At a
  pre-Play verification (`verify_installed`), a file still exactly as
  recorded in the walk taken before that scan keeps its recorded digest even
  once the antivirus takes it (the decision-39 whole rescan after a Resume is
  the case that matters). `verified.txt` is UNCHANGED: every shipped wrapper
  reads it (`wrapper_launch_check`), so the digests live in a file only this
  Client reads; neither authorizes, skips or launches anything. The same
  boundary as `verified.txt` applies (above: a person or process restoring a
  file's size and time on the evaluator's own computer is not solvable): a
  recorded digest is trusted on size and write time.
- A FILE THIS CLIENT DID NOT WRITE (a save, a log, a file the game wrote, the
  developer's own folder) is hashed AT DETECTION only while it is still on
  disk and the scan did not report it gone or changed (`missing`); one the
  antivirus took is `local` with no digest. Nothing is fabricated.
- A finding on the package file itself, wherever the Client knows it as
  the package (the downloaded zip at download or while it is extracted;
  the developer's built package in the developer's verification), states
  `package` with no digest: the package is a container, never one of the
  files VIRULE wrote from it.
- A detection VIRULE Desktop's own precheck, build or packaging met (`establish_host_detection` reads Defender's record for the game's source and evaluation build folders) is attributed WITHOUT a package index: every file it names there, the built package included, is `local`, hashed at detection only while still on disk and not reported taken. Such a developer-side digest never decides anything: the same-finding match is for evaluator reports only, and a hold carrying a developer-side detection is never cleared, so nothing of it is recorded as cleared.
  (`fi::attach` with an empty `fi::Index`.)
- THE FOLDER CASE RULE (owner decision 2026-11-06, VIRULE
  `docs/specs/evaluation-security.md` decision 62): index keys fold case, so
  a digest (from the index, or hashed now) is given only when every folder
  from the file's parent up to the volume's root is established as
  case-insensitive (`detail::CaseCheck`: Windows' per-folder flag, read
  only; FAT, FAT32 and exFAT never case-sensitive; anything that cannot be
  read is not established). A case-sensitive or unestablished folder gives
  no trusted fingerprint and the review reopens; nothing on the file system
  is changed.

Nothing of any file leaves this computer: the digest and the context, in
the incident, to the VIRULE service only. An older Client's incidents carry
no identity and are accepted as they were.

## Developer verification and the upload gate (owner brief 2026-11-02, "Client Security Authority Phase 2"; ON STAGING since 2026-11-02 in Client 0.9.23; `src/client/transfers.hpp`, `upload_verification.hpp`, `client_seal.hpp`)

THE CLIENT OWNS THE DEVELOPER-SIDE VERDICT (`VIRULE/docs/specs/evaluation-security.md`
decisions 19 and 21). The Admin host's `scanning_source` (`Analyzing`) is a
non-authoritative precheck that can only stop a job; it builds, packages and
hands over `packaged`, and it declares nothing clean. A `packaged` job is the
host's statement that it built a package, nothing more.

- VERIFYING (`verify_package`): the job goes to `verifying` (owner 0: this
  Client's stage; the Admin shows `Verifying`). The Client reads the package
  once for its SHA-256 and the SHA-256 of every 32 MiB part, compares the
  whole digest with the one the host packaged, lists the archive's contents
  (the 20 GB cap), checks free space for one more copy, extracts it with the
  install's zip-slip-guarded extractor (THE ZIP ENTRY NAME GUARD) into
  `<package>.verify` beside it,
  copies the wrapper's original executable into `<package>.verify-originals`
  (`extract_wrapped_originals`, never run; the launch file must be that
  wrapper, or the job fails before any scan, as at the install), and scans the package, the
  extraction and the originals (`malware_scan.hpp`, the one engine and
  policy). Both scratch folders are always removed.
- THE RECORD: clean, with the package still the size and last write time it
  was read with, the Client writes `client\upload_verification\<job>.json`:
  job, game, build, package path, size, write time, SHA-256, part digests,
  content size, file count, launch file, scanner and versions, sealed with an
  HMAC-SHA256 under the Client's own random key (`client\seal.key`, DPAPI,
  entropy `VIRULE.Client.Seal.v1`; unreadable, it is replaced, which only
  means verifying again). The job then carries the Client's figures.
- THE GATE (`run_upload`): the record must be sealed by this Client and name
  this job, game, build and package path, and the package must still have
  its size and write time; otherwise the Client verifies again (a first
  upload, a restart, a lost or foreign record, a held upload whose package
  moved) or stops. Nothing in the job (`scan_outcome`, `state`, `incident`)
  is read as authority. The session is opened with the record's digest,
  size, content size, file count and launch file, and each part's SHA-256
  must equal the recorded part before it is sent; a difference drops the
  record and fails the job. Held and resumed uploads keep the record only
  while the package is unchanged.
- FAILURES: unsupported, unavailable, error and incomplete scans fail the job
  with `malware_scan.hpp` `unverified_sentence(..., "Build")`; a detection or
  removal with `Windows Security found a threat in this game, so it was not
  sent.`, and it is the Client's own incident (`scan_package`, its build).
- TESTS: `tests/transfers` `test_upload_gate` (the state the driver sees,
  built directly: a forged clean job, a detection, an incident written into
  a job file, a forged record, the healthy path with wrong host figures,
  bytes changed after verification with the write time put back, a restart
  without the record, held uploads changed and unchanged, another build
  under the same job, a host-reported detection established or not),
  `test_upload_gate_real_defender` (this computer's real scanner) and
  `test_launch_file_must_be_wrapper` (the extractor: a plain, mismatched,
  missing and malformed launch file refused, a plain helper beside the
  wrapper still passing; `verify_package` and `run_install`: plain,
  mismatched and malformed refused, and a missing one failed by the
  earlier existence check; `verify_installed`: plain on a first verification, a
  launch file replaced by a plain one after verification, an empty launch
  file name). In `tests/transfers` and `tools/transfer_test.mjs`, every
  package and installed game a test expects to verify, install or pass the
  pre-Play check has a `Game.exe` that is a real VRULPK1 wrapper built byte
  by byte in the test (`wrapped_game` in `transfers_tests.cpp`, the
  harness's own `wrapper` in `transfer_test.mjs`); no binary is shipped.
- LIMIT: the Client and the Admin are the same Windows user; a program
  running as that user could read the DPAPI-protected key or change the
  package between the read and the extraction and back (accepted MVP
  boundary, decision 23).

## Machine proofs (owner brief 2026-11-02; ON STAGING since 2026-11-02 in Client 0.9.23; `src/shared/machine_proof.hpp`, `src/client/main.cpp` AccountTransferService; the service half `VIRULE_BACKEND/docs/EVALUATIONS.md` "Machine proofs")

The routes only this Client's drivers make carry a proof from this
computer's Ed25519 identity (`dev_machine.cred`), the QA link's convention
(`<API host>|<device id>`, `account_link_qa`):

- BINDING: the evaluator credential request (`ensure_launch_chain`) is
  `{machine_key, timestamp, machine_signature}` over
  `virule-evaluator-bind.v1|<host>|<device id>|<key>|<timestamp>`, and it is
  made at every launch-chain refresh, even when the credential held here
  matches, so a binding the service does not count as proved is proved
  before the wrapper needs it. The developer's key is proved at `POST
  /v1/evaluations/machine` (`virule-developer-machine.v1`).
- REQUEST PROOFS, signed centrally in `AccountTransferService::call` for
  exactly `machine_proof::role_of`'s routes (the evaluator's incident,
  download `complete`/`failed`, evidence package registration, early
  completion and report; the developer's incident, upload session open and
  complete): headers `x-virule-machine-key`, `-timestamp`, `-signature` over
  `virule-evaluation-request.v1|<host>|<device id>|<role>|<METHOD>|<path>|<sha256 of the body>|<timestamp>`,
  signed afresh at every attempt (never stored with a queued request). A
  `machine_not_bound` answer (a first use, a re-issued identity, a staging
  reset) proves the key for the role once and asks once more; the runtime
  report's own proof gets the same treatment (the service answers it
  `machine_not_bound` for an unproved key). A proven route is NEVER sent
  without its proof: no identity or no device id yet is "no answer" (status
  0, the driver's own ladder; the device id is asked for), and an incident
  answered 401 is sent again, never marked reported.
- None of these routes is reachable through the local relay
  (`account_relay.hpp`); the relay's own routes carry no machine proof.
- DOWNLOADS: a receipt the service refuses as `not_delivered` (it never
  streamed the whole package to the assignment) deletes the partial file and
  downloads again from the first byte.
- LIMIT: the machine key is shared with the Admin and the wrapper, so a proof
  establishes this computer, not which VIRULE component asked.

BEFORE EVERY PLAY (`src/client/launcher.hpp`, its header): (1) the
service's current word, the ticket GET bounded at 2 s per step and 3 s to
answer, inside the Admin host's 30 s wait for `game_launch` (`main.cpp`
`prelaunch_service_check`): 409 `security_hold` (and, since 0.9.28,
409 `financial_hold`: a FINANCIAL HOLD on the game's developer, owner brief
2026-11-10; both read by `security_marks::is_hold_refusal`) refuses
Play and sets the hold marker, 200 clears it, no answer refuses with
`Couldn't reach our servers right now.`, any other refusal states the
service's sentence; signed out the Client cannot ask and the wrapper's
check decides; (2) the record: anything unverified asks the driver to
verify and refuses with `Verifying game files. Try again in a moment.`
(code `not_scanned`); (3) the wrapper's own online authorization, signed by
the service at EVERY launch on every path (Client Play, the Admin host's
development start, a double-click, the post-game Play), which refuses a held
game too (`VIRULE_BACKEND` `authorize.ts`; takes effect once IDENTITY_DB
0020 and the Worker are deployed). The wrapper then runs its LOCAL CHECK
(`verified_content.hpp` `wrapper_launch_check`) from this Client's records:
installed in this folder, not held (job or marker), revision scanned clean,
every recorded file unchanged (its own `.virule\logs\` excepted). Files the
record never saw are left to the Client's launcher, so the post-game Play
in the wrapper's panel, and a double-click after a session, can start the
game before files its last session wrote are scanned (they are scanned
when it exits). A staging build's development simulation
(`dev_simulation.json` with no `evaluator.cred`) skips both; it is a
developer's tool, never present on an evaluator's computer by itself.

THE SERVICE'S SECURITY STATE (`src/client/security_marks.hpp`): the runtime
report's answer `security_hold` / `security_protected`, and the pre-Play
ticket answer for the hold, are kept as two marker files beside the
assignment's ticket. Since 0.9.24 (owner brief 2026-11-05, "The security
review" below) the service also answers `security_hold` while the
ASSIGNMENT is paused under a security review (also while it is ready to
resume), so nothing of it is launched before an explicit Resume. A Defender exclusion over a scanned
folder is undetectable unelevated (reported). Stalled Admin-side stages
include the two scanning states (`resume_headless`).

OBSERVED (2026-10-30): Defender once quarantined this repository's unsigned
`tests\transfers` harness built in the Dropbox tree as
`Trojan:Win32/Bearfoos.A!ml` (machine learning); the same source built
elsewhere and the pre-change harness were not flagged, and it did not
reproduce. Unsigned binaries carrying the scanner are a false-positive risk
to watch at the first staging build.

## The launcher (0.9.18, 2026-10-22)

Product contract: `v2_mvp/docs/EVALUATION_VIRULE.md` section 9a ("The
Client owns the launcher"). Code: `src/client/launcher.hpp`, one instance
in `main.cpp`, started before the transfer driver. THE CLIENT IS THE ONE
LOCAL AUTHORITY over a game's launch and whether it is running; the Admin
shows what it says and keeps no running state of its own.

RUNNING, read from the system at the moment of asking, never stored: a
process this Client started for the assignment is alive (its handle); a
process whose image lives inside the assignment's game folder is alive
(found by a scan of the process list at every monitor turn, at most five
seconds apart, and at every launch: the wrapper started some other way, the
game it started, or either one after this Client restarted, ADOPTED and
then waited on like the first); the wrapper's presence mutex exists
(`evaluation_evidence.hpp` `running_mutex_name`, held from its first look at
the assignment through its post-session panel); or a launch of it is being
started. So the pre-game panel, the game and the post-game panel all read
running, and running ends exactly when the last of them is gone.

THE MONITOR (its own thread) waits on every tracked process handle and a
wake event, with a five-second timeout for discovery; an exit is seen the
moment it happens, and every change of the running set moves the change
counter (`evaluation_changes`), so the Admin learns it locally.

`game_launch` refuses while the game is running or a launch of it is being
started, while the install job is anything but `installed` (an update under
way: `updating`; a removal, or nothing installed: `not_installed`), when the
revision on disk is not `required_revision_id` (`update_required`), and when
the launch file is missing, all checked and the wrapper started under one
lock (a launch latch makes `busy` read running across the start). It starts
`<install dir>\<launch exe>` with the game folder as its working
directory, hands on Windows' permission to come to the front (the Admin
host granted it as the person clicked Play: `AllowSetForegroundWindow`,
the same cooperative mechanism the browser sign-in uses), and tracks the
process. Beside the start, never delaying it, it reads the service's
progress for the assignment (bounded: 3 s to connect, 4 s to answer). The transfer driver asks `busy`
(the same running test) before it swaps an update in or removes a game,
so a game is never replaced while any part of it is up.

THE PROGRESS DOCUMENT IS KEPT FROM EVERY ANSWER (0.9.18): besides the
evidence and request answers, the Admin's own workspace read
(`GET /v1/assignments`, relayed through `account_api`) has each order's
progress kept, forward only, at no extra call.

Proof: `tests/launcher` (the harness: this launcher, the transfer driver and
the evidence delivery in one process) driven by
`VIRULE_BACKEND/tools/launcher_lifecycle_staging_e2e.mjs` on live staging
with the real wrapper and the real game.

## The runtime report (2026-10-26; 0.9.21 with expiry cleanup; `src/client/runtime_report.hpp`)

Why: an evaluator's assignment expires at the concealed four-hour buffer
past its six-day deadline only when its game is known NOT to be running;
a running or undetermined game keeps it until Day 7 (owner decision
2026-10-26; the service's half is `VIRULE_BACKEND/docs/EVALUATIONS.md`
"Expiry and reassignment"). The service cannot see this computer, so this
Client, the launcher's authority over what runs, tells it.

WHAT: for every assignment installed here (an install job that is not
`removing` or `removed`, whose `ticket.json` names its evaluator),
`POST /v1/assignments/<id>/runtime` `{machine_key, running, timestamp,
machine_signature}`, `running` the launcher's `busy_scanned` (a fresh
process scan), signed with THIS MACHINE'S identity (`dev_machine.cred`
through `machine_identity::sign_hex`, the key the evaluator credential
binds) over `virule-evaluation-runtime.v1|<assignment>|<evaluator>|
<machine_key>|<1|0>|<timestamp>`. Under the account's own DPoP call
(`AccountTransferService::call`), and only for the signed-in evaluator's
own assignments (the evidence owner decision, `client/evidence_owner.hpp`:
signed out or another account, nothing is sent).

WHEN: at start (after the launcher's first scan, so a game already running
reads running), at every change the launcher notes (its change hook wakes
the thread; a burst settles for two seconds), every 30 minutes, and every
60 seconds while one of the games runs (0.9.26, owner decision 2026-11-05;
0.9.25 every 5 minutes; never more often while no game runs: an answer saying
`security_hold` for a running game closes it, below). The
state is SAMPLED as each report is signed, never queued: a failed post is
simply a new observation at the next wake or interval, so a stale sample
can never arrive after a launch.

THE ANSWER'S STATE (owner brief 2026-10-28): the service answers `{ok:
true, state}`, the assignment's own state. `expired` (truly expired, at
either threshold) starts the MANDATORY CLEANUP below. A wake is also set
for just after each installed assignment's ABSOLUTE instant (168 h from the
service-signed `accepted_utc` in `ticket.json`), so an online Client hears
`expired` at once and no session runs on past it.

THE ABSOLUTE DEADLINE WITHOUT THE SERVICE: when the service cannot be asked
for an assignment (no answer, signed out, another account, no machine
identity) and this computer's clock is more than 15 minutes past its
absolute instant (the service's clock allowance), the Client expires it
locally (mark source `local`). Whenever the service answers, the service
decides. The 4-hour expiry is never decided locally; signed out, its
cleanup waits for the next sign-in (the launch check refuses the game
meanwhile).

WHAT IT CANNOT DO: shorten anything. The service treats a report it cannot
use (none, a running one, one too close to a launch, another machine's
silence) as UNKNOWN, which keeps the assignment until Day 7; a missing
launcher reports running. An older Client sends nothing, with the same
result, so no minimum Client version is needed.

Proof: `tests\runtime_report\run_tests.bat` (the units: the wire byte for
byte, which assignments, the cycle and its refusals; then
`tools\runtime_report_test.mjs`, one real cycle's reports sent to the real
service code in process: accepted for a bound machine and kept as observed,
refused for an unbound machine, a tampered state, another evaluator; an
older observation never replacing a newer one).

## The security review (0.9.24 and 0.9.25, owner decisions 2026-11-05; `src/client/runtime_report.hpp`, `launcher.hpp` `stop_for_security`, `assignment_cleanup.hpp` "security end", `evaluation_recovery.hpp`, `client/account.hpp` `on_resumed`, `transfers.hpp` `request_reverification`)

Why: a security alert pauses execution, not the evaluator's work
(`VIRULE/docs/specs/evaluation-security.md` decisions 24 to 49;
`VIRULE_BACKEND/docs/EVALUATIONS.md` "The security review"). What this
Client does:

- UNDER REVIEW (the runtime answer's `security_hold`, `security_review`):
  NOTHING IS DELETED. The game folder, its saves, the draft, the evidence
  and the ticket stay; no `expired.json` is written. Launching stops: the
  hold marker refuses Play (`launcher.hpp`), the service refuses the ticket
  and every download, the wrapper's signed check answers `not_authorized`.
  The wrapper's crash RECOVERY, which runs the wrapper from the game folder,
  waits (`evaluation_recovery.hpp` `Verdict::Held`): held content is never
  executed by this Client, also when this computer's own scan refused it or
  the assignment ended for security.
- A RUNNING GAME IS CLOSED WHEN ITS REVIEW BECOMES KNOWN (0.9.25, owner
  decision 2026-11-05): a runtime answer saying `security_hold` while the
  game runs calls `cfg.security_stop`, `launcher.hpp` `stop_for_security`:
  every top-level window of the assignment's processes (the ones this Client
  started or found in the game's own folder, `terminate`'s ownership) is
  sent WM_CLOSE, the user's own close, so the game and the wrapper end the
  session the ordinary way and the wrapper writes its evidence; whatever is
  left after `kSecurityCloseGraceMs` (10 s) is terminated. Nothing is
  deleted: the folder, the saves, the draft and the evidence stay; a session
  cut short keeps its checkpoint for the recovery (deferred while held, as
  above). Reports come every 60 seconds while a game runs (0.9.26, owner
  decision 2026-11-05), so a running game learns of a review placed
  elsewhere within about a minute; this computer's own detection acts at
  once, and Play is refused at once. While no game runs there is no 60-second
  cadence (the 30-minute interval, the one-shot deadline reports and the
  launcher's change wakes, as before).
- THE OFFLINE CUT FOLLOWS THE STATED DEADLINE: every answer's `deadline_utc`
  is kept (`evaluator\assignments\<id>\deadline_utc`); offline, the cut is
  that deadline + 24 hours + the 15-minute margin (a deadline restored on a
  Resume moves it); with no stated deadline, acceptance + 7 days as before
  and never for a protected assignment; never while the hold marker says
  nothing may be launched (a frozen deadline never cuts).
- RESUME DEPENDS ON THIS COMPUTER'S CURRENT VERIFICATION (0.9.25, owner
  decision 2026-11-05; until 0.9.24 an earlier refusal here refused the
  Resume for good, `resume_gate`, removed): the relay admits `POST
  /v1/assignments/<id>/resume` for the Admin and relays it; on the
  service's 200, `client/account.hpp` `on_resumed` (set by `main.cpp`) asks
  the transfer driver to verify the cleared revision again
  (`transfers.hpp` `request_reverification`), DURABLY (a file,
  `evaluator\reverify\<assignment>`, removed only once applied, so a Client
  that exits in between applies it at its next start), on EVERY computer:
  the installed copy's scan record is dropped and its whole scan asked at
  once (Play refuses until it is clean; the launcher already refuses as
  Verifying from the moment the request is written,
  `security_marks::reverify_pending`, so nothing runs on the old scan in
  between), and this computer's earlier refusal
  of exactly that revision is set aside (`security_held` cleared, a failed
  install queued again), so a copy the antivirus took is downloaded again
  and scanned before it is placed. Nothing of it runs before a clean result. A current refusal is an
  ordinary incident: the service releases the assignment without fault for
  the same adjudicated finding, or opens a new review for a new one.
  Another revision's or assignment's refusal is untouched. No bypass
  exists: a central clearance never overrides this computer's antivirus.
  The relay also admits `POST /v1/assignments/<id>/security/seen`, the
  evaluator's OK of the one-time security end notice.
- THE SECURITY END (the runtime answer's `state` `released` or `terminated`,
  never `expired`): its own mark, `security_end.json` (never expired.json,
  never removed), then the cleanup, re-entrant every cycle: close the game,
  recover an interrupted session ONLY for a released assignment whose
  content is not held, remove the game folder with the expiry's guard (only
  the job's folder directly inside the installs location, named by the
  game's id) and the temp file; KEEP the unsubmitted draft (owner decision
  2026-11-05 for a terminated one too: kept while any hold applies, never
  delivered), the ticket, the ledger, the outbox and the
  receipts. The launcher refuses it (`ended`, `This evaluation has ended.`,
  WORKING WORDING) and the transfer driver installs nothing for it.
- Older Clients: 0.9.23 would cut a resumed assignment offline at acceptance
  + 7 days only where `security_protected` is false (the service keeps it
  true for any assignment ever reviewed), would ignore a security end, and
  could not relay a Resume; 0.9.24 refuses a Resume for good after an
  earlier detection here, cannot relay the notice's OK and leaves a running
  game running; VIRULE Desktop requires 0.9.25 (`client_requirement.hpp`).
- Tests: `tests/account_relay` (the Resume and `security/seen` routes),
  `tests/transfers` (the reverification, unit), `tests/runtime_report` (the
  stop on a hold, the 60-second cadence while running and none while idle,
  and `stop_for_security` against real
  Windows processes: a windowed one closes itself, one that ignores the close
  is terminated, the folder and a saved game stay). PRE-PRODUCTION
  TEST-INFRASTRUCTURE ITEM (the product's transfer and security paths have
  automated coverage in these suites): the one end-to-end harness executable
  of `tests/transfers` (`tools/transfer_test.mjs` starting the unsigned
  `transfers_tests.exe`) is quarantined intermittently by Microsoft Defender
  before that stage runs, `Trojan:Win32/Bearfoos.A!ml` (ThreatID 2147731250, a
  machine-learning verdict on the unsigned test program; detections
  2026-10-30 13:41, 2026-11-05 15:52, 18:04 and 18:05, the program
  quarantined). The same stage passed 43 of 43 at 2026-11-05 about 17:40 with
  a static-CRT build that Defender quarantined minutes later, so neither
  build is a fix. No exclusion, no disabled protection, nothing whitelisted
  (security posture outranks a green test); the unit stage runs before the
  quarantine and passes. The future fix is a security-compatible test
  artifact (an appropriately signed or reputable test executable); no
  signing project is authorized for it now.

## Expired assignment cleanup (0.9.21, 2026-10-28; `src/client/assignment_cleanup.hpp`)

Why: a truly expired assignment must not leave the developer's game on the
evaluator's computer or ever be played again (owner brief 2026-10-28;
`VIRULE_BACKEND/docs/EVALUATIONS.md` "Expiry and reassignment"; product:
`v2_mvp/docs/EVALUATION_VIRULE.md` section 8).

THE ORDER, each step repeatable (a crash, a locked file or a restart at any
point only means the next cycle runs it again; nothing is ever undone):

1. THE MARK, first, because it is the revoke:
   `evaluator\assignments\<id>\expired.json` (`{version, source:
   "service"|"local", marked_utc}`, written atomically, never removed). From
   then the launcher refuses `game_launch` (`code: "expired"`, `This
   assignment has expired.`) and the transfer driver installs or updates
   nothing for it (an install job is turned to `removing`).
2. CLOSE: `Launcher::terminate` terminates every process of the assignment
   (the wrapper this Client started, any process whose image lives in its
   game folder) and waits up to five seconds for the exits.
3. FINALIZE: the session recovery (`evaluation_recovery.hpp` `check_now`)
   packages a session the close left without a package, while the wrapper
   binary is still there; the package is delivered as usual and the service
   keeps it as record only.
4. REMOVE: only the job's own folder directly inside the installs location
   and named by its game id (the report removal's guards), and the
   download's temp file; the job becomes `removed`. Still running or in use:
   left for the next cycle.
5. THE DRAFT: `report_draft.json` (the unsubmitted prose and scores) is
   deleted. The Admin, if open, also forgets its copy and deletes it.

KEPT: the rest of `evaluator\assignments\<id>\` (ticket, ledger, outbox,
receipts) so evidence on its way still delivers. Nothing outside VIRULE's
own folders is touched. Each cycle of the runtime report thread first
resumes every marked cleanup (`marked()`), so a Client started offline or
after a crash finishes it before anything else, and every launch is
refused from the mark on. A change bumps the change counter, so an open
Admin re-reads the service and moves the order to EXPIRED.

Proof: `tests\runtime_report\run_tests.bat` (the answer's state, the local
cut and its margin, signed out, the wakes; the cleanup: mark first,
waiting while running, closed then recovered then removed, the draft
deleted, the evidence folder and the mark kept, repeated with nothing more
to do, a folder outside the installs location never deleted; the launcher's
refusal).

## The report waits for this computer's sessions (owner brief 2026-11-02; `src/shared/evidence_queue.hpp` `local_completeness`)

The report request is written by the Admin host; the Client posts it
(`run_requests`). Only this Client can know a session its computer finalized
and never sent, so it holds the report, off the failure ladder (looked at
again every 30 s, `local_evidence_pending` in its delivery state), while any
session finalized here (the wrapper's ledger and every package the evidence
root holds for the assignment) has no acknowledgment (a receipt here, or the
service's progress listing it; a simulated receipt counts only through the
staging test transport), while the service is still receiving one, or while
a session is still open here (`open_session.json`). Then it sends the report
naming every one of those sessions in `packages`, replacing whatever list the
request carried, so the service checks each is held whole. The predicate is
the shared `writing_unlock` the Admin host and the wrapper read. The service
keeps its own eligibility and completeness: it cannot know of a session the
machine never sent, and the Client cannot make it count one it does not hold.

## Evaluation evidence delivery (2026-10-14; the service since 0.9.17)

Product contract: `v2_mvp/docs/EVALUATION_VIRULE.md` section 6. Format,
layout, handoff and receipt: `virule/core/evaluation_evidence.hpp`, vendored
byte-identical from v2_mvp (never redefined here). Engine and driver:
`src/shared/evidence_queue.hpp`; wiring: `start_evidence_delivery()` in
`src/client/main.cpp`.

OWNERSHIP, under `%LOCALAPPDATA%\VIRULE\evidence\` (a sibling of `client\`,
so a default uninstall keeps it; Uninstall & Delete Data removes it EXCEPT
undelivered evaluation evidence and report drafts, owner ruling 2026-10-22,
see "Uninstall and undelivered evidence" below):

| Path | Owner |
|---|---|
| `.incoming\<id>\` | the wrapper's session, until its one rename; the Client never touches it |
| `outbox\<id>\` (`package.json` + frames) | the Client, from the rename on |
| `delivery\<id>.json` | Client-written delivery state `{package_id, assignment_id, attempts, failures, next_attempt_utc, last_error, damaged, state, reason, updated_utc, acked}`, atomic; `state`, `reason` and `updated_utc` since 2026-10-22 (below) |
| `receipts\<id>.json` | Client-written receipt; the Admin reads it to unlock writing |
| `progress\<assignment>.json` | Client-written: the service's progress for the assignment as its last answer stated it (0.9.17) |
| `requests\<assignment>.early.json` / `.report.json` | the wrapper's early completion / the Admin host's report, until answered (0.9.17) |
| `receipts\<assignment>.early.json` / `.report.json` | Client-written: the service's answer to the request (0.9.17) |
| `received\<evaluation>\` | the DEVELOPER's Client: `evaluation.json` and each fetched package (`<package>\`, `.done` once whole: `{package_id, sha256, session_index}`, `session_index` since 2026-10-22), until the Admin imports it (0.9.17) |

THE DRIVER is a dedicated thread started in `serve()` on every client. It
runs one FORCED pass at startup (the recovery after a crash, a kill or a
Windows restart, with or without a wake), then blocks on the wake event
`Local\VIRULE.Evidence.Wake`, the earliest `next_attempt_utc`, or its stop
event (set when `serve()` ends). Idle with nothing pending is an infinite
wait. An uninstall (`g_uninstalling` or the intent latch) pauses it, except
while the uninstall itself waits for undelivered evidence (2026-10-22); a
paused driver still hears its wake event. A FORCED PASS (next_attempt
ignored) runs at startup and on a wake after `request_forced_pass()` (a
sign-in, the uninstall's wait). The
Client creates the event auto-reset, initially clear (the parameters the
wrapper's `open_wake_event` uses), with an explicit descriptor: full access
for this user's SID and SYSTEM, medium mandatory label, so a same-user
wrapper at medium or high integrity can signal it. Without the event the
driver polls once a minute.

GUARANTEES, each covered by `tests/evidence`:

- Oldest package first (outbox directory creation time).
- A COMPLETE acknowledgment (every file acked, `complete`, a receipt id)
  writes the receipt atomically, and only then removes the payload
  (`evaluation_evidence::acknowledge`). An outbox package that already has a
  receipt is never delivered or reported again: the pass only finishes
  removing its payload.
- A partial acknowledgment is kept and only unacknowledged files are offered
  again; a duplicate acknowledgment changes nothing. `package.json` is
  delivered as the first file.
- Retry never gives up and never expires: 10 s, 1 min, 5 min, 15 min, 30
  min, then 30 min forever. An answer that grew the acked set restarts the
  ladder. A `next_attempt_utc` more than 30 min ahead (the clock moved back)
  is due.
- A DAMAGED package (unreadable `package.json`, a missing file, a size or
  hash mismatch) is never deleted: it is reported `damaged`, kept, and
  re-checked on the ladder.
- Nothing is reported delivered without a receipt.

TRANSPORTS:

- THE SERVICE (0.9.17, `ServiceTransport`): signed in, under this
  installation's DPoP authorization (`AccountTransferService`), package.json
  as `POST /v1/assignments/<a>/evidence/<id>` with its SHA-256, then each
  file the answer does not hold as `PUT .../files/<file>`; the answer's
  `acked`, `complete` and `receipt_id` are the acknowledgment, and its
  `progress` is written to `progress\<assignment>.json`. An `integrity`
  answer sends that file once more, then waits on the ladder. Signed out
  it sends nothing (unavailable). A deployment without the service's
  evaluation records (production today) answers 503: every package stays
  `pending` and writing stays locked.
- TEST: loopback HTTP JSON against `--evidence-test-endpoint=http://127.0.0.1:<port>/<path>`,
  honored ONLY in a staging build or while `paths::environment_redirected()`
  is true (the client's one development-seam predicate,
  `src/shared/dev_seams.hpp`), and only for a `127.0.0.1`/`localhost` url; otherwise it is
  ignored with a log line. Every receipt it produces carries
  `simulated: true`. Wire: `POST <endpoint>/packages/<id>` registers
  `{v:1, package_id, assignment_id, files:[{file, sha256, bytes}]}`; then
  each unacknowledged file goes as `POST <endpoint>/packages/<id>/files/<file>`
  chunks `{package_id, file, sha256, bytes, offset, last, data(base64)}` of
  at most 192 KiB raw. Every 200 answer is
  `{acked:[...], complete:bool, receipt_id}`; a non-200, an unreadable
  answer or no answer (10 s receive timeout) is a failed attempt. The seam
  rides the crash-restart command line; VIRULE Service does not forward it.

`evidence_status` (bridge, local-only) reads the outbox, the receipts and
the delivery state; damaged rows first, then pending, then acknowledged,
bounded to the 4 KB frame with complete `counts` and `truncated`.

REQUESTS (0.9.17): after the packages, each pass delivers the early
completion and the report under `requests\` to the service
(`/early-completion`, `/report`), oldest first. A 2xx, or the service's
`exists` / `already_submitted` with its record, writes the receipt and
removes the request; a refusal of the request itself (400, another 409) is
kept with the service's sentence until a newer request replaces it;
`session_required`, `evidence_pending`, 5xx and no answer wait on the
ladder. An acknowledged REPORT starts the game's removal (the assignment's
install job, "Game distribution").

THE DEVELOPER'S EVALUATION INBOX (0.9.17, `src/client/evaluation_inbox.hpp`,
`start_inbox()`): its own thread, no polling of its own. It runs once at
startup, then when woken: the relayed `GET /v1/evaluations` answered
something new (its hash moved: an acceptance, a delivery), or the
scheduled update check's six-hour cadence came round. One pass reads `GET
/v1/evaluations/evidence` (the signed-in account's evaluations only), writes
`received\<evaluation>\evaluation.json`, and fetches only the files of
each package it does not hold (`<file>.part`, its SHA-256 checked, then
renamed; `.done` once whole). A failure waits on the same ladder. The Admin
imports a DELIVERED evaluation's packages into its workspace and frees the
Client's copy. Signed out it does nothing; nothing private is in any
public manifest.

A RECEIVED FILE IS FETCHED WHOLE FROM BYTE 0 (2026-10-22): the inbox asks
for `[0, bytes-1]` and takes a 206, or a 200 whose `Content-Length` is
exactly the listed size (`http_client.hpp` `request_to_file`
`whole_length`; `transfers::Service::get_whole_to_file`). The QA-laptop
inbox fetched nothing because the developer file route answered 200 and the
read took only 206. The game package's chunked download keeps requiring
206: a 200 is never appended mid-file. The `.done` marker carries the
service's number of the session from the listing (`session_index`, read
as `session_index` or `index`, 0 when the listing names none), so the
Admin orders renumbered sessions as the service does; a marker written
before it gains the field once, nothing fetched again. The listing's
`session_index` is the service's (`VIRULE_BACKEND/docs/API_CONTRACT_V1.md`,
`GET /v1/evaluations/evidence`).

### Whose evidence it is (2026-10-22, `src/client/evidence_owner.hpp`)

THE QA-LAPTOP ROOT CAUSE: with a developer account signed in on a shared
computer, the evaluator's packages were sent under that account, refused
("Not authorized.") and climbed the ladder to 30 minutes. A package (and a
request: early completion, report) is now delivered ONLY under its
evaluator's account. Signed out, or with another account signed in, it
WAITS: no attempt, no failure, no ladder step (`reason` `signed_out` /
`other_account`, `next_attempt_utc` 0). Every sign-in and sign-out
(`account.hpp` `g_on_account_changed`, fired outside the account lock)
forgets what the previous sign-in learned, asks a forced pass and signals
`Local\VIRULE.Evidence.Wake`, so waiting evidence goes the moment its
evaluator signs in; waiting evidence is also looked at again every five
minutes.

THE CLIENT HOLDS NO ACCOUNT ID: `/v1/account/me` names email, display
name, capabilities and the opaque `account_hint`, never the id, while a
package's `evaluator_id` IS the evaluator's account id. The decision, in
order: nobody signed in -> signed out; the signed-in account's id known
here (the `evaluator_id` of the service-signed `ticket.json` of one of this
account's own install jobs, `account_email` = the signed-in email, or
learned below) -> equal is the account's, else another account's; else
ONE read of the assignment's ticket under this account (`GET
/v1/assignments/<id>/ticket`, which answers only the caller's own
assignment and writes nothing): 200 the account's (and its id is learned),
409 the account's (not active: the service decides), 404 another
account's (remembered for the sign-in), 403 another account's (the
account lacks the evaluator capability; asked again later), 401, 5xx or
no answer: not decidable, the attempt goes and the service decides.
`security\evaluator.cred` is never used for this (one file per computer,
it survives another account's sign-out). The gate applies to the service
transport only; the loopback test transport is not account-bound. A
request's evaluator is its own `evaluator_id`, else its assignment
ticket's.

### The delivery state, file by file (2026-10-22)

`delivery\<id>.json` keeps every earlier field and adds `state`
(`"sending"` while an attempt runs, else `"waiting"`), `reason` (`""` its
turn on the ladder, `signed_out`, `other_account`, `offline` the last
attempt reached no service, `refused` the service answered a refusal that
is not a transient: a 4xx other than 401, 408, 429 and a 409 `integrity`;
`last_error` keeps its sentence; the ladder still never gives up) and
`updated_utc` (unix seconds of the last write). The attempt is written as
it starts, and `acked` is written after EACH acknowledged file, with
`updated_utc` and a change-counter bump, so a kill mid-attempt loses
nothing and the Admin sees files go one by one (`Offer::on_acked`, called
by both transports after every answer).

### Uninstall and undelivered evidence (2026-10-22)

OWNER RULING 2026-10-22: Delete Data removes everything EXCEPT undelivered
evaluation evidence and report drafts; if the Client is uploading them the
uninstall waits; if it cannot (a stall) the evidence stays local and
delivery resumes after a reinstall and a sign-in.

THE WAIT (both modes, `main.cpp` `wait_for_undelivered_evidence`, step 4a
of the ordered teardown): after the update was cancelled and the Admin
closed (no update can finish meanwhile and the outbox is stable) and
before the installation signs out, when the outbox holds a package of the
signed-in account (or one not decidable now), the delivery pause is
lifted for exactly the wait, a forced pass is woken (again every 10 s
while nothing moves), and the uninstall waits until no such package is
left or NO FILE WAS ACKNOWLEDGED FOR 60 s (PENDING OWNER DECISION on the
value; `evidence_queue.hpp` `kUninstallStallMs`). A steady upload keeps
it going: the bound is the stall, not a total. Another account's or a
damaged package is never waited for. No new copy: the "Removing VIRULE…"
card and the site's Removing state stay as they are; pages hold Removing
while the client serves (`uninstalling:true`; the site's 15 s absence
window starts only when the client is gone). The Apps & Features
`--uninstall` path with no serving client cannot wait (no delivery runs
there); its evidence is kept by the rule below.

THE KEPT SET (PENDING OWNER DECISION; `src/shared/evidence_keep.hpp`):
for every evaluator assignment with unfinished business (an outbox or
`.incoming` package of it, a pending request in `evidence\requests`, a
non-empty `evaluator\assignments\<id>\report_draft.json`, or an
`open_session.json`), Delete Data keeps `evidence\outbox\<pkg>`,
`evidence\.incoming\<pkg>`, `evidence\delivery\<pkg>.json`,
`evidence\requests\<assignment>.*`, `evidence\progress\<assignment>.json`,
`evidence\receipts\<pkg>.json` of that assignment's packages, and
`evaluator\assignments\<id>\{ledger.json, open_session*.json,
report_draft.json, captures\}` (what the wrapper's recovery and the
session numbering need). The ticket and `security\` credentials are NOT
kept (the service issues them again). Everything else goes as before;
with nothing kept, the whole data root goes as before, and the helper's
verification reads "everything but the kept set is gone". NOT in the
listed set, flagged for the owner: the request receipts
(`receipts\<assignment>.early.json` / `.report.json`) and the request
delivery state, so after a reinstall the wrapper may offer the early
completion again (the service answers `exists`, which settles it).

## Session recovery (2026-10-22, `src/client/evaluation_recovery.hpp`)

OWNER RULING 2026-10-22: the Client runs the wrapper's own recovery in a
windowless recovery-only mode; the Client never builds evidence itself.
For each INSTALLED evaluator assignment, at Client start (after the
launcher's first scan) and whenever the launcher sees the game's last
process exit (`launcher::Config::on_stopped`), the Client starts `"<install
dir>\<launch exe>" --virule-evaluation-recover` hidden (CREATE_NO_WINDOW,
the game folder as working directory), waits up to 120 s, logs the exit
code (0 done or nothing to do, nonzero failed) and signals the evidence
wake, when ALL hold: recovery is needed (`open_session.json` exists, or
`ledger.json` lists a session id with no outbox package, no `.incoming`
package, no receipt, and not among the progress document's `received[]`);
no process of the game runs (the launcher's busy check after a fresh
process scan); the INSTALLED wrapper's bytes contain the ASCII marker
`VIRULE_EVALUATION_RECOVER_CLI_V1` (older wrappers are NEVER started this
way: they would open their game); and the assignment was not tried in the
last five minutes. The recovery process lives in the game folder, so the
launcher adopts it and the game reads running while it runs (Play is
refused, an update waits); its exit is a last-process exit again, which
the rule and the five-minute limit keep from looping.
