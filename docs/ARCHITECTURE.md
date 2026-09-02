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
| page | `{"type":"status"}` | version + capability list |
| page | `{"type":"qa_accept","token":"<64 hex>"}` | asynchronous QA redemption (below) |
| page | `{"type":"uninstall","nonce","timestamp","signature"}` | full VIRULE uninstall after verification |
| local | `{"type":"qa_verify_url","token"}` | a second instance forwarding a `virule://` launch |
| local | `{"type":"wake"}` / `{"type":"shutdown"}` | keep-alive no-op / clean exit (Setup replacing the exe) |

Client pushes: `{"type":"qa_result","token","state"}` to every connected
page (each page filters by token). Everything else answers
`{"type":"error"}`. Frames over 4 KB, unmasked client frames, and
malformed handshakes drop the connection.

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

Registered per-user (`HKCU\Software\Classes\virule`), byte-identical shape
to the Admin's registration, self-healed on every client run (`--no-register`
skips this for development). The Admin also re-registers on every GUI
launch: whichever VIRULE component ran last holds the protocol, and BOTH
handle `virule://qa/verify/<token>` identically, so the QA flow works
either way. `virule://open` is the plain wake URL. Anything else is
rejected without action.

Single instance: `Local\ViruleClient.Singleton` mutex; a second launch
forwards its URL (or a wake) to the running instance over the bridge and
exits.

## Install / uninstall

Setup installs to `%LOCALAPPDATA%\Programs\VIRULE\virule-client.exe`,
registers `virule://` + the `ViruleClient` HKCU uninstall entry
(DisplayName "VIRULE", `--uninstall`), records the version in state.json,
starts the client, exits. Payload verification order: baked SHA-256 first,
then Authenticode on the staged file.

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
