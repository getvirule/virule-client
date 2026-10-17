// Desktop sign-in, end to end, against the REAL account service code.
//
//   node tools/account_flow_test.mjs [--exe <path to virule-client.exe>]
//
// Runs the built VIRULE Client (default: the STAGING build) in a sandbox
// (LOCALAPPDATA and TEMP under %TEMP%), pointed by the loopback-only
// development seam --account-endpoint at an HTTP server in this process that
// serves the VIRULE_BACKEND account routes (src/auth/oauth.ts and
// src/auth/web.ts, bundled exactly as the Worker bundles them) over the
// real identity migrations. This harness plays the BROWSER: it approves the
// sign-in with a signed-in website session and delivers the redirect to the
// Client's one-shot loopback listener, including forged deliveries.
//
// The machine's real client holds the bridge port and the single-instance
// mutex, so it is asked to leave first (non-destructive) and started again
// at the end, as the other harnesses do.
//
// Proves: sign-in via PAR + PKCE + DPoP; the listener refuses a wrong state
// and a wrong issuer and keeps waiting; tokens never appear in bridge
// answers or on disk in clear; the sign-in survives a Client restart;
// refresh rotation re-confirms capabilities; an evaluator approval reaches
// the Admin's view; a website revocation signs the installation out; sign
// out revokes at the service; page origins cannot use account messages;
// cancel works; the explicit QA link. Since 2026-10-15: every sign-out (by
// the person or by the service) deletes the device key and the next sign-in
// makes a new one; the account appearance is reflected at once, delivered,
// arrives from another installation, waits through offline and a restart,
// never overwrites a newer choice when replayed, and the landing page wears
// the website's theme.

import { execFileSync, spawn } from "node:child_process";
import { createPrivateKey, generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..");
const backend = path.resolve(repo, "..", "..", "VIRULE_BACKEND");
const exeArg = process.argv.indexOf("--exe");
const EXE = exeArg > 0 ? process.argv[exeArg + 1] : path.join(repo, "build", "Release", "x64", "staging", "virule-client.exe");
const REAL_CLIENT = path.join(process.env.LOCALAPPDATA, "Programs", "VIRULE", "virule-client.exe");
const SANDBOX = path.join(os.tmpdir(), "virule-account-flow-sandbox");
const STAGING_ORIGIN = "https://virule-api-staging.heath-michaels9441.workers.dev";

let pass = 0, fail = 0;
const check = (name, cond, extra) => {
  if (cond) { pass++; console.log("ok   " + name); }
  else { fail++; console.log("FAIL " + name + " :: " + JSON.stringify(extra ?? null)); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------ the service, in process
const { startLocalWorker } = await import(pathToFileURL(path.join(backend, "tools", "local_worker.mjs")).href);
const local = await startLocalWorker();
const { identity, env } = local;
const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "virule-acct-bundle-"));
const bundle = (entry, name) => {
  const out = path.join(outDir, name);
  execFileSync(process.execPath, [path.join(backend, "node_modules", "esbuild", "bin", "esbuild"), path.join(backend, entry),
    "--bundle", "--format=esm", "--platform=neutral", "--main-fields=module,main", "--conditions=workerd,worker,browser",
    "--log-level=error", "--outfile=" + out], { stdio: "inherit" });
  return import(pathToFileURL(out).href);
};
const oauth = await bundle("src/auth/oauth.ts", "oauth.mjs");
const web = await bundle("src/auth/web.ts", "web.mjs");
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const u = String(url);
  if (u.startsWith("https://challenges.cloudflare.com/")) {
    return new Response(JSON.stringify({ success: true, action: "signup", hostname: new URL(STAGING_ORIGIN).hostname, challenge_ts: new Date().toISOString() }));
  }
  if (u.startsWith("https://api.pwnedpasswords.com/")) return new Response("");
  return realFetch(url, init);
};
const SENV = { ...env, VIRULE_ENV: "staging", TURNSTILE_SITE_KEY: "k", TURNSTILE_SECRET_KEY: "real" };

// Offline simulation: the "service" drops every connection.
let offline = false;
const server = http.createServer(async (req, res) => {
  if (offline) { req.socket.destroy(); return; }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);
  const url = `http://127.0.0.1:${server.address().port}${req.url}`;
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
  const request = new Request(url, { method: req.method, headers, body: body.length ? body : undefined });
  const p = new URL(url).pathname;
  let r;
  if (p.startsWith("/v1/oauth/")) r = await oauth.handleAccountV1(request, SENV, p.slice("/v1/oauth".length), "oauth");
  else if (p.startsWith("/v1/account/")) r = await oauth.handleAccountV1(request, SENV, p.slice("/v1/account".length), "account");
  else r = new Response("not here", { status: 404 });
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const SEAM = `http://127.0.0.1:${server.address().port}`;

// The website half, called directly (as the site would, same origin).
let cookie = null;
async function site(route, body = {}) {
  const r = await web.handleAuthWeb(new Request(STAGING_ORIGIN + "/auth/api" + route, {
    method: "POST", headers: { origin: STAGING_ORIGIN, "content-type": "application/json", ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  }), SENV, "/api" + route);
  const sc = r.headers.get("set-cookie");
  if (sc) { const m = /^(__Host-virule_session=[^;]*);/.exec(sc); cookie = m ? m[1] : null; }
  return { status: r.status, body: await r.json().catch(() => null) };
}
const EMAIL = "desk@example.com";
const su = await site("/signup", { email: EMAIL, turnstile: "harness-turnstile-token" }); if (su.status !== 202) console.log("signup:", JSON.stringify(su));
const verifyToken = /#t=([A-Za-z0-9_-]{43})/.exec(identity.prepare("SELECT body_text FROM staging_outbox ORDER BY id DESC LIMIT 1").get().body_text)[1];
// The link completes with the first credential (VIRULE_BACKEND docs/ACCOUNTS.md "SIGNUP").
await site("/verify/password", { token: verifyToken, password: "a long enough desktop passphrase" });
const acctId = identity.prepare("SELECT id FROM accounts WHERE email_norm = ?").get(EMAIL).id;

// A machine identity in the exact product format (as a QA redemption would
// have created it): Ed25519 seed under DPAPI, entropy = the install id.
function writeDevMachineCred(file) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  const installId = randomBytes(16).toString("hex");
  const blob = execFileSync("powershell.exe", ["-NoProfile", "-Command",
    "Add-Type -AssemblyName System.Security; " +
    `$s=[Convert]::FromBase64String('${seed.toString("base64")}'); $e=[Text.Encoding]::ASCII.GetBytes('${installId}'); ` +
    "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($s,$e,'CurrentUser'))"], { encoding: "utf8" }).trim();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ version: 1, install_id: installId, public_key: pub, private_blob: blob }, null, 2));
}

// ------------------------------------------------ the local bridge
function bridge(message, { origin = null } = {}) {
  return new Promise((resolve) => {
    const s = net.connect(47612, "127.0.0.1", () => {
      s.write(["GET /v1 HTTP/1.1", "Host: 127.0.0.1:47612", "Upgrade: websocket", "Connection: Upgrade",
        `Sec-WebSocket-Key: ${randomBytes(16).toString("base64")}`, "Sec-WebSocket-Version: 13",
        ...(origin ? [`Origin: ${origin}`] : [])].join("\r\n") + "\r\n\r\n");
    });
    let buf = Buffer.alloc(0), up = false, frames = [];
    const done = (v) => { try { s.destroy(); } catch {} resolve(v); };
    const t = setTimeout(() => done(null), 8000);
    s.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (!up) { const i = buf.indexOf("\r\n\r\n"); if (i < 0) return; up = true; buf = buf.slice(i + 4); }
      while (buf.length >= 2) {
        let len = buf[1] & 0x7f, off = 2;
        if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
        if (buf.length < off + len) return;
        frames.push(buf.slice(off, off + len).toString());
        buf = buf.slice(off + len);
        if (frames.length === 1) {
          const data = Buffer.from(message), mask = randomBytes(4);
          const head = data.length < 126 ? Buffer.from([0x81, 0x80 | data.length]) : Buffer.from([0x81, 0x80 | 126, data.length >> 8, data.length & 255]);
          const masked = Buffer.from(data); for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];
          s.write(Buffer.concat([head, mask, masked]));
        } else if (frames.length === 2) { clearTimeout(t); done(frames[1]); }
      }
    });
    s.on("error", () => { clearTimeout(t); done(null); });
  });
}
const status = async () => JSON.parse((await bridge('{"type":"account_status"}')) ?? "null");
const bridgeUp = async () => (await bridge('{"type":"wake"}')) !== null;

// ------------------------------------------------ evict the real client, start ours
const realWasRunning = await bridgeUp();
for (let i = 0; i < 10 && (await bridgeUp()); i++) { await bridge('{"type":"shutdown"}'); await sleep(800); }
fs.rmSync(SANDBOX, { recursive: true, force: true });
const ROOT = path.join(SANDBOX, "LocalAppData");
fs.mkdirSync(path.join(SANDBOX, "Temp"), { recursive: true });
fs.mkdirSync(ROOT, { recursive: true });
const sandboxEnv = { ...process.env, LOCALAPPDATA: ROOT, TEMP: path.join(SANDBOX, "Temp"), TMP: path.join(SANDBOX, "Temp") };
let child = null;
async function startClient() {
  child = spawn(EXE, ["--no-register", `--account-endpoint=${SEAM}`], { env: sandboxEnv, detached: true, stdio: "ignore" });
  for (let i = 0; i < 40 && !(await bridgeUp()); i++) await sleep(250);
}
async function stopClient() {
  await bridge('{"type":"shutdown"}');
  for (let i = 0; i < 40 && (await bridgeUp()); i++) await sleep(250);
}
async function waitStatus(pred, ms = 15000) {
  const end = Date.now() + ms;
  let s = null;
  while (Date.now() < end) { s = await status(); if (s && pred(s)) return s; await sleep(250); }
  return s;
}
const deliver = (redirect, rewrite = {}) => {
  const u = new URL(redirect);
  for (const [k, v] of Object.entries(rewrite)) u.searchParams.set(k, v);
  return realFetch(u.toString()).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
};

async function signInOnce({ forged = false, ui = null } = {}) {
  const started = JSON.parse(await bridge('{"type":"account_sign_in"}'));
  const s = await waitStatus((x) => !!x.test_authorize_url);
  if (!s?.test_authorize_url) throw new Error("no authorize url; last status " + JSON.stringify(s));
  const au = new URL(s.test_authorize_url);
  const requestUri = au.searchParams.get("request_uri");
  const ap = await site("/authorize/approve", { client_id: "virule-desktop", request_uri: requestUri });
  const redirect = ap.body.redirect;
  let forgedResults = null;
  if (forged) {
    forgedResults = {
      wrongState: await deliver(redirect, { state: "A".repeat(32) }),
      wrongIss: await deliver(redirect, { iss: "https://evil.example" }),
      stillWaiting: (await status()).phase === "browser",
      otherPath: await realFetch(new URL(redirect).origin + "/steal").then((r) => r.status).catch(() => 0),
    };
  }
  // The harness is the browser; the seam origin is this build's issuer.
  const ok = await deliver(redirect, { iss: SEAM, ...(ui ? { ui } : {}) });
  return { started, s, au, ok, forgedResults };
}

try {
  await startClient();
  check("the sandboxed staging client answers on the bridge", await bridgeUp());
  const s0 = await status();
  check("signed out at first", s0 && s0.signed_in === false && s0.phase === "idle", s0);

  // --- page origins cannot touch the account
  const pageAttempt = await bridge('{"type":"account_status"}', { origin: "http://localhost:5173" });
  check("a web page (allowed origin) gets no account answer", pageAttempt === '{"type":"error"}', pageAttempt);
  const pageSignIn = await bridge('{"type":"account_sign_in"}', { origin: "http://localhost:5173" });
  check("a web page cannot start a sign-in", pageSignIn === '{"type":"error"}' && (await status()).phase === "idle");

  // --- sign in
  const r1 = await signInOnce({ forged: true });
  check("sign-in starts and reaches the browser phase", r1.started.started === true && r1.s.phase === "browser");
  check("the authorize URL carries only client_id and an opaque request_uri",
    r1.au.pathname === "/authorize/" && [...r1.au.searchParams.keys()].sort().join(",") === "client_id,request_uri", r1.s.test_authorize_url);
  check("the listener refuses a redirect with the wrong state", r1.forgedResults.wrongState.status === 404);
  check("the listener refuses a redirect from another issuer", r1.forgedResults.wrongIss.status === 404);
  check("and keeps waiting for the real one", r1.forgedResults.stillWaiting === true);
  check("the listener answers nothing but /callback", r1.forgedResults.otherPath === 404);
  check("the real redirect lands on the Client's page", r1.ok.status === 200 && /You are signed into the VIRULE app/.test(r1.ok.text));
  const s1 = await waitStatus((x) => x.signed_in && x.account);
  check("the Client reports the account and its server-decided capabilities",
    s1?.signed_in && s1.account.email === EMAIL && s1.capabilities.developer === "active" && s1.capabilities.evaluator === "none" &&
    s1.effective.developer === true && s1.effective.evaluator === false, s1);
  const raw = JSON.stringify(s1);
  const dbTokens = identity.prepare("SELECT token_hash FROM refresh_tokens").all().length;
  check("no bridge answer carries a token or key", !/refresh_token|access_token|seed|private/.test(raw));
  const sessFile = path.join(ROOT, "VIRULE", "client", "account.staging.dat");
  const devFile = path.join(ROOT, "VIRULE", "security", "account_device.staging.cred");
  const sessText = fs.existsSync(sessFile) ? fs.readFileSync(sessFile, "utf8") : "";
  check("the session is stored DPAPI-protected (no clear JSON, no email in clear)",
    sessText.length > 100 && !sessText.includes(EMAIL) && !sessText.includes("refresh") && /^[A-Za-z0-9+/=]+$/.test(sessText));
  check("the device key file holds a public key and a protected blob only",
    fs.existsSync(devFile) && /"private_blob"/.test(fs.readFileSync(devFile, "utf8")) && !/"seed"/.test(fs.readFileSync(devFile, "utf8")));
  check("the service issued one device authorization", identity.prepare("SELECT COUNT(*) n FROM devices WHERE revoked_epoch IS NULL").get().n === 1 && dbTokens === 1);
  const firstJkt = identity.prepare("SELECT dpop_jkt FROM devices ORDER BY created_epoch LIMIT 1").get().dpop_jkt;
  const firstKeyFile = fs.readFileSync(devFile, "utf8");

  // --- persistence across restarts + refresh rotation
  await stopClient();
  await startClient();
  const s2 = await status();
  check("the sign-in survives a Client restart", s2?.signed_in === true && s2.account.email === EMAIL, s2);
  identity.prepare("INSERT INTO account_capabilities VALUES (?, 'evaluator', 'active', 'operator:test', 1, 1)").run(acctId);
  await bridge('{"type":"account_refresh"}');
  const s3 = await waitStatus((x) => x.effective?.evaluator === true);
  check("a refresh rotates the token and picks up the operator's evaluator approval",
    s3?.effective?.evaluator === true && identity.prepare("SELECT COUNT(*) n FROM refresh_tokens WHERE superseded_epoch IS NOT NULL").get().n >= 1, s3);

  // --- website revocation signs the installation out
  const dev = identity.prepare("SELECT id FROM devices WHERE revoked_epoch IS NULL").get();
  await site("/devices/revoke", { id: dev.id });
  identity.prepare("UPDATE access_tokens SET expires_epoch = 1").run();
  await stopClient(); await startClient();
  await bridge('{"type":"account_refresh"}');
  const s4 = await waitStatus((x) => x.signed_in === false);
  check("a device revoked on the website is signed out by the Client", s4?.signed_in === false && s4.error === "signed_out_by_service", s4);
  check("and its local session file is gone", !fs.existsSync(sessFile));
  check("a service sign-out also deletes the device key (it belonged to that authorization)", !fs.existsSync(devFile));

  // --- cancel
  await bridge('{"type":"account_sign_in"}');
  await waitStatus((x) => x.phase === "browser");
  await bridge('{"type":"account_sign_in_cancel"}');
  const s5 = await waitStatus((x) => x.phase === "idle");
  check("a pending sign-in can be cancelled", s5?.phase === "idle" && s5.error === "cancelled" && !s5.signed_in, s5);

  // --- denial in the browser
  {
    await bridge('{"type":"account_sign_in"}');
    const s = await waitStatus((x) => !!x.test_authorize_url);
    const d = await site("/authorize/deny", { client_id: "virule-desktop", request_uri: new URL(s.test_authorize_url).searchParams.get("request_uri") });
    const res = await deliver(d.body.redirect, { iss: SEAM });
    const after = await waitStatus((x) => x.phase === "idle");
    check("a sign-in cancelled in the browser leaves the Client signed out", res.status === 200 && after?.signed_in === false, after);
  }

  // --- sign in again, then the QA link, then sign out
  const r6 = await signInOnce({ ui: "light" });
  const s6 = await waitStatus((x) => x.signed_in && x.account);
  check("signing in again works after a revocation", s6?.signed_in === true);
  check("the landing page wears the website's theme (ui=light), the same copy",
    r6.ok.status === 200 && /<html lang="en" class="l">/.test(r6.ok.text) && /You are signed into the VIRULE app/.test(r6.ok.text));
  const liveJkt = identity.prepare("SELECT dpop_jkt FROM devices WHERE revoked_epoch IS NULL").get()?.dpop_jkt;
  check("the new sign-in made a NEW device key: a new file and a different key at the service",
    fs.existsSync(devFile) && fs.readFileSync(devFile, "utf8") !== firstKeyFile && liveJkt && liveJkt !== firstJkt);

  // --- the account appearance (2026-10-15)
  const prefRow = () => identity.prepare("SELECT appearance, version FROM account_preferences WHERE account_id = ?").get(acctId);
  const waitPref = async (pred, ms = 15000) => { const end = Date.now() + ms; while (Date.now() < end && !pred(prefRow())) await sleep(250); return prefRow(); };
  check("a new account reports no explicit appearance", s6.appearance === "", s6);
  check("an appearance other than light or dark is refused",
    JSON.parse(await bridge('{"type":"account_set_appearance","appearance":"blue"}')).ok === false);
  const pageSet = await bridge('{"type":"account_set_appearance","appearance":"dark"}', { origin: "http://localhost:5173" });
  check("a web page cannot set the account appearance", pageSet === '{"type":"error"}', pageSet);
  const setD = JSON.parse(await bridge('{"type":"account_set_appearance","appearance":"dark"}'));
  const sD = await status();
  check("an explicit choice is reflected at once", setD.ok === true && sD.appearance === "dark", sD);
  let row = await waitPref((r) => r?.appearance === "dark");
  check("... and delivered to the ACCOUNT at the service (version 1)", row?.appearance === "dark" && row.version === 1, row);
  identity.prepare("UPDATE account_preferences SET appearance = 'light', version = 2 WHERE account_id = ?").run(acctId);
  await stopClient(); await startClient();
  await bridge('{"type":"account_refresh"}');
  const sL = await waitStatus((x) => x.appearance === "light");
  check("a change made on another installation arrives on the next refresh, still signed in", sL?.appearance === "light" && sL.signed_in === true, sL);
  // Offline: the choice is kept, shown, persisted across a restart.
  offline = true;
  const setOff = JSON.parse(await bridge('{"type":"account_set_appearance","appearance":"dark"}'));
  await sleep(2000);
  check("offline: the choice is kept and shown, nothing reached the service",
    setOff.ok === true && (await status()).appearance === "dark" && prefRow().version === 2);
  await stopClient(); await startClient();
  check("offline: the undelivered choice survives a restart", (await status())?.appearance === "dark");
  // Meanwhile another installation changed it again.
  identity.prepare("UPDATE account_preferences SET appearance = 'light', version = 3 WHERE account_id = ?").run(acctId);
  offline = false;
  const sR = await waitStatus((x) => x.appearance === "light", 45000);
  row = prefRow();
  check("reconnected: the stale offline choice never overwrites the newer one; this installation adopts it",
    sR?.appearance === "light" && row.appearance === "light" && row.version === 3, [sR, row]);
  // Offline again with nothing changed elsewhere: the replay applies.
  offline = true;
  await bridge('{"type":"account_set_appearance","appearance":"dark"}');
  await sleep(2000);
  offline = false;
  await stopClient(); await startClient();
  await bridge('{"type":"account_refresh"}');
  row = await waitPref((r) => r.appearance === "dark", 20000);
  check("reconnected with nothing changed elsewhere: the offline choice is delivered (version 4)", row.appearance === "dark" && row.version === 4, row);

  // --- Account Settings opens the website FOR THIS ACCOUNT (2026-10-15)
  const os1 = await bridge('{"type":"account_open_settings"}');
  check("account_open_settings answers ok and carries no link token", JSON.parse(os1).ok === true && !/#h=|[A-Za-z0-9_-]{43}/.test(os1), os1);
  const pageOpen = await bridge('{"type":"account_open_settings"}', { origin: "http://localhost:5173" });
  check("a web page cannot ask for it", pageOpen === '{"type":"error"}', pageOpen);
  const su = (await status()).test_settings_url ?? "";
  const m = /^(.*)\/account\/\?for=([0-9a-f]{32})#h=([A-Za-z0-9_-]{43})$/.exec(su);
  check("it opens <site>/account/?for=<account hint>#h=<single-use link>", !!m && m[1] === SEAM, su);
  const hintRow = identity.prepare("SELECT id FROM accounts WHERE email_norm = ?").get(EMAIL);
  const ins = await site("/handoff/inspect", { token: m?.[3] ?? "" });
  check("the link names this installation's account and its hint", ins.status === 200 && ins.body.account_email === EMAIL && ins.body.account_hint === m?.[2], ins.body);
  check("only the link's hash is kept at the service", identity.prepare("SELECT COUNT(*) n FROM web_handoffs").get().n >= 1 &&
    identity.prepare("SELECT COUNT(*) n FROM web_handoffs WHERE token_hash = ?").get(m?.[3] ?? "").n === 0 && !!hintRow);
  // A QA credential bound to the sandbox machine identity, signed by the service key.
  const devPath = path.join(ROOT, "VIRULE", "security", "dev_machine.cred");
  if (!fs.existsSync(devPath)) writeDevMachineCred(devPath);
  const devMachine = JSON.parse(fs.readFileSync(devPath, "utf8"));
  const servicePriv = createPrivateKey({ key: Buffer.from(env.EMBARGO_SIGNING_KEY_PKCS8, "base64"), format: "der", type: "pkcs8" });
  const org = randomBytes(16).toString("hex"), tester = randomBytes(16).toString("hex"), bound = new Date(Date.now() - 3600e3).toISOString().replace(/\.\d{3}Z$/, "Z");
  const sig = nodeSign(null, Buffer.from(`virule-qa-tester.v2|${org}|${tester}|${devMachine.public_key}|${bound}`), servicePriv).toString("hex");
  fs.writeFileSync(path.join(ROOT, "VIRULE", "security", "qa_tester.cred"), JSON.stringify({ version: 1, credentials: [{
    organization_id: org, tester_id: tester, machine_key: devMachine.public_key, bound_utc: bound, signature: sig, organization_name: "Test Org" }] }));
  // The test service verifies credentials against ITS key; the harness env key is that key.
  const sQa = await status();
  check("a local QA credential is offered for linking", sQa.qa_link_available === true, sQa);
  const link = JSON.parse(await bridge('{"type":"account_link_qa"}'));
  check("the explicit QA link succeeds with the issued credential and machine proof", link.ok === true && link.linked === 1, link);
  const s7 = await waitStatus((x) => x.capabilities?.qa_tester === "active");
  check("the account now shows the QA tester capability and no further link offer", s7?.capabilities.qa_tester === "active" && s7.qa_link_available === false, s7);
  check("the QA credential file is untouched (QA keeps working without the account)",
    JSON.parse(fs.readFileSync(path.join(ROOT, "VIRULE", "security", "qa_tester.cred"), "utf8")).credentials[0].signature === sig);

  // --- a password change on the website signs this installation out with
  // no restart (2026-10-16): its tokens are refused from the change on.
  const qaPath = path.join(ROOT, "VIRULE", "security", "qa_tester.cred");
  const qaBefore = fs.readFileSync(qaPath, "utf8"), machineBefore = fs.readFileSync(devPath, "utf8");
  // Replacing an existing password is /password/change: the current
  // password is the confirmation (/password/set refuses an account that
  // already has one).
  const pc = await site("/password/change", { current: "a long enough desktop passphrase", password: "a changed desktop passphrase here" });
  check("(setup) a verified password change on the website", pc.status === 200, pc.body);
  // The Admin asks on every window activation; the Client contacts the
  // service at most once per 20 seconds, so this ends within that window.
  const pcStart = Date.now();
  let sPc = await status();
  while (sPc?.signed_in !== false && Date.now() - pcStart < 35000) {
    await bridge('{"type":"account_refresh"}');
    await sleep(1000);
    sPc = await status();
  }
  check("a password change signs this running installation out (no restart, within the 20 s check window)",
    sPc?.signed_in === false && sPc.error === "signed_out_by_service" && Date.now() - pcStart < 25000, { sPc, ms: Date.now() - pcStart });
  check("... and leaves the machine identity and the QA credential exactly as they were",
    fs.readFileSync(qaPath, "utf8") === qaBefore && fs.readFileSync(devPath, "utf8") === machineBefore);
  check("the browser that changed the password stays signed in", (await site("/account")).status === 200);
  await signInOnce();
  check("the installation can sign in again afterwards", (await waitStatus((x) => x.signed_in && x.account))?.signed_in === true);

  const so = JSON.parse(await bridge('{"type":"account_sign_out"}'));
  const s8 = await status();
  check("sign out clears the Client", so.ok === true && s8.signed_in === false && !fs.existsSync(sessFile));
  check("sign out deletes the device key; the next person to sign in here starts a new one", !fs.existsSync(devFile));
  check("signed out, no appearance is reported", s8.appearance === undefined, s8);
  check("the QA credential and machine identity are untouched by sign-out (local records stay)",
    fs.existsSync(path.join(ROOT, "VIRULE", "security", "qa_tester.cred")) && fs.existsSync(devPath));
  check("and revokes the device authorization at the service",
    identity.prepare("SELECT COUNT(*) n FROM devices WHERE revoked_epoch IS NULL").get().n === 0 &&
    identity.prepare("SELECT revoked_reason FROM devices ORDER BY last_seen_epoch DESC, created_epoch DESC LIMIT 1").get().revoked_reason === "signout");

  const log = fs.readFileSync(path.join(ROOT, "VIRULE", "client", "logs", "virule-client.log"), "utf8").toString();
  check("the client log holds no token, code or verifier", !/[A-Za-z0-9_-]{43}/.test(log.replace(/[0-9a-f]{64}/g, "")), log.slice(-500));
} finally {
  await stopClient().catch(() => {});
  try { child?.kill(); } catch {}
  server.close();
  globalThis.fetch = realFetch;
  if (realWasRunning && fs.existsSync(REAL_CLIENT)) {
    spawn(REAL_CLIENT, [], { detached: true, stdio: "ignore" }).unref();
    for (let i = 0; i < 40 && !(await bridgeUp()); i++) await sleep(250);
    console.log((await bridgeUp()) ? "(the machine's real client is running again)" : "WARNING: the real client did not come back");
  }
  local.cleanup();
  fs.rmSync(outDir, { recursive: true, force: true });
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
