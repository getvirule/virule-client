// THE CLIENT ENFORCES EVALUATION PURCHASE READINESS ITSELF, WHOEVER ASKS
// (owner decision 2026-11-02; src/shared/evaluation_purchase_readiness.hpp,
// client/account.hpp api_call, shared/account_relay.hpp).
//
//   node tools/purchase_enforcement_test.mjs [--exe <path to virule-client.exe>]
//
// Runs the built VIRULE Client (default: the STAGING build) sandboxed
// (LOCALAPPDATA and TEMP under %TEMP%), pointed by the loopback-only
// development seam --account-endpoint at an HTTP server in this process
// that serves the REAL account routes (VIRULE_BACKEND src/auth) and the REAL
// evaluation routes (src/evaluations/index.ts handleEvaluationsV1, as
// src/v1/index.ts dispatches them) over the real migrations.
// This harness is NOT the Admin: it is an arbitrary local program speaking
// straight to the Client's bridge (127.0.0.1:47612, no Origin).
//
// A computer that is not ready is made with the STAGING-ONLY seam
// --test-purchase-blocker=<reason>, which can only add a refusal on top of
// the real answer (this computer must really be ready for the "fixed" half:
// the harness checks that first and stops if it is not).
//
// Proves, against the real binary:
//   - the readiness query is the Client's answer (local only; a page gets none);
//   - each blocker refuses a direct account_api purchase with its reason and
//     sentence, and NOTHING reaches the service (no request seen, no purchase
//     row), so the idempotency key is unspent;
//   - the Admin host's exact translation of the UI's purchase is refused the
//     same way (the host is pure transport, so this is what a force-enabled
//     control or a direct EvaluationsApi call reaches);
//   - fixed (restarted without the seam), the SAME request with the SAME key
//     completes, once; a repeat is the same purchase;
//   - non-purchase relay calls are untouched while blocked;
//   - the Client's own drivers' routes (machine-bound credential, runtime
//     report, security incidents, download receipt, upload sessions,
//     evidence, report) are refused by the relay before any request leaves.
//
// The machine's real client holds the bridge port and the single-instance
// mutex, so it is asked to leave first (non-destructive) and started again
// at the end, as the other harnesses do.

import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
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
const SANDBOX = path.join(os.tmpdir(), "virule-purchase-enforcement-sandbox");
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
const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "virule-purchase-bundle-"));
const bundle = (entry, name) => {
  const out = path.join(outDir, name);
  execFileSync(process.execPath, [path.join(backend, "node_modules", "esbuild", "bin", "esbuild"), path.join(backend, entry),
    "--bundle", "--format=esm", "--platform=neutral", "--main-fields=module,main", "--conditions=workerd,worker,browser",
    "--log-level=error", "--outfile=" + out], { stdio: "inherit" });
  return import(pathToFileURL(out).href);
};
const oauth = await bundle("src/auth/oauth.ts", "oauth.mjs");
const web = await bundle("src/auth/web.ts", "web.mjs");
const evaluations = await bundle("src/evaluations/index.ts", "evaluations.mjs");
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

// Every evaluation-family request that REACHED the service.
const seen = [];
const server = http.createServer(async (req, res) => {
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
  else if (p.startsWith("/v1/evaluations") || p.startsWith("/v1/assignments")) {
    let key = null;
    try { key = JSON.parse(body.toString("utf8")).idempotency_key ?? null; } catch { /* no JSON body */ }
    seen.push({ method: req.method, path: p, key, dpop: !!req.headers.dpop });
    const side = p.startsWith("/v1/evaluations") ? "evaluations" : "assignments";
    r = await evaluations.handleEvaluationsV1(request, SENV, side, p.slice(("/v1/" + side).length));
  } else r = new Response("not here", { status: 404 });
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const SEAM = `http://127.0.0.1:${server.address().port}`;

// The website half, called directly (as the site would, same origin).
let cookie = null;
async function site(route, b = {}) {
  const r = await web.handleAuthWeb(new Request(STAGING_ORIGIN + "/auth/api" + route, {
    method: "POST", headers: { origin: STAGING_ORIGIN, "content-type": "application/json", ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(b),
  }), SENV, "/api" + route);
  const sc = r.headers.get("set-cookie");
  if (sc) { const m = /^(__Host-virule_session=[^;]*);/.exec(sc); cookie = m ? m[1] : null; }
  return { status: r.status, body: await r.json().catch(() => null) };
}
const EMAIL = "purchase-enforcement@example.com";
await site("/signup", { email: EMAIL, turnstile: "harness-turnstile-token" });
const verifyToken = /#t=([A-Za-z0-9_-]{43})/.exec(identity.prepare("SELECT body_text FROM staging_outbox ORDER BY id DESC LIMIT 1").get().body_text)[1];
await site("/verify/password", { token: verifyToken, password: "a long enough desktop passphrase" });
const acctId = identity.prepare("SELECT id FROM accounts WHERE email_norm = ?").get(EMAIL).id;
identity.prepare("INSERT INTO account_capabilities VALUES (?, 'developer', 'active', 'operator:test', 1, 1)").run(acctId);

// ------------------------------------------------ the local bridge (no Origin: any local program)
function bridge(message, { origin = null } = {}) {
  return new Promise((resolve) => {
    const s = net.connect(47612, "127.0.0.1", () => {
      s.write(["GET /v1 HTTP/1.1", "Host: 127.0.0.1:47612", "Upgrade: websocket", "Connection: Upgrade",
        `Sec-WebSocket-Key: ${randomBytes(16).toString("base64")}`, "Sec-WebSocket-Version: 13",
        ...(origin ? [`Origin: ${origin}`] : [])].join("\r\n") + "\r\n\r\n");
    });
    let buf = Buffer.alloc(0), up = false, frames = [];
    const done = (v) => { try { s.destroy(); } catch {} resolve(v); };
    const t = setTimeout(() => done(null), 30000);
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
const readiness = async () => JSON.parse((await bridge('{"type":"evaluation_purchase_readiness"}')) ?? "null");
const api = async (method, p, body) => JSON.parse((await bridge(JSON.stringify({ type: "account_api", method, path: p, ...(body ? { body } : {}) }))) ?? "null");

const realWasRunning = await bridgeUp();
for (let i = 0; i < 10 && (await bridgeUp()); i++) { await bridge('{"type":"shutdown"}'); await sleep(800); }
fs.rmSync(SANDBOX, { recursive: true, force: true });
const ROOT = path.join(SANDBOX, "LocalAppData");
fs.mkdirSync(path.join(SANDBOX, "Temp"), { recursive: true });
fs.mkdirSync(ROOT, { recursive: true });
const sandboxEnv = { ...process.env, LOCALAPPDATA: ROOT, TEMP: path.join(SANDBOX, "Temp"), TMP: path.join(SANDBOX, "Temp") };
let child = null;
async function startClient(blocker = null) {
  child = spawn(EXE, ["--no-register", `--account-endpoint=${SEAM}`, `--admin-manifest-url=${SEAM}/no-admin-manifest.json`,
    `--self-manifest-url=${SEAM}/no-client-manifest.json`, ...(blocker ? [`--test-purchase-blocker=${blocker}`] : [])],
    { env: sandboxEnv, detached: true, stdio: "ignore" });
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
async function signIn() {
  await bridge('{"type":"account_sign_in"}');
  const s = await waitStatus((x) => !!x.test_authorize_url);
  if (!s?.test_authorize_url) throw new Error("no authorize url; last status " + JSON.stringify(s));
  const ap = await site("/authorize/approve", { client_id: "virule-desktop", request_uri: new URL(s.test_authorize_url).searchParams.get("request_uri") });
  const u = new URL(ap.body.redirect);
  u.searchParams.set("iss", SEAM);
  await realFetch(u.toString()).catch(() => null);
  return waitStatus((x) => x.signed_in && x.account);
}

// The purchase, exactly as the Admin UI builds it (evaluationState.ts completePurchase).
const GAME_UUID = randomBytes(16).toString("hex");
const KEY = randomBytes(16).toString("base64url");
const purchaseBody = {
  idempotency_key: KEY, game_uuid: GAME_UUID, quantity: 2,
  game: { title: "Enforcement Harness Game", description: "A game bought only on a ready computer.", genres: ["horror", "adventure"],
    content_warnings: ["violence"], steam_app_id: "480" },
  acceptance: { terms_url: "https://virule.app/terms/", terms_version: "2026-08-27", privacy_url: "https://virule.app/privacy/",
    privacy_version: "2026-10-01", accepted_at: new Date().toISOString(), context: "evaluation_purchase" },
};
// The Admin host's real translation of the UI's EvaluationsApi purchase
// (v2_mvp src/admin_host/evaluations_relay.hpp to_client_message): the
// fields in its order, the body last. The host relays it untouched.
const hostTranslation = `{"type":"account_api","method":"POST","path":"/v1/evaluations/purchases","body":${JSON.stringify(purchaseBody)}}`;
const purchasesAtService = () => local.identity.prepare("SELECT COUNT(*) AS n FROM evaluation_purchases WHERE idempotency_key = ?").get(KEY).n;
const purchaseRequestsSeen = () => seen.filter((x) => x.method === "POST" && x.path === "/v1/evaluations/purchases").length;

const SENTENCES = {
  unsupported_windows: "VIRULE requires Windows 10 or later.",
  defender_off: "This computer can't verify games because Microsoft Defender Antivirus is off. Turn it on in Windows Security.",
  defender_out_of_date: "This computer can't verify games because Microsoft Defender Antivirus needs an update. Update it in Windows Security.",
  antivirus_unsupported: "This computer can't verify games with the current antivirus configuration. Microsoft Defender Antivirus is recommended.",
};

try {
  await startClient();
  check("the sandboxed staging client answers on the bridge", await bridgeUp());
  const real = await readiness();
  check("this computer is really ready (needed for the fixed half; the seam can only refuse)",
    real?.type === "evaluation_purchase_readiness" && real.ready === true && real.reason === "supported" && real.message === "", real);
  if (!real?.ready) throw new Error("this computer is not ready; the harness cannot prove the fixed half here");
  const pageAsk = await bridge('{"type":"evaluation_purchase_readiness"}', { origin: "http://localhost:5173" });
  check("a web page (allowed origin) gets no readiness answer", pageAsk === '{"type":"error"}', pageAsk);
  const s1 = await signIn();
  check("(setup) signed in as a developer", s1?.signed_in === true && s1.effective?.developer === true, s1);
  const view0 = await api("GET", "/v1/evaluations");
  check("(setup) the developer view is reachable through the relay", view0?.status === 200, view0);

  // ---- BLOCKED: every reason, a direct local caller and the host's translation
  for (const reason of Object.keys(SENTENCES)) {
    await stopClient();
    await startClient(reason);
    const r = await readiness();
    check(`[${reason}] the Client's readiness answer names it with its sentence`,
      r?.ready === false && r.reason === reason && r.message === SENTENCES[reason], r);
    const beforeSeen = seen.length;
    const direct = await api("POST", "/v1/evaluations/purchases", purchaseBody);
    check(`[${reason}] DIRECT LOCAL CALLER: account_api purchase refused by the Client with the same reason and sentence`,
      direct?.type === "account_api" && direct.status === 0 && direct.error === "not_ready" && direct.reason === reason &&
      direct.message === SENTENCES[reason], direct);
    const viaHost = JSON.parse((await bridge(hostTranslation)) ?? "null");
    check(`[${reason}] THE ADMIN HOST'S TRANSLATION (force-enabled control, direct EvaluationsApi): refused the same way`,
      viaHost?.status === 0 && viaHost.error === "not_ready" && viaHost.reason === reason, viaHost);
    check(`[${reason}] nothing reached the service and no purchase exists`,
      seen.length === beforeSeen && purchasesAtService() === 0, seen.slice(beforeSeen));
    const read = await api("GET", "/v1/evaluations");
    check(`[${reason}] a non-purchase relay call is untouched`, read?.status === 200, read);
  }

  // ---- THE CLIENT'S OWN DRIVERS' ROUTES: never relayed (blocked or not)
  {
    const id = randomBytes(16).toString("hex"), id2 = randomBytes(16).toString("hex");
    const before = seen.length;
    const refused = [];
    const tried = [
      ["POST", "/v1/assignments/credential", { machine_key: "ab".repeat(32) }],
      ["POST", `/v1/assignments/${id}/runtime`, { running: true }],
      ["POST", `/v1/assignments/${id}/security/incident`, { threats: [] }],
      ["POST", `/v1/evaluations/games/${id}/security/incident`, { threats: [] }],
      ["POST", `/v1/assignments/${id}/download`, {}],
      ["POST", `/v1/assignments/${id}/download/${id2}/complete`, { sha256: "0".repeat(64), bytes: 1 }],
      ["POST", `/v1/evaluations/games/${id}/uploads`, {}],
      ["POST", `/v1/evaluations/uploads/${id}/complete`, {}],
      ["POST", `/v1/assignments/${id}/evidence/${id2}`, {}],
      ["POST", `/v1/assignments/${id}/report`, {}],
    ];
    for (const [m, p, b] of tried) {
      const a = await api(m, p, b);
      refused.push(a?.status === 0 && a.error === "bad_request");
    }
    check("DRIVER ROUTES: credential, runtime, incidents, download receipt, uploads, evidence, report are refused by the relay",
      refused.every(Boolean), refused);
    // (The Client's own background drivers, e.g. the evidence inbox's GET
    // /v1/evaluations/evidence, keep talking to the service meanwhile: only
    // the routes attempted here are compared.)
    const attempted = new Set(tried.map(([, p]) => p));
    const leaked = seen.slice(before).filter((x) => attempted.has(x.path));
    check("...and none of them reached the service", leaked.length === 0, leaked);
  }

  // ---- FIXED: the same logical purchase, the same key, completes once
  await stopClient();
  await startClient();
  const fixed = await readiness();
  check("fixed: the Client answers ready", fixed?.ready === true, fixed);
  const done = await api("POST", "/v1/evaluations/purchases", purchaseBody);
  check("fixed: the SAME request with the SAME idempotency key completes at the service",
    (done?.status === 200 || done?.status === 201) && purchasesAtService() === 1, done);
  check("...it reached the service under the Client's DPoP authorization, exactly once",
    purchaseRequestsSeen() === 1 && seen.filter((x) => x.path === "/v1/evaluations/purchases").every((x) => x.dpop && x.key === KEY));
  const again = JSON.parse((await bridge(hostTranslation)) ?? "null");
  check("a repeat (the host's translation, same key) is the same purchase, never a second",
    (again?.status === 200 || again?.status === 201) && purchasesAtService() === 1, again);

  const log = fs.readFileSync(path.join(ROOT, "VIRULE", "client", "logs", "virule-client.log"), "utf8");
  check("the Client log records each refusal at the purchase", /account: evaluation purchase refused here: defender_off/.test(log));
  check("the client log holds no token", !/[A-Za-z0-9_-]{43}/.test(log.replace(/[0-9a-f]{64}/g, "")));
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
