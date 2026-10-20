// EXPLICIT DEVELOPER ENROLLMENT ONLY, against LIVE STAGING with the
// PUBLISHED staging Client (owner rule 2026-10-20; docs/ARCHITECTURE.md
// "ROLES ARE THE ACCOUNT'S").
//
//   node tools/enrollment_live_staging_test.mjs
//
// Downloads the virule-client.exe the staging release serves, checks it
// against the staging manifest, and runs it in a sandbox (LOCALAPPDATA/TEMP
// under %TEMP%) with the STAGING-ONLY seam --account-browser=capture, as
// tools/account_live_staging_test.mjs does. The Admin manifest seam points
// at a closed loopback port, so an install/update request is accepted and
// recorded exactly as on a QA machine and then fails fast instead of
// downloading the package. Every capability is read from the LIVE staging
// identity database and the Client's own account answer, never from
// navigation.
//
// Proves, on a fresh ordinary staging account (e2e-enroll-*@e2e.virule.test):
//   1. signing in grants nothing (no developer);
//   2. an evaluator-only account stays evaluator only through the homepage
//      Update (the exact admin_install the staging site sends from the
//      staging origin), the Admin's Settings Update, a Client restart and a
//      sign-out + sign-in;
//   3. Install Dev Tools (capability_enable dev_tools: the homepage's Get
//      VIRULE Dev Tools / Settings > Install Dev Tools) makes it developer
//      AND evaluator;
//   4. that dual-role account keeps both roles through further Updates.
//
// The machine's real client is asked to leave first and started again at
// the end. Nothing is installed; nothing touches production.

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..");
const ORIGIN = "https://virule-api-staging.heath-michaels9441.workers.dev";
const REL = "https://github.com/getvirule/virule-staging-releases/releases/download/client-staging";
const REAL_CLIENT = path.join(process.env.LOCALAPPDATA, "Programs", "VIRULE", "virule-client.exe");
const SANDBOX = path.join(os.tmpdir(), "virule-enrollment-live-sandbox");
const ROOT = path.join(SANDBOX, "LocalAppData");
const EDGE = "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const { d1 } = await import(pathToFileURL(path.resolve(repo, "..", "..", "VIRULE_BACKEND", "tools", "accounts_admin.mjs")).href);
const { accountRowsSql, phcHash } = await import(pathToFileURL(path.resolve(repo, "..", "..", "VIRULE_BACKEND", "tools", "desktop_identity.mjs")).href);
const { chromium } = await import(pathToFileURL(path.resolve(repo, "..", "v1_mvp_site", "node_modules", "playwright-core", "index.mjs")).href);

let pass = 0, fail = 0;
const check = (name, cond, extra) => {
  if (cond) { pass++; console.log("ok   " + name); }
  else { fail++; console.log("FAIL " + name + " :: " + JSON.stringify(extra ?? null)); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const lit = (s) => "'" + s.replace(/'/g, "''") + "'";

// ------------------------------------------------ the published binary
const manifest = await (await fetch(`${REL}/manifest.json`)).json();
const exeBytes = Buffer.from(await (await fetch(`${REL}/virule-client.exe`)).arrayBuffer());
const entry = manifest.client ?? manifest;
check(`the published staging client matches its manifest (version ${entry.version})`,
  createHash("sha256").update(exeBytes).digest("hex") === entry.sha256 && exeBytes.length === entry.size);
fs.rmSync(SANDBOX, { recursive: true, force: true });
fs.mkdirSync(path.join(SANDBOX, "Temp"), { recursive: true });
fs.mkdirSync(ROOT, { recursive: true });
const EXE = path.join(SANDBOX, "virule-client.exe");
fs.writeFileSync(EXE, exeBytes);

// ------------------------------------------------ the deployed staging site
// The Update the staging homepage sends: its bundle must carry the explicit
// flag only on the Get VIRULE Dev Tools path (enroll_developer exists, and
// the plain admin_install shape exists beside it).
const home = await (await fetch(ORIGIN + "/")).text();
const bundles = [...home.matchAll(/src="(\/assets\/[^"]+\.js)"/g)].map((m) => m[1]);
let siteJs = "";
for (const b of bundles) siteJs += await (await fetch(ORIGIN + b)).text();
for (const m of siteJs.matchAll(/import\("\.\/([^"]+\.js)"\)|"\.\/([^"]+\.js)"/g)) {
  const f = m[1] ?? m[2];
  if (f) siteJs += await (await fetch(ORIGIN + "/assets/" + f)).text().catch(() => "");
}
check("the deployed staging site sends enroll_developer only as an explicit, separate admin_install shape",
  siteJs.includes("enroll_developer") && siteJs.includes("enrollDeveloper"), { bundles });

// ------------------------------------------------ the local bridge
function bridge(message, origin = null) {
  return new Promise((resolve) => {
    const s = net.connect(47612, "127.0.0.1", () => s.write(["GET /v1 HTTP/1.1", "Host: 127.0.0.1:47612", "Upgrade: websocket",
      "Connection: Upgrade", `Sec-WebSocket-Key: ${randomBytes(16).toString("base64")}`, "Sec-WebSocket-Version: 13",
      ...(origin ? [`Origin: ${origin}`] : [])].join("\r\n") + "\r\n\r\n"));
    let buf = Buffer.alloc(0), up = false; const frames = [];
    const done = (v) => { try { s.destroy(); } catch {} resolve(v); };
    const t = setTimeout(() => done(null), 8000);
    s.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (!up) { const i = buf.indexOf("\r\n\r\n"); if (i < 0) return; up = true; buf = buf.slice(i + 4); }
      while (buf.length >= 2) {
        let len = buf[1] & 0x7f, off = 2;
        if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
        if (buf.length < off + len) return;
        frames.push(buf.slice(off, off + len).toString()); buf = buf.slice(off + len);
        if (frames.length === 1) {
          const data = Buffer.from(message), mask = randomBytes(4), m = Buffer.from(data);
          for (let i = 0; i < m.length; i++) m[i] ^= mask[i & 3];
          const head = data.length < 126 ? Buffer.from([0x81, 0x80 | data.length]) : Buffer.from([0x81, 0x80 | 126, data.length >> 8, data.length & 255]);
          s.write(Buffer.concat([head, mask, m]));
        } else { clearTimeout(t); done(frames[1]); }
      }
    });
    s.on("error", () => { clearTimeout(t); done(null); });
  });
}
const up = async () => (await bridge('{"type":"wake"}')) !== null;
const status = async () => JSON.parse((await bridge('{"type":"account_status"}')) ?? "null");
const waitStatus = async (pred, ms = 20000) => {
  const end = Date.now() + ms; let s = null;
  while (Date.now() < end) { s = await status(); if (s && pred(s)) return s; await sleep(300); }
  return s;
};
const env = { ...process.env, LOCALAPPDATA: ROOT, TEMP: path.join(SANDBOX, "Temp"), TMP: path.join(SANDBOX, "Temp") };
const start = async () => {
  spawn(EXE, ["--no-register", "--account-browser=capture", "--admin-manifest-url=http://127.0.0.1:9/no-admin-manifest.json"],
    { env, detached: true, stdio: "ignore" }).unref();
  for (let i = 0; i < 40 && !(await up()); i++) await sleep(250);
};
const stop = async () => { await bridge('{"type":"shutdown"}'); for (let i = 0; i < 40 && (await up()); i++) await sleep(250); };

// ------------------------------------------------ the live account
const email = `e2e-enroll-${randomBytes(3).toString("hex")}@e2e.virule.test`;
const PASSWORD = "an enrollment live staging passphrase " + randomBytes(4).toString("hex");
const caps = () => Object.fromEntries(d1(`SELECT c.capability, c.status FROM account_capabilities c JOIN accounts a ON a.id = c.account_id WHERE a.email_norm = ${lit(email)}`)
  .map((r) => [r.capability, r.status]));
const roles = (c) => `${c.developer === "active" ? "developer" : "-"},${c.evaluator === "active" ? "evaluator" : "-"}`;
const rolesFile = path.join(ROOT, "VIRULE", "client", "account_roles.json");
const intentPending = () => fs.existsSync(rolesFile) && fs.readFileSync(rolesFile, "utf8").includes('"pending_developer":true');
// The homepage's Update and the Admin's Settings Update, exactly as sent.
const HOMEPAGE_UPDATE = '{"type":"admin_install","shortcut":false,"capability":"dev_tools"}';
const SETTINGS_UPDATE = '{"type":"admin_install"}';

const realWasRunning = await up();
for (let i = 0; i < 10 && (await up()); i++) { await bridge('{"type":"shutdown"}'); await sleep(800); }
const browser = await chromium.launch({ executablePath: EDGE, headless: true });
let page = null;
async function signIn() {
  const started = JSON.parse(await bridge('{"type":"account_sign_in"}'));
  const sb = await waitStatus((x) => !!x.test_authorize_url);
  await page.goto(sb?.test_authorize_url ?? "about:blank");
  await page.waitForSelector("text=Sign in to VIRULE on this computer?");
  await page.click("button:has-text('Continue')");
  await page.waitForURL(/^http:\/\/127\.0\.0\.1:\d+\/callback/, { timeout: 20000 }).catch(() => {});
  return started.started === true && !!(await waitStatus((x) => x.signed_in && x.account));
}
try {
  await start();
  check("the published staging client serves the bridge in the sandbox", JSON.parse((await bridge('{"type":"status"}')) ?? "{}").version === entry.version);

  // A fresh ordinary account with no capability, created as the backend's
  // staging e2e harnesses do (the live signup page needs a human Turnstile);
  // that signup and activation grant nothing is proven by VIRULE_BACKEND
  // tools/auth_test.mjs. The browser signs in to it by password.
  // Only the account row: accountRowsSql's capability rows would write
  // `revoked` grants, which no ordinary account has.
  d1(accountRowsSql({ id: randomBytes(16).toString("hex"), email, displayName: "", phc: await phcHash(PASSWORD), capabilities: [] })[0]);
  const ctx = await browser.newContext({ colorScheme: "light" });
  page = await ctx.newPage();
  const login = await ctx.request.post(ORIGIN + "/auth/api/password/login",
    { headers: { origin: ORIGIN, "content-type": "application/json" }, data: { email, password: PASSWORD } });
  check("(setup) the browser signs in to the fresh staging account", login.status() === 200, login.status());

  // 1. An ordinary account.
  check("(setup) the Client signs in to a fresh ordinary staging account", await signIn());
  await sleep(2000);
  const s1 = await status();
  check("9. a new ordinary account has no role at all (service and Client)",
    roles(caps()) === "-,-" && s1.effective?.developer === false && s1.effective?.evaluator === false, [caps(), s1.effective]);

  // 2. VIRULE approves it as an evaluator (the operator grant, as an
  // accepted invitation writes it).
  const now = Math.floor(Date.now() / 1000);
  d1(`INSERT INTO account_capabilities (account_id, capability, status, granted_by, created_epoch, updated_epoch)
      SELECT id, 'evaluator', 'active', 'invitation', ${now}, ${now} FROM accounts WHERE email_norm = ${lit(email)}
      ON CONFLICT(account_id, capability) DO UPDATE SET status = 'active', granted_by = 'invitation', updated_epoch = ${now}`);
  await bridge('{"type":"account_refresh"}');
  const s2 = await waitStatus((x) => x.effective?.evaluator === true, 45000);
  check("1. the evaluator-only account: service evaluator only, Client effective evaluator only",
    roles(caps()) === "-,evaluator" && s2?.effective?.developer === false && s2.effective.evaluator === true, [caps(), s2?.effective]);

  const u1 = await bridge(HOMEPAGE_UPDATE, ORIGIN);
  const u2 = await bridge(SETTINGS_UPDATE);
  check("(setup) the homepage Update (staging origin) and the Settings Update are accepted",
    /admin_install_started/.test(u1 ?? "") && /admin_install_started/.test(u2 ?? ""), [u1, u2]);
  await sleep(6000);
  check("2-4. after the Updates the service still reports evaluator only, and no intent is recorded",
    roles(caps()) === "-,evaluator" && !intentPending(), [caps(), intentPending()]);
  await stop();
  await start();
  await bridge('{"type":"account_refresh"}');
  await sleep(4000);
  const s3 = await waitStatus((x) => x.signed_in && x.account);
  check("3. after a Client restart: still evaluator only (service and Client)",
    roles(caps()) === "-,evaluator" && s3?.effective?.developer === false && s3.effective.evaluator === true, [caps(), s3?.effective]);

  const so = JSON.parse(await bridge('{"type":"account_sign_out"}'));
  check("(setup) sign out", so.ok === true);
  check("(setup) sign in again", await signIn());
  await sleep(3000);
  const s5 = await status();
  check("5. signing out and back in does not add developer",
    roles(caps()) === "-,evaluator" && s5.effective?.developer === false && s5.effective.evaluator === true, [caps(), s5.effective]);

  // 3. The explicit Install Dev Tools.
  const en = JSON.parse(await bridge('{"type":"capability_enable","capability":"dev_tools"}', ORIGIN));
  check("(setup) Get VIRULE Dev Tools (capability_enable dev_tools) is accepted", en.type === "capability_enabled", en);
  let dual = false;
  for (let i = 0; i < 60 && !dual; i++) { dual = roles(caps()) === "developer,evaluator"; if (!dual) await sleep(500); }
  const grant = d1(`SELECT c.granted_by FROM account_capabilities c JOIN accounts a ON a.id = c.account_id WHERE a.email_norm = ${lit(email)} AND c.capability = 'developer'`)[0];
  check("6. explicitly choosing Get Dev Tools grants developer and keeps evaluator", dual && grant?.granted_by === "install-dev-tools", [caps(), grant]);
  await bridge('{"type":"account_refresh"}');
  const s6 = await waitStatus((x) => x.effective?.developer === true && x.effective?.evaluator === true, 45000);
  check("7. the Client reports both roles (all four workspaces)", s6?.effective?.developer === true && s6.effective.evaluator === true, s6?.effective);

  // 4. Ordinary updates keep both.
  await bridge(HOMEPAGE_UPDATE, ORIGIN);
  await bridge(SETTINGS_UPDATE);
  await sleep(5000);
  await stop();
  await start();
  await sleep(3000);
  const s8 = await waitStatus((x) => x.signed_in && x.account);
  check("8. a dual-role account keeps both roles through ordinary Updates and a restart",
    roles(caps()) === "developer,evaluator" && s8?.effective?.developer === true && s8.effective.evaluator === true, [caps(), s8?.effective]);

  await bridge('{"type":"account_sign_out"}');
  check("(cleanup) signed out", (await status())?.signed_in === false);
  console.log(`(staging test account: ${email})`);
} finally {
  await stop().catch(() => {});
  await browser.close();
  if (realWasRunning && fs.existsSync(REAL_CLIENT)) {
    spawn(REAL_CLIENT, [], { detached: true, stdio: "ignore" }).unref();
    for (let i = 0; i < 40 && !(await up()); i++) await sleep(250);
    console.log((await up()) ? "(the machine's real client is running again)" : "WARNING: the real client did not come back");
  }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
