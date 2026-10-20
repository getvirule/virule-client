// Desktop sign-in against LIVE STAGING with the PUBLISHED staging Client.
//
//   node tools/account_live_staging_test.mjs
//
// Downloads the virule-client.exe the staging release serves (exactly the
// bytes a QA machine installs), checks it against the staging manifest's
// SHA-256 and size and that it names only staging hosts, then runs it in a
// sandbox (LOCALAPPDATA/TEMP under %TEMP%) with the STAGING-ONLY harness seam
// --account-browser=capture: every request goes to the real staging
// service; only "open the default browser" is replaced by headless Edge,
// which signs up (real Turnstile widget, staging outbox, CDP virtual
// authenticator), approves the desktop sign-in on the real /authorize page
// and is redirected to the Client's own loopback listener.
//
// Proves on live staging: sign-in lands the account in the Client; it
// survives a Client restart; a refresh re-confirms it; the website lists the
// computer; sign-out revokes it at the service. Since 2026-10-15: an
// explicit appearance chosen through the Client reaches the account and
// the website follows it over an OS-light browser with no new sign-in; the
// landing page wears the website's theme; sign-out deletes the device key.
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
const SANDBOX = path.join(os.tmpdir(), "virule-account-live-sandbox");
const ROOT = path.join(SANDBOX, "LocalAppData");
const EDGE = "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const { d1 } = await import(pathToFileURL(path.resolve(repo, "..", "..", "VIRULE_BACKEND", "tools", "accounts_admin.mjs")).href);
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
const sha = createHash("sha256").update(exeBytes).digest("hex");
const entry = manifest.client ?? manifest;
check(`the published staging client matches its manifest (version ${entry.version})`,
  sha === entry.sha256 && exeBytes.length === entry.size, { sha, want: entry.sha256, size: exeBytes.length, want_size: entry.size });
const ascii = exeBytes.toString("latin1");
const wide = exeBytes.toString("utf16le") + exeBytes.subarray(1).toString("utf16le");
const names = (s) => ascii.includes(s) || wide.includes(s);
check("it names the staging service host", names("virule-api-staging.heath-michaels9441.workers.dev"));
check("it names no production service or site host", !names("api.virule.app") && !names("https://virule.app"));
fs.rmSync(SANDBOX, { recursive: true, force: true });
fs.mkdirSync(path.join(SANDBOX, "Temp"), { recursive: true });
fs.mkdirSync(ROOT, { recursive: true });
const EXE = path.join(SANDBOX, "virule-client.exe");
fs.writeFileSync(EXE, exeBytes);

// ------------------------------------------------ the local bridge
function bridge(message) {
  return new Promise((resolve) => {
    const s = net.connect(47612, "127.0.0.1", () => s.write(["GET /v1 HTTP/1.1", "Host: 127.0.0.1:47612", "Upgrade: websocket",
      "Connection: Upgrade", `Sec-WebSocket-Key: ${randomBytes(16).toString("base64")}`, "Sec-WebSocket-Version: 13"].join("\r\n") + "\r\n\r\n"));
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
          s.write(Buffer.concat([Buffer.from([0x81, 0x80 | data.length]), mask, m]));
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
  spawn(EXE, ["--no-register", "--account-browser=capture"], { env, detached: true, stdio: "ignore" }).unref();
  for (let i = 0; i < 40 && !(await up()); i++) await sleep(250);
};
const stop = async () => { await bridge('{"type":"shutdown"}'); for (let i = 0; i < 40 && (await up()); i++) await sleep(250); };

const realWasRunning = await up();
for (let i = 0; i < 10 && (await up()); i++) { await bridge('{"type":"shutdown"}'); await sleep(800); }

const browser = await chromium.launch({ executablePath: EDGE, headless: true });
const email = `qa-live+${randomBytes(4).toString("hex")}@example.com`;
try {
  await start();
  const hello = await bridge('{"type":"status"}');
  check("the published staging client serves the bridge in the sandbox", !!hello && JSON.parse(hello).version === entry.version, hello);

  // A real website account: sign up, confirm from the outbox, create a passkey.
  const ctx = await browser.newContext({ colorScheme: "light" });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto(ORIGIN + "/signup/");
  await page.fill("input[type=email]", email);
  await page.waitForFunction(() => !document.querySelector("button[type=submit]")?.disabled, null, { timeout: 30000 });
  await page.click("button[type=submit]");
  await page.waitForSelector("text=Check your email");
  let link = null;
  for (let i = 0; i < 20 && !link; i++) {
    const r = d1(`SELECT body_text FROM staging_outbox WHERE lower(to_addr) = ${lit(email)} ORDER BY id DESC LIMIT 1`);
    link = r[0] && /(\/verify#t=[A-Za-z0-9_-]{43})/.exec(r[0].body_text)?.[1];
    if (!link) await sleep(1000);
  }
  await page.goto(ORIGIN + link);
  // The signup browser confirms automatically (no Confirm screen).
  await page.waitForSelector("text=Your email is confirmed", { timeout: 20000 });
  await page.click("button:has-text('Create a passkey')");
  await page.waitForSelector("h1.acct-title:text-is('Your account')", { timeout: 20000 });
  check("a staging website account exists and is signed in in the browser", true);

  // Account > Sign In, as the Admin asks it.
  const s0 = await status();
  check("the Client starts signed out", s0?.signed_in === false, s0);
  const started = JSON.parse(await bridge('{"type":"account_sign_in"}'));
  const sb = await waitStatus((x) => !!x.test_authorize_url);
  const au = new URL(sb?.test_authorize_url ?? "http://invalid/");
  check("sign-in reached the real staging service (PAR) and produced the site's authorize URL",
    started.started === true && au.origin === ORIGIN && au.pathname === "/authorize/" && au.searchParams.get("client_id") === "virule-desktop", sb);
  await page.goto(au.toString());
  await page.waitForSelector("text=Sign in to VIRULE on this computer?");
  check("the approval page names this account", await page.locator(`text=${email}`).isVisible());
  await page.click("button:has-text('Continue')");
  await page.waitForURL(/^http:\/\/127\.0\.0\.1:\d+\/callback/, { timeout: 20000 }).catch(() => {});
  const landed = await page.content();
  check("the browser was handed to the Client's loopback page", /You are signed into the VIRULE app/.test(landed), page.url());
  const s1 = await waitStatus((x) => x.signed_in && x.account);
  // A fresh signup holds no role (developer only through Install Dev Tools).
  check("the Client reports the account with the service's capabilities (none: signing up grants nothing)",
    s1?.signed_in && s1.account.email === email && s1.effective?.developer === false && s1.effective?.evaluator === false, s1);
  check("no token in the Client's answer", !/refresh_token|access_token/.test(JSON.stringify(s1)));
  const sess = path.join(ROOT, "VIRULE", "client", "account.staging.dat");
  check("the staging session file exists, protected (no email in clear)", fs.existsSync(sess) && !fs.readFileSync(sess, "utf8").includes(email));

  // Close and reopen.
  await stop();
  await start();
  const s2 = await status();
  check("closing and reopening keeps the account signed in", s2?.signed_in === true && s2.account?.email === email, s2);
  const before = s2.checked;
  await sleep(1100);
  await bridge('{"type":"account_refresh"}');
  const s3 = await waitStatus((x) => x.checked > before);
  check("a refresh re-confirms the account with the live service (rotated token)", s3?.checked > before && s3.signed_in, s3);

  await page.goto(ORIGIN + "/account/");
  await page.waitForSelector("h1.acct-title:text-is('Your account')");
  check("the website lists the signed-in computer", (await page.locator(".acct-section", { hasText: "VIRULE on your computers" }).locator(".acct-item").count()) === 1);
  check("before any choice the website follows the OS (light here)", (await page.evaluate(() => document.documentElement.getAttribute("data-theme"))) === "light");

  // The account appearance, through the published Client, live.
  const setD = JSON.parse(await bridge('{"type":"account_set_appearance","appearance":"dark"}'));
  let pref = [];
  for (let i = 0; i < 40; i++) {
    pref = d1(`SELECT p.appearance, p.version FROM account_preferences p JOIN accounts a ON a.id = p.account_id WHERE a.email_norm = ${lit(email)}`);
    if (pref[0]?.appearance === "dark") break;
    await new Promise((r) => setTimeout(r, 500));
  }
  check("an explicit Dark chosen through the Client is recorded on the account at the live service",
    setD.ok === true && pref[0]?.appearance === "dark" && pref[0]?.version === 1, pref);
  check("the Client reports it", (await status())?.appearance === "dark");
  await page.reload();
  await page.waitForSelector("h1.acct-title:text-is('Your account')");
  await page.waitForTimeout(600);
  check("the website, on an OS-LIGHT browser, now wears the account's Dark with no new sign-in",
    (await page.evaluate(() => document.documentElement.getAttribute("data-theme"))) === "dark");
  const devKey = path.join(ROOT, "VIRULE", "security", "account_device.staging.cred");
  check("the device key exists while signed in", fs.existsSync(devKey));

  // Account Settings from the app, live: a SIGNED-OUT browser gets one
  // click naming the app's account; the browser already signed in to it
  // goes straight to the account page.
  JSON.parse(await bridge('{"type":"account_open_settings"}'));
  const settingsUrl = (await status())?.test_settings_url ?? "";
  check("Account Settings opens <site>/account/?for=<hint>#h=<single-use link>",
    settingsUrl.startsWith(ORIGIN + "/account/?for=") && /^[0-9a-f]{32}#h=[A-Za-z0-9_-]{43}$/.test(settingsUrl.slice((ORIGIN + "/account/?for=").length)), settingsUrl);
  const fresh = await browser.newContext({ colorScheme: "dark" });
  const fp = await fresh.newPage();
  await fp.goto(settingsUrl);
  await fp.waitForSelector("h1.acct-title:text-is('Continue to your account')", { timeout: 15000 }).catch(() => {});
  check("a signed-out browser is asked once, naming the app's account, and the link leaves the address bar",
    (await fp.locator("h1.acct-title").textContent()) === "Continue to your account" && await fp.locator(`text=${email}`).isVisible() && !fp.url().includes("#h="));
  await fp.click("button:has-text('Continue')");
  await fp.waitForSelector("h1.acct-title:text-is('Your account')", { timeout: 15000 }).catch(() => {});
  check("Continue signs that browser in to the app's account", (await fp.locator("h1.acct-title").textContent()) === "Your account" && await fp.locator(`text=${email}`).first().isVisible());
  await fresh.close();
  JSON.parse(await bridge('{"type":"account_open_settings"}'));
  await page.goto((await status())?.test_settings_url ?? "");
  await page.waitForSelector("h1.acct-title", { timeout: 15000 }).catch(() => {});
  check("a browser already signed in to the app's account goes straight to the account page", (await page.locator("h1.acct-title").textContent()) === "Your account");

  // Sign out.
  const so = JSON.parse(await bridge('{"type":"account_sign_out"}'));
  const s4 = await status();
  check("sign out clears the Client", so.ok === true && s4.signed_in === false && !fs.existsSync(sess), s4);
  const dev = d1(`SELECT d.revoked_reason FROM devices d JOIN accounts a ON a.id = d.account_id WHERE a.email_norm = ${lit(email)}`);
  check("and revokes the computer at the live service", dev.length === 1 && dev[0].revoked_reason === "signout", dev);
  check("sign out deletes the device key", !fs.existsSync(devKey));
  await page.reload();
  await page.waitForSelector("h1.acct-title:text-is('Your account')");
  check("the website no longer lists it", await page.locator("text=No computers are signed in").isVisible());
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
