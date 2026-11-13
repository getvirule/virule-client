// THE OPERATOR ROLLBACK REACHES INSTALLED DESKTOPS (owner ruling 2026-11-13,
// VIRULE/docs/scratchpads/OWNER_ROLLBACK_PULLBACK_RULING_2026-11-13.md;
// src/client/admin_version.hpp update_wanted). Sandboxed like
// client_requirement_test.mjs: a throwaway LOCALAPPDATA/TEMP, the client
// copied in AS the sandbox's managed install, --no-register, --dev-unsigned,
// the --admin-manifest-url seam against a local manifest server and
// --self-manifest-url at a 404. The real client is asked to leave 47612 first;
// every destructive message is preceded by the sandbox guard (the synthetic
// installed version must be in the status answer).
//
// The installed Desktop is "0.1.1-alpha.2"; the manifest restores the OLDER
// approved "0.1.1-alpha.1" (a real zip of the required files):
//   A. NO ARBITRARY DOWNGRADE: a lower approved version that does not
//      withdraw the installed one is no update (admin_update_check, the launch
//      check), a list naming another version is no update, and a malformed list
//      is no update while the manifest itself is still accepted (the approved
//      version is still known);
//   B. the withdrawn list names the installed version: admin_update_check
//      claims the update for Settings and for the launch check;
//   C. a listed version whose package does not hash to the manifest is
//      refused by the pipeline: the installed Desktop is untouched;
//   D. THE THREE UPDATE PATHS, each from the withdrawn alpha.2:
//      Settings (local admin_install, what the Desktop's StartAdminUpdate
//      sends), the application restart (local admin_update_check
//      {"context":"launch"} then admin_launch, what virule.exe sends), and the
//      website (a PAGE admin_install from the staging origin, what the site's
//      Update sends): each installs alpha.1 (installed-release.json) and then
//      claims no further update;
//   F. THE CACHE FOLLOWS THE OPERATION: a rollback that arrives while the
//      client caches the forward manifest; after the website's Update pulls
//      the Desktop back, no update is claimed (the rehearsal finding);
//   E. THE LOOP BREAKER SURVIVES A RESTART: a failed launch-time pull-back
//      records the hold for alpha.1; a restarted client keeps it (the old
//      "moot" rule cleared it at every start because alpha.1 < alpha.2), so the
//      launch check does not re-download at once.
//
// Run: node tools/rollback_pullback_test.mjs [--exe=<virule-client.exe>]
// (default: build\Release\x64\staging\virule-client.exe)

import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import os from "node:os";
import zlib from "node:zlib";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const exeArg = process.argv.find((a) => a.startsWith("--exe="));
const SOURCE_EXE = exeArg ? path.resolve(exeArg.slice(6)) : path.join(repo, "build", "Release", "x64", "staging", "virule-client.exe");
const SANDBOX = path.join(os.tmpdir(), "virule-client-pullback-sandbox");
const PORT = 47612;
const PAGE_ORIGIN = "https://virule-api-staging.heath-michaels9441.workers.dev";
const INSTALLED = "0.1.1-alpha.2";   // the withdrawn version; also the sandbox guard
const RESTORED = "0.1.1-alpha.1";

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wsKey = () => crypto.randomBytes(16).toString("base64");

// ---- WebSocket plumbing (client_requirement_test.mjs) ----
function maskFrame(payload) {
  const data = Buffer.from(payload, "utf8");
  const head = [0x81];
  if (data.length < 126) head.push(0x80 | data.length);
  else head.push(0x80 | 126, (data.length >> 8) & 0xff, data.length & 0xff);
  const mask = crypto.randomBytes(4);
  const body = Buffer.from(data);
  for (let i = 0; i < body.length; i++) body[i] ^= mask[i & 3];
  return Buffer.concat([Buffer.from(head), mask, body]);
}
function parseFrames(buf) {
  const messages = [];
  let i = 0;
  while (i + 2 <= buf.length) {
    const opcode = buf[i] & 0x0f;
    let len = buf[i + 1] & 0x7f;
    let off = i + 2;
    if (len === 126) { if (off + 2 > buf.length) break; len = (buf[off] << 8) | buf[off + 1]; off += 2; }
    if (off + len > buf.length) break;
    messages.push({ opcode, text: buf.slice(off, off + len).toString("utf8") });
    i = off + len;
  }
  return [messages, buf.slice(i)];
}
function connect(origin = null) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PORT, "127.0.0.1", () => {
      const lines = [`GET /v1 HTTP/1.1`, `Host: 127.0.0.1:${PORT}`, "Upgrade: websocket", "Connection: Upgrade",
        `Sec-WebSocket-Key: ${wsKey()}`, "Sec-WebSocket-Version: 13"];
      if (origin) lines.push(`Origin: ${origin}`);
      socket.write(lines.join("\r\n") + "\r\n\r\n");
    });
    let buffer = Buffer.alloc(0);
    let upgraded = false;
    const queue = [];
    const waiters = [];
    const api = {
      sendText(payload) { socket.write(maskFrame(payload)); },
      next(timeoutMs = 5000) {
        return new Promise((res) => {
          if (queue.length) return res(queue.shift());
          const timer = setTimeout(() => res(null), timeoutMs);
          waiters.push((m) => { clearTimeout(timer); res(m); });
        });
      },
      end() { socket.destroy(); },
    };
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!upgraded) {
        const at = buffer.indexOf("\r\n\r\n");
        if (at === -1) return;
        const head = buffer.slice(0, at).toString("utf8");
        buffer = buffer.slice(at + 4);
        if (!head.startsWith("HTTP/1.1 101")) { socket.destroy(); return reject(new Error("no upgrade")); }
        upgraded = true;
        resolve(api);
      }
      const [messages, rest] = parseFrames(buffer);
      buffer = rest;
      for (const m of messages) {
        if (m.opcode !== 0x1) continue;
        const waiter = waiters.shift();
        if (waiter) waiter(m.text); else queue.push(m.text);
      }
    });
    socket.on("close", () => { if (!upgraded) reject(new Error("closed before upgrade")); });
    socket.on("error", () => reject(new Error("refused")));
    setTimeout(() => { if (!upgraded) { socket.destroy(); reject(new Error("upgrade timeout")); } }, 12000);
  });
}
async function ask(message, answerNeedle, { origin = null, timeoutMs = 25000 } = {}) {
  const c = await connect(origin);
  await c.next(); // hello
  c.sendText(message);
  const deadline = Date.now() + timeoutMs;
  let answer = null;
  for (;;) {
    const left = deadline - Date.now();
    if (left <= 0) break;
    const m = await c.next(left);
    if (m === null) break;
    if (m.includes(answerNeedle)) { answer = m; break; }
  }
  c.end();
  return answer;
}

// ---- a stored (uncompressed) zip, enough for the client's miniz reader ----
function crc32(buf) { return zlib.crc32 ? zlib.crc32(buf) >>> 0 : crcSlow(buf); }
function crcSlow(buf) {
  let c = ~0;
  for (const b of buf) { c ^= b; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); }
  return ~c >>> 0;
}
function makeZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const nb = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(0, 8);
    lh.writeUInt32LE(0, 10); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nb.length, 26); lh.writeUInt16LE(0, 28);
    locals.push(lh, nb, data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(0, 10);
    ch.writeUInt32LE(0, 12); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nb.length, 28); ch.writeUInt16LE(0, 30); ch.writeUInt16LE(0, 32); ch.writeUInt16LE(0, 34); ch.writeUInt16LE(0, 36);
    ch.writeUInt32LE(0, 38); ch.writeUInt32LE(offset, 42);
    centrals.push(ch, nb);
    offset += 30 + nb.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(0, 4); end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16); end.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, cd, end]);
}

// ---- the sandbox ----
function sandboxEnv(root) {
  const temp = path.join(root, "temp");
  fs.mkdirSync(temp, { recursive: true });
  return { ...process.env, LOCALAPPDATA: root, TEMP: temp, TMP: temp };
}
const INSTALL_DIR = path.join(SANDBOX, "Programs", "VIRULE");
const CLIENT_EXE = path.join(INSTALL_DIR, "virule-client.exe");
const ADMIN_DIR = path.join(INSTALL_DIR, "Admin");
const STATE_DIR = path.join(SANDBOX, "VIRULE", "client");
const REQUIRED = ["virule.exe", ".resources/admin/ViruleAdminHost.exe", ".resources/bin/Win32/SidecarK32.dll",
  ".resources/bin/Win32/SidecarKHost.exe", ".resources/bin/x64/SidecarK64.dll", ".resources/bin/x64/SidecarKHost.exe"];
function writeAdminTree(dir, version) {
  fs.rmSync(dir, { recursive: true, force: true });
  for (const rel of REQUIRED) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "MZ fake installed " + rel);
  }
  fs.writeFileSync(path.join(dir, "outreach_providers.json"), "{}");
  fs.writeFileSync(path.join(dir, "installed-release.json"), JSON.stringify({ version }));
}
function installedVersion() {
  try { return JSON.parse(fs.readFileSync(path.join(ADMIN_DIR, "installed-release.json"), "utf8")).version; } catch { return ""; }
}
function writeState(extra = {}) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(path.join(STATE_DIR, "state.json"), JSON.stringify({ version: 1, installed_version: "0.0.0", admin_version: INSTALLED,
    enabled_recorded: true, enabled_dev_tools: true, enabled_evaluator: false, ...extra }));
}
function readState() { try { return JSON.parse(fs.readFileSync(path.join(STATE_DIR, "state.json"), "utf8")); } catch { return {}; } }
function clientLog() {
  for (const p of [path.join(SANDBOX, "VIRULE", "logs", "client.log"), path.join(SANDBOX, "VIRULE", "client", "client.log")]) {
    try { return fs.readFileSync(p, "utf8"); } catch { /* next */ }
  }
  return "";
}

let clientProc = null;
async function freePort() {
  for (let i = 0; i < 10; i++) {
    try { const c = await connect(); await c.next(); c.sendText('{"type":"shutdown"}'); await c.next(2000); c.end(); await sleep(600); }
    catch { return; }
  }
}
async function startClient(manifestUrl) {
  await freePort();
  clientProc = spawn(CLIENT_EXE, ["--no-register", "--dev-unsigned", `--admin-manifest-url=${manifestUrl}`,
    `--self-manifest-url=${manifestUrl.replace("admin-manifest.json", "no-client-manifest.json")}`],
    { env: sandboxEnv(SANDBOX), stdio: "ignore", detached: false, cwd: INSTALL_DIR });
  for (let i = 0; i < 60; i++) {
    await sleep(250);
    try { const c = await connect(); const hello = await c.next(); c.end(); if (hello && hello.includes('"virule_client":1')) return true; }
    catch { /* not yet */ }
  }
  return false;
}
async function stopClient() {
  try { const c = await connect(); await c.next(); c.sendText('{"type":"shutdown"}'); await c.next(2000); c.end(); } catch { /* gone */ }
  if (clientProc) {
    const proc = clientProc;
    clientProc = null;
    await new Promise((res) => { const t = setTimeout(() => { try { proc.kill(); } catch {} res(); }, 6000); proc.once("exit", () => { clearTimeout(t); res(); }); });
  }
  await sleep(300);
}
// The sandbox guard: the status answer must come from THIS client (its exe
// path is the sandbox's) before anything that installs is sent.
async function requireSandbox(label) {
  const st = await ask('{"type":"status"}', '"type":"status"');
  const ours = clientProc && clientProc.exitCode === null;
  const port = await new Promise((res) => {
    const s = net.connect(PORT, "127.0.0.1", () => { s.destroy(); res(true); });
    s.on("error", () => res(false));
  });
  if (!st || !ours || !port || !(st.includes(INSTALLED) || st.includes(RESTORED))) {
    console.error(`ABORT (${label}): not the sandbox client; status = ${st}`);
    throw new Error("sandbox guard");
  }
  return st;
}
async function waitFor(pred, ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) { if (pred()) return true; await sleep(250); }
  return pred();
}

// ---- the local manifest server ----
const pkg = makeZip([...REQUIRED.map((rel) => [rel, Buffer.from("MZ fake restored " + rel)]),
  ["outreach_providers.json", Buffer.from("{}")]]);
const pkgSha = crypto.createHash("sha256").update(pkg).digest("hex");
let withdrawn;          // undefined = no field
let shaServed = pkgSha;
let packageFetches = 0;
let forward = false;    // true = the forward manifest: approved = the installed alpha.2
const server = http.createServer((req, res) => {
  if (req.url.startsWith("/admin-manifest.json")) {
    const m = { version: forward ? INSTALLED : RESTORED, channel: "alpha", url: `http://127.0.0.1:${server.address().port}/package.zip`,
      sha256: shaServed, size: pkg.length, minimumClientVersion: "0.9.0" };
    if (withdrawn !== undefined && !forward) m.withdrawn = withdrawn;
    req.on("data", () => {});
    req.on("end", () => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(m)); });
    return;
  }
  if (req.url === "/package.zip") { packageFetches++; res.writeHead(200, { "content-type": "application/zip" }); res.end(pkg); return; }
  res.writeHead(404); res.end();
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const manifestUrl = `http://127.0.0.1:${server.address().port}/admin-manifest.json`;

async function restart() {
  await stopClient();
  return startClient(manifestUrl);
}
const claim = (launch) => ask(launch ? '{"type":"admin_update_check","context":"launch"}' : '{"type":"admin_update_check"}', '"admin_update_status"');

// ---- the run ----
if (!fs.existsSync(SOURCE_EXE)) { console.error("client build not found: " + SOURCE_EXE); process.exit(2); }
fs.rmSync(SANDBOX, { recursive: true, force: true });
fs.mkdirSync(INSTALL_DIR, { recursive: true });
fs.copyFileSync(SOURCE_EXE, CLIENT_EXE);
writeAdminTree(ADMIN_DIR, INSTALLED);
writeState();

try {
  console.log("A. no arbitrary downgrade");
  check("sandbox client serving", await startClient(manifestUrl));
  await requireSandbox("A");
  let u = await claim(false);
  check("lower approved version, no withdrawn field: no update (Settings)", !!u && /"update":false/.test(u) && u.includes(`"approved_version":"${RESTORED}"`), u);
  u = await claim(true);
  check("...and no update for the launch check", !!u && /"update":false/.test(u), u);
  withdrawn = ["0.1.1-alpha.3"];
  await restart(); await requireSandbox("A2");
  u = await claim(false);
  check("a list naming ANOTHER version: no update", !!u && /"update":false/.test(u), u);
  withdrawn = [2];
  await restart(); await requireSandbox("A3");
  u = await claim(false);
  check("a malformed list: no update, and the manifest is still accepted (approved version known)",
    !!u && /"update":false/.test(u) && u.includes(`"approved_version":"${RESTORED}"`), u);
  check("...nothing was fetched", packageFetches === 0, String(packageFetches));

  console.log("B. the withdrawn version claims the ordinary update");
  withdrawn = [INSTALLED];
  await restart(); await requireSandbox("B");
  u = await claim(false);
  check("Settings: update:true toward the restored release", !!u && /"update":true/.test(u) && u.includes(`"approved_version":"${RESTORED}"`) && u.includes(`"admin_version":"${INSTALLED}"`), u);
  u = await claim(true);
  check("launch check: update:true", !!u && /"update":true/.test(u), u);

  console.log("C. a bad hash is refused by the pipeline");
  shaServed = "0".repeat(64);
  await restart(); await requireSandbox("C");
  const s0 = packageFetches;
  check("local admin_install accepted", !!(await ask('{"type":"admin_install"}', "admin_install_started", { timeoutMs: 10000 })));
  await waitFor(() => packageFetches > s0, 15000);
  await sleep(2500);
  check("...the package was fetched and REFUSED: the installed Desktop is untouched", packageFetches > s0 && installedVersion() === INSTALLED, `${packageFetches} ${installedVersion()}`);
  shaServed = pkgSha;

  console.log("D1. Settings path (local admin_install)");
  await restart(); await requireSandbox("D1");
  check("accepted", !!(await ask('{"type":"admin_install"}', "admin_install_started", { timeoutMs: 10000 })));
  check("...the Desktop is now the restored release (installed-release.json)", await waitFor(() => installedVersion() === RESTORED, 20000), installedVersion());
  check("...the replaced files are the package's", fs.readFileSync(path.join(ADMIN_DIR, "virule.exe"), "utf8").includes("restored"));
  u = await claim(false);
  check("...and no further update is claimed", !!u && /"update":false/.test(u) && u.includes(`"admin_version":"${RESTORED}"`), u);

  console.log("D2. application restart path (launch check + admin_launch)");
  await stopClient(); writeAdminTree(ADMIN_DIR, INSTALLED); writeState();
  check("client restarted on the withdrawn Desktop", await startClient(manifestUrl)); await requireSandbox("D2");
  u = await claim(true);
  check("the launch check says update", !!u && /"update":true/.test(u), u);
  check("admin_launch handed over", !!(await ask('{"type":"admin_launch"}', "admin_launch_started", { timeoutMs: 10000 })));
  check("...the Desktop is now the restored release", await waitFor(() => installedVersion() === RESTORED, 30000), installedVersion());

  console.log("D3. website path (a PAGE admin_install from the staging origin)");
  await stopClient(); writeAdminTree(ADMIN_DIR, INSTALLED); writeState();
  check("client restarted on the withdrawn Desktop", await startClient(manifestUrl)); await requireSandbox("D3");
  const pageAck = await ask('{"type":"admin_install","shortcut":false,"capability":"dev_tools"}', "admin_install_started", { origin: PAGE_ORIGIN, timeoutMs: 10000 });
  check("the page's Update is accepted", !!pageAck, pageAck);
  check("...the Desktop is now the restored release", await waitFor(() => installedVersion() === RESTORED, 30000), installedVersion());

  console.log("F. the cache follows the operation's own manifest (staging rehearsal finding, 2026-11-13)");
  // The client caches the FORWARD manifest (approved = the installed alpha.2:
  // current), then the operator rolls back while it keeps running: the
  // website's Update (it reads the manifest itself) pulls the Desktop back,
  // and afterwards NO update may be claimed (before 0.9.33 the cache still
  // named alpha.2, so the relaunched Desktop handed its launch straight back).
  await stopClient(); writeAdminTree(ADMIN_DIR, INSTALLED); writeState();
  forward = true;
  check("client restarted on alpha.2 with the forward manifest (approved alpha.2)", await startClient(manifestUrl)); await requireSandbox("F");
  u = await claim(false);
  check("...current: no update, approved alpha.2 cached", !!u && /"update":false/.test(u) && u.includes(`"approved_version":"${INSTALLED}"`), u);
  forward = false; withdrawn = [INSTALLED];
  const pageAck2 = await ask('{"type":"admin_install","shortcut":false,"capability":"dev_tools"}', "admin_install_started", { origin: PAGE_ORIGIN, timeoutMs: 10000 });
  check("the website's Update after the rollback is accepted", !!pageAck2, pageAck2);
  check("...the Desktop is now the restored release", await waitFor(() => installedVersion() === RESTORED, 30000), installedVersion());
  await waitFor(() => false, 1500);
  u = await claim(true);
  check("...and the launch check claims NOTHING (the cache is the operation's manifest, not the stale forward one)",
    !!u && /"update":false/.test(u) && u.includes(`"approved_version":"${RESTORED}"`), u);

  console.log("E. the launch-update hold survives a restart");
  await stopClient(); writeAdminTree(ADMIN_DIR, INSTALLED); writeState();
  shaServed = "0".repeat(64);
  check("client restarted on the withdrawn Desktop (bad hash served)", await startClient(manifestUrl)); await requireSandbox("E");
  check("admin_launch handed over", !!(await ask('{"type":"admin_launch"}', "admin_launch_started", { timeoutMs: 10000 })));
  check("...the failed pull-back records the hold for the restored version",
    await waitFor(() => readState().admin_hold_version === RESTORED, 30000), JSON.stringify(readState()));
  await restart(); await requireSandbox("E2");
  await sleep(1000);
  check("...a restarted client KEEPS the hold (not 'moot' because the held version is older)",
    readState().admin_hold_version === RESTORED, JSON.stringify(readState()));
  u = await claim(true);
  check("...so the launch check claims nothing while the hold lasts", !!u && /"update":false/.test(u), u);
  check("...and the installed Desktop is untouched", installedVersion() === INSTALLED, installedVersion());
} catch (e) {
  fail++;
  console.log("  FAIL  " + e.message);
} finally {
  await stopClient();
  server.close();
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
