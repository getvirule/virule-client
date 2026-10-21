// ADMIN AND CLIENT UPDATES CONVERGE (0.9.15; docs/ARCHITECTURE.md "Admin
// and Client updates converge"). Sandboxed like p2_recovery_test.mjs: a
// throwaway LOCALAPPDATA/TEMP, the client copied in AS the sandbox's managed
// install (Programs\VIRULE\virule-client.exe, so the self-update and the
// pending-update record are enabled), --no-register, --dev-unsigned, and the
// --admin-manifest-url dev seam against a local manifest server. No real
// client is touched (the sandbox guard checks the synthetic Admin version).
//
//   1. the approved Admin manifest names a Client NEWER than this one:
//      admin_update_check still answers the approved version, update:true,
//      and the requirement (client_required, client_version);
//   2. an Admin update asked for meanwhile (local admin_install) installs
//      NOTHING (the package is never fetched; the fake Admin tree is
//      untouched), RECORDS the request (client\pending_admin_update.json,
//      recorded_by = this client) and reports status updating:true while
//      the record stands;
//   3. the SAME client version starting again finds its own record and
//      discards it (never a loop): updating:false, the file gone;
//   4. a manifest this client satisfies (no minimum, or an older one) is
//      installed as before: the package IS fetched.
//
// Run: node tools/client_requirement_test.mjs [--exe=<virule-client.exe>]
// (default: build\Release\x64\virule-client.exe; the staging build at
// build\Release\x64\staging\virule-client.exe works the same way)

import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import os from "node:os";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const exeArg = process.argv.find((a) => a.startsWith("--exe="));
const SOURCE_EXE = exeArg ? path.resolve(exeArg.slice(6)) : path.join(repo, "build", "Release", "x64", "virule-client.exe");
const SANDBOX = path.join(os.tmpdir(), "virule-client-requirement-sandbox");
const PORT = 47612;
const MARKER_VERSION = "0.1.1-alpha.1";   // the fake installed Admin: the sandbox guard

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wsKey = () => crypto.randomBytes(16).toString("base64");

// ---- WebSocket plumbing (the proven client half) ----
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
function connect() {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PORT, "127.0.0.1", () => {
      socket.write([`GET /v1 HTTP/1.1`, `Host: 127.0.0.1:${PORT}`, "Upgrade: websocket", "Connection: Upgrade",
        `Sec-WebSocket-Key: ${wsKey()}`, "Sec-WebSocket-Version: 13"].join("\r\n") + "\r\n\r\n");
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
async function localAsk(message, answerNeedle, timeoutMs = 25000) {
  const c = await connect();
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

// ---- the sandbox ----
function sandboxEnv(root) {
  const temp = path.join(root, "temp");
  fs.mkdirSync(temp, { recursive: true });
  return { ...process.env, LOCALAPPDATA: root, TEMP: temp, TMP: temp };
}
const INSTALL_DIR = path.join(SANDBOX, "Programs", "VIRULE");
const CLIENT_EXE = path.join(INSTALL_DIR, "virule-client.exe");
const STATE_DIR = path.join(SANDBOX, "VIRULE", "client");
const PENDING = path.join(STATE_DIR, "pending_admin_update.json");

// The managed Admin the pipeline recognizes (admin_install kRequiredSigned)
// plus the atomic install metadata, so admin_update_check can CLAIM an update.
const REQUIRED = ["virule.exe", ".resources/admin/ViruleAdminHost.exe", ".resources/bin/Win32/SidecarK32.dll",
  ".resources/bin/Win32/SidecarKHost.exe", ".resources/bin/x64/SidecarK64.dll", ".resources/bin/x64/SidecarKHost.exe"];
function writeAdminTree(dir, version) {
  for (const rel of REQUIRED) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "MZ fake " + rel);
  }
  fs.writeFileSync(path.join(dir, "outreach_providers.json"), "{}");
  fs.writeFileSync(path.join(dir, "installed-release.json"), JSON.stringify({ version }));
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
  // The client's OWN manifest is pointed at this server too (a 404): the
  // forced self-update check that the requirement triggers reaches no real
  // release, stages nothing and installs no VIRULE Service into the sandbox
  // (a sandbox service would start a second client, whose startup would
  // discard the record as its own).
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
async function requireSandbox(label) {
  const st = await localAsk('{"type":"status"}', '"type":"status"');
  if (!st || !st.includes(MARKER_VERSION)) { console.error(`ABORT (${label}): not the sandbox client; status = ${st}`); throw new Error("sandbox guard"); }
  return st;
}

// ---- the local manifest server ----
const packageBytes = Buffer.from("not a real package; the pipeline refuses it after the fetch");
const packageSha = crypto.createHash("sha256").update(packageBytes).digest("hex");
let minimumClient = "9.9.9";
let packageFetches = 0;
let manifestFetches = 0;
const server = http.createServer((req, res) => {
  if (req.url.startsWith("/admin-manifest.json")) {
    manifestFetches++;
    const m = { version: "0.1.1-alpha.2", channel: "alpha", url: `http://127.0.0.1:${server.address().port}/package.zip`,
      sha256: packageSha, size: packageBytes.length };
    if (minimumClient) m.minimumClientVersion = minimumClient;
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(m)); });
    return;
  }
  if (req.url === "/package.zip") { packageFetches++; res.writeHead(200, { "content-type": "application/zip" }); res.end(packageBytes); return; }
  res.writeHead(404); res.end();
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const manifestUrl = `http://127.0.0.1:${server.address().port}/admin-manifest.json`;

// ---- the run ----
if (!fs.existsSync(SOURCE_EXE)) { console.error("client build not found: " + SOURCE_EXE); process.exit(2); }
fs.rmSync(SANDBOX, { recursive: true, force: true });
fs.mkdirSync(INSTALL_DIR, { recursive: true });
fs.copyFileSync(SOURCE_EXE, CLIENT_EXE);
writeAdminTree(path.join(INSTALL_DIR, "Admin"), MARKER_VERSION);
fs.mkdirSync(STATE_DIR, { recursive: true });
fs.writeFileSync(path.join(STATE_DIR, "state.json"), JSON.stringify({ version: 1, installed_version: "0.0.0", admin_version: MARKER_VERSION,
  enabled_recorded: true, enabled_dev_tools: true, enabled_evaluator: false }));

try {
  // 1. The approved Admin needs a newer Client: known, offered, and said.
  check("sandbox client (managed install, dev seams) is serving", await startClient(manifestUrl));
  const st0 = await requireSandbox("start");
  const clientVersion = (st0.match(/"version":"([^"]+)"/) || [])[1];
  const upd = await localAsk('{"type":"admin_update_check"}', '"admin_update_status"');
  check("admin_update_check: the approved Admin is KNOWN and offered although this client is too old",
    !!upd && /"approved_version":"0\.1\.1-alpha\.2"/.test(upd) && /"update":true/.test(upd), upd);
  check("...and the requirement is said: client_required 9.9.9, client_version = this client",
    !!upd && /"client_required":"9\.9\.9"/.test(upd) && upd.includes(`"client_version":"${clientVersion}"`), upd);
  check("...the manifest was fetched, the package never", manifestFetches >= 1 && packageFetches === 0, `manifest ${manifestFetches} package ${packageFetches}`);

  // 2. An Admin update asked for meanwhile: recorded, not installed.
  const started = await localAsk('{"type":"admin_install"}', "admin_install_started", 10000);
  check("a local admin_install (Settings Update) is accepted", !!started, started);
  let recorded = false;
  for (let i = 0; i < 40 && !recorded; i++) { await sleep(250); recorded = fs.existsSync(PENDING); }
  check("...the request is RECORDED for the new client (pending_admin_update.json)", recorded);
  const rec = recorded ? JSON.parse(fs.readFileSync(PENDING, "utf8")) : {};
  check("...recorded by this client version, native feedback (a local caller), no launch after",
    rec.recorded_by === clientVersion && rec.native_feedback === true && rec.launch_after === false && rec.requested_utc > 0, JSON.stringify(rec));
  await sleep(1500);
  check("...NOTHING was installed: the package was never fetched and the Admin tree is untouched",
    packageFetches === 0 && fs.readFileSync(path.join(INSTALL_DIR, "Admin", "installed-release.json"), "utf8").includes(MARKER_VERSION), `package ${packageFetches}`);
  const st1 = await localAsk('{"type":"status"}', '"type":"status"');
  check("...status reports updating:true while the record stands (the Settings overlay keeps waiting)", !!st1 && /"updating":true/.test(st1), st1);
  check("...the client itself is still serving (its own update is what it waits for; none exists here)", !!st1 && st1.includes(MARKER_VERSION));

  // 3. The same client version again: its own record is discarded, never resumed.
  await stopClient();
  check("the same client version starts again", await startClient(manifestUrl));
  await requireSandbox("restart");
  let gone = false;
  for (let i = 0; i < 40 && !gone; i++) { await sleep(250); gone = !fs.existsSync(PENDING); }
  check("...a record written by this very version is discarded at startup (never a loop)", gone);
  const st2 = await localAsk('{"type":"status"}', '"type":"status"');
  check("...and status no longer claims an update in flight", !!st2 && /"updating":false/.test(st2), st2);
  check("...still no package fetch", packageFetches === 0, String(packageFetches));

  // 4. A manifest this client satisfies installs as before (the package is fetched).
  minimumClient = "";
  await stopClient();
  check("client restarted against a manifest without a requirement", await startClient(manifestUrl));
  await requireSandbox("no requirement");
  const upd2 = await localAsk('{"type":"admin_update_check"}', '"admin_update_status"');
  check("admin_update_check: update offered, no requirement named", !!upd2 && /"update":true/.test(upd2) && /"client_required":""/.test(upd2), upd2);
  const started2 = await localAsk('{"type":"admin_install"}', "admin_install_started", 10000);
  check("admin_install accepted", !!started2);
  let fetched = false;
  for (let i = 0; i < 60 && !fetched; i++) { await sleep(250); fetched = packageFetches > 0; }
  check("...the pipeline runs: the package IS fetched (and then refused, as a fake)", fetched, String(packageFetches));
  check("...no pending record is written for a manifest this client satisfies", !fs.existsSync(PENDING));
} finally {
  await stopClient();
  server.close();
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
