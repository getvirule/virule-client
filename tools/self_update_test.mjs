// CLIENT SELF-UPDATE targeted tests (owner spec 2026-09-04). Sandboxed
// like uninstall_lifecycle_test.mjs: LOCALAPPDATA/TEMP point at a
// throwaway tree, the client runs AS the sandbox's managed install
// (Programs\VIRULE\virule-client.exe) with --no-register and the
// --self-manifest-url dev seam against a local manifest server. The hash
// gate always holds; --dev-unsigned (where used) waives only signatures,
// exactly Virule-Setup's seam.
//
//   pre-suite (node tools/self_update_test.mjs pre):
//     A  startup check never blocks the bridge (dead manifest host)
//     B  installed == approved: no download, no restart
//     E  busy client defers the swap (QA activity holds the safe point)
//     F  uninstall latch wins: staged update discarded, no helper
//     G  swap failure (live exe locked): known-good client restored, no loop
//     H  new client failing health: deterministic rollback, no loop
//
//   swap-suite (node tools/self_update_test.mjs swap --old=<exe> --new=<exe> --newver=<v>):
//     C  real self-update: old serving -> stage -> helper swap -> new serving
//     D  a connected page rides through the swap inside the 5s hysteresis
//
// NOTE: test F toggles the REAL HKCU uninstall-intent latch for a few
// seconds (the latch is a registry contract and cannot be sandboxed); it
// is restored in a finally block.

import net from "node:net";
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawn, execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BUILD_EXE = path.join(repo, "build", "Release", "x64", "virule-client.exe");
const SANDBOX = path.join(os.tmpdir(), "virule-self-update-test-sandbox");
const PORT = 47612;

const args = process.argv.slice(2);
const MODE = args[0] || "pre";
const argOf = (name) => {
  const a = args.find((x) => x.startsWith(`--${name}=`));
  return a ? a.slice(name.length + 3) : null;
};

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wsKey = () => crypto.randomBytes(16).toString("base64");

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
    if (len === 126) {
      if (off + 2 > buf.length) break;
      len = (buf[off] << 8) | buf[off + 1];
      off += 2;
    }
    if (off + len > buf.length) break;
    messages.push({ opcode, text: buf.slice(off, off + len).toString("utf8") });
    i = off + len;
  }
  return [messages, buf.slice(i)];
}

function connect({ origin = "https://virule.app", timeoutMs = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PORT, "127.0.0.1", () => {
      const headers = [
        `GET /v1 HTTP/1.1`,
        `Host: 127.0.0.1:${PORT}`,
        "Upgrade: websocket",
        "Connection: Upgrade",
        `Sec-WebSocket-Key: ${wsKey()}`,
        "Sec-WebSocket-Version: 13",
      ];
      if (origin !== null) headers.push(`Origin: ${origin}`);
      socket.write(headers.join("\r\n") + "\r\n\r\n");
    });
    let buffer = Buffer.alloc(0);
    let upgraded = false;
    const queue = [];
    const waiters = [];
    let closed = false;
    const api = {
      sendText(payload) { socket.write(maskFrame(payload)); },
      next(timeoutMs2 = 5000) {
        return new Promise((res) => {
          if (queue.length) return res(queue.shift());
          const waiter = (m) => { clearTimeout(timer); res(m); };
          const timer = setTimeout(() => {
            const i = waiters.indexOf(waiter);
            if (i >= 0) waiters.splice(i, 1);
            res(null);
          }, timeoutMs2);
          waiters.push(waiter);
        });
      },
      end() { socket.destroy(); },
      get closed() { return closed; },
      onClose(fn) { socket.once("close", fn); },
    };
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!upgraded) {
        const at = buffer.indexOf("\r\n\r\n");
        if (at === -1) return;
        const head = buffer.slice(0, at).toString("utf8");
        buffer = buffer.slice(at + 4);
        if (!head.startsWith("HTTP/1.1 101")) {
          socket.destroy();
          return reject(new Error("no upgrade"));
        }
        upgraded = true;
        resolve(api);
      }
      const [messages, rest] = parseFrames(buffer);
      buffer = rest;
      for (const m of messages) {
        if (m.opcode !== 0x1) continue;
        const waiter = waiters.shift();
        if (waiter) waiter(m.text);
        else queue.push(m.text);
      }
    });
    socket.on("close", () => { closed = true; });
    socket.on("error", () => { closed = true; reject(new Error("refused")); });
    setTimeout(() => {
      if (!upgraded) { socket.destroy(); reject(new Error("upgrade timeout")); }
    }, timeoutMs);
  });
}

async function statusOf(conn) {
  conn.sendText('{"type":"status"}');
  const deadline = Date.now() + 5000;
  for (;;) {
    const left = deadline - Date.now();
    if (left <= 0) return null;
    const m = await conn.next(left);
    if (m === null) return null;
    if (m.includes('"type":"status"')) return m;
  }
}

async function helloVersion() {
  const c = await connect({ origin: null });
  try {
    const hello = await c.next(4000);
    const m = hello && hello.match(/"version":"([^"]+)"/);
    return m ? m[1] : null;
  } finally { c.end(); }
}

async function freePort() {
  for (let i = 0; i < 12; i++) {
    try {
      const c = await connect({ origin: null, timeoutMs: 2500 });
      await c.next(2000);
      c.sendText('{"type":"shutdown"}');
      await c.next(2000);
      c.end();
      await sleep(700);
    } catch { return; }
  }
}

// ---- sandbox ----

const ROOT = path.join(SANDBOX, "root");
const INSTALL_DIR = path.join(ROOT, "Programs", "VIRULE");
const TARGET_EXE = path.join(INSTALL_DIR, "virule-client.exe");
const STAGED_EXE = path.join(INSTALL_DIR, "virule-client.exe.update");
const OLD_EXE_FILE = path.join(INSTALL_DIR, "virule-client.exe.old");
const TXN_FILE = path.join(ROOT, "VIRULE", "client", "self_update.json");
const LOG_FILE = path.join(ROOT, "VIRULE", "client", "logs", "virule-client.log");

function sandboxEnv() {
  const temp = path.join(ROOT, "temp");
  fs.mkdirSync(temp, { recursive: true });
  return { ...process.env, LOCALAPPDATA: ROOT, TEMP: temp, TMP: temp };
}

async function resetSandbox(clientExe) {
  // Bounded retries: the previous scenario's client (or its helper) may
  // still be releasing handles for a moment after shutdown.
  for (let i = 0; i < 30; i++) {
    try {
      fs.rmSync(SANDBOX, { recursive: true, force: true });
      break;
    } catch { await sleep(500); }
  }
  fs.mkdirSync(INSTALL_DIR, { recursive: true });
  fs.copyFileSync(clientExe, TARGET_EXE);
}

function readLog() {
  try { return fs.readFileSync(LOG_FILE, "utf8"); } catch { return ""; }
}
function countLog(needle) {
  return readLog().split("\n").filter((l) => l.includes(needle)).length;
}

let clientProc = null;
async function startSandboxClient(extraArgs, { waitHello = true } = {}) {
  await freePort();
  clientProc = spawn(TARGET_EXE, ["--no-register", ...extraArgs], {
    env: sandboxEnv(), stdio: "ignore", detached: false,
  });
  if (!waitHello) return Date.now();
  for (let i = 0; i < 40; i++) {
    await sleep(250);
    try {
      const c = await connect({ origin: null, timeoutMs: 2000 });
      const hello = await c.next(1500);
      c.end();
      if (hello && hello.includes('"virule_client":1')) return true;
    } catch { /* not yet */ }
  }
  return false;
}

async function shutdownServingClient() {
  try {
    const c = await connect({ origin: null, timeoutMs: 2500 });
    await c.next(1500);
    c.sendText('{"type":"shutdown"}');
    await c.next(1500);
    c.end();
  } catch { /* gone */ }
  if (clientProc && clientProc.exitCode === null) {
    const proc = clientProc;
    await new Promise((res) => {
      const t = setTimeout(() => { try { proc.kill(); } catch {} res(); }, 6000);
      proc.once("exit", () => { clearTimeout(t); res(); });
    });
  }
  await sleep(600);
  clientProc = null;
}

// ---- local manifest server ----

let server = null;
let serverPort = 0;
let served = { version: "", payload: null, delayMs: 0 };
let downloadCount = 0;

function manifestJson() {
  const sha = crypto.createHash("sha256").update(served.payload).digest("hex");
  return `{"version":"${served.version}","url":"http://127.0.0.1:${serverPort}/client.exe","sha256":"${sha}","size":${served.payload.length}}`;
}

function startServer() {
  return new Promise((resolve) => {
    server = http.createServer(async (req, res) => {
      if (served.delayMs) await sleep(served.delayMs);
      if (req.url === "/manifest.json") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(manifestJson());
      } else if (req.url === "/client.exe") {
        downloadCount++;
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(served.payload);
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    server.listen(0, "127.0.0.1", () => {
      serverPort = server.address().port;
      resolve();
    });
  });
}

const manifestArg = () => `--self-manifest-url=http://127.0.0.1:${serverPort}/manifest.json`;

// ---- uninstall latch (registry; real HKCU, restored in finally) ----

const LATCH_KEY = "HKCU\\Software\\VIRULE\\Lifecycle";
function setLatch() {
  execSync(`reg add "${LATCH_KEY}" /v UninstallInProgress /t REG_DWORD /d 1 /f`, { stdio: "ignore" });
}
function clearLatch() {
  try { execSync(`reg delete "${LATCH_KEY}" /v UninstallInProgress /f`, { stdio: "ignore" }); } catch {}
  try { execSync(`reg delete "${LATCH_KEY}" /v UninstallStartedUtc /f`, { stdio: "ignore" }); } catch {}
  try { execSync(`reg delete "${LATCH_KEY}" /f`, { stdio: "ignore" }); } catch {}
}
function latchWasSet() {
  try {
    execSync(`reg query "${LATCH_KEY}" /v UninstallInProgress`, { stdio: "ignore" });
    return true;
  } catch { return false; }
}

async function waitFor(fn, timeoutMs, everyMs = 400) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() >= deadline) return false;
    await sleep(everyMs);
  }
}

// ---- the pre-suite ----

async function preSuite() {
  const buildVersion = (() => {
    const h = fs.readFileSync(path.join(repo, "src", "shared", "version.h"), "utf8");
    return h.match(/VIRULE_CLIENT_VERSION_STRING\s+"([^"]+)"/)[1];
  })();
  console.log(`pre-suite against build ${buildVersion}`);
  await startServer();

  // A. startup check never blocks the bridge (dead manifest host).
  console.log("A. startup check does not block startup");
  await resetSandbox(BUILD_EXE);
  {
    const t0 = await startSandboxClient(["--self-manifest-url=http://127.0.0.1:1/manifest.json"], { waitHello: false });
    let helloAt = 0;
    for (let i = 0; i < 24; i++) {
      await sleep(250);
      try {
        const v = await helloVersion();
        if (v) { helloAt = Date.now() - t0; break; }
      } catch { /* not yet */ }
    }
    check("bridge answered promptly with the manifest host dead",
      helloAt > 0 && helloAt <= 3500, `${helloAt}ms`);
    await shutdownServingClient();
  }

  // B. installed == approved: no download, no restart.
  console.log("B. no update when installed == approved");
  await resetSandbox(BUILD_EXE);
  {
    served = { version: buildVersion, payload: fs.readFileSync(BUILD_EXE), delayMs: 0 };
    downloadCount = 0;
    check("client starts", await startSandboxClient([manifestArg()]));
    await sleep(6000);
    check("no payload download", downloadCount === 0, `${downloadCount}`);
    check("nothing staged", !fs.existsSync(STAGED_EXE) && !fs.existsSync(TXN_FILE));
    check("client still serving the same version", await helloVersion() === buildVersion);
    await shutdownServingClient();
  }

  // E. busy client defers the swap.
  console.log("E. busy client defers the actual swap (staging is fine)");
  await resetSandbox(BUILD_EXE);
  {
    // The manifest answer is delayed so the busy state below is always in
    // place before staging can complete (no race with the swap monitor).
    served = { version: "0.7.99", payload: fs.readFileSync(BUILD_EXE), delayMs: 6000 };
    check("client starts", await startSandboxClient([manifestArg(), "--dev-unsigned"]));
    // Make it busy FIRST: a page-driven QA redemption stamps qa activity,
    // which holds the safe point for 120s.
    const page = await connect();
    await page.next(1500);
    const token = crypto.randomBytes(24).toString("base64url").slice(0, 32);
    page.sendText(`{"type":"qa_accept","token":"${token}"}`);
    await page.next(2000);
    const staged = await waitFor(() => fs.existsSync(TXN_FILE) &&
      fs.readFileSync(TXN_FILE, "utf8").includes('"state":"verified"'), 30000);
    check("update staged and verified while busy", staged);
    await sleep(35000); // two swap-monitor attempts land in here
    check("swap deferred: same client still serving", await helloVersion() === buildVersion);
    check("staged update still waiting", fs.existsSync(STAGED_EXE));
    check("no helper started", countLog("replacement helper started") === 0);
    page.end();
    await shutdownServingClient();
  }

  // F. explicit uninstall wins over a staged update.
  console.log("F. uninstall latch discards the staged update");
  await resetSandbox(BUILD_EXE);
  const latchBefore = latchWasSet();
  try {
    served = { version: "0.7.99", payload: fs.readFileSync(BUILD_EXE), delayMs: 6000 };
    check("client starts", await startSandboxClient([manifestArg(), "--dev-unsigned"]));
    const page = await connect();
    await page.next(1500);
    const token = crypto.randomBytes(24).toString("base64url").slice(0, 32);
    page.sendText(`{"type":"qa_accept","token":"${token}"}`); // hold the swap
    await page.next(2000);
    const staged = await waitFor(() => fs.existsSync(STAGED_EXE), 30000);
    check("update staged", staged);
    setLatch();
    const discarded = await waitFor(() =>
      !fs.existsSync(STAGED_EXE) && !fs.existsSync(TXN_FILE), 25000);
    check("staged update discarded under the latch", discarded);
    check("no helper started", countLog("replacement helper started") === 0);
    check("client did not restart/replace itself", await helloVersion() === buildVersion);
    page.end();
    await shutdownServingClient();
  } finally {
    if (!latchBefore) clearLatch();
  }

  // G. swap failure: the live exe is locked; known-good client restored.
  console.log("G. swap failure restores the known-good client, no loop");
  await resetSandbox(BUILD_EXE);
  {
    // Delayed manifest: the lock below is guaranteed to be held before
    // staging can complete and the swap can start.
    served = { version: "0.7.98", payload: fs.readFileSync(BUILD_EXE), delayMs: 5000 };
    check("client starts", await startSandboxClient([manifestArg(), "--dev-unsigned"]));
    // Hold a read-share-only handle on the live exe: rename (DELETE) is
    // blocked, execution (read) still works.
    const locker = spawn("powershell", ["-NoProfile", "-Command",
      `$f=[IO.File]::Open('${TARGET_EXE.replace(/'/g, "''")}','Open','Read','Read'); Start-Sleep 120`],
      { stdio: "ignore" });
    await sleep(1500);
    const failed = await waitFor(() => fs.existsSync(TXN_FILE) &&
      fs.readFileSync(TXN_FILE, "utf8").includes('"state":"failed"'), 90000);
    check("swap failed and was recorded", failed);
    const back = await waitFor(async () => (await helloVersion().catch(() => null)) === buildVersion, 30000);
    check("known-good client restored and serving", back);
    check("staged binary cleaned", !fs.existsSync(STAGED_EXE));
    const helpers = countLog("replacement helper started");
    await sleep(20000);
    check("no helper respawn loop", countLog("replacement helper started") === helpers,
      `${countLog("replacement helper started")} vs ${helpers}`);
    try { locker.kill(); } catch {}
    await shutdownServingClient();
  }

  // H. the new client never becomes healthy: deterministic rollback.
  console.log("H. unhealthy new client rolls back to known-good");
  await resetSandbox(BUILD_EXE);
  {
    // The payload passes every stage gate but reports the WRONG version
    // once running (it is this very build), so the helper's takeover
    // confirmation fails and the rollback path runs end to end.
    served = { version: "9.9.9", payload: fs.readFileSync(BUILD_EXE), delayMs: 0 };
    check("client starts", await startSandboxClient([manifestArg(), "--dev-unsigned"]));
    const rolled = await waitFor(() => readLog().includes("rolling back"), 120000);
    check("helper detected the unhealthy takeover and rolled back", rolled);
    const back = await waitFor(async () => (await helloVersion().catch(() => null)) === buildVersion, 40000);
    check("known-good client restored and serving", back);
    const done = await waitFor(() => fs.existsSync(TXN_FILE) &&
      fs.readFileSync(TXN_FILE, "utf8").includes('"state":"failed"') &&
      !fs.existsSync(STAGED_EXE) && !fs.existsSync(OLD_EXE_FILE), 20000);
    const txnNow = fs.existsSync(TXN_FILE) ? fs.readFileSync(TXN_FILE, "utf8") : "MISSING";
    check("failed transaction recorded, residue cleaned", done,
      `txn=${txnNow} staged=${fs.existsSync(STAGED_EXE)} old=${fs.existsSync(OLD_EXE_FILE)}`);
    await sleep(20000);
    check("exactly one helper for the whole scenario (no loop)",
      countLog("replacement helper started") === 1,
      `${countLog("replacement helper started")}`);
    check("no re-download of the failed version",
      countLog("staged and verified") === 1, `${countLog("staged and verified")}`);
    await shutdownServingClient();
  }
}

// ---- the swap-suite (real old -> new binaries) ----

async function swapSuite() {
  const oldExe = argOf("old");
  const newExe = argOf("new");
  const newVer = argOf("newver");
  if (!oldExe || !newExe || !newVer) {
    console.error("swap suite needs --old=<exe> --new=<exe> --newver=<version>");
    process.exit(2);
  }
  await startServer();

  console.log("C/D. real self-update with a page connected through it");
  await resetSandbox(oldExe);
  served = { version: newVer, payload: fs.readFileSync(newExe), delayMs: 0 };
  check("old client starts", await startSandboxClient([manifestArg()]));
  const oldVersion = await helloVersion();
  console.log(`  old client serving ${oldVersion}; approved ${newVer}`);

  // D setup: a virule.app page stays connected across the swap.
  const page = await connect();
  await page.next(1500);
  const dropAt = { t: 0 };
  page.onClose(() => { dropAt.t = Date.now(); });

  // C: staged, swapped, new client serving the new version.
  const swapped = await waitFor(async () => {
    const v = await helloVersion().catch(() => null);
    return v === newVer;
  }, 120000, 500);
  check("new client serving the new version (no Setup involved)", swapped);

  // D: the page's disconnect-to-reconnectable gap fits the 5s hysteresis.
  check("page connection dropped exactly once (the restart)", dropAt.t > 0);
  let reconnectGap = -1;
  if (dropAt.t > 0) {
    const deadline = Date.now() + 8000;
    for (;;) {
      try {
        const p2 = await connect({ timeoutMs: 1500 });
        const hello = await p2.next(1500);
        p2.end();
        if (hello && hello.includes(`"version":"${newVer}"`)) {
          reconnectGap = Date.now() - dropAt.t;
          break;
        }
      } catch { /* not yet */ }
      if (Date.now() > deadline) break;
      await sleep(200);
    }
  }
  check("page could reconnect within the 5s hysteresis",
    reconnectGap >= 0 && reconnectGap <= 5000, `${reconnectGap}ms`);

  const clean = await waitFor(() =>
    !fs.existsSync(STAGED_EXE) && !fs.existsSync(OLD_EXE_FILE) && !fs.existsSync(TXN_FILE), 30000);
  check("update residue fully cleaned", clean);
  const state = fs.readFileSync(path.join(ROOT, "VIRULE", "client", "state.json"), "utf8");
  check("state.json installed_version healed to the new version",
    state.includes(`"installed_version":"${newVer}"`), state);
  check("old process exited", clientProc === null || clientProc.exitCode !== null);

  page.end();
  await shutdownServingClient();
}

async function main() {
  if (MODE === "pre") await preSuite();
  else if (MODE === "swap") await swapSuite();
  else { console.error(`unknown mode ${MODE}`); process.exit(2); }

  if (server) server.close();
  await freePort();
  for (let i = 0; i < 30; i++) {
    try { fs.rmSync(SANDBOX, { recursive: true, force: true }); break; }
    catch { await sleep(500); }
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("harness error:", e);
  clearLatch();
  process.exit(2);
});
