// VIRULE P2 update/relaunch crash-recovery matrix (audit H3 / M2 / M15,
// P2 pass 2026-09-04). Sandboxed like uninstall_lifecycle_test.mjs: every
// spawned client gets LOCALAPPDATA *and* TEMP pointed at throwaway
// directories, runs --no-register, and (new for this harness) uses the
// two admin-pipeline dev seams: --dev-unsigned (signature gates only) and
// --admin-manifest-url= (a local manifest server; grammar/size/hash gates
// hold exactly as in production).
//
//   A. VALIDATED Admin.previous startup recovery: Admin\ missing, a
//      structurally complete previous -> restored locally, installed
//      reported, no package download.
//   B. INVALID previous: an incomplete tree is NEVER promoted (and never
//      deleted at startup); Admin reads absent, repair/install remains.
//   C. PERSISTED launch-update failure hold: a seeded hold suppresses the
//      launch-context claim across a client restart; the 90s
//      claim-suppression window governs no-context callers; an expired
//      claim window frees Settings while the launch window still holds.
//   D. HOLD EXPIRY / NEW VERSION: an expired hold is cleared at startup
//      and the launch claim returns; a hold for X never blocks approved Y.
//   E2E. A genuinely FAILED launch handoff WRITES the hold (audit M2) and
//      exercises the bounded relaunch recovery (audit M15): one automatic
//      retry, then the client-owned Try again card; installation intact.
//   S. SUCCESS PATH: a completing update (local package server) clears
//      the hold and lands the new version (dev-seam pipeline E2E).
//   H. ADMIN REFUSES TO CLOSE during a requested update: truthful
//      admin_running result, nothing changed, no partial swap.
//
// Run: node tools/p2_recovery_test.mjs   (client build must exist)

import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import os from "node:os";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLIENT_EXE = path.join(repo, "build", "Release", "x64", "virule-client.exe");
const SANDBOX = path.join(os.tmpdir(), "virule-p2-test-sandbox");
const PORT = 47612;

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wsKey = () => crypto.randomBytes(16).toString("base64");
const nowS = () => Math.floor(Date.now() / 1000);

// ---- WebSocket plumbing (the proven client half) ----

function maskFrame(payload, { masked = true, opcode = 0x1 } = {}) {
  const data = Buffer.from(payload, "utf8");
  const head = [0x80 | opcode];
  if (data.length < 126) head.push((masked ? 0x80 : 0) | data.length);
  else head.push((masked ? 0x80 : 0) | 126, (data.length >> 8) & 0xff, data.length & 0xff);
  if (!masked) return Buffer.concat([Buffer.from(head), data]);
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

function connect({ origin = "https://virule.app", port = PORT, wsPath = "/v1" } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      const headers = [
        `GET ${wsPath} HTTP/1.1`,
        `Host: 127.0.0.1:${port}`,
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
      socket,
      get closed() { return closed; },
      sendText(payload) { socket.write(maskFrame(payload)); },
      next(timeoutMs = 5000) {
        return new Promise((res) => {
          if (queue.length) return res(queue.shift());
          const timer = setTimeout(() => res(null), timeoutMs);
          waiters.push((m) => { clearTimeout(timer); res(m); });
        });
      },
      waitClose(timeoutMs = 3000) {
        return new Promise((res) => {
          if (closed) return res(true);
          const timer = setTimeout(() => res(false), timeoutMs);
          socket.once("close", () => { clearTimeout(timer); res(true); });
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
        if (!head.startsWith("HTTP/1.1 101")) {
          socket.destroy();
          return reject(new Error("no upgrade: " + head.split("\r\n")[0]));
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
    socket.on("close", () => {
      closed = true;
      if (!upgraded) reject(new Error("closed before upgrade"));
    });
    socket.on("error", () => { closed = true; reject(new Error("refused")); });
    setTimeout(() => {
      if (!upgraded) { socket.destroy(); reject(new Error("upgrade timeout")); }
    }, 12000);
  });
}

// Request/response over a fresh local connection, skipping pushes.
async function localAsk(message, answerNeedle, timeoutMs = 8000) {
  const c = await connect({ origin: null });
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

// ---- sandboxed processes ----

function sandboxEnv(root) {
  const temp = path.join(root, "temp");
  fs.mkdirSync(temp, { recursive: true });
  return { ...process.env, LOCALAPPDATA: root, TEMP: temp, TMP: temp };
}

let clientProc = null;

async function freePort() {
  for (let i = 0; i < 10; i++) {
    try {
      const c = await connect({ origin: null });
      await c.next();
      c.sendText('{"type":"shutdown"}');
      await c.next(2000);
      c.end();
      await sleep(600);
    } catch { return; }
  }
}

async function startClient(root, { expectServe = true, manifestUrl = null } = {}) {
  await freePort();
  const args = ["--no-register", "--dev-unsigned"];
  if (manifestUrl) args.push(`--admin-manifest-url=${manifestUrl}`);
  clientProc = spawn(CLIENT_EXE, args, {
    env: sandboxEnv(root), stdio: "ignore", detached: false,
  });
  const tries = expectServe ? 40 : 12;
  for (let i = 0; i < tries; i++) {
    await sleep(250);
    try {
      const c = await connect({ origin: null });
      const hello = await c.next();
      if (hello && hello.includes('"virule_client":1')) { c.end(); return true; }
      c.end();
    } catch { /* not yet */ }
  }
  return false;
}

async function stopClient() {
  try {
    const c = await connect({ origin: null });
    await c.next();
    c.sendText('{"type":"shutdown"}');
    await c.next(2000);
    c.end();
  } catch { /* already gone */ }
  if (clientProc) {
    const proc = clientProc;
    clientProc = null;
    await new Promise((res) => {
      const t = setTimeout(() => { try { proc.kill(); } catch {} res(); }, 6000);
      proc.once("exit", () => { clearTimeout(t); res(); });
    });
  }
  await sleep(300);
}

async function waitFor(fn, timeoutMs, everyMs = 500) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (fn()) return true;
    if (Date.now() >= deadline) return false;
    await sleep(everyMs);
  }
}

// SANDBOX GUARD: never talk destructively to a client that is not this
// harness's sandbox client (marker = the synthetic installed version).
async function requireSandbox(marker, label) {
  const st = await localAsk('{"type":"status"}', '"type":"status"');
  if (!st || !st.includes(marker)) {
    console.error(`ABORT (${label}): not the sandbox client; status = ${st}`);
    throw new Error("sandbox guard tripped");
  }
}

function closeResultCard() {
  const ps = `
$sig = '[DllImport("user32.dll")] public static extern System.IntPtr FindWindowW(string c, string t);
[DllImport("user32.dll")] public static extern bool PostMessageW(System.IntPtr h, uint m, System.IntPtr w, System.IntPtr l);';
$u = Add-Type -MemberDefinition $sig -Name U -Namespace W -PassThru
$h = [W.U]::FindWindowW('ViruleClientResultWindow', $null)
if ($h -ne [System.IntPtr]::Zero) { [W.U]::PostMessageW($h, 0x0010, [System.IntPtr]::Zero, [System.IntPtr]::Zero) | Out-Null; 'closed' } else { 'none' }`;
  try {
    return execFileSync("powershell.exe",
      ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
      { stdio: "pipe" }).toString().trim();
  } catch { return "error"; }
}

// ---- fixtures ----

// The six components the pipeline requires (admin_install kRequiredSigned)
// plus the atomic install metadata.
const REQUIRED = [
  "virule.exe",
  ".resources/admin/ViruleAdminHost.exe",
  ".resources/bin/Win32/SidecarK32.dll",
  ".resources/bin/Win32/SidecarKHost.exe",
  ".resources/bin/x64/SidecarK64.dll",
  ".resources/bin/x64/SidecarKHost.exe",
];

function writeAdminTree(dir, version) {
  for (const rel of REQUIRED) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "stub-" + rel);
  }
  fs.writeFileSync(path.join(dir, "installed-release.json"),
    JSON.stringify({ version }));
}

function programsDir(root) { return path.join(root, "Programs", "VIRULE"); }
function adminDir(root) { return path.join(programsDir(root), "Admin"); }
function previousDir(root) { return path.join(programsDir(root), "Admin.previous"); }
function stateFile(root) { return path.join(root, "VIRULE", "client", "state.json"); }
function clientLog(root) {
  return path.join(root, "VIRULE", "client", "logs", "virule-client.log");
}
function readLog(root) {
  try { return fs.readFileSync(clientLog(root), "utf8"); } catch { return ""; }
}
function readState(root) {
  try { return JSON.parse(fs.readFileSync(stateFile(root), "utf8")); } catch { return null; }
}
function writeState(root, obj) {
  fs.mkdirSync(path.dirname(stateFile(root)), { recursive: true });
  fs.writeFileSync(stateFile(root), JSON.stringify(obj));
}
function baseState(extra = {}) {
  return {
    version: 1, created_dev_machine_cred: false, installed_version: "0.7.2",
    admin_version: "2.0.0-test", created_desktop_shortcut: false, ...extra,
  };
}

// One controllable manifest server; each scenario sets its response.
let manifestBody = null;
const manifestServer = http.createServer((req, res) => {
  if (req.url.startsWith("/admin-manifest.json") && manifestBody) {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(manifestBody));
  } else if (req.url.startsWith("/pkg.zip") && manifestServer.pkgBytes) {
    res.end(manifestServer.pkgBytes);
  } else { res.statusCode = 404; res.end(); }
});

async function main() {
  fs.rmSync(SANDBOX, { recursive: true, force: true });
  fs.mkdirSync(SANDBOX, { recursive: true });
  await new Promise((r) => manifestServer.listen(0, "127.0.0.1", r));
  const mport = manifestServer.address().port;
  const manifestUrl = `http://127.0.0.1:${mport}/admin-manifest.json`;
  // An https package URL nothing listens on: instant, offline download
  // failure (the failure scenarios never pull real bytes).
  const deadPackage = { version: "2.0.1-test",
    url: "https://127.0.0.1:9/pkg.zip",
    sha256: "0".repeat(64), size: 1000 };

  try {
    await freePort();

    console.log("A. validated Admin.previous restored at startup");
    {
      const root = path.join(SANDBOX, "a");
      writeAdminTree(previousDir(root), "2.0.0-test");
      fs.mkdirSync(path.join(programsDir(root), "Admin.staging"), { recursive: true });
      fs.writeFileSync(path.join(programsDir(root), "Admin.staging", "junk.txt"), "x");
      fs.writeFileSync(path.join(programsDir(root), "admin-download.zip"), "x");
      manifestBody = deadPackage; // keep even the quiet checks off the network
      check("client starts (A)", await startClient(root, { manifestUrl }));
      const st = await localAsk('{"type":"status"}', '"type":"status"');
      check("previous promoted to Admin",
        fs.existsSync(path.join(adminDir(root), "virule.exe")) &&
        !fs.existsSync(previousDir(root)));
      check("restored install reports installed + version",
        !!st && st.includes('"installed":true') && st.includes('"version":"2.0.0-test"'),
        st ?? "none");
      check("staging debris removed",
        !fs.existsSync(path.join(programsDir(root), "Admin.staging")));
      check("download debris removed",
        !fs.existsSync(path.join(programsDir(root), "admin-download.zip")));
      check("restore breadcrumb logged",
        readLog(root).includes("recovered known-good install from Admin.previous"));
      await stopClient();
    }

    console.log("B. invalid Admin.previous is NOT promoted (and not destroyed)");
    {
      const root = path.join(SANDBOX, "b");
      writeAdminTree(previousDir(root), "2.0.0-test");
      // Gut a required component: no longer a known-good installation.
      fs.rmSync(path.join(previousDir(root), ".resources", "admin",
        "ViruleAdminHost.exe"));
      check("client starts (B)", await startClient(root, { manifestUrl }));
      const st = await localAsk('{"type":"status"}', '"type":"status"');
      check("Admin reads absent (no junk promoted)",
        !!st && st.includes('"installed":false'), st ?? "none");
      check("invalid previous left in place (not deleted at startup)",
        fs.existsSync(path.join(previousDir(root), "virule.exe")));
      check("refusal breadcrumb logged",
        readLog(root).includes("Admin.previous NOT restored"));
      await stopClient();
    }

    console.log("C. persisted launch-update failure hold across restarts");
    {
      const root = path.join(SANDBOX, "c");
      writeAdminTree(adminDir(root), "2.0.0-test");
      manifestBody = deadPackage;
      const t = nowS();
      writeState(root, baseState({
        admin_hold_version: "2.0.1-test",
        admin_hold_failed_utc: t,
        admin_hold_until_utc: t + 6 * 3600,
      }));
      check("client starts (C1)", await startClient(root, { manifestUrl }));
      await requireSandbox('"version":"2.0.0-test"', "C");
      let r = await localAsk('{"type":"admin_update_check","context":"launch"}',
        "admin_update_status", 15000);
      check("launch-context claim suppressed by the hold",
        !!r && r.includes('"update":false') &&
        r.includes('"approved_version":"2.0.1-test"'), r ?? "none");
      r = await localAsk('{"type":"admin_update_check"}', "admin_update_status", 15000);
      check("no-context claim also suppressed inside the 90s window",
        !!r && r.includes('"update":false'), r ?? "none");
      await stopClient();

      check("client restarts (C2)", await startClient(root, { manifestUrl }));
      r = await localAsk('{"type":"admin_update_check","context":"launch"}',
        "admin_update_status", 15000);
      check("hold SURVIVES the client restart (audit M2)",
        !!r && r.includes('"update":false'), r ?? "none");
      await stopClient();

      // Past the 90s claim window, still inside the launch-retry window:
      // Settings-style callers see the update again, launches stay held.
      writeState(root, baseState({
        admin_hold_version: "2.0.1-test",
        admin_hold_failed_utc: nowS() - 600,
        admin_hold_until_utc: nowS() + 6 * 3600,
      }));
      check("client restarts (C3)", await startClient(root, { manifestUrl }));
      r = await localAsk('{"type":"admin_update_check"}', "admin_update_status", 15000);
      check("no-context claim returns after the 90s window",
        !!r && r.includes('"update":true'), r ?? "none");
      r = await localAsk('{"type":"admin_update_check","context":"launch"}',
        "admin_update_status", 15000);
      check("launch-context claim still held (retry-after)",
        !!r && r.includes('"update":false'), r ?? "none");
      await stopClient();
    }

    console.log("D. hold expiry and a newer approved version");
    {
      const root = path.join(SANDBOX, "d");
      writeAdminTree(adminDir(root), "2.0.0-test");
      manifestBody = deadPackage;
      writeState(root, baseState({
        admin_hold_version: "2.0.1-test",
        admin_hold_failed_utc: nowS() - 7200,
        admin_hold_until_utc: nowS() - 10,
      }));
      check("client starts (D1)", await startClient(root, { manifestUrl }));
      let r = await localAsk('{"type":"admin_update_check","context":"launch"}',
        "admin_update_status", 15000);
      check("expired hold frees the launch claim",
        !!r && r.includes('"update":true'), r ?? "none");
      check("expired hold cleared from state at startup",
        await waitFor(() => {
          const s = readState(root);
          return !!s && s.admin_hold_version === "";
        }, 5000));
      await stopClient();

      manifestBody = { ...deadPackage, version: "2.0.2-test" };
      writeState(root, baseState({
        admin_hold_version: "2.0.1-test",
        admin_hold_failed_utc: nowS(),
        admin_hold_until_utc: nowS() + 6 * 3600,
      }));
      check("client starts (D2)", await startClient(root, { manifestUrl }));
      r = await localAsk('{"type":"admin_update_check","context":"launch"}',
        "admin_update_status", 15000);
      check("a hold for X never blocks approved Y",
        !!r && r.includes('"update":true') &&
        r.includes('"approved_version":"2.0.2-test"'), r ?? "none");
      await stopClient();
    }

    console.log("E2E. failed launch handoff writes the hold + bounded relaunch recovery");
    {
      const root = path.join(SANDBOX, "e");
      writeAdminTree(adminDir(root), "2.0.0-test");
      manifestBody = deadPackage;
      check("client starts (E)", await startClient(root, { manifestUrl }));
      await requireSandbox('"version":"2.0.0-test"', "E");
      const ack = await localAsk('{"type":"admin_launch"}', "admin_launch_started");
      check("launch handoff accepted", !!ack, ack ?? "none");
      // The pipeline fails offline (dead package url); the hold must be
      // recorded, and the fallback relaunch of the stub virule.exe fails
      // -> one automatic retry -> the Try again card (audit M15).
      check("failure hold PERSISTED after the failed launch update (audit M2)",
        await waitFor(() => {
          const s = readState(root);
          return !!s && s.admin_hold_version === "2.0.1-test" &&
                 s.admin_hold_until_utc > nowS();
        }, 45000));
      check("relaunch watched + one automatic retry",
        await waitFor(() => readLog(root).includes("retrying once"), 20000));
      check("bounded recovery ends at the Try again card, not a loop",
        await waitFor(() => readLog(root).includes("recovery card shown (Try again)"),
          20000));
      await sleep(1500);
      const log = readLog(root);
      check("exactly one automatic retry (no retry loop)",
        (log.match(/retrying once/g) || []).length === 1);
      check("installation preserved (no re-download, tree intact)",
        fs.readFileSync(path.join(adminDir(root), "installed-release.json"), "utf8")
          .includes("2.0.0-test"));
      closeResultCard();
      await stopClient();
    }

    console.log("S. a completing update clears the hold (dev pipeline E2E)");
    {
      const root = path.join(SANDBOX, "s");
      writeAdminTree(adminDir(root), "2.0.0-test");
      // Build a real package zip carrying the required components.
      const stage = path.join(SANDBOX, "s-pkg");
      writeAdminTree(stage, "ignored"); // metadata is written by the pipeline
      fs.rmSync(path.join(stage, "installed-release.json"));
      const zipPath = path.join(SANDBOX, "s-pkg.zip");
      // .NET ZipFile, not Compress-Archive: PS 5.1's Compress-Archive
      // writes backslash entry names, which breaks zip directory
      // detection (real release packages carry spec-compliant names).
      execFileSync("powershell.exe", ["-NoProfile", "-Command",
        "Add-Type -AssemblyName System.IO.Compression.FileSystem; " +
        `[System.IO.Compression.ZipFile]::CreateFromDirectory('${stage}', '${zipPath}')`],
        { stdio: "pipe" });
      const pkgBytes = fs.readFileSync(zipPath);
      manifestServer.pkgBytes = pkgBytes;
      manifestBody = {
        version: "2.0.1-test",
        url: `http://127.0.0.1:${mport}/pkg.zip`,
        sha256: crypto.createHash("sha256").update(pkgBytes).digest("hex"),
        size: pkgBytes.length,
      };
      writeState(root, baseState({
        admin_hold_version: "2.0.1-test",
        admin_hold_failed_utc: nowS() - 600,
        admin_hold_until_utc: nowS() + 6 * 3600,
      }));
      check("client starts (S)", await startClient(root, { manifestUrl }));
      await requireSandbox('"version":"2.0.0-test"', "S");
      const page = await connect();
      await page.next();
      const started = await localAsk('{"type":"admin_install"}', "admin_install_started");
      check("update accepted", !!started, started ?? "none");
      let result = null;
      const deadline = Date.now() + 60000;
      for (;;) {
        const left = deadline - Date.now();
        if (left <= 0) break;
        const m = await page.next(left);
        if (m === null) break;
        if (m.includes('"admin_result"')) { result = m; break; }
      }
      check("update completed (updated push)",
        !!result && result.includes('"updated"'), result ?? "none");
      check("new version landed atomically",
        fs.readFileSync(path.join(adminDir(root), "installed-release.json"), "utf8")
          .includes("2.0.1-test"));
      check("success CLEARED the persisted hold",
        await waitFor(() => {
          const s = readState(root);
          return !!s && s.admin_hold_version === "";
        }, 10000));
      check("no residue (previous/staging/zip cleaned)",
        !fs.existsSync(previousDir(root)) &&
        !fs.existsSync(path.join(programsDir(root), "Admin.staging")) &&
        !fs.existsSync(path.join(programsDir(root), "admin-download.zip")));
      page.end();
      await stopClient();
      manifestServer.pkgBytes = null;
    }

    console.log("H. Admin refuses to close during a requested update: truthful, unchanged");
    {
      const root = path.join(SANDBOX, "h");
      writeAdminTree(adminDir(root), "2.0.0-test");
      // A windowless process out of the managed Admin dir: WM_CLOSE can
      // never reach it, so the graceful close times out.
      const lockerExe = path.join(adminDir(root), "locker.exe");
      fs.copyFileSync("C:\\Windows\\System32\\ping.exe", lockerExe);
      const locker = spawn(lockerExe, ["-n", "120", "127.0.0.1"],
        { stdio: "ignore", windowsHide: true });
      manifestBody = deadPackage;
      check("client starts (H)", await startClient(root, { manifestUrl }));
      await requireSandbox('"version":"2.0.0-test"', "H");
      const page = await connect();
      await page.next();
      const started = await localAsk('{"type":"admin_install"}', "admin_install_started");
      check("update accepted while Admin running", !!started, started ?? "none");
      let result = null;
      const deadline = Date.now() + 45000;
      for (;;) {
        const left = deadline - Date.now();
        if (left <= 0) break;
        const m = await page.next(left);
        if (m === null) break;
        if (m.includes('"admin_result"')) { result = m; break; }
      }
      check("truthful admin_running result (no misleading failure)",
        !!result && result.includes('"admin_running"'), result ?? "none");
      check("nothing changed (no partial swap)",
        fs.readFileSync(path.join(adminDir(root), "installed-release.json"), "utf8")
          .includes("2.0.0-test") && !fs.existsSync(previousDir(root)));
      const st = await localAsk('{"type":"status"}', '"type":"status"');
      check("transaction released (updating:false)",
        !!st && st.includes('"updating":false'), st ?? "none");
      page.end();
      try { locker.kill(); } catch {}
      await stopClient();
    }
  } finally {
    closeResultCard();
    await stopClient();
    manifestServer.close();
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
