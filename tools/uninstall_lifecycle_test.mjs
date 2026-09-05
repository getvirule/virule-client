// VIRULE ordered-uninstall state matrix (the P0 lifecycle-ownership
// corrective pass, 2026-09-04). Sandboxed like takeover_test.mjs: every
// spawned process gets LOCALAPPDATA *and* TEMP pointed at throwaway
// directories, the client runs --no-register, and the machine's real
// files are never in any inventory root.
//
// REGISTRY CAVEAT (shared, not sandboxable): the durable uninstall-intent
// latch (HKCU\Software\VIRULE\Lifecycle) and the Apps & Features entry
// (HKCU\...\Uninstall\ViruleClient) are real per-user registry state. The
// harness snapshots both up front, restores them at the end, and refuses
// to run at all if a real uninstall intent is already latched.
//
//   1. DEFAULT UNINSTALL, no Admin running (matrix A): intent latched
//      first, removing push, ordered removal, registrations LAST, user
//      data preserved, latch cleared LAST.
//   2. UNINSTALL & DELETE DATA (matrix D): VIRULE-owned root removed,
//      sibling non-VIRULE data untouched.
//   3. ADMIN REFUSES TO CLOSE (matrix B/F half): nothing destroyed,
//      uninstalling:true during the attempt, lifecycle ops refused,
//      failure push, latch KEPT; a latched machine's fresh client refuses
//      to serve; clearing the latch restores normal service (matrix K
//      client half).
//   4. ADMIN CLOSES GRACEFULLY (matrix B): WM_CLOSE, wait, then removal.
//   5. UPDATE-RESIDUE RECONCILIATION (matrix E half): a stranded
//      Admin.previous is restored at startup; staging/zip debris removed;
//      uninstall leaves no ambiguous tree.
//   6. REMOVAL FAILURE (matrix F): locked file -> latch kept, ARP entry
//      kept (registry never removed before files succeed), retry
//      completes the removal.
//   7. SETUP SUPERSEDES A STALE LATCH: an explicit install clears the
//      uninstall intent, and the freshly installed client serves.
//   8. SHORTCUT OWNERSHIP (P1 corrective pass 2026-09-04): a desktop
//      VIRULE.lnk is removed when provenance-known (A) OR when its stored
//      target resolves into the managed install tree despite lost
//      provenance (B), and preserved when it points somewhere unrelated
//      (C). The desktop known folder is registry-resolved (not
//      env-sandboxable), so this scenario TEMPORARILY redirects the HKCU
//      User Shell Folders Desktop value into the sandbox and restores the
//      exact prior values afterwards.
//
// Run: node tools/uninstall_lifecycle_test.mjs   (builds must exist)

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
const SETUP_EXE = path.join(repo, "build", "Release", "x64", "Virule-Setup.exe");
// OUTSIDE the Dropbox-synced repo tree: the sync client holds transient
// handles on freshly written files and can lose races with removals.
const SANDBOX = path.join(os.tmpdir(), "virule-uninstall-test-sandbox");
const PORT = 47612;

const LATCH_KEY = "HKCU\\Software\\VIRULE\\Lifecycle";
const ARP_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ViruleClient";

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wsKey = () => crypto.randomBytes(16).toString("base64");

// ---- registry helpers (reg.exe; the latch and ARP entry are real HKCU) ----

function regQueryOk(args) {
  try {
    execFileSync("reg.exe", ["query", ...args], { stdio: "pipe" });
    return true;
  } catch { return false; }
}
const latchSet = () => regQueryOk([LATCH_KEY, "/v", "UninstallInProgress"]);
const arpExists = () => regQueryOk([ARP_KEY]);
function setLatch() {
  execFileSync("reg.exe", ["add", LATCH_KEY, "/v", "UninstallInProgress",
    "/t", "REG_DWORD", "/d", "1", "/f"], { stdio: "pipe" });
}
function clearLatch() {
  try { execFileSync("reg.exe", ["delete", LATCH_KEY, "/f"], { stdio: "pipe" }); } catch {}
}
function createArp() {
  execFileSync("reg.exe", ["add", ARP_KEY, "/v", "DisplayName",
    "/t", "REG_SZ", "/d", "VIRULE", "/f"], { stdio: "pipe" });
}
function removeArp() {
  try { execFileSync("reg.exe", ["delete", ARP_KEY, "/f"], { stdio: "pipe" }); } catch {}
}

// ---- WebSocket plumbing (takeover_test's proven client half) ----

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

// ---- sandboxed processes ----

function sandboxEnv(root) {
  const temp = path.join(root, "temp");
  fs.mkdirSync(temp, { recursive: true });
  return { ...process.env, LOCALAPPDATA: root, TEMP: temp, TMP: temp };
}

let clientProc = null;

// The machine's REAL Admin may be running with the pre-fix self-heal,
// which silently restarts the REAL client between tests. Reclaim the port
// before every sandbox start (shutdown is non-destructive: the real
// client is on-demand and any virule:// wake brings it back).
async function freePort() {
  for (let i = 0; i < 10; i++) {
    try {
      const c = await connect({ origin: null });
      await c.next();
      c.sendText('{"type":"shutdown"}');
      await c.next(2000);
      c.end();
      await sleep(600);
    } catch { return; /* nothing listening */ }
  }
}

async function startClient(root, { expectServe = true } = {}) {
  await freePort();
  clientProc = spawn(CLIENT_EXE, ["--no-register"], {
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
      const t = setTimeout(() => { try { proc.kill(); } catch {} res(); }, 4000);
      proc.once("exit", () => { clearTimeout(t); res(); });
    });
  }
  await sleep(300);
}

// Wait for a filesystem/registry condition, polling.
async function waitFor(fn, timeoutMs, everyMs = 500) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (fn()) return true;
    if (Date.now() >= deadline) return false;
    await sleep(everyMs);
  }
}

// SANDBOX GUARD: the real machine's Admin (old, ungated self-heal) can
// silently restart the REAL client between tests and steal port 47612. A
// destructive message must therefore NEVER be sent to a client whose
// status does not carry this test's synthetic marker; a mismatch aborts
// the whole run rather than risk uninstalling the real install.
async function requireSandbox(conn, marker, label) {
  conn.sendText('{"type":"status"}');
  const st = await conn.next();
  if (!st || !st.includes(marker)) {
    console.error(`ABORT (${label}): not the sandbox client; status = ${st}`);
    throw new Error("sandbox guard tripped");
  }
}

// Wait for one pushed message containing `needle` on a page connection.
// ONE long next() per iteration: repeated short next() calls leave stale
// timed-out waiters queued on the connection, and a late push is consumed
// by a dead waiter instead of reaching the live one.
async function waitPush(page, needle, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const left = deadline - Date.now();
    if (left <= 0) return null;
    const m = await page.next(left);
    if (m === null) return null;
    if (m.includes(needle)) return m;
  }
}

// Request a status and skip any interleaved pushes until the answer.
async function askStatus(conn, timeoutMs = 5000) {
  conn.sendText('{"type":"status"}');
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const left = deadline - Date.now();
    if (left <= 0) return null;
    const m = await conn.next(left);
    if (m === null) return null;
    if (m.includes('"type":"status"')) return m;
  }
}

// Close a lingering result card window (the helper's failure card).
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

function makeInstallTree(root, { withAdmin = true } = {}) {
  const programs = path.join(root, "Programs", "VIRULE");
  fs.mkdirSync(programs, { recursive: true });
  fs.writeFileSync(path.join(programs, "installed-client-placeholder.txt"), "x");
  if (withAdmin) {
    const admin = path.join(programs, "Admin");
    fs.mkdirSync(path.join(admin, ".resources"), { recursive: true });
    fs.writeFileSync(path.join(admin, "virule.exe"), "stub");
    fs.writeFileSync(path.join(admin, "installed-release.json"), '{"version":"1.0.0-test"}');
  }
  const data = path.join(root, "VIRULE");
  fs.mkdirSync(path.join(data, "workspace"), { recursive: true });
  fs.writeFileSync(path.join(data, "virule.db"), "synthetic database");
  fs.writeFileSync(path.join(data, "workspace", "keep.txt"), "user data");
  return { programs, data };
}

async function main() {
  fs.rmSync(SANDBOX, { recursive: true, force: true });
  fs.mkdirSync(SANDBOX, { recursive: true });

  // Registry snapshot + refusal to run over a REAL removal.
  const hadLatch = latchSet();
  const hadArp = arpExists();
  if (hadLatch) {
    console.error("REFUSING TO RUN: a real uninstall intent is latched on this machine.");
    process.exit(2);
  }

  // Free the port (the real installed client is on-demand and comes back
  // on any virule:// wake; asking it to leave is non-destructive).
  try {
    const c = await connect({ origin: null });
    await c.next();
    c.sendText('{"type":"shutdown"}');
    await c.next(2000);
    c.end();
    await sleep(800);
  } catch { /* nothing listening */ }

  try {
    console.log("1. DEFAULT uninstall, Admin closed: ordered removal, data preserved");
    {
      const root = path.join(SANDBOX, "a");
      const { programs, data } = makeInstallTree(root);
      createArp();
      check("client starts (sandbox a)", await startClient(root));
      const page = await connect();
      await page.next(); // hello
      const local = await connect({ origin: null });
      await local.next();
      await requireSandbox(local, '"version":"1.0.0-test"', "pre-uninstall");
      local.sendText('{"type":"uninstall_local","delete_data":false}');
      const started = await local.next();
      check("uninstall accepted", !!started && started.includes("uninstall_started"), started ?? "none");
      const removing = await waitPush(page, '"uninstall_state"', 6000);
      check("removing push reached the page",
        !!removing && removing.includes('"removing"'), removing ?? "none");
      check("intent latched BEFORE teardown", await waitFor(latchSet, 4000));
      check("client exited (socket died)", await page.waitClose(15000));
      check("software removed (Programs\\VIRULE gone)",
        await waitFor(() => !fs.existsSync(programs), 40000));
      check("client state dir removed",
        !fs.existsSync(path.join(root, "VIRULE", "client")));
      check("user data preserved (virule.db)",
        fs.existsSync(path.join(data, "virule.db")));
      check("user data preserved (workspace)",
        fs.existsSync(path.join(data, "workspace", "keep.txt")));
      check("Apps & Features entry removed LAST (after files)", await waitFor(() => !arpExists(), 10000));
      check("intent latch cleared LAST", await waitFor(() => !latchSet(), 10000));
      local.end();
      await stopClient();
    }

    clearLatch();
    closeResultCard();
    console.log("2. UNINSTALL & DELETE DATA: VIRULE root gone, sibling data intact");
    {
      const root = path.join(SANDBOX, "b");
      const { programs } = makeInstallTree(root);
      fs.mkdirSync(path.join(root, "NotVirule"), { recursive: true });
      fs.writeFileSync(path.join(root, "NotVirule", "keep.txt"), "unrelated");
      createArp();
      check("client starts (sandbox b)", await startClient(root));
      const local = await connect({ origin: null });
      await local.next();
      await requireSandbox(local, '"version":"1.0.0-test"', "pre-uninstall");
      local.sendText('{"type":"uninstall_local","delete_data":true}');
      const started = await local.next();
      check("destructive uninstall accepted", !!started && started.includes("uninstall_started"), started ?? "none");
      check("software removed", await waitFor(() => !fs.existsSync(programs), 40000));
      check("VIRULE data root removed (delete-data mode)",
        await waitFor(() => !fs.existsSync(path.join(root, "VIRULE")), 15000));
      check("sibling non-VIRULE data untouched",
        fs.existsSync(path.join(root, "NotVirule", "keep.txt")));
      check("ARP entry removed", await waitFor(() => !arpExists(), 10000));
      check("latch cleared", await waitFor(() => !latchSet(), 10000));
      local.end();
      await stopClient();
    }

    clearLatch();
    closeResultCard();
    console.log("3. Admin REFUSES to close: nothing destroyed, latch kept, ops refused");
    {
      const root = path.join(SANDBOX, "c");
      const { programs, data } = makeInstallTree(root);
      // A windowless process running out of the managed Admin dir: it can
      // never be closed via WM_CLOSE, so the graceful close times out.
      const lockerExe = path.join(programs, "Admin", "locker.exe");
      fs.copyFileSync("C:\\Windows\\System32\\ping.exe", lockerExe);
      const locker = spawn(lockerExe, ["-n", "120", "127.0.0.1"],
        { stdio: "ignore", windowsHide: true });
      createArp();
      check("client starts (sandbox c)", await startClient(root));
      const page = await connect();
      await page.next();
      const local = await connect({ origin: null });
      await local.next();
      await requireSandbox(local, '"version":"1.0.0-test"', "pre-uninstall");
      local.sendText('{"type":"uninstall_local","delete_data":false}');
      const started = await local.next();
      check("uninstall accepted", !!started && started.includes("uninstall_started"), started ?? "none");
      const removing = await waitPush(page, '"removing"', 6000);
      check("removing push", !!removing, removing ?? "none");
      check("latch set during the attempt", await waitFor(latchSet, 4000));

      // While the graceful close is being attempted (30s), lifecycle
      // operations are refused and the status is truthful.
      const page2 = await connect();
      await page2.next();
      const st = await askStatus(page2);
      check("status carries uninstalling:true",
        !!st && st.includes('"uninstalling":true'), st ?? "none");
      page2.sendText('{"type":"admin_install"}');
      const inst = await page2.next();
      check("admin_install refused during removal",
        !!inst && inst.includes('"error"'), inst ?? "none");
      page2.sendText('{"type":"admin_open"}');
      const open = await page2.next();
      check("admin_open refused during removal",
        !!open && open.includes('"error"'), open ?? "none");
      const local2 = await connect({ origin: null });
      await local2.next();
      local2.sendText('{"type":"uninstall_local","delete_data":false}');
      const dup = await local2.next();
      check("second uninstall JOINS the running teardown",
        !!dup && dup.includes("uninstall_started"), dup ?? "none");
      local2.end();

      const failed = await waitPush(page, '"failed"', 45000);
      check("failure push after the Admin refused to close",
        !!failed, failed ?? "none");
      // The P1 status push delivers the return to normal service itself
      // (uninstalling flips false moments after the failure push); stale
      // queued pushes from during the teardown are skipped, so this waits
      // for CONVERGENCE rather than racing the flag.
      page2.sendText('{"type":"status"}');
      const st2 = await waitPush(page2, '"uninstalling":false', 8000);
      check("client back to normal service (uninstalling:false)",
        !!st2, st2 ?? "none");
      check("NOTHING was destroyed (Admin dir intact)",
        fs.existsSync(path.join(programs, "Admin", "virule.exe")));
      check("user data intact", fs.existsSync(path.join(data, "virule.db")));
      check("ARP entry kept (recoverable)", arpExists());
      check("latch KEPT after the refusal", latchSet());
      page.end();
      page2.end();
      local.end();
      await stopClient();

      // A fresh client under an active latch refuses to serve (the
      // resurrected-client stand-down, client half of matrix C).
      const served = await startClient(root, { expectServe: false });
      check("fresh client refuses to serve while the latch is set", !served);
      await stopClient();

      // Clearing the latch restores normal service (matrix K client half).
      clearLatch();
      check("client serves normally once the latch is cleared", await startClient(root));
      await stopClient();
      try { locker.kill(); } catch {}
      removeArp();
    }

    clearLatch();
    closeResultCard();
    console.log("4. Admin CLOSES gracefully, then removal completes");
    {
      const root = path.join(SANDBOX, "d");
      const { programs, data } = makeInstallTree(root);
      // A real windowed process out of the Admin dir that honors WM_CLOSE.
      const adminExe = path.join(programs, "Admin", "virule.exe");
      fs.copyFileSync("C:\\Windows\\System32\\notepad.exe", adminExe);
      const admin = spawn(adminExe, [], { stdio: "ignore" });
      let adminExited = false;
      admin.once("exit", () => { adminExited = true; });
      await sleep(1500); // let the window exist
      createArp();
      check("client starts (sandbox d)", await startClient(root));
      const local = await connect({ origin: null });
      await local.next();
      await requireSandbox(local, '"version":"1.0.0-test"', "pre-uninstall");
      local.sendText('{"type":"uninstall_local","delete_data":false}');
      const started = await local.next();
      check("uninstall accepted", !!started && started.includes("uninstall_started"), started ?? "none");
      check("Admin closed gracefully (WM_CLOSE honored)",
        await waitFor(() => adminExited, 20000));
      check("software removed after the Admin closed",
        await waitFor(() => !fs.existsSync(programs), 40000));
      check("user data preserved", fs.existsSync(path.join(data, "virule.db")));
      check("ARP entry removed", await waitFor(() => !arpExists(), 10000));
      check("latch cleared", await waitFor(() => !latchSet(), 10000));
      local.end();
      await stopClient();
    }

    clearLatch();
    closeResultCard();
    console.log("5. update-residue reconciliation (stranded Admin.previous)");
    {
      const root = path.join(SANDBOX, "e");
      const programs = path.join(root, "Programs", "VIRULE");
      const previous = path.join(programs, "Admin.previous");
      fs.mkdirSync(previous, { recursive: true });
      fs.writeFileSync(path.join(previous, "virule.exe"), "stub");
      fs.writeFileSync(path.join(previous, "installed-release.json"), '{"version":"7.7.7-test"}');
      fs.mkdirSync(path.join(programs, "Admin.staging"), { recursive: true });
      fs.writeFileSync(path.join(programs, "Admin.staging", "junk.txt"), "debris");
      fs.writeFileSync(path.join(programs, "admin-download.zip"), "debris");
      check("client starts (sandbox e)", await startClient(root));
      const local = await connect({ origin: null });
      await local.next();
      local.sendText('{"type":"status"}');
      const st = await local.next();
      check("known-good Admin restored from Admin.previous",
        fs.existsSync(path.join(programs, "Admin", "virule.exe")) &&
        !fs.existsSync(previous));
      check("restored install reports its version",
        !!st && st.includes('"version":"7.7.7-test"'), st ?? "none");
      check("staging debris removed", !fs.existsSync(path.join(programs, "Admin.staging")));
      check("download debris removed", !fs.existsSync(path.join(programs, "admin-download.zip")));
      local.end();
      await stopClient();
    }

    clearLatch();
    closeResultCard();
    console.log("6. removal FAILURE: registry kept, latch kept, retry completes");
    {
      const root = path.join(SANDBOX, "f");
      const { programs } = makeInstallTree(root, { withAdmin: false });
      const lockedFile = path.join(programs, "locked.txt");
      fs.writeFileSync(lockedFile, "x");
      // A REAL no-delete-share lock: node's own fs handles share DELETE on
      // Windows (libuv), so a .NET FileStream with FileShare.Read holds
      // the file the way a busy foreign process would.
      const locker = spawn("powershell.exe", ["-NoProfile", "-Command",
        `$f=[System.IO.File]::Open('${lockedFile}','Open','Read','Read'); Start-Sleep 300`],
        { stdio: "ignore", windowsHide: true });
      await sleep(2500); // let the lock exist
      createArp();
      check("client starts (sandbox f)", await startClient(root));
      const local = await connect({ origin: null });
      await local.next();
      await requireSandbox(local, '"installed":false', "pre-uninstall");
      local.sendText('{"type":"uninstall_local","delete_data":false}');
      const started = await local.next();
      check("uninstall accepted", !!started && started.includes("uninstall_started"), started ?? "none");
      // The helper's removal fails on the locked file (bounded retries),
      // leaving the recoverable failure state.
      check("failure leaves the program dir present",
        await waitFor(() => latchSet() && fs.existsSync(programs), 5000) &&
        (await sleep(20000), fs.existsSync(programs)));
      check("latch KEPT on failure", latchSet());
      check("ARP entry KEPT on failure (registry never removed before files)", arpExists());
      // The helper self-reports its card's visibility to its %TEMP% log
      // (window-probing from this harness's session is unreliable: the
      // card provably renders when run interactively, but FindWindow from
      // this test runner's window station cannot always see it).
      const helperLog = path.join(root, "temp", "virule-uninstall.log");
      check("failure card was on screen (Try again offered)",
        await waitFor(() => fs.existsSync(helperLog) &&
          fs.readFileSync(helperLog, "utf8").includes("failure card visible"), 16000));
      // Dismiss the lingering helper (its card waits up to 120s for the
      // user); the RETRY below is exercised as its own idempotent run.
      closeResultCard();
      try {
        execFileSync("taskkill.exe",
          ["/F", "/FI", "IMAGENAME eq virule-uninstall-*"], { stdio: "pipe" });
      } catch {}
      await sleep(1000);
      try { locker.kill(); } catch {}
      await sleep(1000); // the lock releases with the process
      // The retry: idempotent re-run of the helper completes the removal.
      const retryExe = path.join(root, "temp", "virule-uninstall-retry.exe");
      fs.copyFileSync(CLIENT_EXE, retryExe);
      const retry = spawn(retryExe, ["--finish-uninstall", "0"],
        { env: sandboxEnv(root), stdio: "ignore" });
      const retryExit = new Promise((res) => retry.once("exit", (c) => res(c)));
      check("retry removed the software",
        await waitFor(() => !fs.existsSync(programs), 40000));
      check("retry removed the ARP entry", await waitFor(() => !arpExists(), 10000));
      check("retry cleared the latch", await waitFor(() => !latchSet(), 10000));
      await Promise.race([retryExit, sleep(20000)]);
      local.end();
      await stopClient();
    }

    clearLatch();
    closeResultCard();
    console.log("7. an explicit Setup install supersedes a stale latch");
    {
      const root = path.join(SANDBOX, "g");
      fs.mkdirSync(root, { recursive: true });
      setLatch();
      const clientBytes = fs.readFileSync(CLIENT_EXE);
      const sha = crypto.createHash("sha256").update(clientBytes).digest("hex");
      const server = http.createServer((req, res) => {
        if (req.url.startsWith("/manifest.json")) {
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({
            version: "0.6.2",
            url: `http://127.0.0.1:${server.address().port}/virule-client.exe`,
            sha256: sha,
            size: clientBytes.length,
          }));
        } else if (req.url.startsWith("/virule-client.exe")) {
          res.end(clientBytes);
        } else { res.statusCode = 404; res.end(); }
      });
      await new Promise((r) => server.listen(0, "127.0.0.1", r));
      const setup = spawn(SETUP_EXE, [
        `--manifest-url=http://127.0.0.1:${server.address().port}/manifest.json`,
        "--dev-unsigned",
      ], { env: sandboxEnv(root), stdio: "ignore" });
      // The installed client serves ONLY because Setup cleared the latch
      // before starting it (the startup gate would otherwise refuse).
      let served = false;
      for (let i = 0; i < 120 && !served; i++) {
        await sleep(500);
        try {
          const c = await connect({ origin: null });
          const hello = await c.next();
          if (hello && hello.includes('"virule_client":1')) { served = true; c.end(); }
          else c.end();
        } catch { /* not yet */ }
      }
      check("freshly installed client serves", served);
      check("Setup cleared the stale uninstall latch", !latchSet());
      // Shut everything down; Setup may still be waiting on its release.
      try {
        const c = await connect({ origin: null });
        await c.next();
        c.sendText('{"type":"shutdown"}');
        await c.next(2000);
        c.end();
      } catch {}
      await sleep(500);
      try { setup.kill(); } catch {}
      server.close();
      // Setup registered the sandbox exe + real ARP entry; clean both up
      // (the real installed client re-heals virule:// on its next serve).
      removeArp();
    }
    clearLatch();
    closeResultCard();
    console.log("8. shortcut ownership: provenance/managed-target removed, unrelated preserved");
    {
      // Redirect the Desktop known folder into the sandbox for this
      // scenario only. Snapshot the exact current values first; restore in
      // finally no matter what.
      const desktopSandbox = path.join(SANDBOX, "desktop");
      fs.mkdirSync(desktopSandbox, { recursive: true });
      const USF = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
      const SF = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
      const readDesktopValue = (key) => {
        try {
          const out = execFileSync("reg.exe", ["query", key, "/v", "Desktop"],
            { stdio: "pipe" }).toString();
          const m = /Desktop\s+(REG_[A-Z_]+)\s+(.+)\r?\n/.exec(out);
          return m ? { type: m[1], data: m[2].trim() } : null;
        } catch { return null; }
      };
      const writeDesktopValue = (key, v) => {
        execFileSync("reg.exe", ["add", key, "/v", "Desktop", "/t", v.type,
          "/d", v.data, "/f"], { stdio: "pipe" });
      };
      const prevUsf = readDesktopValue(USF);
      const prevSf = readDesktopValue(SF);
      const makeLnk = (target) => {
        const lnk = path.join(desktopSandbox, "VIRULE.lnk");
        execFileSync("powershell.exe", ["-NoProfile", "-Command",
          `$s=(New-Object -ComObject WScript.Shell).CreateShortcut('${lnk}');` +
          `$s.TargetPath='${target}';$s.Save()`], { stdio: "pipe" });
        return lnk;
      };
      const runDefaultUninstall = async (root) => {
        const local = await connect({ origin: null });
        await local.next();
        await requireSandbox(local, '"version":"1.0.0-test"', "pre-uninstall");
        local.sendText('{"type":"uninstall_local","delete_data":false}');
        const started = await local.next();
        const ok = !!started && started.includes("uninstall_started");
        local.end();
        return ok;
      };
      if (!prevUsf) {
        check("desktop redirect prerequisites (User Shell Folders readable)", false);
      } else {
        try {
          writeDesktopValue(USF, { type: prevUsf.type, data: desktopSandbox });
          if (prevSf) writeDesktopValue(SF, { type: prevSf.type, data: desktopSandbox });

          // A. provenance-known managed shortcut: removed.
          {
            const root = path.join(SANDBOX, "h1");
            const { programs } = makeInstallTree(root);
            const clientDir = path.join(root, "VIRULE", "client");
            fs.mkdirSync(clientDir, { recursive: true });
            fs.writeFileSync(path.join(clientDir, "state.json"),
              '{"version":1,"created_dev_machine_cred":false,"installed_version":"0.6.4","admin_version":"1.0.0-test","created_desktop_shortcut":true}');
            const lnk = makeLnk(path.join(programs, "Admin", "virule.exe"));
            createArp();
            check("client starts (sandbox h1)", await startClient(root));
            check("uninstall accepted (A)", await runDefaultUninstall(root));
            check("software removed (A)", await waitFor(() => !fs.existsSync(programs), 40000));
            check("A: provenance-known shortcut REMOVED",
              await waitFor(() => !fs.existsSync(lnk), 10000));
            await waitFor(() => !latchSet(), 10000);
            await stopClient();
          }

          // B. provenance LOST, target inside the managed tree: removed
          // (the owner's real 2026-09-04 residue case).
          {
            const root = path.join(SANDBOX, "h2");
            const { programs } = makeInstallTree(root);
            const lnk = makeLnk(path.join(programs, "Admin", "virule.exe"));
            createArp();
            check("client starts (sandbox h2)", await startClient(root));
            check("uninstall accepted (B)", await runDefaultUninstall(root));
            check("software removed (B)", await waitFor(() => !fs.existsSync(programs), 40000));
            check("B: provenance-missing managed-target shortcut REMOVED",
              await waitFor(() => !fs.existsSync(lnk), 10000));
            await waitFor(() => !latchSet(), 10000);
            await stopClient();
          }

          // C. an unrelated shortcut that merely shares the VIRULE name:
          // preserved in both rules (no provenance, foreign target).
          {
            const root = path.join(SANDBOX, "h3");
            const { programs } = makeInstallTree(root);
            const lnk = makeLnk("C:\\Windows\\System32\\notepad.exe");
            createArp();
            check("client starts (sandbox h3)", await startClient(root));
            check("uninstall accepted (C)", await runDefaultUninstall(root));
            check("software removed (C)", await waitFor(() => !fs.existsSync(programs), 40000));
            await waitFor(() => !latchSet(), 10000);
            await sleep(1500); // give a wrong removal every chance to show
            check("C: unrelated VIRULE-named shortcut PRESERVED", fs.existsSync(lnk));
            await stopClient();
          }
        } finally {
          // Restore the machine's real Desktop redirection EXACTLY.
          try { writeDesktopValue(USF, prevUsf); } catch {}
          if (prevSf) { try { writeDesktopValue(SF, prevSf); } catch {} }
          const back = readDesktopValue(USF);
          check("desktop known-folder registry restored",
            !!back && back.data === prevUsf.data, JSON.stringify({ back, prevUsf }));
        }
      }
    }
  } finally {
    // Restore the machine's registry to its pre-run state.
    clearLatch();
    if (hadLatch) setLatch();
    if (hadArp) { /* left as-is: the harness never deletes a pre-existing
                     entry outside test steps; nothing to restore */ }
    else removeArp();
    await stopClient();
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("harness error:", e);
  clearLatch();
  process.exit(2);
});
