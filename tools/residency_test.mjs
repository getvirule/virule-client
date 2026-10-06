// CORE SERVICES RESIDENCY tests (2026-10-06): virule-client.exe ("VIRULE
// Core Services") and ViruleService.exe ("VIRULE Service") keep one another
// resident (src/shared/residency.hpp). Sandboxed like the other client
// harnesses: LOCALAPPDATA and TEMP point at a throwaway tree under %TEMP%,
// both binaries are copied in AS the sandbox's managed install
// (Programs\VIRULE\), the client runs --no-register, and a local manifest
// server stands in for the GitHub release (--self-manifest-url, which the
// residency layer forwards between the two processes; --dev-unsigned waives
// only the signature gates).
//
// WHAT IS NOT SANDBOXABLE, and how it is handled:
//   - Local\ named kernel objects are per SESSION: the machine's real client
//     holds Local\ViruleClient.Singleton, so it is asked to leave first (a
//     non-destructive shutdown) and is started again at the end.
//   - The uninstall-intent latch (HKCU\Software\VIRULE\Lifecycle) and the
//     Apps & Features entry (HKCU\...\Uninstall\ViruleClient) are real HKCU:
//     the run refuses to start over a real latch, exports the ARP entry
//     first and imports it back at the end (the sandboxed uninstall removes
//     that key unconditionally, by design).
//
// Scenarios (the owner's list, 2026-10-06):
//    1 service alone -> exactly one Core Services
//    2 Core Services alone -> exactly one service
//    3 kill Core Services -> the service restores it
//    4 kill the service -> Core Services restores it
//    5 simultaneous start of several of each -> one of each
//    6 a second service exits harmlessly
//    7 a second client launch forwards and exits (existing singleton)
//    8 uninstall latch -> neither resurrects the other
//    9 Core Services self-update (real swap + rollback) -> the service stands down
//   10 service update (real, through the client) -> no recovery fight
//   11 Setup replacement (real Virule-Setup) -> no recovery fight
//   12 maintenance finishes -> residency resumes
//   13 Core Services that dies at once -> bounded backoff, no storm
//   14 a service that dies at once -> bounded backoff, no storm
//   15 login-style start race -> one of each
//   16 full uninstall -> both binaries gone, the service stood down
//   17 install / repair -> both managed artifacts restored
//
// Run: node tools/residency_test.mjs   (Release x64 builds must exist)

import net from "node:net";
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BUILD = path.join(repo, "build", "Release", "x64");
const BUILD_CLIENT = path.join(BUILD, "virule-client.exe");
const BUILD_SERVICE = path.join(BUILD, "ViruleService.exe");
const BUILD_SETUP = path.join(BUILD, "Virule-Setup.exe");
const SANDBOX = path.join(os.tmpdir(), "virule-residency-test-sandbox");
const ROOT = path.join(SANDBOX, "root");
const INSTALL = path.join(ROOT, "Programs", "VIRULE");
const CLIENT = path.join(INSTALL, "virule-client.exe");
const SERVICE = path.join(INSTALL, "ViruleService.exe");
const LOGS = path.join(ROOT, "VIRULE", "client", "logs");
const SERVICE_LOG = path.join(LOGS, "virule-service.log");
const CLIENT_LOG = path.join(LOGS, "virule-client.log");
const PORT = 47612;
const LATCH_KEY = "HKCU\\Software\\VIRULE\\Lifecycle";
const ARP_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ViruleClient";
const REAL_CLIENT = path.join(process.env.LOCALAPPDATA, "Programs", "VIRULE", "virule-client.exe");

const ONLY = (process.argv.find((a) => a.startsWith("--only=")) || "").slice(7)
  .split(",").filter(Boolean).map(Number);
const want = (n) => ONLY.length === 0 || ONLY.includes(n);

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeoutMs, everyMs = 500) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() >= deadline) return false;
    await sleep(everyMs);
  }
}

// ---- PowerShell plumbing ----

function ps(script) {
  return execFileSync("powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
    { stdio: ["ignore", "pipe", "pipe"] }).toString();
}

// The sandbox's resident processes, by FULL image path (never by name alone).
function procs() {
  const out = ps(`Get-CimInstance Win32_Process -Filter "Name='virule-client.exe' OR Name='ViruleService.exe'" | ForEach-Object { '{0}|{1}' -f $_.ProcessId, $_.ExecutablePath }`);
  const r = { client: [], service: [] };
  for (const line of out.split(/\r?\n/)) {
    const [pid, exe] = line.split("|");
    if (!pid || !exe) continue;
    const e = exe.toLowerCase();
    if (e === CLIENT.toLowerCase()) r.client.push(Number(pid));
    if (e === SERVICE.toLowerCase()) r.service.push(Number(pid));
  }
  return r;
}
const counts = () => { const p = procs(); return `${p.client.length} client / ${p.service.length} service`; };
const exactlyOneEach = () => { const p = procs(); return p.client.length === 1 && p.service.length === 1; };

function setNamedEvent(name) {
  try { ps(`[System.Threading.EventWaitHandle]::OpenExisting('${name}').Set() | Out-Null; 'ok'`); return true; }
  catch { return false; }
}

// A process that HOLDS the residency maintenance mutex until it is killed
// (killing it abandons the mutex, exactly like a crashed maintainer).
async function holdMaintenance() {
  const child = spawn("powershell.exe", ["-NoProfile", "-Command",
    "$m = New-Object System.Threading.Mutex($false, 'Local\\VIRULE.Residency.Maintenance'); " +
    "try { [void]$m.WaitOne() } catch [System.Threading.AbandonedMutexException] { } ; " +
    "[Console]::Out.WriteLine('HELD'); [Console]::Out.Flush(); Start-Sleep -Seconds 900"],
    { stdio: ["ignore", "pipe", "ignore"] });
  await new Promise((res) => {
    const t = setTimeout(res, 15000);
    child.stdout.on("data", (d) => { if (d.toString().includes("HELD")) { clearTimeout(t); res(); } });
  });
  return { release: async () => { try { child.kill(); } catch {} await sleep(500); } };
}

// ---- registry (reg.exe; real HKCU) ----

function regOk(args) {
  try { execFileSync("reg.exe", args, { stdio: "pipe" }); return true; } catch { return false; }
}
const latchSet = () => regOk(["query", LATCH_KEY, "/v", "UninstallInProgress"]);
const setLatch = () => regOk(["add", LATCH_KEY, "/v", "UninstallInProgress", "/t", "REG_DWORD", "/d", "1", "/f"]);
const clearLatch = () => regOk(["delete", LATCH_KEY, "/f"]);

// ---- bridge (minimal local control connection) ----

function maskFrame(payload) {
  const data = Buffer.from(payload, "utf8");
  const head = [0x81, 0x80 | data.length];
  const mask = crypto.randomBytes(4);
  const body = Buffer.from(data);
  for (let i = 0; i < body.length; i++) body[i] ^= mask[i & 3];
  return Buffer.concat([Buffer.from(head), mask, body]);
}

function localSend(message, waitMs = 3000) {
  return new Promise((resolve) => {
    const socket = net.connect(PORT, "127.0.0.1", () => {
      socket.write([`GET /v1 HTTP/1.1`, `Host: 127.0.0.1:${PORT}`, "Upgrade: websocket",
        "Connection: Upgrade", `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString("base64")}`,
        "Sec-WebSocket-Version: 13"].join("\r\n") + "\r\n\r\n");
    });
    let buf = "";
    let sent = false;
    const done = (v) => { try { socket.destroy(); } catch {} resolve(v); };
    socket.on("data", (d) => {
      buf += d.toString("latin1");
      if (!sent && buf.includes("virule_client")) { sent = true; socket.write(maskFrame(message)); }
    });
    // A client that answers and then leaves (uninstall) closes the socket:
    // what arrived before that is the answer.
    socket.on("error", () => done(sent ? buf : null));
    socket.on("close", () => done(sent ? buf : null));
    setTimeout(() => done(sent ? buf : null), waitMs);
  });
}
const bridgeUp = async () => (await localSend('{"type":"status"}', 1500)) !== null;
async function bridgeVersion() {
  const r = await localSend('{"type":"status"}', 2000);
  const m = r && r.match(/"version":"([^"]+)"/);
  return m ? m[1] : null;
}

// ---- the sandbox ----

function sandboxEnv() {
  const temp = path.join(ROOT, "temp");
  fs.mkdirSync(temp, { recursive: true });
  return { ...process.env, LOCALAPPDATA: ROOT, TEMP: temp, TMP: temp };
}

let manifestUrl = "";
const SEAMS = () => ["--no-register", "--dev-unsigned", `--self-manifest-url=${manifestUrl}`];

function launch(exe, args = []) {
  const p = spawn(exe, args, { env: sandboxEnv(), detached: true, stdio: "ignore" });
  p.unref();
  return p;
}
const startClient = (extra = []) => launch(CLIENT, [...SEAMS(), ...extra]);
const startService = () => launch(SERVICE, SEAMS());

function killPid(pid) { try { process.kill(pid); } catch {} }

// Stop everything resident in the sandbox without either side restoring the
// other: hold maintenance, kill, release.
async function resetWorld() {
  const m = await holdMaintenance();
  for (let i = 0; i < 3; i++) {
    const p = procs();
    for (const pid of [...p.client, ...p.service]) killPid(pid);
    if (await waitFor(() => { const q = procs(); return q.client.length + q.service.length === 0; }, 5000)) break;
  }
  await m.release();
  await sleep(1500);
}

function copyFresh(src, dst) {
  for (let i = 0; i < 20; i++) {
    try { fs.copyFileSync(src, dst); return; } catch { execFileSync("cmd.exe", ["/c", "ping -n 2 127.0.0.1 >nul"]); }
  }
  fs.copyFileSync(src, dst);
}

function installBinaries() {
  fs.mkdirSync(INSTALL, { recursive: true });
  copyFresh(BUILD_CLIENT, CLIENT);
  copyFresh(BUILD_SERVICE, SERVICE);
}

const logText = (f) => { try { return fs.readFileSync(f, "utf8"); } catch { return ""; } };
const countLines = (f, needle) => logText(f).split(/\r?\n/).filter((l) => l.includes(needle)).length;
const sha256 = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");

// ---- the local release server (manifest + assets) ----

const served = { manifest: "", files: {} };
function startServer() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const name = req.url.split("?")[0].replace(/^\//, "");
      if (name === "manifest.json") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(served.manifest);
      }
      if (served.files[name]) {
        res.writeHead(200, { "Content-Type": "application/octet-stream" });
        return res.end(served.files[name]);
      }
      res.writeHead(404); res.end();
    });
    srv.listen(0, "127.0.0.1", () => resolve(srv));
  });
}
function serveRelease(base, { version, client, service }) {
  served.files = {};
  let m = `{"version":"${version}"`;
  if (client) {
    served.files["virule-client.exe"] = client;
    m += `,"url":"${base}/virule-client.exe","sha256":"${crypto.createHash("sha256").update(client).digest("hex")}","size":${client.length}`;
  }
  if (service) {
    served.files["ViruleService.exe"] = service;
    m += `,"service_url":"${base}/ViruleService.exe","service_sha256":"${crypto.createHash("sha256").update(service).digest("hex")}","service_size":${service.length}`;
  }
  served.manifest = m + "}";
}

// Close any lingering native lifecycle card the sandboxed processes showed.
function closeCards() {
  try {
    ps(`$sig = '[DllImport("user32.dll")] public static extern System.IntPtr FindWindowW(string c, string t);
[DllImport("user32.dll")] public static extern bool PostMessageW(System.IntPtr h, uint m, System.IntPtr w, System.IntPtr l);'
$u = Add-Type -MemberDefinition $sig -Name U -Namespace W -PassThru
foreach ($i in 1..5) { $h = [W.U]::FindWindowW('ViruleClientResultWindow', $null); if ($h -eq [System.IntPtr]::Zero) { break }; [W.U]::PostMessageW($h, 0x0010, [System.IntPtr]::Zero, [System.IntPtr]::Zero) | Out-Null; Start-Sleep -Milliseconds 300 }`);
  } catch {}
}

async function main() {
  for (const f of [BUILD_CLIENT, BUILD_SERVICE, BUILD_SETUP]) {
    if (!fs.existsSync(f)) { console.error(`missing build: ${f}`); process.exit(2); }
  }
  if (latchSet()) {
    console.error("REFUSING TO RUN: a real uninstall intent is latched on this machine.");
    process.exit(2);
  }
  const arpBackup = path.join(os.tmpdir(), `virule-residency-arp-${Date.now()}.reg`);
  const hadArp = regOk(["export", ARP_KEY, arpBackup, "/y"]);

  // The machine's real client holds the session's client singleton: ask it
  // to leave (non-destructive) and remember to bring it back.
  const realWasRunning = await bridgeUp();
  for (let i = 0; i < 10 && (await bridgeUp()); i++) {
    await localSend('{"type":"shutdown"}', 1500);
    await sleep(800);
  }

  fs.rmSync(SANDBOX, { recursive: true, force: true });
  fs.mkdirSync(ROOT, { recursive: true });
  const server = await startServer();
  const base = `http://127.0.0.1:${server.address().port}`;
  manifestUrl = `${base}/manifest.json`;
  const clientBytes = fs.readFileSync(BUILD_CLIENT);
  const serviceBytes = fs.readFileSync(BUILD_SERVICE);
  const clientVersion = (fs.readFileSync(path.join(repo, "src", "shared", "version.h"), "utf8")
    .match(/VIRULE_CLIENT_VERSION_STRING\s+"([^"]+)"/) || [])[1];
  // The release this client IS, with its own service: nothing to update.
  serveRelease(base, { version: clientVersion, client: clientBytes, service: serviceBytes });

  try {
    installBinaries();

    if (want(1)) {
      console.log("1. VIRULE Service alone -> exactly one Core Services");
      await resetWorld();
      startService();
      check("Core Services appeared", await waitFor(() => procs().client.length === 1, 20000), counts());
      check("bridge answers", await waitFor(bridgeUp, 10000));
      await sleep(4000);
      check("exactly one of each, stable", exactlyOneEach(), counts());
    }

    if (want(2)) {
      console.log("2. Core Services alone -> exactly one VIRULE Service");
      await resetWorld();
      startClient();
      check("VIRULE Service appeared", await waitFor(() => procs().service.length === 1, 20000), counts());
      await sleep(4000);
      check("exactly one of each, stable", exactlyOneEach(), counts());
    }

    if (want(3)) {
      console.log("3. kill Core Services -> the service restores it");
      if (!exactlyOneEach()) { await resetWorld(); startClient(); await waitFor(exactlyOneEach, 20000); }
      const before = procs();
      killPid(before.client[0]);
      check("Core Services restored with a new pid",
        await waitFor(() => { const p = procs(); return p.client.length === 1 && p.client[0] !== before.client[0]; }, 30000), counts());
      check("restored client serves", await waitFor(bridgeUp, 10000));
      check("service log names the unexpected exit",
        countLines(SERVICE_LOG, "Core Services exited unexpectedly") >= 1);
      await sleep(3000);
      check("exactly one of each", exactlyOneEach(), counts());
    }

    if (want(4)) {
      console.log("4. kill VIRULE Service -> Core Services restores it");
      if (!exactlyOneEach()) { await resetWorld(); startClient(); await waitFor(exactlyOneEach, 20000); }
      const before = procs();
      killPid(before.service[0]);
      check("VIRULE Service restored with a new pid",
        await waitFor(() => { const p = procs(); return p.service.length === 1 && p.service[0] !== before.service[0]; }, 30000), counts());
      check("client log names the unexpected exit",
        countLines(CLIENT_LOG, "VIRULE Service exited unexpectedly") >= 1);
      await sleep(3000);
      check("exactly one of each", exactlyOneEach(), counts());
    }

    if (want(5)) {
      console.log("5. simultaneous start of 3 clients and 3 services -> one of each");
      await resetWorld();
      for (let i = 0; i < 3; i++) { startClient(); startService(); }
      await sleep(12000);
      check("exactly one of each survives", exactlyOneEach(), counts());
      check("bridge answers", await bridgeUp());
    }

    if (want(6)) {
      console.log("6. a second VIRULE Service exits harmlessly");
      if (!exactlyOneEach()) { await resetWorld(); startClient(); await waitFor(exactlyOneEach, 20000); }
      const before = procs();
      const dup = startService();
      const code = await new Promise((r) => { const t = setTimeout(() => r("timeout"), 5000); dup.once("exit", (c) => { clearTimeout(t); r(c); }); });
      check("duplicate service exited 0", code === 0, String(code));
      const after = procs();
      check("the resident service is untouched", after.service.length === 1 && after.service[0] === before.service[0], counts());
    }

    if (want(7)) {
      console.log("7. a second client launch forwards and exits (existing singleton)");
      if (!exactlyOneEach()) { await resetWorld(); startClient(); await waitFor(exactlyOneEach, 20000); }
      const before = procs();
      const dup = startClient();
      const code = await new Promise((r) => { const t = setTimeout(() => r("timeout"), 8000); dup.once("exit", (c) => { clearTimeout(t); r(c); }); });
      check("second client exited 0", code === 0, String(code));
      const after = procs();
      check("the serving client is untouched", after.client.length === 1 && after.client[0] === before.client[0], counts());
      check("no service churn", after.service.length === 1 && after.service[0] === before.service[0], counts());
    }

    if (want(8)) {
      console.log("8. uninstall latch -> neither resurrects the other");
      if (!exactlyOneEach()) { await resetWorld(); startClient(); await waitFor(exactlyOneEach, 20000); }
      try {
        setLatch();
        const p = procs();
        killPid(p.client[0]);
        check("the service stands down on a latched exit",
          await waitFor(() => procs().service.length === 0, 15000), counts());
        await sleep(8000);
        check("nothing came back while latched", procs().client.length + procs().service.length === 0, counts());
        const s = startService();
        const code = await new Promise((r) => { const t = setTimeout(() => r("timeout"), 5000); s.once("exit", (c) => { clearTimeout(t); r(c); }); });
        check("a service started under the latch exits at once", code === 0 && procs().client.length === 0, `${code} ${counts()}`);
      } finally { clearLatch(); }
    }

    if (want(12) || want(9) || want(10)) {
      console.log("12. maintenance: no restore while held, residency resumes after");
      await resetWorld();
      startClient();
      check("pair up", await waitFor(exactlyOneEach, 20000), counts());
      await sleep(62000); // a sustained run, so the next restore is the 1 s one
      const m = await holdMaintenance();
      const p = procs();
      killPid(p.client[0]);
      await sleep(10000);
      check("no Core Services restored while maintenance is held", procs().client.length === 0, counts());
      check("the service is waiting, not gone", procs().service.length === 1, counts());
      await m.release();
      const releasedAt = Date.now();
      // 10 s post-maintenance grace for the maintainer's own restart, then
      // the service restores one itself.
      check("residency resumes when maintenance ends (abandoned holder)",
        await waitFor(() => procs().client.length === 1, 30000, 250), counts());
      const waited = Date.now() - releasedAt;
      check("it waited out the post-maintenance grace first", waited >= 9000, `${waited} ms`);
      await sleep(3000);
      check("exactly one of each", exactlyOneEach(), counts());
    }

    if (want(9)) {
      console.log("9. Core Services self-update (real swap, then rollback) -> the service stands down");
      // An approved "upgrade" whose bytes are this same build: the client
      // stages and verifies it, announces its exit, and the helper swaps
      // under the maintenance lock; the swapped-in client reports the old
      // version, so the helper rolls back. The service must restore nothing
      // through all of it.
      if (!exactlyOneEach()) { await resetWorld(); startClient(); await waitFor(exactlyOneEach, 20000); }
      serveRelease(base, { version: "99.0.0", client: clientBytes, service: serviceBytes });
      // Force a check now (a fresh client runs one at startup): the old
      // client is replaced under maintenance, the way Setup would.
      const p0 = procs();
      const m = await holdMaintenance(); killPid(p0.client[0]); await sleep(1500); startClient(); await sleep(2000); await m.release();
      const servicePid = procs().service[0];
      const restoredBefore = countLines(SERVICE_LOG, "Core Services restored");
      const swapped = await waitFor(() => /self-update helper: (new client failed|client .* is serving)/.test(logText(CLIENT_LOG)), 120000, 1000);
      check("the swap ran (helper finished)", swapped);
      await sleep(8000);
      check("the service restored nothing during the swap",
        countLines(SERVICE_LOG, "Core Services restored") === restoredBefore,
        `${countLines(SERVICE_LOG, "Core Services restored")} vs ${restoredBefore}`);
      check("the service saw an intentional exit or maintenance",
        /Core Services exited intentionally|maintenance in progress/.test(logText(SERVICE_LOG)));
      check("the same service is still resident", procs().service.length === 1 && procs().service[0] === servicePid, counts());
      check("exactly one Core Services serving after", await waitFor(() => procs().client.length === 1, 20000) && await bridgeUp(), counts());
      serveRelease(base, { version: clientVersion, client: clientBytes, service: serviceBytes });
      // the failed swap record holds that version; clear it for later scenarios
      try { fs.rmSync(path.join(ROOT, "VIRULE", "client", "self_update.json"), { force: true }); } catch {}
    }

    if (want(10)) {
      console.log("10. VIRULE Service update through the client -> no recovery fight");
      // Same release version, a different service artifact (appended bytes
      // keep it a runnable PE): the client replaces it under maintenance.
      const newService = Buffer.concat([serviceBytes, Buffer.from("\0VIRULE-TEST-SERVICE-UPDATE\0")]);
      serveRelease(base, { version: clientVersion, client: clientBytes, service: newService });
      await resetWorld();
      const restoredBefore = countLines(CLIENT_LOG, "service watch: VIRULE Service started");
      startClient();
      const updated = await waitFor(() => fs.existsSync(SERVICE) && sha256(SERVICE) === crypto.createHash("sha256").update(newService).digest("hex"), 60000, 1000);
      check("the installed service was replaced with the manifest's", updated);
      check("the replacement is resident", await waitFor(exactlyOneEach, 20000), counts());
      check("client log: resident after replacement", /service: VIRULE Service is resident/.test(logText(CLIENT_LOG)));
      check("no .old / .update residue",
        !fs.existsSync(path.join(INSTALL, "ViruleService.exe.old")) && !fs.existsSync(path.join(INSTALL, "ViruleService.exe.update")));
      await sleep(5000);
      check("exactly one of each after the update", exactlyOneEach(), counts());
      serveRelease(base, { version: clientVersion, client: clientBytes, service: serviceBytes });
      void restoredBefore;
    }

    if (want(11) || want(17)) {
      console.log("11/17. Virule-Setup install over a running pair, and fresh install -> both placed, one of each");
      await resetWorld();
      startClient();
      await waitFor(exactlyOneEach, 20000);
      const oldClientPid = procs().client[0];
      const setup = launch(BUILD_SETUP, ["--dev-unsigned", `--manifest-url=${manifestUrl}`]);
      const setupCode = await new Promise((r) => { const t = setTimeout(() => r("timeout"), 180000); setup.once("exit", (c) => { clearTimeout(t); r(c); }); });
      check("Setup completed", setupCode === 0, String(setupCode));
      closeCards();
      check("client replaced and serving", await waitFor(async () => { const p = procs(); return p.client.length === 1 && p.client[0] !== oldClientPid && await bridgeUp(); }, 30000), counts());
      check("service binary is the release's", sha256(SERVICE) === crypto.createHash("sha256").update(serviceBytes).digest("hex"));
      await sleep(5000);
      check("exactly one of each after Setup", exactlyOneEach(), counts());

      // 17: a fresh install into an empty tree, then a client repair of a
      // deleted service binary.
      await resetWorld();
      fs.rmSync(INSTALL, { recursive: true, force: true });
      const setup2 = launch(BUILD_SETUP, ["--dev-unsigned", `--manifest-url=${manifestUrl}`]);
      const code2 = await new Promise((r) => { const t = setTimeout(() => r("timeout"), 180000); setup2.once("exit", (c) => { clearTimeout(t); r(c); }); });
      closeCards();
      check("fresh Setup completed", code2 === 0, String(code2));
      check("fresh install: both binaries present", fs.existsSync(CLIENT) && fs.existsSync(SERVICE));
      // Setup starts the installed client WITHOUT dev seams; restart the pair
      // with the seams so the repair below fetches from the local server.
      await resetWorld();
      startClient();
      check("fresh install: one of each", await waitFor(exactlyOneEach, 20000), counts());
      {
        const m = await holdMaintenance();
        for (const pid of procs().service) killPid(pid);
        await waitFor(() => procs().service.length === 0, 5000);
        fs.rmSync(SERVICE, { force: true });
        await m.release();
      }
      check("repair: the deleted service is downloaded, verified and resident again",
        await waitFor(() => fs.existsSync(SERVICE) && procs().service.length === 1, 60000, 1000), counts());
      await sleep(3000);
      check("repair: exactly one of each", exactlyOneEach(), counts());
    }

    if (want(13)) {
      console.log("13. Core Services that dies at once -> bounded backoff");
      await resetWorld();
      // ViruleService.exe copied AS virule-client.exe runs from a path that
      // is not the managed service, so it exits immediately: a perfect
      // instant-death client.
      copyFresh(BUILD_SERVICE, CLIENT);
      const before = countLines(SERVICE_LOG, "Core Services restored");
      startService();
      await sleep(45000);
      const launches = countLines(SERVICE_LOG, "Core Services restored") - before;
      check("at most 4 launches in 45 s (5 s, 30 s, 2 min ladder)", launches >= 2 && launches <= 4, String(launches));
      check("the service itself is still resident", procs().service.length === 1, counts());
      await resetWorld();
      copyFresh(BUILD_CLIENT, CLIENT);
    }

    if (want(14)) {
      console.log("14. a VIRULE Service that dies at once -> bounded backoff");
      await resetWorld();
      // The client binary AS ViruleService.exe: not the managed client
      // path, and its singleton is taken, so it leaves at once. The release
      // served here describes NO service: otherwise the client's update
      // check would (correctly) repair the broken binary with the release's
      // service and end the loop, which is not what this scenario measures.
      serveRelease(base, { version: clientVersion, client: clientBytes });
      copyFresh(BUILD_CLIENT, SERVICE);
      const before = countLines(CLIENT_LOG, "service watch: VIRULE Service started");
      startClient();
      await sleep(45000);
      const launches = countLines(CLIENT_LOG, "service watch: VIRULE Service started") - before;
      check("at most 4 launches in 45 s", launches >= 2 && launches <= 4, String(launches));
      check("Core Services itself is still serving", procs().client.length === 1 && await bridgeUp(), counts());
      await resetWorld();
      copyFresh(BUILD_SERVICE, SERVICE);
      serveRelease(base, { version: clientVersion, client: clientBytes, service: serviceBytes });
    }

    if (want(15)) {
      console.log("15. login-style start race (the Run value's client and a service at once) -> one of each");
      await resetWorld();
      startClient(); startService(); startClient();
      await sleep(10000);
      check("exactly one of each", exactlyOneEach(), counts());
    }

    if (want(16)) {
      console.log("16. full uninstall -> the service stands down, both binaries removed");
      await resetWorld();
      installBinaries();
      startClient();
      check("pair up", await waitFor(exactlyOneEach, 20000), counts());
      const r = await localSend('{"type":"uninstall_local","delete_data":false}', 3000);
      check("uninstall accepted", !!r && r.includes("uninstall"), r ?? "none");
      check("both resident processes gone", await waitFor(() => { const p = procs(); return p.client.length + p.service.length === 0; }, 30000), counts());
      check("install dir removed (client + service binaries)", await waitFor(() => !fs.existsSync(INSTALL), 60000, 1000));
      check("latch cleared after success", await waitFor(() => !latchSet(), 20000));
      await sleep(6000);
      check("nothing resurrected", procs().client.length + procs().service.length === 0, counts());
      closeCards();
    }
  } finally {
    await resetWorld().catch(() => {});
    clearLatch();
    if (hadArp) regOk(["import", arpBackup]);
    try { fs.rmSync(arpBackup, { force: true }); } catch {}
    server.close();
    if (realWasRunning && fs.existsSync(REAL_CLIENT)) {
      const p = spawn(REAL_CLIENT, [], { detached: true, stdio: "ignore", cwd: path.dirname(REAL_CLIENT) });
      p.unref();
      await waitFor(bridgeUp, 15000);
      console.log("  (the machine's real client was started again)");
    }
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("harness error:", e);
  clearLatch();
  process.exit(2);
});
