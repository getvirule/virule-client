// End-to-end evaluation evidence delivery test: THE CLIENT'S EVIDENCE THREAD
// (shared/evidence_queue.hpp run_driver + select_transport, through
// tests\evidence\evidence_tests.exe "drive") against a loopback test
// endpoint in this process, in a SANDBOX.
//
//   tests\evidence\run_tests.bat            builds the exe, then runs this
//   node tools\evidence_queue_test.mjs <path to evidence_tests.exe>
//
// WHY NOT THE FULL CLIENT. virule-client.exe holds the per-session
// Local\ViruleClient.Singleton mutex and the fixed bridge port 47612, so a
// sandboxed client cannot run beside the owner's resident client, and this
// test must never evict it. The delivery thread is self-contained (it owns
// no bridge, no mutex), so the harness runs the SAME driver code in the test
// exe, which main.cpp starts in serve(). Isolation:
//   - LOCALAPPDATA and TEMP point at a throwaway tree under %TEMP%; the exe's
//     helper modes refuse to run when LOCALAPPDATA is not redirected, and
//     the test transport is honored here only because it is redirected;
//   - the wake event is a per-run name (Local\VIRULE.Evidence.Wake.Harness.
//     <pid>), never the real Local\VIRULE.Evidence.Wake;
//   - kills are taskkill /F on the driver's own PID only;
//   - port 47612 is never opened; the endpoint is an ephemeral 127.0.0.1 port.
//
// Covers: a cold start with pending packages and no wake (a Windows
// restart), a wake-driven delivery, a kill mid-delivery then restart
// (resumes, only unacknowledged files resent, one receipt), a 500, a partial
// acknowledgment, no answer at all, a clean stop, a restart after
// everything is delivered (no request, receipts unchanged), payload kept
// until the acknowledgment, receipts simulated:true. The wrapper is never
// present: the client delivers on its own.

import { spawn, execFile, execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const exe = process.argv[2];
if (!exe || !fs.existsSync(exe)) {
  console.error("usage: node tools/evidence_queue_test.mjs <evidence_tests.exe>");
  process.exit(2);
}

let pass = 0, fail = 0;
const check = (name, cond, extra) => {
  if (cond) { pass++; console.log("ok   " + name); }
  else { fail++; console.log("FAIL " + name + (extra === undefined ? "" : " :: " + JSON.stringify(extra))); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeoutMs, everyMs = 200) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await sleep(everyMs);
  }
  return null;
}

// ---- sandbox
const REAL_LOCAL = process.env.LOCALAPPDATA;
const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), "virule-evidence-test-"));
const ROOT = path.join(SANDBOX, "root");
const TEMP = path.join(SANDBOX, "temp");
fs.mkdirSync(ROOT, { recursive: true });
fs.mkdirSync(TEMP, { recursive: true });
if (!REAL_LOCAL || path.resolve(ROOT).toLowerCase() === path.resolve(REAL_LOCAL).toLowerCase()) {
  console.error("refusing: the sandbox would be the real LOCALAPPDATA");
  process.exit(2);
}
const ENV = { ...process.env, LOCALAPPDATA: ROOT, TEMP, TMP: TEMP };
const EVIDENCE = path.join(ROOT, "VIRULE", "evidence");
const OUTBOX = path.join(EVIDENCE, "outbox");
const RECEIPTS = path.join(EVIDENCE, "receipts");
const DELIVERY = path.join(EVIDENCE, "delivery");
const EVENT = `Local\\VIRULE.Evidence.Wake.Harness.${process.pid}`;
const ASSIGNMENT = crypto.randomBytes(16).toString("hex");

// The real evidence root is only LOOKED at, before and after, to prove the
// run never wrote there.
const REAL_EVIDENCE = path.join(REAL_LOCAL, "VIRULE", "evidence");
const snapshotReal = () => {
  const out = [];
  for (const sub of ["outbox", "receipts", "delivery"]) {
    try { for (const n of fs.readdirSync(path.join(REAL_EVIDENCE, sub))) out.push(sub + "/" + n); } catch { /* absent */ }
  }
  return out.sort().join("|");
};
const realBefore = snapshotReal();

const execFileAsync = promisify(execFile);
const run = async (...args) => (await execFileAsync(exe, args, { encoding: "utf8", env: ENV })).stdout.trim();
const seed = (frames, bytes = 4096) => run("seed", ASSIGNMENT, String(frames), String(bytes));
const signal = () => run("signal", EVENT);
const status = async () => JSON.parse(await run("status", ASSIGNMENT));
const ls = (dir) => { try { return fs.readdirSync(dir); } catch { return []; } };
const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; } };
const receipt = (id) => readJson(path.join(RECEIPTS, id + ".json"));
const deliveryState = (id) => readJson(path.join(DELIVERY, id + ".json"));
const inOutbox = (id) => fs.existsSync(path.join(OUTBOX, id));

// ---- the loopback test endpoint (the wire protocol in evidence_queue.hpp)
const mode = { kind: "normal", partialLimit: 0, delayMs: 0 };
const packages = new Map(); // id -> { files: Map(name -> {sha, bytes}), verified: Set, uploads: Map, receipt }
const held = new Set();
let requests = 0;
let receiptsIssued = 0;
const answer = (res, pkg) => {
  const acked = [...pkg.verified];
  const complete = pkg.files.size > 0 && acked.length === pkg.files.size;
  if (complete && !pkg.receipt) { pkg.receipt = "rcpt-" + crypto.randomBytes(6).toString("hex"); receiptsIssued++; }
  res.statusCode = 200;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(complete ? { acked, complete, receipt_id: pkg.receipt } : { acked, complete }));
};
const server = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  requests++;
  if (mode.kind === "hang") { held.add(res); return; }
  if (mode.kind === "error") { res.statusCode = 500; res.end("{}"); return; }
  if (mode.delayMs) await sleep(mode.delayMs);
  let body;
  try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { res.statusCode = 400; res.end("{}"); return; }
  const m = /^\/evidence\/packages\/([0-9a-f]{32})(?:\/files\/([A-Za-z0-9._-]+))?$/.exec(req.url);
  if (!m || req.method !== "POST") { res.statusCode = 404; res.end("{}"); return; }
  const id = m[1];
  if (!m[2]) {
    let pkg = packages.get(id);
    if (!pkg) {
      pkg = { files: new Map(), verified: new Set(), uploads: new Map(), parts: new Map(), receipt: null, assignment: body.assignment_id };
      packages.set(id, pkg);
    }
    for (const f of body.files || []) pkg.files.set(f.file, { sha: f.sha256, bytes: f.bytes });
    answer(res, pkg);
    return;
  }
  const pkg = packages.get(id);
  if (!pkg) { res.statusCode = 409; res.end("{}"); return; }
  const name = m[2];
  if (mode.kind === "partial" && !pkg.verified.has(name) && pkg.verified.size >= mode.partialLimit) {
    answer(res, pkg); // refuses more files for now; acknowledges what it has
    return;
  }
  const parts = pkg.parts.get(name) || [];
  if (body.offset === 0) parts.length = 0;
  parts.push(Buffer.from(body.data || "", "base64"));
  pkg.parts.set(name, parts);
  if (body.last) {
    const all = Buffer.concat(parts);
    const sha = crypto.createHash("sha256").update(all).digest("hex");
    const want = pkg.files.get(name);
    pkg.uploads.set(name, (pkg.uploads.get(name) || 0) + 1);
    if (want && sha === want.sha && all.length === want.bytes && sha === body.sha256) pkg.verified.add(name);
    pkg.parts.delete(name);
  }
  answer(res, pkg);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const ENDPOINT = `http://127.0.0.1:${server.address().port}/evidence`;
const releaseHeld = () => { for (const r of held) { try { r.socket.destroy(); } catch { /* gone */ } } held.clear(); };

// ---- the driver process
let driver = null;
let driverOut = "";
const startDriver = async () => {
  driverOut = "";
  driver = spawn(exe, ["drive", EVENT, ENDPOINT], { env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  driver.stdout.on("data", (d) => { driverOut += d.toString(); });
  driver.stderr.on("data", (d) => { driverOut += d.toString(); });
  driver.exited = new Promise((r) => driver.on("exit", (code) => r(code)));
  return waitFor(() => driverOut.includes("driving test"), 5000);
};
const killDriver = async () => {
  if (!driver) return;
  try { execFileSync("taskkill", ["/F", "/PID", String(driver.pid)], { stdio: "ignore" }); } catch { /* gone */ }
  await driver.exited;
  driver = null;
};
const stopDriver = async () => {
  // The clean stop: the driver's own "<event>.Stop" (main.cpp sets its stop
  // event when serve() ends).
  const ps = `$e=[System.Threading.EventWaitHandle]::OpenExisting('${EVENT}.Stop'); [void]$e.Set()`;
  try { execFileSync("powershell.exe", ["-NoProfile", "-Command", ps], { stdio: "ignore" }); } catch { /* none */ }
  const t0 = Date.now();
  const code = await Promise.race([driver.exited, sleep(5000).then(() => "timeout")]);
  const ms = Date.now() - t0;
  if (code === "timeout") await killDriver();
  driver = null;
  return { code, ms };
};

const delivered = (id) => receipt(id) !== null && !inOutbox(id);

try {
  // 1. A WINDOWS RESTART: packages wait in the outbox, the client starts cold
  //    and nobody signals.
  console.log("-- cold start with pending packages, no wake (Windows restart)");
  const cold = [await seed(3), await seed(2)];
  check("packages handed off into the sandbox outbox", cold.every(inOutbox));
  check("driver runs the TEST transport (sandbox seam)", await startDriver(), driverOut);
  check("both delivered by the startup pass alone", await waitFor(() => cold.every(delivered), 15000));
  for (const id of cold) {
    const r = receipt(id);
    check("receipt is simulated:true and matches the service " + id.slice(0, 6),
      r && r.simulated === true && r.receipt_id === packages.get(id)?.receipt && r.assignment_id === ASSIGNMENT, r);
    check("receipt lists every file " + id.slice(0, 6), r && r.files.length === packages.get(id).files.size);
  }

  // 2. WAKE: the client is idle; a handoff signals it.
  console.log("-- wake-driven delivery");
  const before = requests;
  await sleep(1500);
  check("idle driver makes no request", requests === before);
  const woke = await seed(2);
  await signal();
  check("delivered promptly after the wake", await waitFor(() => delivered(woke), 5000));

  // 3. KILL MID-DELIVERY, then restart.
  console.log("-- client killed mid-delivery, restarted");
  mode.delayMs = 600;
  const big = await seed(8, 300 * 1024); // 2 chunks per frame
  await signal();
  const midway = await waitFor(() => (packages.get(big)?.verified.size || 0) >= 3, 30000, 100);
  check("delivery under way when killed", midway);
  await killDriver();
  check("payload kept after the kill", inOutbox(big) && fs.existsSync(path.join(OUTBOX, big, "000008.jpg")));
  check("no receipt after the kill", receipt(big) === null);
  const verifiedAtKill = packages.get(big).verified.size;
  mode.delayMs = 0;
  check("restarted", await startDriver(), driverOut);
  check("delivery resumed and finished", await waitFor(() => delivered(big), 20000));
  const uploads = [...packages.get(big).uploads.values()];
  check("no file the service had verified was sent again",
    uploads.every((n) => n === 1) && uploads.length === 9, { verifiedAtKill, uploads });
  check("exactly one receipt issued for it", receipt(big)?.receipt_id === packages.get(big).receipt);

  // 4. A SERVICE ERROR.
  console.log("-- 500: pending, retried, delivered");
  mode.kind = "error";
  const err = await seed(1);
  await signal();
  const errState = await waitFor(() => { const s = deliveryState(err); return s && s.attempts >= 1 ? s : null; }, 8000);
  check("500 keeps it pending with the reason", errState && errState.last_error === "test endpoint answered 500" && inOutbox(err), errState);
  const st500 = await status();
  check("evidence_status reports pending with attempts",
    st500.packages.some((p) => p.id === err && p.state === "pending" && p.attempts >= 1 && p.simulated === false), st500);
  mode.kind = "normal";
  check("delivered on the backoff timer once the service recovers", await waitFor(() => delivered(err), 20000));

  // 5. A PARTIAL ACKNOWLEDGMENT.
  console.log("-- partial acknowledgment: only the rest resent");
  mode.kind = "partial";
  mode.partialLimit = 3; // package.json + 2 frames
  const part = await seed(5);
  await signal();
  const pState = await waitFor(() => { const s = deliveryState(part); return s && s.last_error === "partial acknowledgment" ? s : null; }, 8000);
  check("partial acknowledgment kept, payload kept", pState && pState.acked.length === 3 && inOutbox(part), pState);
  mode.kind = "normal";
  check("completed after the partial", await waitFor(() => delivered(part), 20000));
  check("acknowledged files were not resent", [...packages.get(part).uploads.values()].every((n) => n === 1));

  // 6. NO ANSWER AT ALL.
  console.log("-- no answer: pending, then delivered");
  mode.kind = "hang";
  const quiet = await seed(1);
  await signal();
  const qState = await waitFor(() => { const s = deliveryState(quiet); return s && s.attempts >= 1 && s.state === "waiting" ? s : null; }, 20000);
  check("no answer keeps it pending (reason offline)", qState && qState.last_error === "no answer from the test endpoint" && qState.reason === "offline" && inOutbox(quiet), qState);
  mode.kind = "normal";
  releaseHeld();
  check("delivered after the silence", await waitFor(() => delivered(quiet), 20000));

  // 7. CLEAN STOP, then a restart with everything delivered.
  console.log("-- clean stop; restart re-reports nothing");
  const stopped = await stopDriver();
  check("driver stops cleanly on its stop event", stopped.code === 0 && stopped.ms < 3000, stopped);
  const all = [...cold, woke, big, err, part, quiet];
  const receiptText = all.map((id) => fs.readFileSync(path.join(RECEIPTS, id + ".json"), "utf8"));
  const reqBefore = requests;
  const issuedBefore = receiptsIssued;
  check("restarted again", await startDriver(), driverOut);
  await sleep(2500);
  check("no request for delivered packages", requests === reqBefore);
  check("receipts unchanged", all.every((id, i) => fs.readFileSync(path.join(RECEIPTS, id + ".json"), "utf8") === receiptText[i]));
  check("one receipt per package, no duplicates", ls(RECEIPTS).filter((n) => n.endsWith(".json")).length === all.length &&
    receiptsIssued === issuedBefore && issuedBefore === all.length);
  check("outbox and delivery state empty", ls(OUTBOX).length === 0 && ls(DELIVERY).filter((n) => n.endsWith(".json")).length === 0);
  check("every receipt simulated:true", all.every((id) => receipt(id)?.simulated === true));
  const final = await status();
  check("evidence_status: all acknowledged, simulated",
    final.counts.acknowledged === all.length && final.counts.pending === 0 &&
    final.packages.every((p) => p.state === "acknowledged" && p.simulated === true), final.counts);
  await stopDriver();
} finally {
  if (driver) await killDriver();
  releaseHeld();
  server.close();
  check("the real %LOCALAPPDATA%\\VIRULE\\evidence was not touched", snapshotReal() === realBefore);
  try { fs.rmSync(SANDBOX, { recursive: true, force: true }); } catch { /* best effort */ }
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
