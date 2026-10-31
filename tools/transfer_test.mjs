// End-to-end game distribution transfer test: THE CLIENT'S TRANSFER THREAD
// (client/transfers.hpp run_driver, through tests\transfers\transfers_tests.exe
// "drive") against a loopback stand-in of the VIRULE service in this
// process, in a SANDBOX.
//
//   tests\transfers\run_tests.bat            builds the exe, then runs this
//   node tools\transfer_test.mjs <path to transfers_tests.exe>
//
// The stand-in speaks the service's distribution contract (VIRULE_BACKEND
// src/evaluations/distribution.ts): upload sessions resumed by build, parts
// with their SHA-256 and MD5 (a part whose MD5 the "storage" does not
// reproduce is refused with 409 integrity), storage expiry (410), session
// loss (404), completion; download authorization, ranged 206 reads, the
// verified completion and the failed receipt; the ticket and the
// credential. It records everything the driver sends.
//
// Isolation: LOCALAPPDATA and TEMP point at a throwaway tree under %TEMP%
// (the exe's helper modes refuse an unredirected profile); the wake event
// is a per-run name; kills are taskkill /F on the driver's own PID; port
// 47612 is never opened.
//
// Covers: a cold start with a packaged job and no wake (a Windows restart);
// one session per build, every part sent once with its digests; a kill
// mid-upload then restart resends only the parts the service does not
// hold; a damaged part is sent again; an expired storage upload is renewed
// and resent; a lost session is reopened; the service down backs off and
// never gives up; the package changed on disk fails the job; another
// account's job waits untouched; an install: the download in ranges,
// resumed from a kill, verified, extracted, the ticket and credential
// written, the completion reported; a wrong package fails and tells the
// service; Pause and Resume; UPLOAD ELIGIBILITY: an upload refused for want
// of a purchased evaluation still owed (or of any purchase) is held with its
// package, asked again on a release, continued once eligible; one refused at
// completion completes the same session; a newer build retires a held job;
// another account's game (404) fails rather than holds.

import { spawn, execFile, execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const exe = process.argv[2];
if (!exe || !fs.existsSync(exe)) {
  console.error("usage: node tools/transfer_test.mjs <transfers_tests.exe>");
  process.exit(2);
}

let pass = 0, fail = 0;
const check = (name, cond, extra) => {
  if (cond) { pass++; console.log("ok   " + name); }
  else { fail++; console.log("FAIL " + name + (extra === undefined ? "" : " :: " + JSON.stringify(extra))); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeoutMs, everyMs = 150) {
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
const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), "virule-transfer-test-"));
const ROOT = path.join(SANDBOX, "root");
const TEMP = path.join(SANDBOX, "temp");
fs.mkdirSync(ROOT, { recursive: true });
fs.mkdirSync(TEMP, { recursive: true });
if (!REAL_LOCAL || path.resolve(ROOT).toLowerCase() === path.resolve(REAL_LOCAL).toLowerCase()) {
  console.error("refusing: the sandbox would be the real LOCALAPPDATA");
  process.exit(2);
}
const ENV = { ...process.env, LOCALAPPDATA: ROOT, TEMP, TMP: TEMP };
const VROOT = path.join(ROOT, "VIRULE");
const TRANSFERS = path.join(VROOT, "transfers");
const EVENT = `Local\\VIRULE.Transfers.Wake.Harness.${process.pid}`;
const EMAIL = "dev@harness.test";
const MACHINE = crypto.randomBytes(32).toString("hex");

const execFileAsync = promisify(execFile);
const run = async (...args) => (await execFileAsync(exe, args, { encoding: "utf8", env: ENV })).stdout.trim();
const signal = () => run("signal", EVENT);
const readJob = (id) => { try { return JSON.parse(fs.readFileSync(path.join(TRANSFERS, id, "job.json"), "utf8")); } catch { return null; } };
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const md5 = (b) => crypto.createHash("md5").update(b).digest("hex");
const PART = 32 * 1024 * 1024;

// ---- the loopback service
const mode = { down: false, dropUploads: false, loseSessions: false, damageOnce: 0,
  // UPLOAD ELIGIBILITY (2026-10-22): games with no purchased evaluation still
  // owed (409 no_pending_evaluation at open and completion), games nobody
  // ever bought for (the same 409), another account's game (404).
  ineligible: new Set(), unbought: new Set(), foreign: new Set() };
const sessions = new Map();     // session id -> { build_uuid, package_bytes, sha, parts: Map(n -> {sha, md5, bytes}), uploadAlive, state, game }
const byBuild = new Map();      // build uuid -> session id
const log = [];                 // every request
const packages = new Map();     // revision id -> { bytes: Buffer, sha, launch }
const downloads = new Map();    // download id -> { assignment, revision, state }
const assignments = new Map();  // assignment id -> { revision }
const tickets = [];
const credentials = [];
const rid = () => crypto.randomBytes(16).toString("hex");
const json = (res, status, body) => { res.statusCode = status; res.setHeader("content-type", "application/json"); res.end(JSON.stringify(body)); };
const err = (res, status, code, message) => json(res, status, { error: { code, message } });

const server = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks);
  const url = req.url;
  log.push({ method: req.method, url, bytes: raw.length, headers: { sha: req.headers["x-virule-part-sha256"], md5: req.headers["x-virule-part-md5"], range: req.headers.range } });
  if (mode.down) { res.statusCode = 503; res.end("{}"); return; }
  let m;
  // ---- uploads
  if ((m = /^\/v1\/evaluations\/games\/([0-9a-f]{32})\/uploads$/.exec(url)) && req.method === "POST") {
    const b = JSON.parse(raw.toString("utf8"));
    if (b.content_bytes > 20 * 1024 ** 3) return err(res, 400, "invalid_request", "This game is 23 GB. The limit is 20 GB.");
    if (mode.foreign.has(m[1])) return err(res, 404, "not_found", "No such game.");
    if (mode.unbought.has(m[1])) return err(res, 409, "no_pending_evaluation", "A pending evaluation is required.");
    if (mode.ineligible.has(m[1]) && !(byBuild.has(b.build_uuid) && sessions.get(byBuild.get(b.build_uuid)).state === "verified")) {
      return err(res, 409, "no_pending_evaluation", "A pending evaluation is required.");
    }
    if (byBuild.has(b.build_uuid)) {
      const s = sessions.get(byBuild.get(b.build_uuid));
      if (s.sha !== b.package_sha256) return err(res, 409, "conflict", "This build was already uploaded with different contents.");
      return json(res, 200, { session_id: s.id, build_uuid: s.build_uuid, state: s.state, part_bytes: PART, parts_total: s.parts_total,
        uploaded: s.state === "uploading" ? [...s.parts.keys()].sort((x, y) => x - y) : [] });
    }
    const s = { id: rid(), build_uuid: b.build_uuid, game: m[1], package_bytes: b.package_bytes, sha: b.package_sha256,
      parts_total: Math.max(1, Math.ceil(b.package_bytes / PART)), parts: new Map(), uploadAlive: true, state: "uploading", launch: b.launch_exe };
    sessions.set(s.id, s);
    byBuild.set(b.build_uuid, s.id);
    return json(res, 201, { session_id: s.id, build_uuid: s.build_uuid, state: "uploading", part_bytes: PART, parts_total: s.parts_total, uploaded: [] });
  }
  if ((m = /^\/v1\/evaluations\/uploads\/([0-9a-f]{32})$/.exec(url)) && req.method === "GET") {
    const s = sessions.get(m[1]);
    if (!s || mode.loseSessions) return err(res, 404, "not_found", "No such upload.");
    return json(res, 200, { session_id: s.id, state: s.state, parts_total: s.parts_total, uploaded: [...s.parts.keys()].sort((x, y) => x - y) });
  }
  if ((m = /^\/v1\/evaluations\/uploads\/([0-9a-f]{32})\/parts\/(\d+)$/.exec(url)) && req.method === "PUT") {
    const s = sessions.get(m[1]);
    if (!s || mode.loseSessions) return err(res, 404, "not_found", "No such upload.");
    if (s.state === "verified") return err(res, 409, "conflict", "This upload is already complete.");
    if (!s.uploadAlive || mode.dropUploads) { s.uploadAlive = false; return err(res, 410, "session_expired", "This upload session has ended."); }
    const n = Number(m[2]);
    const expected = n < s.parts_total ? PART : s.package_bytes - (s.parts_total - 1) * PART;
    if (raw.length !== expected) return err(res, 400, "invalid_request", "Wrong part size.");
    const declaredSha = req.headers["x-virule-part-sha256"], declaredMd5 = req.headers["x-virule-part-md5"];
    if (!/^[0-9a-f]{64}$/.test(declaredSha || "") || !/^[0-9a-f]{32}$/.test(declaredMd5 || "")) return err(res, 400, "invalid_request", "Part digests are required.");
    if (mode.damageOnce > 0) { mode.damageOnce--; return err(res, 409, "integrity", "The part did not arrive intact. Send it again."); }
    if (md5(raw) !== declaredMd5 || sha256(raw) !== declaredSha) return err(res, 409, "integrity", "The part did not arrive intact. Send it again.");
    s.parts.set(n, { sha: declaredSha, md5: declaredMd5, bytes: raw, received: (s.parts.get(n)?.received ?? 0) + 1 });
    return json(res, 200, { session_id: s.id, n, bytes: expected, uploaded: [...s.parts.keys()].sort((x, y) => x - y) });
  }
  if ((m = /^\/v1\/evaluations\/uploads\/([0-9a-f]{32})\/renew$/.exec(url)) && req.method === "POST") {
    const s = sessions.get(m[1]);
    if (!s || mode.loseSessions) return err(res, 404, "not_found", "No such upload.");
    s.parts.clear(); s.uploadAlive = true; mode.dropUploads = false; s.renewed = (s.renewed ?? 0) + 1;
    return json(res, 200, { session_id: s.id, state: s.state, parts_total: s.parts_total, uploaded: [] });
  }
  if ((m = /^\/v1\/evaluations\/uploads\/([0-9a-f]{32})\/complete$/.exec(url)) && req.method === "POST") {
    const s = sessions.get(m[1]);
    if (!s || mode.loseSessions) return err(res, 404, "not_found", "No such upload.");
    if (s.state === "verified") return json(res, 200, { session: { session_id: s.id, state: "verified" } });
    if (mode.ineligible.has(s.game) || mode.refuseCompleteFor === s.game) return err(res, 409, "no_pending_evaluation", "A pending evaluation is required.");
    if (s.parts.size !== s.parts_total) return err(res, 409, "incomplete", "Not every part has arrived.");
    const whole = Buffer.concat([...s.parts.keys()].sort((x, y) => x - y).map((k) => s.parts.get(k).bytes));
    if (whole.length !== s.package_bytes || sha256(whole) !== s.sha) return err(res, 409, "integrity", "The parts do not add up to the package.");
    s.state = "verified"; s.completed = (s.completed ?? 0) + 1;
    packages.set(s.id, { bytes: whole, sha: s.sha, launch: s.launch });
    return json(res, 200, { session: { session_id: s.id, state: "verified" }, purchased: true, games: [] });
  }
  // ---- downloads
  if ((m = /^\/v1\/assignments\/([0-9a-f]{32})\/download$/.exec(url)) && req.method === "POST") {
    const a = assignments.get(m[1]);
    if (!a) return err(res, 404, "not_found", "No such assignment.");
    const pkg = packages.get(a.revision);
    if (!pkg) return err(res, 409, "no_build", "No build is available for this game yet.");
    let d = [...downloads.values()].find((x) => x.assignment === m[1] && x.state === "authorized");
    if (!d) { d = { id: rid(), assignment: m[1], revision: a.revision, state: "authorized" }; downloads.set(d.id, d); }
    return json(res, 200, { download_id: d.id, revision_id: a.revision, build_uuid: "b".repeat(32), revision: 1, package_bytes: pkg.bytes.length,
      content_bytes: pkg.bytes.length - 64, package_sha256: pkg.sha, launch_exe: pkg.launch, installed: false, expires_utc: "2030-01-01T00:00:00Z" });
  }
  if ((m = /^\/v1\/assignments\/([0-9a-f]{32})\/download\/([0-9a-f]{32})$/.exec(url)) && req.method === "GET") {
    const d = downloads.get(m[2]);
    if (!d || d.assignment !== m[1]) return err(res, 404, "not_found", "No such download.");
    if (d.state !== "authorized") return err(res, 409, "conflict", "This download is finished.");
    const pkg = packages.get(d.revision);
    const r = /^bytes=(\d+)-(\d*)$/.exec(req.headers.range || "");
    if (!r) return err(res, 416, "invalid_request", "Unsupported range.");
    const from = Number(r[1]);
    const to = Math.min(pkg.bytes.length - 1, r[2] ? Number(r[2]) : from + 64 * 1024 * 1024 - 1, from + 64 * 1024 * 1024 - 1);
    if (from >= pkg.bytes.length || to < from) return err(res, 416, "invalid_request", "Unsupported range.");
    const slice = pkg.bytes.subarray(from, to + 1);
    d.served = (d.served ?? 0) + slice.length;
    res.statusCode = 206;
    res.setHeader("content-type", "application/zip");
    res.setHeader("content-length", String(slice.length));
    res.setHeader("content-range", `bytes ${from}-${to}/${pkg.bytes.length}`);
    if (mode.cutDownloadAfter && d.served > mode.cutDownloadAfter) { res.socket.destroy(); return; }
    res.end(slice);
    return;
  }
  if ((m = /^\/v1\/assignments\/([0-9a-f]{32})\/download\/([0-9a-f]{32})\/(complete|failed)$/.exec(url)) && req.method === "POST") {
    const d = downloads.get(m[2]);
    if (!d || d.assignment !== m[1]) return err(res, 404, "not_found", "No such download.");
    const b = JSON.parse(raw.toString("utf8"));
    if (m[3] === "failed") { d.state = "failed"; d.failure = b.reason; return json(res, 200, { ok: true }); }
    const pkg = packages.get(d.revision);
    if (d.state === "failed") return err(res, 409, "conflict", "This download was not received. Ask for it again.");
    if (b.sha256 !== pkg.sha || b.bytes !== pkg.bytes.length) return err(res, 409, "integrity", "The downloaded package does not match the build.");
    d.state = "completed";
    return json(res, 200, { ok: true, replayed: false });
  }
  if ((m = /^\/v1\/assignments\/([0-9a-f]{32})\/ticket$/.exec(url)) && req.method === "GET") {
    if (!assignments.has(m[1])) return err(res, 404, "not_found", "No such assignment.");
    // A game under a security hold (VIRULE_BACKEND security.ts heldRefusal).
    if (assignments.get(m[1]).held) return err(res, 409, "security_hold", "This game is unavailable while it is reviewed.");
    const t = { version: 1, assignment_id: m[1], evaluator_id: "e".repeat(32), game_uuid: assignments.get(m[1]).game, accepted_utc: "2026-10-20T10:00:00Z", signature: "1".repeat(128) };
    tickets.push(t);
    return json(res, 200, { ticket: t });
  }
  if (url === "/v1/assignments/credential" && req.method === "POST") {
    const b = JSON.parse(raw.toString("utf8"));
    const c = { version: 1, evaluator_id: "e".repeat(32), machine_key: b.machine_key, bound_utc: "2026-10-20T10:00:00Z", signature: "2".repeat(128) };
    credentials.push(c);
    return json(res, 201, { credential: c });
  }
  return err(res, 404, "not_found", "Unknown endpoint.");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const ENDPOINT = `http://127.0.0.1:${server.address().port}`;

// ---- the driver process
let driver = null;
let driverOut = "";
function startDriver(email = EMAIL) {
  driverOut = "";
  driver = spawn(exe, ["drive", EVENT, ENDPOINT, email, MACHINE], { env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  driver.stdout.on("data", (d) => { driverOut += d.toString(); });
  driver.stderr.on("data", (d) => { driverOut += d.toString(); });
  return waitFor(() => driverOut.includes("driver: up"), 5000);
}
function killDriver() {
  if (!driver) return;
  try { execFileSync("taskkill", ["/F", "/PID", String(driver.pid)], { stdio: "ignore" }); } catch { /* gone */ }
  driver = null;
}
async function stopDriver() {
  if (!driver) return;
  const stopName = EVENT + ".Stop";
  try { await run("signal", stopName); } catch { /* not up */ }
  const exited = await waitFor(() => driver.exitCode !== null, 5000);
  if (!exited) killDriver();
  driver = null;
}
const requestsFor = (re) => log.filter((l) => re.test(l.url));

try {
  // ======================================= 1. a cold start carries an upload
  const G1 = rid();
  const [J1, S1] = (await run("package", VROOT, G1, String(PART + 70000))).split(" ");
  check("a packaged job was written (two parts)", readJob(J1)?.state === "packaged" && readJob(J1).parts_total === 2);
  await startDriver();
  let done = await waitFor(() => readJob(J1)?.state === "done", 30000);
  check("the driver carried the job to done without a wake (the startup pass)", !!done, readJob(J1));
  const s1 = sessions.get(byBuild.get(readJob(J1).build_uuid));
  check("one session, both parts once, each with its SHA-256 and MD5, then completed once",
    s1?.completed === 1 && s1.parts.size === 2 && requestsFor(/parts\/1$/).length === 1 && requestsFor(/parts\/2$/).length === 1 &&
    requestsFor(/parts\//).every((l) => /^[0-9a-f]{64}$/.test(l.headers.sha) && /^[0-9a-f]{32}$/.test(l.headers.md5)), log.filter((l) => /parts/.test(l.url)).length);
  check("the assembled package is the file, byte for byte", packages.get(s1.id)?.sha === S1);
  check("the record holds the session and every part", readJob(J1).session_id === s1.id && readJob(J1).parts_done.length === 2 && readJob(J1).bytes_done === PART + 70000);

  // ============================ 2. a kill mid-upload resends only what is missing
  const G2 = rid();
  const [J2] = (await run("package", VROOT, G2, String(2 * PART + 10))).split(" ");
  const before = log.length;
  await signal();
  await waitFor(() => readJob(J2)?.parts_done?.length >= 1, 20000);
  killDriver();
  const partsBefore = readJob(J2).parts_done.length;
  check("the job records the parts sent before the kill", partsBefore >= 1 && readJob(J2).state === "uploading", readJob(J2));
  await startDriver();
  done = await waitFor(() => readJob(J2)?.state === "done", 40000);
  check("the restarted driver finishes the job", !!done, readJob(J2));
  const s2 = sessions.get(readJob(J2).session_id);
  const sentAfter = log.slice(before).filter((l) => /parts\//.test(l.url) && l.url.includes(s2.id));
  check("no part was sent twice (the session was read back first)", s2.parts_total === 3 && sentAfter.length === 3 && [...s2.parts.values()].every((p) => p.received === 1), sentAfter.length);
  check("one session for the build: the restart read it back instead of opening another",
    requestsFor(new RegExp(`games/${G2}/uploads`)).length === 1 && log.some((l) => l.method === "GET" && l.url === `/v1/evaluations/uploads/${s2.id}`) && byBuild.size === 2);

  // ======================================= 3. a damaged part is sent again
  const G3 = rid();
  const [J3] = (await run("package", VROOT, G3, "5000")).split(" ");
  mode.damageOnce = 2;
  await signal();
  done = await waitFor(() => readJob(J3)?.state === "done", 20000);
  const sent3 = requestsFor(new RegExp(`uploads/${readJob(J3).session_id}/parts/1$`)).length;
  check("a part the storage did not reproduce is sent again until it arrives", !!done && sent3 === 3, sent3);

  // ===================================== 4. an expired storage upload is renewed
  const G4 = rid();
  const [J4] = (await run("package", VROOT, G4, String(PART + 5))).split(" ");
  mode.dropUploads = true;
  await signal();
  done = await waitFor(() => readJob(J4)?.state === "done", 30000);
  const s4 = sessions.get(readJob(J4).session_id);
  check("after 410 the session is renewed under the same id and every part sent again", !!done && s4.renewed === 1 && s4.parts.size === 2, { renewed: s4?.renewed, state: readJob(J4)?.state });

  // ================================================ 5. a lost session is reopened
  const G5 = rid();
  const [J5] = (await run("package", VROOT, G5, "4000")).split(" ");
  mode.loseSessions = true;
  await signal();
  await waitFor(() => readJob(J5)?.session_id === "" && readJob(J5).state === "packaged", 15000);
  mode.loseSessions = false;
  await signal();
  done = await waitFor(() => readJob(J5)?.state === "done", 20000);
  check("a session the service no longer knows is opened again and finished", !!done, readJob(J5));

  // ================================== 6. the service down: backoff, never give up
  const G6 = rid();
  const [J6] = (await run("package", VROOT, G6, "3000")).split(" ");
  mode.down = true;
  await signal();
  const deferred = await waitFor(() => readJob(J6)?.next_attempt_utc > 0, 10000);
  check("with the service down the job is deferred on the ladder (attempt 1 = 10 s)", !!deferred && readJob(J6).attempts === 1 && readJob(J6).state === "packaged", readJob(J6));
  mode.down = false;
  done = await waitFor(() => readJob(J6)?.state === "done", 25000);
  check("...and is carried once the service answers again", !!done, readJob(J6));

  // =========================================== 7. a package that changed fails
  const G7 = rid();
  const [J7] = (await run("package", VROOT, G7, "2000")).split(" ");
  fs.appendFileSync(readJob(J7).package_path, "tampered");
  await signal();
  const failed = await waitFor(() => readJob(J7)?.state === "failed", 10000);
  check("a package whose bytes changed since it was built fails and says so", !!failed && /changed since it was built/.test(readJob(J7).error), readJob(J7));

  // ================================ 8. another account's job waits untouched
  const G8 = rid();
  const [J8] = (await run("package", VROOT, G8, "2000")).split(" ");
  const j8 = readJob(J8); j8.account_email = "someone-else@harness.test";
  fs.writeFileSync(path.join(TRANSFERS, J8, "job.json"), JSON.stringify(j8));
  await signal();
  await sleep(1500);
  check("a job of another account is never carried under this one", readJob(J8).state === "packaged" && readJob(J8).session_id === "", readJob(J8));

  // ============================= 8b. upload eligibility: held, never failed
  // (owner brief 2026-10-22) The service refuses an upload for a game with no
  // purchased evaluation still owed or never bought for (409 no_pending_evaluation): the job
  // is HELD with its package; a release (a purchase changed the developer's
  // evaluations) asks again and the upload continues; one refused at its
  // completion keeps its session and completes once released.
  const release = () => run("signal", EVENT + ".Release");
  const GH = rid();
  mode.ineligible.add(GH);
  const [JH] = (await run("package", VROOT, GH, "6000")).split(" ");
  await signal();
  const heldH = await waitFor(() => readJob(JH)?.state === "held", 10000);
  check("every evaluation delivered: the upload is held, not failed, its package kept",
    !!heldH && fs.existsSync(readJob(JH).package_path) && readJob(JH).next_attempt_utc > Date.now() / 1000 + 60, readJob(JH));
  const opensWhileHeld = requestsFor(new RegExp(`games/${GH}/uploads`)).length;
  await signal();
  await sleep(1200);
  check("a plain wake does not ask again while it is held", requestsFor(new RegExp(`games/${GH}/uploads`)).length === opensWhileHeld && readJob(JH).state === "held");
  await release();
  await sleep(1200);
  check("a release asks again and, still refused, it stays held", requestsFor(new RegExp(`games/${GH}/uploads`)).length === opensWhileHeld + 1 && readJob(JH).state === "held", readJob(JH));
  mode.ineligible.delete(GH);
  await release();
  done = await waitFor(() => readJob(JH)?.state === "done", 20000);
  check("eligible (a purchase): released, it uploads and completes from the same package", !!done && packages.get(readJob(JH).session_id)?.sha === readJob(JH).package_sha256, readJob(JH));
  const GN = rid();
  mode.unbought.add(GN);
  const [JN] = (await run("package", VROOT, GN, "3000")).split(" ");
  await signal();
  check("never bought for (the same 409): held too", !!(await waitFor(() => readJob(JN)?.state === "held", 10000)), readJob(JN));
  mode.unbought.delete(GN);
  await release();
  check("the first purchase releases it", !!(await waitFor(() => readJob(JN)?.state === "done", 20000)), readJob(JN));
  // Refused at completion: the parts went, the evaluation was delivered meanwhile.
  const GC = rid();
  const [JC] = (await run("package", VROOT, GC, "7000")).split(" ");
  const sessionsBefore = sessions.size;
  // The open goes through; only the completion is refused.
  mode.refuseCompleteFor = GC;
  await signal();
  const heldC = await waitFor(() => readJob(JC)?.state === "held", 15000);
  check("refused at completion: held with its session and its parts", !!heldC && readJob(JC).session_id !== "" &&
    sessions.get(readJob(JC).session_id)?.parts.size === 1 && sessions.size === sessionsBefore + 1, readJob(JC));
  mode.refuseCompleteFor = "";
  await release();
  done = await waitFor(() => readJob(JC)?.state === "done", 20000);
  check("released: the same session completes, no part sent twice", !!done && sessions.get(readJob(JC).session_id).parts.get(1).received === 1 &&
    sessions.size === sessionsBefore + 1, readJob(JC));
  // A newer Build for Evaluation of the same game: the driver, the held job's
  // only writer, retires the held one and carries the new one.
  const GR = rid();
  mode.ineligible.add(GR);
  const [JR] = (await run("package", VROOT, GR, "2500")).split(" ");
  await signal();
  await waitFor(() => readJob(JR)?.state === "held", 10000);
  const opensR = requestsFor(new RegExp(`games/${GR}/uploads`)).length;
  mode.ineligible.delete(GR);
  await sleep(1100); // a later creation second than the held job's
  const [JR2] = (await run("package", VROOT, GR, "2600")).split(" ");
  await release();
  done = await waitFor(() => readJob(JR2)?.state === "done", 20000);
  check("a newer build of the game retires the held job (failed, never carried) and uploads itself",
    !!done && readJob(JR).state === "failed" && readJob(JR).error === "Replaced by a newer build." &&
    requestsFor(new RegExp(`games/${GR}/uploads`)).length === opensR + 1, [readJob(JR), readJob(JR2)?.state]);
  // Another account's game (404) is not a hold: the job fails as before.
  const GF = rid();
  mode.foreign.add(GF);
  const [JF] = (await run("package", VROOT, GF, "1500")).split(" ");
  await signal();
  check("another account's game (404) fails the job, never holds it", !!(await waitFor(() => readJob(JF)?.state === "failed", 10000)), readJob(JF));

  // ===================================================== 9. an install, end to end
  const A1 = rid();
  const GI = rid();
  // The package the evaluator receives: a real zip with Game.exe inside.
  const zipRevision = (() => {
    const s = [...sessions.values()].find((x) => x.id === readJob(J1).session_id);
    return s.id;
  })();
  // Replace revision J1's bytes with a real archive (built by the C++ unit
  // test's own writer would be circular; a minimal stored zip is written here).
  const { bytes: zipBytes } = (() => {
    const name = Buffer.from("Game.exe");
    const data = Buffer.from("exe bytes " + "x".repeat(200000));
    const crc = (() => { let c = ~0; for (const b of data) { c ^= b; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1)); } return ~c >>> 0; })();
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6); local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10); local.writeUInt16LE(0, 12); local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22); local.writeUInt16LE(name.length, 26); local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10); central.writeUInt16LE(0, 12); central.writeUInt16LE(0, 14); central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30); central.writeUInt16LE(0, 32); central.writeUInt16LE(0, 34); central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38); central.writeUInt32LE(0, 42);
    const end = Buffer.alloc(22);
    const cdOffset = local.length + name.length + data.length;
    const cdSize = central.length + name.length;
    end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(0, 4); end.writeUInt16LE(0, 6); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10);
    end.writeUInt32LE(cdSize, 12); end.writeUInt32LE(cdOffset, 16); end.writeUInt16LE(0, 20);
    return { bytes: Buffer.concat([local, name, data, central, name, end]) };
  })();
  packages.set(zipRevision, { bytes: zipBytes, sha: sha256(zipBytes), launch: "Game.exe" });
  assignments.set(A1, { revision: zipRevision, game: GI });
  const JI = await run("install", VROOT, A1, GI, zipRevision, sha256(zipBytes), String(zipBytes.length), "Game.exe");
  await signal();
  const installed = await waitFor(() => readJob(JI)?.state === "installed", 30000);
  check("the install ran to installed", !!installed, readJob(JI));
  const installDir = path.join(VROOT, "installs", GI);
  check("the game is in its own folder under the installs location, launch file present",
    fs.existsSync(path.join(installDir, "Game.exe")) && fs.readFileSync(path.join(installDir, "Game.exe"), "utf8").startsWith("exe bytes"));
  const d1 = [...downloads.values()].find((d) => d.assignment === A1);
  check("the service received the verified completion", d1?.state === "completed");
  const ticket = JSON.parse(fs.readFileSync(path.join(VROOT, "evaluator", "assignments", A1, "ticket.json"), "utf8"));
  check("the ticket is written with the install location and launch file", ticket.assignment_id === A1 && ticket.install_path === installDir && ticket.launch_exe === "Game.exe" && ticket.signature === "1".repeat(128), ticket);
  const cred = JSON.parse(fs.readFileSync(path.join(VROOT, "security", "evaluator.cred"), "utf8"));
  check("the credential is written for this machine", cred.machine_key === MACHINE && cred.evaluator_id === "e".repeat(32), cred);
  check("the partial download was removed", !fs.existsSync(readJob(JI).temp_path));
  check("the download was fetched in ranges", requestsFor(new RegExp(`download/${d1.id}$`)).length >= 1 && requestsFor(new RegExp(`download/${d1.id}$`)).every((l) => /^bytes=\d+-\d+$/.test(l.headers.range)));

  // ============ 9b. the verified content record (owner brief 2026-10-30 section 3)
  // The install's clean scan (real Microsoft Defender on this computer) is
  // recorded beside the job: the revision and every delivered file.
  const recordPath = path.join(VROOT, "transfers", JI, "verified.txt");
  const recordOf = () => {
    try {
      const lines = fs.readFileSync(recordPath, "utf8").split("\n");
      const files = new Map(lines.slice(2).filter(Boolean).map((l) => { const [size, mtime, key] = l.split("\t"); return [key, { size: Number(size), mtime }]; }));
      return { format: lines[0], revision: lines[1], files };
    } catch { return null; }
  };
  const rec1 = recordOf();
  check("the install records what its clean scan verified: the revision and the delivered launch file",
    !!rec1 && rec1.format === "virule-verified-content.v1" && rec1.revision === zipRevision && rec1.files.get("game.exe")?.size === 200010 &&
    readJob(JI).scan_revision_id === zipRevision && readJob(JI).scan_outcome === "clean", { rec1, job: readJob(JI) });
  // Files the game wrote after it ran (a save) and a changed data file are
  // NOT verified until they are scanned: the driver verifies them at its
  // first pass (and whenever the launcher or a game's exit asks), and the
  // record then takes them in.
  fs.mkdirSync(path.join(installDir, "Saves"), { recursive: true });
  fs.writeFileSync(path.join(installDir, "Saves", "slot1.sav"), "save data ".repeat(50));
  fs.writeFileSync(path.join(installDir, "readme.txt"), "a file the record never saw");
  killDriver();
  await startDriver();
  const verified = await waitFor(() => { const r = recordOf(); return r && r.files.has("saves/slot1.sav") && r.files.has("readme.txt") ? r : null; }, 60000);
  check("new and changed files are scanned and taken into the record; the delivered file stays vouched for",
    !!verified && verified.files.get("game.exe")?.mtime === rec1.files.get("game.exe").mtime && readJob(JI).scan_revision_id === zipRevision &&
    readJob(JI).state === "installed" && !readJob(JI).security_held,
    { verified: verified && [...verified.files.keys()], scan: readJob(JI).scan_outcome, log: driverOut.split("\n").filter((l) => /installed content/.test(l)) });

  // ===== 9c. a held game is refused BEFORE anything is placed (section 3)
  const AHX = rid();
  const GHX = rid();
  const heldRevision = rid();
  packages.set(heldRevision, { bytes: zipBytes, sha: sha256(zipBytes), launch: "Game.exe" });
  assignments.set(AHX, { revision: heldRevision, game: GHX, held: true });
  const JHX = await run("install", VROOT, AHX, GHX, heldRevision, sha256(zipBytes), String(zipBytes.length), "Game.exe");
  await signal();
  const heldDone = await waitFor(() => readJob(JHX)?.state === "failed", 30000);
  const dHX = [...downloads.values()].find((d) => d.assignment === AHX);
  check("a game held while it was downloaded and scanned is never placed: failed with the service's sentence, no folder, no package, no completion",
    !!heldDone && readJob(JHX).error === "This game is unavailable while it is reviewed." && !fs.existsSync(path.join(VROOT, "installs", GHX)) &&
    !fs.existsSync(readJob(JHX).temp_path) && dHX?.state !== "completed", readJob(JHX));
  await run("control", VROOT, JSON.stringify({ type: "transfer_control", assignment_id: AHX, action: "retry" }));
  await signal();
  await sleep(1500);
  check("Retry asks again and the hold still refuses it (never placed)", !fs.existsSync(path.join(VROOT, "installs", GHX)), readJob(JHX));

  // ========================================= 10. a wrong package fails and tells
  const A2 = rid();
  const GB = rid();
  const badRevision = rid();
  packages.set(badRevision, { bytes: Buffer.from("not the bytes declared"), sha: "0".repeat(64), launch: "Game.exe" });
  assignments.set(A2, { revision: badRevision, game: GB });
  const JB = await run("install", VROOT, A2, GB, badRevision, "0".repeat(64), "22", "Game.exe");
  await signal();
  const badDone = await waitFor(() => readJob(JB)?.state === "failed", 20000);
  const dB = [...downloads.values()].find((d) => d.assignment === A2);
  check("a package that does not verify fails the install, tells the service, keeps nothing", !!badDone && dB?.state === "failed" && dB.failure === "integrity" &&
    /did not verify/.test(readJob(JB).error) && !fs.existsSync(path.join(VROOT, "installs", GB)), readJob(JB));

  // ============================================ 11. a kill mid-download resumes
  const A3 = rid();
  const G3i = rid();
  const bigRevision = rid();
  const big = Buffer.concat([zipBytes, Buffer.alloc(0)]);
  packages.set(bigRevision, { bytes: big, sha: sha256(big), launch: "Game.exe" });
  assignments.set(A3, { revision: bigRevision, game: G3i });
  mode.cutDownloadAfter = 1;   // the first range is cut mid-stream
  const J3i = await run("install", VROOT, A3, G3i, bigRevision, sha256(big), String(big.length), "Game.exe");
  await signal();
  await waitFor(() => readJob(J3i)?.next_attempt_utc > 0 || readJob(J3i)?.state === "installed", 15000);
  mode.cutDownloadAfter = 0;
  killDriver();
  await startDriver();
  const resumed = await waitFor(() => readJob(J3i)?.state === "installed", 40000);
  check("an interrupted download is retried and finished after a restart", !!resumed, readJob(J3i));

  // ================================================ 12. Pause and Resume
  const A4 = rid();
  const G4i = rid();
  const slowRevision = rid();
  const slow = Buffer.concat([zipBytes]);
  packages.set(slowRevision, { bytes: slow, sha: sha256(slow), launch: "Game.exe" });
  assignments.set(A4, { revision: slowRevision, game: G4i });
  const J4i = await run("install", VROOT, A4, G4i, slowRevision, sha256(slow), String(slow.length), "Game.exe");
  await run("control", VROOT, JSON.stringify({ type: "transfer_control", assignment_id: A4, action: "pause" }));
  await signal();
  await sleep(1500);
  check("a paused assignment's install does not download", ["queued", "paused"].includes(readJob(J4i)?.state) && ![...downloads.values()].some((d) => d.assignment === A4), readJob(J4i)?.state);
  await run("control", VROOT, JSON.stringify({ type: "transfer_control", assignment_id: A4, action: "resume" }));
  await signal();
  const after = await waitFor(() => readJob(J4i)?.state === "installed", 30000);
  check("Resume carries it to installed", !!after, readJob(J4i));
  const status = JSON.parse(await run("status", VROOT));
  check("transfer_status lists the jobs", status.type === "transfer_status" && status.jobs.length >= 5);

  await stopDriver();
  check("the driver stops on its stop event", /driver: stopped/.test(driverOut));
} catch (e) {
  check("the run reached the end", false, String(e?.stack ?? e));
} finally {
  killDriver();
  server.close();
  try { fs.rmSync(SANDBOX, { recursive: true, force: true }); } catch { /* best effort */ }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
