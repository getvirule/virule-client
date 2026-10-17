// VIRULE bootstrap/handoff regression matrix (2026-09-03 pass).
//
// Targets the NEW state transitions directly, sandboxed away from the real
// machine state (every spawned process gets LOCALAPPDATA pointed at a
// throwaway directory; the client runs --no-register):
//
//   1. setup_takeover QA_ACCEPT with a live page: the native "Finishing
//      up…" continuation releases Setup, and the page receives the
//      qa_result push in parallel.
//   2. setup_takeover INSTALL_ADMIN with a live page: THE NATIVE
//      CONTINUATION IS UNCONDITIONAL (P1 final handoff correction
//      2026-09-04) - the client shows "Finishing up…" and RUNS the
//      operation itself even though a page is connected; it never steps
//      aside into native dead air.
//   3. setup_takeover with NO envelope (standalone): released only after
//      the full grace watch, via the native "VIRULE is ready" card (a
//      merely-connected idle page no longer suppresses it).
//   4. Version recovery (the false-"up to date" fix): metadata file wins,
//      state.json heals, and an UNKNOWN installed version never claims an
//      update in either direction.
//   5. Virule-Setup.exe end to end against a LOCAL manifest server
//      (--manifest-url + --dev-unsigned): handoff listener origin policy,
//      envelope accept, install, takeover transfer, release, exit 0.
//   6. THE STANDALONE CONCLUSION IS REVOCABLE (P1 corrective pass,
//      2026-09-04; the measured 00:38 incident replayed): a STANDALONE
//      takeover concludes with the ready card because no operation
//      identified itself during the grace, then a page arrives LATE and
//      drives admin_install - the standalone conclusion must be
//      superseded and the standing card must close, because the browser
//      owned a pending INSTALL_ADMIN the whole time.
//   7. LATE INTENT DURING THE WATCH (P1 final handoff correction): a
//      page-driven admin_install arriving BEFORE the standalone
//      conclusion is terminal converts the watch into the native
//      "Finishing up…" continuation; Ready/Continue never flashes first.
//   8. INSTALLED CAPABILITIES (0.9.9): the one-time migration (no record
//      + no Admin = nothing; Admin present = dev_tools; a recorded record
//      is never re-migrated; a pre-0.9.9 state.json keeps every field),
//      `enabled` in status and account_status, a LOCAL admin_install
//      records nothing, capability_enable from a page adds evaluator
//      without removing dev_tools (and pushes status to pages), an
//      unknown capability is refused, a page admin_install records
//      dev_tools by default and evaluator when asked, persistence across
//      a client restart.
//   9. The Setup envelope carries the capability: Virule-Setup.exe end to
//      end with INSTALL_ADMIN + "capability":"evaluator" records evaluator
//      in the installed client (and nothing else).
//
// Run: node tools/takeover_test.mjs           (builds must exist already)
//      node tools/takeover_test.mjs --staging (the -Environment Staging
//        build in build\Release\x64\staging, pages from the staging site)
//      --only=8,9 runs only the listed scenarios.

import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STAGING = process.argv.includes("--staging");
const BUILD_DIR = STAGING
  ? path.join(repo, "build", "Release", "x64", "staging")
  : path.join(repo, "build", "Release", "x64");
const CLIENT_EXE = path.join(BUILD_DIR, "virule-client.exe");
const SETUP_EXE = path.join(BUILD_DIR, "Virule-Setup.exe");
// A page's Origin: this build's own site (the environments' site lists do
// not overlap, so a staging client never answers virule.app).
const PAGE_ORIGIN = STAGING
  ? "https://virule-api-staging.heath-michaels9441.workers.dev"
  : "https://virule.app";
const ONLY = (() => {
  const a = process.argv.find((x) => x.startsWith("--only="));
  return a ? new Set(a.slice(7).split(",").map(Number)) : null;
})();
const runs = (n) => !ONLY || ONLY.has(n);
const REAL_CLIENT = path.join(process.env.LOCALAPPDATA, "Programs", "VIRULE", "virule-client.exe");
const SANDBOX = path.join(repo, "build", "takeover-test-sandbox");
const PORT = 47612;
const HANDOFF_PORT = 47613;

// REGISTRY CAVEAT (P3 ARP contamination fix, 2026-09-05): sandboxEnv
// redirects only the FILESYSTEM; HKCU is always the real user's hive. A
// pre-fix run of scenario 5 stamped this sandbox's paths into the real
// Apps & Features entry. The product now refuses machine registrations
// from a redirected environment, and this harness proves it stays that
// way: the real entry is snapshotted up front and must be byte-identical
// after the Setup end-to-end scenario and at the end of the run.
const ARP_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ViruleClient";
function readRealArp() {
  try {
    return execFileSync("reg.exe", ["query", ARP_KEY, "/s"], { encoding: "utf8" });
  } catch { return null; } // absent is a legitimate real state
}
function checkArpUntouched(snapshot, when) {
  const now = readRealArp();
  check(`real ARP entry untouched (${when})`, now === snapshot,
    now === snapshot ? "" : `real entry changed:\n${now ?? "ABSENT"}`);
}

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wsKey = () => crypto.randomBytes(16).toString("base64");

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

function connect({ origin = PAGE_ORIGIN, port = PORT, wsPath = "/v1" } = {}) {
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

// ---- process management (sandboxed) ----

let clientProc = null;

function sandboxEnv(root) {
  return { ...process.env, LOCALAPPDATA: root };
}

async function startClient(root) {
  clientProc = spawn(CLIENT_EXE, ["--no-register"], {
    env: sandboxEnv(root), stdio: "ignore", detached: false,
  });
  for (let i = 0; i < 40; i++) {
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

async function pollReleased(local, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    local.sendText('{"type":"setup_wait"}');
    const answer = await local.next(3000);
    if (answer && answer.includes('"released":true')) return true;
    if (Date.now() >= deadline) return false;
    await sleep(400);
  }
}

const FAKE_TOKEN = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"; // 32-char Base64URL grammar

// ---- installed capabilities (0.9.9) helpers ----

// Free the bridge port for real (an earlier scenario's client may still be
// exiting; a held singleton would make the next sandbox client
// forward-and-exit and every check would hit the WRONG client).
async function freePort() {
  for (let i = 0; i < 10; i++) {
    try {
      const c = await connect({ origin: null });
      await c.next();
      c.sendText('{"type":"shutdown"}');
      await c.next(2000);
      c.end();
      await sleep(900);
    } catch { break; }
  }
}

const stateText = (root) => {
  try { return fs.readFileSync(path.join(root, "VIRULE", "client", "state.json"), "utf8"); }
  catch { return ""; }
};
// "dev_tools,evaluator" out of any frame carrying the enabled block.
const enabledOf = (text) => {
  const m = /"enabled":\{"dev_tools":(true|false),"evaluator":(true|false)\}/.exec(text ?? "");
  return m ? `${m[1]},${m[2]}` : null;
};
// The same pair out of state.json ("recorded|dev_tools,evaluator").
const stateEnabled = (root) => {
  const t = stateText(root);
  const b = (k) => (t.includes(`"${k}":true`) ? "true" : "false");
  return `${b("enabled_recorded")}|${b("enabled_dev_tools")},${b("enabled_evaluator")}`;
};
// Send one message and return the first answer of the wanted type (a page
// connection may receive a pushed status frame in between).
async function ask(conn, message, type, timeoutMs = 5000) {
  conn.sendText(message);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const m = await conn.next(Math.max(1, deadline - Date.now()));
    if (m === null) return null;
    if (m.includes(`"type":"${type}"`)) return m;
  }
  return null;
}
async function waitFor(pred, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (pred()) return true;
    if (Date.now() >= deadline) return false;
    await sleep(150);
  }
}
const writeStubAdmin = (root) => {
  const adminDir = path.join(root, "Programs", "VIRULE", "Admin");
  fs.mkdirSync(adminDir, { recursive: true });
  fs.writeFileSync(path.join(adminDir, "virule.exe"), "stub");
  fs.writeFileSync(path.join(adminDir, "installed-release.json"), '{"version":"0.0.1-test.1"}');
};
const writeState = (root, body) => {
  const dir = path.join(root, "VIRULE", "client");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "state.json"), body);
};

async function scenarioCapabilities() {
  console.log("8. installed capabilities (0.9.9)");

  // 8a. Migration default: no record and no Admin = nothing enabled.
  {
    await freePort();
    const root = path.join(SANDBOX, "h");
    fs.mkdirSync(root, { recursive: true });
    check("client starts (sandbox h)", await startClient(root));
    check("migration recorded: no Admin = nothing enabled",
      await waitFor(() => stateEnabled(root) === "true|false,false", 4000), stateText(root));
    const local = await connect({ origin: null });
    await local.next();
    const st = await ask(local, '{"type":"status"}', "status");
    check("status carries enabled {dev_tools:false,evaluator:false}",
      enabledOf(st) === "false,false", st ?? "none");
    const acct = await ask(local, '{"type":"account_status"}', "account_status");
    check("account_status carries enabled while signed out",
      !!acct && acct.includes('"signed_in":false') && enabledOf(acct) === "false,false", acct ?? "none");

    // A LOCAL admin_install (the Admin's Settings Update) records nothing.
    const li = await ask(local, '{"type":"admin_install"}', "admin_install_started");
    check("local admin_install accepted", !!li, li ?? "none");
    await sleep(600);
    check("local admin_install recorded nothing", stateEnabled(root) === "true|false,false", stateText(root));

    // capability_enable from a page adds evaluator; every other open page
    // receives the pushed status at once.
    const p1 = await connect();
    await p1.next();
    const p2 = await connect();
    await p2.next();
    const en = await ask(p1, '{"type":"capability_enable","capability":"evaluator"}', "capability_enabled");
    check("capability_enable evaluator answers capability_enabled",
      !!en && en.includes('"capability":"evaluator"') && enabledOf(en) === "false,true", en ?? "none");
    let pushed = null;
    for (let i = 0; i < 10 && !pushed; i++) {
      const m = await p2.next(500);
      if (m && m.includes('"type":"status"') && enabledOf(m) === "false,true") pushed = m;
    }
    check("another open page received the pushed status", !!pushed);
    check("state.json records evaluator", stateEnabled(root) === "true|false,true", stateText(root));
    const unk = await ask(p1, '{"type":"capability_enable","capability":"superuser"}', "error");
    check("unknown capability refused", unk === '{"type":"error"}', unk ?? "none");
    const none = await ask(p1, '{"type":"capability_enable"}', "error");
    check("missing capability refused", none === '{"type":"error"}', none ?? "none");
    const again = await ask(p1, '{"type":"capability_enable","capability":"evaluator"}', "capability_enabled");
    check("capability_enable is idempotent", enabledOf(again) === "false,true", again ?? "none");

    // A page admin_install with no capability is the Dev Tools entry, and
    // it ADDS: evaluator stays.
    const pi = await ask(p1, '{"type":"admin_install","shortcut":false}', "admin_install_started");
    check("page admin_install accepted", !!pi, pi ?? "none");
    check("page admin_install records dev_tools (default), evaluator kept",
      await waitFor(() => stateEnabled(root) === "true|true,true", 3000), stateText(root));
    const st2 = await ask(local, '{"type":"status"}', "status");
    check("status reflects both", enabledOf(st2) === "true,true", st2 ?? "none");
    p1.end();
    p2.end();
    local.end();
    await stopClient();

    // Persistence across a client restart.
    await freePort();
    check("client restarts (sandbox h)", await startClient(root));
    const l2 = await connect({ origin: null });
    await l2.next();
    const st3 = await ask(l2, '{"type":"status"}', "status");
    check("enabled survives a restart (status)", enabledOf(st3) === "true,true", st3 ?? "none");
    const acct3 = await ask(l2, '{"type":"account_status"}', "account_status");
    check("enabled survives a restart (account_status)", enabledOf(acct3) === "true,true", acct3 ?? "none");
    l2.end();
    await stopClient();
  }

  // 8b. A page admin_install naming evaluator records evaluator only; an
  // unrecognized name is the Dev Tools entry.
  for (const [name, capability, want] of [["i", "evaluator", "true|false,true"],
                                          ["j", "bogus", "true|true,false"]]) {
    await freePort();
    const root = path.join(SANDBOX, name);
    fs.mkdirSync(root, { recursive: true });
    check(`client starts (sandbox ${name})`, await startClient(root));
    const p = await connect();
    await p.next();
    const r = await ask(p, JSON.stringify({ type: "admin_install", shortcut: false, capability }),
      "admin_install_started");
    check(`page admin_install capability "${capability}" accepted`, !!r, r ?? "none");
    check(`page admin_install capability "${capability}" records ${want}`,
      await waitFor(() => stateEnabled(root) === want, 3000), stateText(root));
    p.end();
    await stopClient();
  }

  // 8c. Migration with a managed Admin present.
  {
    await freePort();
    const root = path.join(SANDBOX, "k");
    writeStubAdmin(root);
    check("client starts (sandbox k, Admin present, no state)", await startClient(root));
    check("migration: Admin present = dev_tools",
      await waitFor(() => stateEnabled(root) === "true|true,false", 4000), stateText(root));
    await stopClient();

    // Already recorded: never migrated again (a recorded "nothing" stays).
    writeState(root, '{"version":1,"created_dev_machine_cred":false,"installed_version":"0.5.0","admin_version":"0.0.1-test.1","created_desktop_shortcut":false,"admin_hold_version":"","admin_hold_failed_utc":0,"admin_hold_until_utc":0,"enabled_recorded":true,"enabled_dev_tools":false,"enabled_evaluator":false}');
    await freePort();
    check("client restarts (sandbox k, recorded)", await startClient(root));
    await sleep(1200);
    check("a recorded record is never re-migrated", stateEnabled(root) === "true|false,false", stateText(root));
    await stopClient();

    // A pre-0.9.9 state.json: migrated, and every existing field kept.
    writeState(root, '{"version":1,"created_dev_machine_cred":true,"installed_version":"0.5.0","admin_version":"0.0.1-test.1","created_desktop_shortcut":true,"admin_hold_version":"","admin_hold_failed_utc":0,"admin_hold_until_utc":0}');
    await freePort();
    check("client restarts (sandbox k, pre-0.9.9 state)", await startClient(root));
    check("pre-0.9.9 state migrated to dev_tools",
      await waitFor(() => stateEnabled(root) === "true|true,false", 4000), stateText(root));
    const t = stateText(root);
    check("existing state.json fields kept",
      t.includes('"created_dev_machine_cred":true') && t.includes('"installed_version":"0.5.0"') &&
      t.includes('"admin_version":"0.0.1-test.1"') && t.includes('"created_desktop_shortcut":true'), t);
    await stopClient();
  }
}

async function scenarioSetupCapability(arpSnapshot) {
  console.log("9. Virule-Setup.exe carries the envelope's capability to the client");
  await freePort();
  const root = path.join(SANDBOX, "l");
  fs.mkdirSync(root, { recursive: true });
  const clientBytes = fs.readFileSync(CLIENT_EXE);
  const sha = crypto.createHash("sha256").update(clientBytes).digest("hex");
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/manifest.json")) {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({
        version: "0.5.0",
        url: `http://127.0.0.1:${server.address().port}/virule-client.exe`,
        sha256: sha,
        size: clientBytes.length,
      }));
    } else if (req.url.startsWith("/virule-client.exe")) {
      res.setHeader("content-type", "application/octet-stream");
      res.end(clientBytes);
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const setup = spawn(SETUP_EXE, [
    `--manifest-url=http://127.0.0.1:${server.address().port}/manifest.json`,
    "--dev-unsigned",
  ], { env: sandboxEnv(root), stdio: "ignore" });
  const setupExit = new Promise((res) => setup.once("exit", (code) => res(code)));

  let handoff = null;
  for (let i = 0; i < 40 && !handoff; i++) {
    await sleep(250);
    try { handoff = await connect({ port: HANDOFF_PORT, wsPath: "/handoff" }); } catch { /* not yet */ }
  }
  check("handoff listener answered", !!handoff);
  if (handoff) {
    await handoff.next(); // hello
    handoff.sendText(JSON.stringify({
      type: "handoff", v: 1, op: "INSTALL_ADMIN", shortcut: false, capability: "evaluator",
    }));
    const accepted = await handoff.next();
    check("INSTALL_ADMIN envelope with capability accepted",
      !!accepted && accepted.includes("handoff_accepted"), accepted ?? "none");
    handoff.end();
  }
  // The installed client records the envelope's capability at the start
  // of the takeover (no Admin here, so the migration alone would record
  // nothing, and a dropped capability would record dev_tools instead).
  check("the installed client recorded evaluator (and only evaluator)",
    await waitFor(() => stateEnabled(root) === "true|false,true", 60000), stateText(root));
  const code = await Promise.race([setupExit, sleep(90000).then(() => "timeout")]);
  check("Setup exited cleanly after the release", code === 0, String(code));
  // Shut the sandboxed client down promptly (its Admin install is doomed).
  await freePort();
  server.close();
  checkArpUntouched(arpSnapshot, "after sandboxed Setup capability run");
}

async function main() {
  fs.rmSync(SANDBOX, { recursive: true, force: true });
  fs.mkdirSync(SANDBOX, { recursive: true });

  const arpSnapshot = readRealArp();

  // Make sure no other client holds the port (a real installed client, an
  // earlier test run). Asking it to shut down is non-destructive: it is an
  // on-demand process that virule:// or Setup restarts at any time, and
  // this run starts the machine's real client again at the end when it
  // was running.
  let realWasRunning = false;
  try {
    const probe = await connect({ origin: null });
    realWasRunning = !!(await probe.next());
    probe.end();
  } catch { /* nothing was listening */ }
  try {
    const c = await connect({ origin: null });
    await c.next();
    c.sendText('{"type":"shutdown"}');
    await c.next(2000);
    c.end();
    await sleep(800);
  } catch { /* nothing was listening */ }

  if (runs(1)) {
  console.log("1. QA_ACCEPT takeover with a live page");
    const root = path.join(SANDBOX, "a");
    fs.mkdirSync(root, { recursive: true });
    check("client starts (sandbox a)", await startClient(root));
    const page = await connect();
    await page.next(); // hello
    const local = await connect({ origin: null });
    await local.next();
    local.sendText('{"type":"setup_wait"}');
    const pre = await local.next();
    check("not released before takeover", !!pre && pre.includes('"released":false'), pre ?? "none");
    local.sendText(JSON.stringify({
      type: "setup_takeover", op: "QA_ACCEPT", token: FAKE_TOKEN, game: "Night Jackal",
    }));
    const ack = await local.next();
    check("takeover acknowledged", !!ack && ack.includes('"takeover"'), ack ?? "none");
    page.sendText('{"type":"surface_ack"}');
    const ackOk = await page.next();
    check("surface_ack answered", !!ackOk && ackOk.includes('"ok"'), ackOk ?? "none");
    check("released after page ack", await pollReleased(local, 10000));
    // The redemption runs against the real service with a made-up token;
    // the page must still receive the pushed outcome.
    let result = null;
    for (let i = 0; i < 30 && !result; i++) {
      const m = await page.next(1000);
      if (m && m.includes('"qa_result"')) result = m;
    }
    check("page received qa_result push", !!result && result.includes(FAKE_TOKEN), result ?? "none");
    page.end();
    local.end();
    await stopClient();
  }

  if (runs(2)) {
  console.log("2. INSTALL_ADMIN takeover with a live page (native continuation, no stepping aside)");
    const root = path.join(SANDBOX, "b");
    fs.mkdirSync(root, { recursive: true });
    check("client starts (sandbox b)", await startClient(root));
    const logFile = path.join(root, "VIRULE", "client", "logs", "virule-client.log");
    const logNow = () => { try { return fs.readFileSync(logFile, "utf8"); } catch { return ""; } };
    const page = await connect();
    await page.next();
    const local = await connect({ origin: null });
    await local.next();
    local.sendText('{"type":"setup_takeover","op":"INSTALL_ADMIN","shortcut":true}');
    const ack = await local.next();
    check("takeover acknowledged", !!ack && ack.includes('"takeover"'), ack ?? "none");
    // Released only into the READY native surface (the card), page or no
    // page - never quietly.
    check("released via the native continuation", await pollReleased(local, 10000));
    check("native continuation logged (never steps aside for the page)",
      logNow().includes("takeover: INSTALL_ADMIN; native continuation"),
      logNow().split("\n").slice(-5).join(" | "));
    // The client RUNS the operation itself (the sandbox install is doomed
    // against the real manifest; shut down before the download grows).
    let opStarted = false;
    for (let i = 0; i < 20 && !opStarted; i++) {
      await sleep(250);
      opStarted = logNow().includes("admin: install requested");
    }
    check("the client runs the Admin operation itself", opStarted,
      logNow().split("\n").slice(-5).join(" | "));
    page.end();
    local.end();
    await stopClient();
  }

  if (runs(3)) {
  console.log("3. standalone takeover (no envelope) -> ready card");
    const root = path.join(SANDBOX, "c");
    fs.mkdirSync(root, { recursive: true });
    check("client starts (sandbox c)", await startClient(root));
    const local = await connect({ origin: null });
    await local.next();
    const t0 = Date.now();
    local.sendText('{"type":"setup_takeover"}');
    const ack = await local.next();
    check("takeover acknowledged", !!ack && ack.includes('"takeover"'), ack ?? "none");
    const released = await pollReleased(local, 20000);
    const elapsed = Date.now() - t0;
    check("released via the standalone card", released);
    // The FULL grace watch always runs now (P1 final handoff correction):
    // a merely-connected idle page - a real virule.app tab on the dev
    // machine included - is not an operation and no longer suppresses or
    // pre-empts the standalone conclusion.
    check("release respected the full grace watch (>=9s)",
      elapsed >= 9000, `${elapsed}ms`);
    local.end();
    await stopClient();
  }

  if (runs(4)) {
  console.log("4. version recovery / unknown-version claims");
    const root = path.join(SANDBOX, "d");
    const adminDir = path.join(root, "Programs", "VIRULE", "Admin");
    fs.mkdirSync(adminDir, { recursive: true });
    fs.writeFileSync(path.join(adminDir, "virule.exe"), "stub");
    fs.writeFileSync(path.join(adminDir, "installed-release.json"),
      '{"version":"0.0.1-test.1"}');
    check("client starts (sandbox d)", await startClient(root));
    const local = await connect({ origin: null });
    await local.next();
    local.sendText('{"type":"status"}');
    const status = await local.next();
    check("installed version recovered from metadata (no state.json)",
      !!status && status.includes('"installed":true') &&
      status.includes('"version":"0.0.1-test.1"'), status ?? "none");
    local.sendText('{"type":"admin_update_check"}');
    const upd = await local.next(25000);
    check("known-version comparison claims the genuine upgrade",
      !!upd && upd.includes('"update":true') &&
      upd.includes('"admin_version":"0.0.1-test.1"'), upd ?? "none");
    // SEMVER ORDERING (2026-09-04): an installed Admin NEWER than the
    // approved manifest is never offered an automatic downgrade.
    fs.writeFileSync(path.join(adminDir, "installed-release.json"),
      '{"version":"9.9.9-test.1"}');
    local.sendText('{"type":"admin_update_check"}');
    const down = await local.next(25000);
    check("newer-than-approved install claims NO update (no downgrade)",
      !!down && down.includes('"update":false') &&
      down.includes('"admin_version":"9.9.9-test.1"'), down ?? "none");
    // state.json must have been healed from the startup metadata.
    const state = fs.readFileSync(path.join(root, "VIRULE", "client", "state.json"), "utf8");
    check("state.json mirror healed", state.includes("0.0.1-test.1"), state);
    local.end();
    await stopClient();

    // Unknown installed version: metadata gone AND state gone. The client
    // must report installed with an EMPTY version and claim no update.
    fs.rmSync(path.join(adminDir, "installed-release.json"), { force: true });
    fs.rmSync(path.join(root, "VIRULE", "client", "state.json"), { force: true });
    check("client restarts (sandbox d)", await startClient(root));
    const local2 = await connect({ origin: null });
    await local2.next();
    local2.sendText('{"type":"status"}');
    const status2 = await local2.next();
    check("unknown version reports installed + empty version",
      !!status2 && status2.includes('"installed":true') &&
      /"admin":\{"installed":true,"version":""/.test(status2), status2 ?? "none");
    local2.sendText('{"type":"admin_update_check"}');
    const upd2 = await local2.next(25000);
    check("unknown version claims NO update (approved may be known)",
      !!upd2 && upd2.includes('"update":false'), upd2 ?? "none");
    local2.end();
    await stopClient();

    // Reverse heal: state.json knows, metadata missing -> metadata written.
    const clientDir = path.join(root, "VIRULE", "client");
    fs.mkdirSync(clientDir, { recursive: true });
    fs.writeFileSync(path.join(clientDir, "state.json"),
      '{"version":1,"created_dev_machine_cred":false,"installed_version":"0.5.0","admin_version":"8.8.8-test.2","created_desktop_shortcut":false}');
    check("client restarts again (sandbox d)", await startClient(root));
    await sleep(700);
    const metaHealed = fs.existsSync(path.join(adminDir, "installed-release.json")) &&
      fs.readFileSync(path.join(adminDir, "installed-release.json"), "utf8").includes("8.8.8-test.2");
    check("install metadata written from surviving state", metaHealed);
    await stopClient();
  }

  if (runs(5)) {
  console.log("5. Virule-Setup.exe end to end (local manifest, sandboxed install)");
    const root = path.join(SANDBOX, "e");
    fs.mkdirSync(root, { recursive: true });
    const clientBytes = fs.readFileSync(CLIENT_EXE);
    const sha = crypto.createHash("sha256").update(clientBytes).digest("hex");
    const server = http.createServer((req, res) => {
      if (req.url.startsWith("/manifest.json")) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({
          version: "0.5.0",
          url: `http://127.0.0.1:${server.address().port}/virule-client.exe`,
          sha256: sha,
          size: clientBytes.length,
        }));
      } else if (req.url.startsWith("/virule-client.exe")) {
        res.setHeader("content-type", "application/octet-stream");
        res.end(clientBytes);
      } else {
        res.statusCode = 404;
        res.end();
      }
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));

    const setup = spawn(SETUP_EXE, [
      `--manifest-url=http://127.0.0.1:${server.address().port}/manifest.json`,
      "--dev-unsigned",
    ], { env: sandboxEnv(root), stdio: "ignore" });
    const setupExit = new Promise((res) => setup.once("exit", (code) => res(code)));

    // The handoff listener comes up first. Origin policy checks, then the
    // real envelope.
    let handoff = null;
    for (let i = 0; i < 40 && !handoff; i++) {
      await sleep(250);
      try {
        handoff = await connect({ port: HANDOFF_PORT, wsPath: "/handoff" });
      } catch { /* not yet */ }
    }
    check("handoff listener answered", !!handoff);
    if (handoff) {
      const hello = await handoff.next();
      check("handoff hello identifies Setup",
        !!hello && hello.includes('"virule_setup":1'), hello ?? "none");
      // A local (no-Origin) connection must be dropped.
      let localDropped = false;
      try {
        const nolocal = await connect({ port: HANDOFF_PORT, wsPath: "/handoff", origin: null });
        localDropped = await nolocal.waitClose(4000);
        nolocal.end();
      } catch { localDropped = true; }
      check("no-Origin handoff connection dropped", localDropped);
      // A malformed envelope earns an error.
      handoff.sendText('{"type":"handoff","v":1,"op":"RUN_ANYTHING","path":"C:\\\\x.exe"}');
      const bad = await handoff.next();
      check("unknown op refused", !!bad && bad.includes('"error"'), bad ?? "none");
      handoff.sendText(JSON.stringify({
        type: "handoff", v: 1, op: "QA_ACCEPT", token: FAKE_TOKEN, game: "Night Jackal",
      }));
      const accepted = await handoff.next();
      check("envelope accepted", !!accepted && accepted.includes("handoff_accepted"), accepted ?? "none");
      handoff.end();
    }

    // The freshly installed client comes up; the fake page owns the flow.
    let page = null;
    for (let i = 0; i < 120 && !page; i++) {
      await sleep(500);
      try {
        const c = await connect();
        const hello = await c.next();
        if (hello && hello.includes('"virule_client":1')) page = c;
        else c.end();
      } catch { /* not yet */ }
    }
    check("installed client came up", !!page);
    if (page) {
      page.sendText('{"type":"surface_ack"}');
      await page.next();
      let result = null;
      for (let i = 0; i < 30 && !result; i++) {
        const m = await page.next(1000);
        if (m && m.includes('"qa_result"')) result = m;
      }
      check("carried envelope reached the client (qa_result pushed)",
        !!result && result.includes(FAKE_TOKEN), result ?? "none");
    }

    const code = await Promise.race([setupExit, sleep(90000).then(() => "timeout")]);
    check("Setup exited cleanly after the release", code === 0, String(code));
    check("client installed into the sandbox",
      fs.existsSync(path.join(root, "Programs", "VIRULE", "virule-client.exe")));
    if (page) page.end();
    // Shut the sandboxed client down.
    try {
      const c = await connect({ origin: null });
      await c.next();
      c.sendText('{"type":"shutdown"}');
      await c.next(2000);
      c.end();
    } catch { /* gone */ }
    server.close();
    // The scenario that once contaminated the real machine: the sandboxed
    // Setup registered, the sandboxed client refreshed. Neither may have
    // touched the real entry.
    checkArpUntouched(arpSnapshot, "after sandboxed Setup end to end");
  }

  if (runs(6)) {
  console.log("6. standalone conclusion revoked by a LATE page-driven admin_install");
    const root = path.join(SANDBOX, "f");
    fs.mkdirSync(root, { recursive: true });
    // Scenario 5's sandbox-installed client may still be exiting; a held
    // singleton would make the sandbox-f client forward-and-exit and every
    // check below would hit the WRONG client. Free the port for real.
    for (let i = 0; i < 10; i++) {
      try {
        const c = await connect({ origin: null });
        await c.next();
        c.sendText('{"type":"shutdown"}');
        await c.next(2000);
        c.end();
        await sleep(900);
      } catch { break; }
    }
    check("client starts (sandbox f)", await startClient(root));
    const local = await connect({ origin: null });
    await local.next();
    local.sendText('{"type":"setup_takeover"}');
    const ack = await local.next();
    check("takeover acknowledged", !!ack && ack.includes('"takeover"'), ack ?? "none");
    // No operation for the whole grace: the standalone card shows (the
    // incident precondition - a closed/asleep browser holding a pending
    // intent). An idle real virule.app tab connecting to the sandbox
    // client changes nothing (not an operation).
    check("released (standalone conclusion reached)", await pollReleased(local, 20000));
    const logFile = path.join(root, "VIRULE", "client", "logs", "virule-client.log");
    const logNow = () => { try { return fs.readFileSync(logFile, "utf8"); } catch { return ""; } };
    check("standalone completion surface reached",
      logNow().includes("standalone completion surface"),
      logNow().split("\n").slice(-5).join(" | "));
    // THE LATE BROWSER: a page connects and drives admin_install (the
    // pending INSTALL_ADMIN it held all along).
    const page = await connect();
    await page.next(); // hello
    page.sendText('{"type":"admin_install","shortcut":false}');
    const started = await page.next();
    check("late admin_install accepted", !!started && started.includes("admin_install_started"), started ?? "none");
    {
      let superseded = false;
      for (let i = 0; i < 20 && !superseded; i++) {
        await sleep(250);
        superseded = logNow().includes("standalone superseded by a browser-owned operation");
      }
      check("standalone conclusion superseded (card closed)", superseded, logNow().split("\n").slice(-6).join(" | "));
    }
    // Shut down promptly: the (doomed) sandbox admin install must not keep
    // downloading the real package.
    page.end();
    local.end();
    await stopClient();
  }

  if (runs(7)) {
  console.log("7. intent arrives DURING the watch: continuation, never a Ready flash");
    const root = path.join(SANDBOX, "g");
    fs.mkdirSync(root, { recursive: true });
    // Free the port for real (scenario 6's client may still be exiting).
    for (let i = 0; i < 10; i++) {
      try {
        const c = await connect({ origin: null });
        await c.next();
        c.sendText('{"type":"shutdown"}');
        await c.next(2000);
        c.end();
        await sleep(900);
      } catch { break; }
    }
    check("client starts (sandbox g)", await startClient(root));
    const logFile = path.join(root, "VIRULE", "client", "logs", "virule-client.log");
    const logNow = () => { try { return fs.readFileSync(logFile, "utf8"); } catch { return ""; } };
    const local = await connect({ origin: null });
    await local.next();
    local.sendText('{"type":"setup_takeover"}');
    const ack = await local.next();
    check("takeover acknowledged", !!ack && ack.includes('"takeover"'), ack ?? "none");
    // ~2s into the 10s watch, the page's pending INSTALL_ADMIN arrives.
    await sleep(2000);
    const page = await connect();
    await page.next();
    page.sendText('{"type":"admin_install","shortcut":false}');
    const started = await page.next();
    check("mid-watch admin_install accepted",
      !!started && started.includes("admin_install_started"), started ?? "none");
    check("released via the continuation", await pollReleased(local, 15000));
    check("continuation surface logged (intent won the watch)",
      logNow().includes("browser-owned Admin operation; native continuation"),
      logNow().split("\n").slice(-5).join(" | "));
    check("Ready/Continue never flashed",
      !logNow().includes("standalone completion surface"),
      logNow().split("\n").slice(-5).join(" | "));
    // Shut down promptly (the doomed sandbox install again).
    page.end();
    local.end();
    await stopClient();
  }

  if (runs(8)) await scenarioCapabilities();
  if (runs(9)) await scenarioSetupCapability(arpSnapshot);

  // Cleanup with retries: the just-shut-down sandbox client (or Dropbox
  // sync) can hold a lock for a moment; a leftover sandbox is never a
  // failure.
  for (let i = 0; i < 10; i++) {
    await sleep(600);
    try {
      fs.rmSync(SANDBOX, { recursive: true, force: true });
      break;
    } catch { /* retry */ }
  }

  checkArpUntouched(arpSnapshot, "end of run");

  if (realWasRunning && fs.existsSync(REAL_CLIENT)) {
    spawn(REAL_CLIENT, [], { detached: true, stdio: "ignore" }).unref();
    let back = false;
    for (let i = 0; i < 40 && !back; i++) {
      await sleep(250);
      try {
        const c = await connect({ origin: null });
        back = !!(await c.next());
        c.end();
      } catch { /* not yet */ }
    }
    console.log(back ? "(the machine's real client is running again)"
                     : "WARNING: the real client did not come back");
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
