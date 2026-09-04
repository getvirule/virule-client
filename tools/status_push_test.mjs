// Lifecycle status push (P1, 2026-09-04): the client PUSHES an ordinary
// status frame to every connected virule.app page when the lifecycle core
// (the admin block + the uninstalling flag) changes, so open tabs converge
// in about a second instead of their 15s poll. Targeted and sandboxed like
// uninstall_lifecycle_test.mjs: LOCALAPPDATA/TEMP point at a throwaway
// tree, the client runs --no-register, and the sandbox guard refuses to
// touch a client that is not this test's.
//
//   1. a page learns "Admin running" flipped TRUE by push (a process
//      starting out of the managed Admin dir), within the ~1s watcher;
//   2. the same page learns it flipped back FALSE by push;
//   3. local control connections receive NO pushes (pages only);
//   4. steady state pushes NOTHING (no chatter between real changes);
//   5. request/response status still works alongside the pushes.
//
// Run: node tools/status_push_test.mjs   (build must exist)

import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLIENT_EXE = path.join(repo, "build", "Release", "x64", "virule-client.exe");
const SANDBOX = path.join(os.tmpdir(), "virule-status-push-test-sandbox");
const PORT = 47612;

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

function connect({ origin = "https://virule.app" } = {}) {
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
      next(timeoutMs = 5000) {
        return new Promise((res) => {
          if (queue.length) return res(queue.shift());
          // A timed-out waiter REMOVES itself: a stale waiter left queued
          // would silently eat the next real push (the trap
          // uninstall_lifecycle_test.mjs documents).
          const waiter = (m) => { clearTimeout(timer); res(m); };
          const timer = setTimeout(() => {
            const i = waiters.indexOf(waiter);
            if (i >= 0) waiters.splice(i, 1);
            res(null);
          }, timeoutMs);
          waiters.push(waiter);
        });
      },
      end() { socket.destroy(); },
      get closed() { return closed; },
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
    }, 12000);
  });
}

// ONE long next() per iteration (stale short waiters eat late pushes).
async function waitPush(conn, needle, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const left = deadline - Date.now();
    if (left <= 0) return null;
    const m = await conn.next(left);
    if (m === null) return null;
    if (m.includes(needle)) return m;
  }
}

function sandboxEnv(root) {
  const temp = path.join(root, "temp");
  fs.mkdirSync(temp, { recursive: true });
  return { ...process.env, LOCALAPPDATA: root, TEMP: temp, TMP: temp };
}

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

let clientProc = null;
async function startClient(root) {
  await freePort();
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
}

async function main() {
  fs.rmSync(SANDBOX, { recursive: true, force: true });
  const root = path.join(SANDBOX, "a");
  const admin = path.join(root, "Programs", "VIRULE", "Admin");
  fs.mkdirSync(path.join(admin, ".resources"), { recursive: true });
  fs.writeFileSync(path.join(admin, "virule.exe"), "stub");
  fs.writeFileSync(path.join(admin, "installed-release.json"), '{"version":"1.0.0-test"}');
  // A runnable process image INSIDE the managed Admin dir: starting and
  // stopping it flips the client's admin_running answer.
  const runnerExe = path.join(admin, "status-push-runner.exe");
  fs.copyFileSync("C:\\Windows\\System32\\ping.exe", runnerExe);

  check("sandbox client starts", await startClient(root));

  const page = await connect();
  await page.next(); // hello
  // SANDBOX GUARD: never proceed against a client that is not this test's.
  page.sendText('{"type":"status"}');
  const st0 = await waitPush(page, '"type":"status"', 5000);
  if (!st0 || !st0.includes('"version":"1.0.0-test"')) {
    console.error("ABORT: not the sandbox client; status =", st0);
    await stopClient();
    process.exit(2);
  }
  check("baseline status: installed, not running",
    st0.includes('"installed":true') && st0.includes('"running":false'), st0);

  const local = await connect({ origin: null });
  await local.next(); // hello

  // Drain the watcher's one initial broadcast (its stored key starts
  // empty, so the first tick after a page connects pushes once).
  await sleep(2500);
  for (;;) { const m = await page.next(200); if (m === null) break; }

  console.log("1. Admin running flips TRUE: pushed to the page within ~2s");
  const runner = spawn(runnerExe, ["-n", "30", "127.0.0.1"],
    { stdio: "ignore", windowsHide: true });
  const t0 = Date.now();
  const up = await waitPush(page, '"running":true', 6000);
  check("status push arrived with running:true", !!up, up ?? "none");
  check("push arrived fast (within 3s, not the 15s poll)",
    up !== null && Date.now() - t0 <= 3000, `${Date.now() - t0}ms`);
  check("push is an ordinary status frame (admin block intact)",
    !!up && up.includes('"type":"status"') && up.includes('"installed":true') &&
    up.includes('"uninstalling":false'), up ?? "none");

  console.log("2. Admin running flips FALSE: pushed again");
  try { runner.kill(); } catch {}
  const down = await waitPush(page, '"running":false', 6000);
  check("status push arrived with running:false", !!down, down ?? "none");

  console.log("3. local control connections receive no pushes");
  const localPush = await local.next(1500);
  check("no push reached the local connection", localPush === null, localPush ?? "");

  console.log("4. steady state pushes nothing");
  const spurious = await page.next(4000);
  check("no pushes without a state change", spurious === null, spurious ?? "");

  console.log("5. request/response status still works alongside pushes");
  page.sendText('{"type":"status"}');
  const st1 = await waitPush(page, '"type":"status"', 5000);
  check("status answered on request", !!st1 && st1.includes('"running":false'), st1 ?? "none");

  page.end();
  local.end();
  await stopClient();
  fs.rmSync(SANDBOX, { recursive: true, force: true });
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
