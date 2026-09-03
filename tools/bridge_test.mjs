// VIRULE Client bridge test harness. Raw-socket WebSocket client so every
// header (Origin included) and every frame byte is under test control.
//
// Run with the client already started:  node tools/bridge_test.mjs
// (start it as:  build\Release\x64\virule-client.exe --no-register )

import net from "node:net";
import crypto from "node:crypto";

const PORT = 47612;
let pass = 0;
let fail = 0;

function check(name, ok, detail = "") {
  if (ok) {
    pass++;
    console.log(`  ok    ${name}`);
  } else {
    fail++;
    console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`);
  }
}

function wsKey() {
  return crypto.randomBytes(16).toString("base64");
}

function maskFrame(payload, { masked = true, opcode = 0x1 } = {}) {
  const data = Buffer.from(payload, "utf8");
  const head = [0x80 | opcode];
  if (data.length < 126) head.push((masked ? 0x80 : 0) | data.length);
  else {
    head.push((masked ? 0x80 : 0) | 126, (data.length >> 8) & 0xff, data.length & 0xff);
  }
  if (!masked) return Buffer.concat([Buffer.from(head), data]);
  const mask = crypto.randomBytes(4);
  const body = Buffer.from(data);
  for (let i = 0; i < body.length; i++) body[i] ^= mask[i & 3];
  return Buffer.concat([Buffer.from(head), mask, body]);
}

// Parse server frames out of a rolling buffer; returns [messages, rest].
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

// Open one connection; returns helpers. `origin: null` = local control.
function connect({ origin = "https://virule.app", path = "/v1" } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PORT, "127.0.0.1", () => {
      const headers = [
        `GET ${path} HTTP/1.1`,
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
      socket,
      get closed() { return closed; },
      sendText(payload, opts) { socket.write(maskFrame(payload, opts)); },
      sendRaw(buf) { socket.write(buf); },
      next(timeoutMs = 4000) {
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
      if (!upgraded) {
        socket.destroy();
        reject(new Error("upgrade timeout"));
      }
    }, 12000);
  });
}

async function main() {
  console.log("A. discovery + handshake");
  {
    const c = await connect();
    const hello = await c.next();
    check("hello identifies the client", !!hello && hello.includes('"virule_client":1'), hello ?? "none");
    c.sendText('{"type":"status"}');
    const status = await c.next();
    check("status answers version + capabilities",
      !!status && status.includes('"version"') && status.includes('"qa"') && status.includes('"uninstall"'),
      status ?? "none");
    c.end();
  }

  console.log("A2. connected-page count (Setup's browser-handoff signal)");
  {
    // Setup asks over a LOCAL control connection whether a virule.app PAGE
    // reached the client. A non-zero answer means the browser is still
    // driving the flow and Setup must not open a second window.
    const pagesFrom = (text) => {
      const m = /"pages":(\d+)/.exec(text ?? "");
      return m ? Number(m[1]) : null;
    };

    const local = await connect({ origin: null });
    await local.next(); // hello
    local.sendText('{"type":"status"}');
    const idle = await local.next();
    check("no pages connected reads 0", pagesFrom(idle) === 0, idle ?? "none");

    const page = await connect();
    await page.next(); // hello
    local.sendText('{"type":"status"}');
    const withPage = await local.next();
    check("one open page reads 1 (local connections never count)",
      pagesFrom(withPage) === 1, withPage ?? "none");

    page.end();
    await new Promise((r) => setTimeout(r, 400));
    local.sendText('{"type":"status"}');
    const after = await local.next();
    check("a closed page stops counting", pagesFrom(after) === 0, after ?? "none");
    local.end();
  }

  console.log("B. versioned path");
  {
    let refused = false;
    try { await connect({ path: "/" }); } catch { refused = true; }
    check("unversioned path is refused", refused);
    let refused2 = false;
    try { await connect({ path: "/v2" }); } catch { refused2 = true; }
    check("unknown version is refused", refused2);
  }

  console.log("C. origin policy");
  {
    let dropped = false;
    try {
      const c = await connect({ origin: "https://evil.example" });
      // If the 101 sneaks through, the connection must still die instantly.
      dropped = await c.waitClose(1500);
    } catch { dropped = true; }
    check("foreign web origin is dropped", dropped);

    const local = await connect({ origin: null });
    const hello = await local.next();
    check("local no-origin control connection accepted", !!hello && hello.includes('"virule_client"'));
    local.end();
  }

  console.log("D. frame discipline");
  {
    const c = await connect();
    await c.next(); // hello
    c.sendText('{"type":"status"}', { masked: false });
    const died = await c.waitClose(2500);
    check("unmasked client frame closes the connection", died);
  }

  console.log("E. message validation");
  {
    const c = await connect();
    await c.next(); // hello
    c.sendText('{"type":"qa_accept","token":"nothex"}');
    const r1 = await c.next();
    check("qa_accept with malformed token answers error", r1 === '{"type":"error"}', r1 ?? "none");
    c.sendText('{"type":"launch_game","path":"C:\\\\evil.exe"}');
    const r2 = await c.next();
    check("unknown command answers error", r2 === '{"type":"error"}', r2 ?? "none");
    c.sendText('{"type":"uninstall","nonce":"00000000000000000000000000000000","timestamp":"2026-09-02T00:00:00Z","signature":"' + "0".repeat(128) + '"}');
    const r3 = await c.next();
    check("uninstall with invalid authorization is refused", r3 === '{"type":"error"}', r3 ?? "none");
    c.end();
  }

  console.log("F. privileged ops need a page origin");
  {
    const local = await connect({ origin: null });
    await local.next(); // hello
    local.sendText('{"type":"uninstall","nonce":"00000000000000000000000000000000","timestamp":"2026-09-02T00:00:00Z","signature":"' + "0".repeat(128) + '"}');
    const r = await local.next();
    check("uninstall from a local no-origin connection is refused", r === '{"type":"error"}', r ?? "none");
    local.end();
  }

  console.log("G. qa_accept end-to-end against the real service (invalid token)");
  {
    const c = await connect();
    await c.next(); // hello
    const bogus = crypto.randomBytes(32).toString("hex");
    c.sendText(`{"type":"qa_accept","token":"${bogus}"}`);
    const r1 = await c.next();
    check("qa_accept acknowledged", r1 === '{"type":"accepted"}', r1 ?? "none");
    // The client redeems against production; a random token resolves
    // invalid and the result is pushed to this page connection.
    const r2 = await c.next(20000);
    check("qa_result pushed with state invalid",
      !!r2 && r2.includes('"qa_result"') && r2.includes(`"${bogus}"`) && r2.includes('"invalid"'),
      r2 ?? "none");
    c.end();
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("harness error:", err.message);
  process.exit(1);
});
