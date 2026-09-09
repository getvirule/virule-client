// VIRULE STAGING ENVIRONMENT end-to-end test.
//
// Proves the property the staging environment exists for: a machine that
// starts at the staging URL stays in staging for the whole journey, and a
// machine that starts at virule.app stays in production with its signature
// enforcement intact.
//
// It exercises the real artifacts (the staging Virule-Setup.exe, the staging
// virule-client.exe, the staging Admin package served by the staging Worker)
// against the real staging services, sandboxed so the owner's own VIRULE
// installation is never touched:
//
//   - every spawned process gets LOCALAPPDATA pointed at a throwaway tree;
//   - the client is started with --no-register;
//   - the real Apps & Features entry is snapshotted and must be byte
//     identical at the end (the product refuses machine registrations from a
//     redirected environment; this proves it stays that way).
//
// Run:  node tools/staging_env_test.mjs
//       node tools/staging_env_test.mjs --skip-admin-install   (skips the
//       300 MB package download and the Admin launch)

import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.dirname(here);
const viruleRoot = path.dirname(repo);

const STAGING_BASE = "https://virule-api-staging.heath-michaels9441.workers.dev";
const STAGING_ORIGIN = STAGING_BASE;
const PROD_ORIGIN = "https://virule.app";
const STAGING_REPO = "getvirule/virule-staging-releases";
const PROD_HOST = "api.virule.app";
const STAGING_HOST = "virule-api-staging.heath-michaels9441.workers.dev";

const STAGING_CLIENT = path.join(repo, "build", "Release", "x64", "staging", "virule-client.exe");
const STAGING_SETUP = path.join(repo, "build", "Release", "x64", "staging", "Virule-Setup.exe");
// The production-configured client built from the SAME seamed source. The
// staging seam is only trustworthy if a production build of the same tree is
// still a production client, so the test proves that on a fresh build rather
// than on the older signed artifact beside it.
const PROD_CLIENT_FRESH = path.join(repo, "build", "Release", "x64", "prodcheck", "virule-client.exe");
const PROD_CLIENT_SIGNED = path.join(repo, "build", "Release", "x64", "virule-client.exe");
const PROD_CLIENT = fs.existsSync(PROD_CLIENT_FRESH) ? PROD_CLIENT_FRESH : PROD_CLIENT_SIGNED;
const SITE_STAGING_DIST = path.join(viruleRoot, "v1_mvp_site", "dist-staging");
const SITE_PROD_DIST = path.join(viruleRoot, "v1_mvp_site", "dist");

// The sandbox lives in the OS temp dir, NOT under Dropbox: a 300 MB Admin
// install inside a synced folder is both slow and antisocial.
const SANDBOX = path.join(os.tmpdir(), "virule-staging-env-test");

const PORT = 47612;
const SKIP_ADMIN_INSTALL = process.argv.includes("--skip-admin-install");

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
}
function info(m) { console.log(`  --    ${m}`); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wsKey = () => crypto.randomBytes(16).toString("base64");

// ---- the real machine state that must not move ----
const ARP_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ViruleClient";
function readRealArp() {
  try { return execFileSync("reg.exe", ["query", ARP_KEY, "/s"], { encoding: "utf8" }); }
  catch { return null; }
}

// ---- raw WebSocket, so Origin is under test control ----
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
    let len = buf[i + 1] & 0x7f;
    let off = i + 2;
    if (len === 126) {
      if (off + 2 > buf.length) break;
      len = (buf[off] << 8) | buf[off + 1];
      off += 2;
    }
    if (off + len > buf.length) break;
    messages.push(buf.slice(off, off + len).toString("utf8"));
    i = off + len;
  }
  return [messages, buf.slice(i)];
}
function connect({ origin = STAGING_ORIGIN, wsPath = "/v1" } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PORT, "127.0.0.1", () => {
      const headers = [
        `GET ${wsPath} HTTP/1.1`,
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
    const timer = setTimeout(() => { if (!upgraded) { socket.destroy(); reject(new Error("no upgrade")); } }, 8000);
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!upgraded) {
        const end = buffer.indexOf("\r\n\r\n");
        if (end < 0) return;
        const head = buffer.slice(0, end).toString("latin1");
        if (!head.startsWith("HTTP/1.1 101")) { socket.destroy(); return; }
        upgraded = true;
        clearTimeout(timer);
        buffer = buffer.slice(end + 4);
        resolve(api);
      }
      const [messages, rest] = parseFrames(buffer);
      buffer = rest;
      for (const m of messages) {
        if (waiters.length) waiters.shift()(m);
        else queue.push(m);
      }
    });
    socket.on("close", () => { closed = true; while (waiters.length) waiters.shift()(null); });
    socket.on("error", () => { closed = true; if (!upgraded) { clearTimeout(timer); reject(new Error("refused")); } });
    const api = {
      sendText: (s) => { if (!closed) socket.write(maskFrame(s)); },
      next: (timeoutMs = 15000) => new Promise((res) => {
        if (queue.length) return res(queue.shift());
        if (closed) return res(null);
        const t = setTimeout(() => {
          const i = waiters.indexOf(w);
          if (i >= 0) waiters.splice(i, 1);
          res(null);
        }, timeoutMs);
        const w = (m) => { clearTimeout(t); res(m); };
        waiters.push(w);
      }),
      end: () => { closed = true; try { socket.destroy(); } catch {} },
      get closed() { return closed; },
    };
  });
}

// Does the connection get accepted at all? Used for the origin policy.
async function originAccepted(origin) {
  try {
    const c = await connect({ origin });
    const hello = await c.next(4000);
    c.end();
    return typeof hello === "string" && hello.includes('"virule_client":1');
  } catch { return false; }
}

function containsLiteral(file, needle) {
  const bytes = fs.readFileSync(file);
  return bytes.includes(Buffer.from(needle, "ascii")) ||
         bytes.includes(Buffer.from(needle, "utf16le"));
}

async function getText(url) {
  const r = await fetch(url + (url.includes("?") ? "&" : "?") + "t=" + Date.now(),
                        { cache: "no-store" });
  return { status: r.status, text: await r.text(), type: r.headers.get("content-type") || "" };
}

// ---- sandboxed process management ----
let clientProc = null;
const sandboxEnv = (root) => ({ ...process.env, LOCALAPPDATA: root });

async function shutdownWhateverHoldsThePort() {
  try {
    const c = await connect({ origin: null });
    await c.next(3000);
    c.sendText('{"type":"shutdown"}');
    await c.next(2000);
    c.end();
    await sleep(1200);
  } catch { /* nothing listening */ }
}

async function startClient(exe, root) {
  clientProc = spawn(exe, ["--no-register"], { env: sandboxEnv(root), stdio: "ignore" });
  for (let i = 0; i < 40; i++) {
    await sleep(250);
    try {
      const c = await connect({ origin: null });
      const hello = await c.next(3000);
      c.end();
      if (hello && hello.includes('"virule_client":1')) return true;
    } catch { /* not yet */ }
  }
  return false;
}

async function stopClient() {
  await shutdownWhateverHoldsThePort();
  if (clientProc) {
    const p = clientProc;
    clientProc = null;
    await new Promise((res) => {
      const t = setTimeout(() => { try { p.kill(); } catch {} res(); }, 5000);
      p.once("exit", () => { clearTimeout(t); res(); });
    });
  }
  await sleep(400);
}

function killByName(name) {
  try { execFileSync("taskkill.exe", ["/IM", name, "/F", "/T"], { stdio: "ignore" }); } catch {}
}

// =============================================================== the test ===
async function main() {
  console.log("VIRULE STAGING ENVIRONMENT end-to-end test");
  console.log(`  staging url : ${STAGING_BASE}`);
  console.log(`  sandbox     : ${SANDBOX}`);
  console.log("");

  fs.rmSync(SANDBOX, { recursive: true, force: true });
  fs.mkdirSync(SANDBOX, { recursive: true });
  const arpSnapshot = readRealArp();
  await shutdownWhateverHoldsThePort();

  // ---------------------------------------------------------------------
  console.log("1. ONE staging URL serves the site and the services");
  {
    const root = await getText(STAGING_BASE + "/");
    check("GET / is the VIRULE site", root.status === 200 && root.type.includes("text/html") &&
      root.text.includes("<div id=\"root\">"), `status=${root.status}`);
    for (const p of ["/privacy", "/terms"]) {
      const r = await getText(STAGING_BASE + p);
      check(`GET ${p} is served`, r.status === 200 && r.type.includes("text/html"), `status=${r.status}`);
    }
    const health = await getText(STAGING_BASE + "/v1/health");
    check("GET /v1/health is the API", health.status === 200 && health.text.includes('"status":"ok"'));
    const manifest = await getText(STAGING_BASE + "/client/admin-manifest.json");
    check("GET /client/admin-manifest.json is same-origin with the site",
      manifest.status === 200 && manifest.type.includes("application/json"));
    let m = null;
    try { m = JSON.parse(manifest.text); } catch {}
    check("the staging manifest points at the staging release repo",
      !!m && typeof m.url === "string" && m.url.includes(STAGING_REPO), m ? m.url : "unparseable");
    check("the staging manifest carries a package hash and size",
      !!m && /^[0-9a-f]{64}$/.test(m.sha256 || "") && typeof m.size === "number" && m.size > 0);
    globalThis.__stagingManifest = m;
  }

  // ---------------------------------------------------------------------
  console.log("2. the site bundles carry ONE environment each");
  {
    const stagingJs = fs.readdirSync(path.join(SITE_STAGING_DIST, "assets"))
      .filter((f) => f.startsWith("main-") && f.endsWith(".js"))
      .map((f) => fs.readFileSync(path.join(SITE_STAGING_DIST, "assets", f), "utf8")).join("");
    check("the staging bundle offers the STAGING Setup",
      stagingJs.includes(`${STAGING_REPO}/releases/download/client-staging/Virule-Setup.exe`));
    check("the staging bundle contains no production Setup url",
      !stagingJs.includes("getvirule/virule-client/releases"));
    if (fs.existsSync(path.join(SITE_PROD_DIST, "assets"))) {
      const prodJs = fs.readdirSync(path.join(SITE_PROD_DIST, "assets"))
        .filter((f) => f.startsWith("main-") && f.endsWith(".js"))
        .map((f) => fs.readFileSync(path.join(SITE_PROD_DIST, "assets", f), "utf8")).join("");
      check("the production bundle offers the PRODUCTION Setup",
        prodJs.includes("getvirule/virule-client/releases/latest/download/Virule-Setup.exe"));
      check("the production bundle contains no staging url",
        !prodJs.includes(STAGING_REPO) && !prodJs.includes(STAGING_HOST));
    } else {
      info("production site bundle not built locally; skipped its two checks");
    }
    const served = await getText(STAGING_BASE + "/");
    const asset = /\/assets\/(main-[A-Za-z0-9_-]+\.js)/.exec(served.text);
    check("the deployed staging page references a bundle", !!asset);
    if (asset) {
      const js = await getText(`${STAGING_BASE}/assets/${asset[1]}`);
      check("the DEPLOYED bundle is the staging one",
        js.text.includes(`${STAGING_REPO}/releases/download/client-staging/Virule-Setup.exe`) &&
        !js.text.includes("getvirule/virule-client/releases"));
    }
  }

  // ---------------------------------------------------------------------
  console.log("3. the artifacts are the right environment's artifacts");
  {
    check("the staging client exists", fs.existsSync(STAGING_CLIENT), STAGING_CLIENT);
    check("the staging Setup exists", fs.existsSync(STAGING_SETUP), STAGING_SETUP);
    if (fs.existsSync(STAGING_CLIENT)) {
      check("the staging client targets the staging Worker",
        containsLiteral(STAGING_CLIENT, STAGING_HOST));
      check("the staging client carries no production API host",
        !containsLiteral(STAGING_CLIENT, PROD_HOST));
      check("the staging client pins the staging release repo",
        containsLiteral(STAGING_CLIENT, `${STAGING_REPO}/releases/download/`) &&
        !containsLiteral(STAGING_CLIENT, "getvirule/virule-overlay-releases"));
    }
    if (fs.existsSync(STAGING_SETUP)) {
      check("the staging Setup reads the staging client manifest",
        containsLiteral(STAGING_SETUP, `${STAGING_REPO}/releases/download/client-staging/manifest.json`));
    }
    if (fs.existsSync(PROD_CLIENT)) {
      info(`production client under test: ${PROD_CLIENT}`);
      check("the production client still targets virule.app",
        containsLiteral(PROD_CLIENT, "https://virule.app"));
      check("the production client carries no staging host",
        !containsLiteral(PROD_CLIENT, STAGING_HOST));
      check("the production client still pins the production release repos",
        containsLiteral(PROD_CLIENT, "getvirule/virule-client/releases/download/") &&
        containsLiteral(PROD_CLIENT, "getvirule/virule-overlay-releases/releases/download/") &&
        !containsLiteral(PROD_CLIENT, STAGING_REPO));
      check("the production client still carries the PRODUCTION embargo key",
        containsLiteral(PROD_CLIENT, "6e7b1142a6913f202667430c3af50a76ba460f3a784558577cbe4eef3fa4df0b") &&
        !containsLiteral(PROD_CLIENT, "13d5379c752210233590f308b6e4826f9ca5ee1bfeb489d8594b51c6641a5681"));
    } else {
      info("no production client built locally; skipped its checks");
    }
    if (fs.existsSync(PROD_CLIENT_SIGNED)) {
      check("the SIGNED production client artifact was not rebuilt by any of this",
        fs.statSync(PROD_CLIENT_SIGNED).mtimeMs < Date.parse("2026-09-08T00:00:00Z") ||
        !containsLiteral(PROD_CLIENT_SIGNED, STAGING_HOST));
    }
  }

  // ---------------------------------------------------------------------
  console.log("4. the staging client answers the staging site and nothing else");
  {
    const root = path.join(SANDBOX, "client-origin");
    fs.mkdirSync(root, { recursive: true });
    check("staging client starts (sandboxed)", await startClient(STAGING_CLIENT, root));
    check("accepts the staging site origin", await originAccepted(STAGING_ORIGIN));
    check("REFUSES the production site origin", !(await originAccepted(PROD_ORIGIN)));
    check("REFUSES an unrelated origin", !(await originAccepted("https://example.com")));

    const local = await connect({ origin: null });
    await local.next();
    local.sendText('{"type":"status"}');
    const status = await local.next(6000);
    check("answers status over the local control connection",
      !!status && status.includes('"type":"status"'), status || "no answer");
    local.end();
    await stopClient();

    // The mirror image: a PRODUCTION build of the same source answers
    // virule.app and refuses the staging site. The two allowlists do not
    // overlap, which is what keeps a staging page from ever driving a
    // production install.
    if (fs.existsSync(PROD_CLIENT)) {
      const proot = path.join(SANDBOX, "client-origin-prod");
      fs.mkdirSync(proot, { recursive: true });
      check("production client starts (sandboxed)", await startClient(PROD_CLIENT, proot));
      check("production client accepts the production origin", await originAccepted(PROD_ORIGIN));
      check("production client REFUSES the staging origin", !(await originAccepted(STAGING_ORIGIN)));
      await stopClient();
    }
  }

  // ---------------------------------------------------------------------
  console.log("5. Virule-Setup installs the STAGING client with no signature");
  {
    const root = path.join(SANDBOX, "setup");
    fs.mkdirSync(root, { recursive: true });
    const setup = spawn(STAGING_SETUP, [], { env: sandboxEnv(root), stdio: "ignore" });
    const installed = path.join(root, "Programs", "VIRULE", "virule-client.exe");
    let ok = false;
    for (let i = 0; i < 180; i++) {
      await sleep(1000);
      if (fs.existsSync(installed) && fs.statSync(installed).size > 0) { ok = true; break; }
    }
    check("Setup downloaded and installed the client into the sandbox", ok, installed);
    if (ok) {
      check("the installed client is the STAGING client",
        containsLiteral(installed, STAGING_HOST) && !containsLiteral(installed, PROD_HOST));
      const local = fs.readFileSync(STAGING_CLIENT);
      const got = fs.readFileSync(installed);
      check("it is byte-identical to the published staging client",
        crypto.createHash("sha256").update(local).digest("hex") ===
        crypto.createHash("sha256").update(got).digest("hex"));
    }
    // Setup hands over to the client it installed; let it settle, then stop.
    await sleep(4000);
    await shutdownWhateverHoldsThePort();
    try { setup.kill(); } catch {}
    killByName("Virule-Setup.exe");
    await sleep(800);
    const now = readRealArp();
    check("the real Apps & Features entry was not touched by the sandboxed Setup",
      now === arpSnapshot);
  }

  // ---------------------------------------------------------------------
  if (SKIP_ADMIN_INSTALL) {
    console.log("6. Admin install through the bridge  (skipped: --skip-admin-install)");
  } else {
    console.log("6. the staging client installs the STAGING Admin through the bridge");
    const root = path.join(SANDBOX, "admin");
    fs.mkdirSync(root, { recursive: true });
    check("staging client starts (sandboxed)", await startClient(STAGING_CLIENT, root));
    const page = await connect({ origin: STAGING_ORIGIN });
    await page.next(); // hello
    page.sendText('{"type":"admin_install","shortcut":false}');
    let result = null;
    const deadline = Date.now() + 20 * 60 * 1000;
    while (Date.now() < deadline) {
      const m = await page.next(60000);
      if (m === null) continue;
      if (m.includes('"type":"admin_result"')) { result = m; break; }
    }
    check("the install reported a result", !!result, "timed out");
    check("the install SUCCEEDED against unsigned staging artifacts",
      !!result && (result.includes('"state":"installed"') || result.includes('"state":"updated"')),
      result || "");
    const adminExe = path.join(root, "Programs", "VIRULE", "Admin", "virule.exe");
    check("the managed Admin is installed", fs.existsSync(adminExe), adminExe);
    const rel = path.join(root, "Programs", "VIRULE", "Admin", "installed-release.json");
    if (fs.existsSync(rel)) {
      const j = JSON.parse(fs.readFileSync(rel, "utf8"));
      const m = globalThis.__stagingManifest;
      check("the installed version is the staging manifest's version",
        !!m && j.version === m.version, `installed=${j.version} manifest=${m && m.version}`);
    } else {
      check("installed-release.json was written", false, rel);
    }
    if (fs.existsSync(adminExe)) {
      check("the installed Admin is a STAGING build",
        containsLiteral(adminExe, STAGING_HOST) && !containsLiteral(adminExe, PROD_HOST));
    }
    // A fresh install launches the Admin. Prove it started, then stop it:
    // this is a sandbox, not the owner's machine.
    let launched = false;
    for (let i = 0; i < 30; i++) {
      await sleep(1000);
      try {
        const out = execFileSync("tasklist.exe", ["/FI", "IMAGENAME eq virule.exe"], { encoding: "utf8" });
        if (out.includes("virule.exe")) { launched = true; break; }
      } catch {}
    }
    check("the Admin launched automatically after a fresh install", launched);
    killByName("virule.exe");
    killByName("ViruleAdminHost.exe");
    page.end();
    await stopClient();

    // ---- update through the normal flow -----------------------------------
    console.log("7. an approved staging update reinstalls through the same flow");
    {
      check("staging client restarts (same sandbox)", await startClient(STAGING_CLIENT, root));
      const p2 = await connect({ origin: STAGING_ORIGIN });
      await p2.next();
      p2.sendText('{"type":"status"}');
      const st = await p2.next(8000);
      check("the client reports the Admin as installed",
        !!st && st.includes('"installed":true'), st || "no status");
      p2.sendText('{"type":"admin_install","shortcut":false}');
      let r2 = null;
      const dl = Date.now() + 20 * 60 * 1000;
      while (Date.now() < dl) {
        const m = await p2.next(60000);
        if (m === null) continue;
        if (m.includes('"type":"admin_result"')) { r2 = m; break; }
      }
      check("a re-install over an existing install reports a result", !!r2, "timed out");
      check("the re-install succeeded",
        !!r2 && (r2.includes('"state":"installed"') || r2.includes('"state":"updated"')), r2 || "");
      check("the known-good install survived", fs.existsSync(adminExe));
      killByName("virule.exe");
      killByName("ViruleAdminHost.exe");
      p2.end();
      await stopClient();
    }
  }

  // ---------------------------------------------------------------------
  console.log("8. production is untouched and still strict");
  {
    const prod = await getText("https://virule.app/client/admin-manifest.json");
    let pm = null;
    try { pm = JSON.parse(prod.text); } catch {}
    check("the production admin manifest is served", prod.status === 200 && !!pm);
    check("it still points at the PRODUCTION release repo",
      !!pm && pm.url.includes("getvirule/virule-overlay-releases"), pm ? pm.url : "");
    check("it does not point at anything staging",
      !!pm && !pm.url.includes(STAGING_REPO) && !pm.url.includes(STAGING_HOST));
    const api = await getText("https://api.virule.app/v1/health");
    check("the production API is healthy", api.status === 200 && api.text.includes('"status":"ok"'));
    const site = await getText("https://virule.app/");
    check("the production site is served", site.status === 200 && site.type.includes("text/html"));
    check("the real Apps & Features entry is unchanged", readRealArp() === arpSnapshot);
  }

  console.log("");
  console.log(`  ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("HARNESS ERROR:", e);
  process.exit(1);
});
