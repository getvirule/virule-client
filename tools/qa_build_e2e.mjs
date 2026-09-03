/**
 * QA GAME DELIVERY end-to-end, against the REAL production service and REAL
 * private artifacts.
 *
 * This drives the actual shipped surfaces: the VIRULE backend over HTTPS, the
 * running virule-client.exe over its loopback bridge, and the filesystem the
 * client writes. Nothing is mocked.
 *
 * THE MACHINE PLAYS THE TESTER. The synthetic game is published by a
 * throwaway developer key generated here, so this machine's own identity is
 * NOT the issuer and can redeem normally, exactly as a real tester's would.
 * (Super Admin QA TEST MODE is deliberately not used: it redeems with an
 * ephemeral key it then discards, so a test-mode credential can never satisfy
 * a later proof-of-possession call. That is a pre-existing property of test
 * mode, not of this feature.)
 *
 * Every artifact it touches is synthetic. It backs up and restores the real
 * credential and client state files, and prints the KV records to delete.
 *
 * Preconditions:
 *   - virule-client.exe (0.3.1+) running:  build\Release\x64\virule-client.exe --no-register
 *   - the two synthetic build artifacts published (see QA_E2E_* below)
 *
 *   node tools/qa_build_e2e.mjs
 */

import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const PORT = 47612;
const API = process.env.QA_API || "https://api.virule.app";

const GAME = process.env.QA_E2E_GAME || "7e5109c14a2b48d3b6f0c9a1e2d34567";
const BUILD1 = {
  build_uuid: process.env.QA_E2E_B1 || "11aa22bb33cc44dd55ee66ff77008811",
  release_id: process.env.QA_E2E_B1_RELEASE || "381788063",
  asset_id: process.env.QA_E2E_B1_ASSET || "542322663",
  sha256: process.env.QA_E2E_B1_SHA || "60d09da8b6cc14853f3776b89ea416c750dc3ac1febe7f733647ae6d7a69752b",
  size: Number(process.env.QA_E2E_B1_SIZE || 1859),
};
const BUILD2 = {
  build_uuid: process.env.QA_E2E_B2 || "22bb33cc44dd55ee66ff770088119922",
  release_id: process.env.QA_E2E_B2_RELEASE || "381788088",
  asset_id: process.env.QA_E2E_B2_ASSET || "542322723",
  sha256: process.env.QA_E2E_B2_SHA || "e7f9debba2a5217e0272451d57209c13fb072e20c97c69bf0d1cf428f159c055",
  size: Number(process.env.QA_E2E_B2_SIZE || 1859),
};
const EXE_REL = "NightJackalQA.exe";
const REPO = "getvirule/virule-qa-builds";

const LOCAL = process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
const SECURITY_DIR = path.join(LOCAL, "VIRULE", "security");
const CLIENT_DIR = path.join(LOCAL, "VIRULE", "client");
const CRED_FILE = path.join(SECURITY_DIR, "qa_tester.cred");
const STATE_FILE = path.join(CLIENT_DIR, "state.json");
const INSTALLS_FILE = path.join(CLIENT_DIR, "qa_installs.json");
const LIB_ROOT = path.join(os.tmpdir(), "virule-qa-e2e-library");

let pass = 0, fail = 0;
const check = (name, ok, detail) => {
  if (ok) { pass++; console.log("  ok    " + name); }
  else { fail++; console.log("  FAIL  " + name + (detail !== undefined ? "  " + JSON.stringify(detail) : "")); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------- service side ---
const makeKeys = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { pub: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex"), priv: privateKey };
};
const signHex = (priv, msg) => crypto.sign(null, Buffer.from(msg, "utf8"), priv).toString("hex");
const nowUtc = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const rid = () => crypto.randomBytes(16).toString("hex");

async function post(pathname, body) {
  const r = await fetch(API + pathname, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  let parsed = null;
  try { parsed = await r.json(); } catch (e) {}
  return { status: r.status, body: parsed };
}

/**
 * A DETERMINISTIC key from a fixed seed. The publishing identity, the game
 * and the organization all have to be stable across runs, because the service
 * pins the developer key to a game on first publish and writes the
 * organization into the immutable artifact record. Random values would be
 * refused by those very rules on the second run. Test-only material that
 * authorizes nothing beyond this synthetic game.
 */
const fixedKeys = (seedHex) => {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedHex, "hex"),
  ]);
  const priv = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pub = crypto.createPublicKey(priv).export({ format: "der", type: "spki" })
    .subarray(-32).toString("hex");
  return { pub, priv };
};

const dev = fixedKeys("7e5109c14a2b48d3b6f0c9a1e2d3456700ff11ee22dd33cc44bb55aa66997788");
const org = process.env.QA_E2E_ORG || "b41d90c7e8a24f5390c6d2b7a1e4f836";
// The tester is fresh per run: a new relationship is fine, because it is
// pinned to the fixed developer key above.
const tester = rid();

const issueInvite = () => {
  const ts = nowUtc();
  return post("/v1/qa/invite", {
    organization_id: org, tester_id: tester,
    organization_name: "Umbrella QA Co", game_name: "Night Jackal 2", game_uuid: GAME,
    timestamp: ts, developer_public_key: dev.pub,
    developer_signature: signHex(dev.priv, `virule-qa-invite.v1|${org}|${tester}|${ts}`),
  });
};

const registerBuild = (b) => {
  const ts = nowUtc();
  return post("/v1/qa/build/register", {
    game_uuid: GAME, build_uuid: b.build_uuid, organization_id: org,
    repo: REPO, tag: "qa-" + b.build_uuid, release_id: b.release_id,
    asset_id: b.asset_id, asset_name: "qa-" + b.build_uuid + ".zip",
    sha256: b.sha256, size: b.size, exe_rel_path: EXE_REL, format: "zip",
    timestamp: ts, developer_public_key: dev.pub,
    developer_signature: signHex(dev.priv,
      `virule-qa-build-register.v1|${GAME}|${b.build_uuid}|${b.sha256}|${ts}`),
  });
};

const publishRoster = (roster) => {
  const ts = nowUtc();
  return post("/v1/qa/access", {
    game_uuid: GAME, roster, timestamp: ts, developer_public_key: dev.pub,
    developer_signature: signHex(dev.priv, `virule-qa-access.v1|${GAME}|${roster}|${ts}`),
  });
};

// ----------------------------------------------------------- bridge side ---
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
  const out = [];
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
    out.push({ opcode, text: buf.slice(off, off + len).toString("utf8") });
    i = off + len;
  }
  return [out, buf.slice(i)];
}

function connect() {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PORT, "127.0.0.1", () => {
      socket.write([
        "GET /v1 HTTP/1.1", `Host: 127.0.0.1:${PORT}`, "Upgrade: websocket",
        "Connection: Upgrade", `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString("base64")}`,
        "Sec-WebSocket-Version: 13", "Origin: https://virule.app", "",
      ].join("\r\n") + "\r\n");
    });
    let buffer = Buffer.alloc(0), upgraded = false;
    const queue = [], waiters = [];
    const api = {
      send(o) { socket.write(maskFrame(JSON.stringify(o))); },
      next(timeoutMs = 8000) {
        return new Promise((res) => {
          if (queue.length) return res(queue.shift());
          const t = setTimeout(() => res(null), timeoutMs);
          waiters.push((m) => { clearTimeout(t); res(m); });
        });
      },
      // Wait for a specific message type, ignoring anything else.
      async await(type, timeoutMs = 120000) {
        const deadline = Date.now() + timeoutMs;
        for (;;) {
          const left = deadline - Date.now();
          if (left <= 0) return null;
          const m = await api.next(Math.min(left, 5000));
          if (m === null) continue;
          let p = null;
          try { p = JSON.parse(m); } catch (e) { continue; }
          if (p.type === type) return p;
        }
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
        if (!head.startsWith("HTTP/1.1 101")) { socket.destroy(); return reject(new Error("no upgrade")); }
        upgraded = true;
        resolve(api);
      }
      const [msgs, rest] = parseFrames(buffer);
      buffer = rest;
      for (const m of msgs) {
        if (m.opcode !== 0x1) continue;
        const w = waiters.shift();
        if (w) w(m.text); else queue.push(m.text);
      }
    });
    socket.on("error", () => reject(new Error("refused")));
    setTimeout(() => { if (!upgraded) { socket.destroy(); reject(new Error("timeout")); } }, 10000);
  });
}

const status = async (c) => {
  c.send({ type: "qa_build_status", game_uuid: GAME });
  return await c.await("qa_build_status", 40000);
};

// ----------------------------------------------------------------- files ---
const backups = new Map();
function backup(file) {
  backups.set(file, fs.existsSync(file) ? fs.readFileSync(file) : null);
}
function restore() {
  for (const [file, data] of backups) {
    if (data === null) { if (fs.existsSync(file)) fs.rmSync(file, { force: true }); }
    else fs.writeFileSync(file, data);
  }
}
function readState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); } catch (e) { return {}; }
}
function writeState(s) {
  fs.mkdirSync(CLIENT_DIR, { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(s));
}

// ------------------------------------------------------------------ main ---
async function main() {
  console.log("QA GAME DELIVERY end-to-end");
  console.log("  api " + API + "   game " + GAME);
  console.log("");

  backup(CRED_FILE); backup(STATE_FILE); backup(INSTALLS_FILE);
  fs.rmSync(LIB_ROOT, { recursive: true, force: true });
  fs.mkdirSync(LIB_ROOT, { recursive: true });

  let c = await connect();
  await c.next(); // hello

  // ---- 1. the invitation carries the game, and ACCEPT writes a credential
  console.log("invitation and credential");
  const inv = await issueInvite();
  check("invite issued", inv.status === 200 && !!inv.body.url, inv.body);
  const token = (inv.body.url || "").split("#")[1];

  c.send({ type: "qa_accept", token });
  const accepted = await c.await("accepted", 10000);
  check("client accepted the invitation", accepted !== null);
  const qaResult = await c.await("qa_result", 60000);
  check("client redeemed it as this machine",
    qaResult !== null && qaResult.state === "verified", qaResult);
  check("the tester credential was written", fs.existsSync(CRED_FILE));

  // ---- 2. no build published yet
  console.log("");
  console.log("before a build exists");
  let s = await status(c);
  check("status answers", s !== null, s);
  check("an authorized tester with no build is not offered one",
    s && (s.state === "no_build" || s.state === "unauthorized"), s && s.state);

  // ---- 3. publish and authorize
  console.log("");
  console.log("publish and authorize");
  check("build 1 registered", (await registerBuild(BUILD1)).status === 200);
  check("roster published", (await publishRoster(tester)).status === 200);

  // ---- 4. first install asks for a location
  console.log("");
  console.log("first install asks where games go");
  let st = readState();
  delete st.qa_games_root;
  writeState(st);
  await sleep(16000); // let the client's 15s status memo lapse
  s = await status(c);
  check("with no library root the build reads not_installed",
    s && s.state === "not_installed", s && s.state);
  check("and the client reports it has no root", s && s.have_root === false, s && s.have_root);

  c.send({ type: "qa_build_install", game_uuid: GAME });
  await c.await("qa_build_started", 10000);
  const needRoot = await c.await("qa_build_result", 60000);
  check("installing without a root asks for one instead of guessing",
    needRoot && needRoot.state === "need_root", needRoot);
  check("nothing was written outside a chosen root",
    fs.readdirSync(LIB_ROOT).length === 0);

  // The picker itself is a modal Windows dialog and cannot be driven from a
  // harness; recording the choice is exactly what it does on OK.
  st = readState();
  st.qa_games_root = LIB_ROOT.replace(/\\/g, "/");
  writeState(st);
  s = await status(c);
  check("a recorded root is recognized", s && s.have_root === true, s && s.have_root);

  // ---- 5. install
  console.log("");
  console.log("install");
  c.send({ type: "qa_build_install", game_uuid: GAME });
  await c.await("qa_build_started", 10000);
  const installed = await c.await("qa_build_result", 180000);
  check("install completed", installed && installed.state === "installed", installed);

  const gameDir = path.join(LIB_ROOT, "VIRULE QA", GAME);
  const gameExe = path.join(gameDir, EXE_REL);
  check("the managed game directory exists", fs.existsSync(gameDir));
  check("the package contents are at the install root (no extra nesting)",
    fs.existsSync(gameExe), fs.existsSync(gameDir) ? fs.readdirSync(gameDir) : null);
  check("the package's own data landed too",
    fs.existsSync(path.join(gameDir, "assets", "data.bin")));
  check("no staging or download leftovers",
    !fs.readdirSync(path.join(LIB_ROOT, "VIRULE QA")).some((n) => n.startsWith(".")),
    fs.readdirSync(path.join(LIB_ROOT, "VIRULE QA")));

  const rec = JSON.parse(fs.readFileSync(INSTALLS_FILE, "utf8")).installs
    .find((r) => r.game_uuid === GAME);
  check("a managed install record was written by ID", !!rec && rec.build_uuid === BUILD1.build_uuid, rec);
  check("the record carries the package hash it verified",
    rec && rec.sha256 === BUILD1.sha256, rec && rec.sha256);

  s = await status(c);
  check("status reads installed", s && s.state === "installed", s && s.state);
  check("the game was NOT auto-launched", s && s.state !== "running");

  // ---- 6. play
  console.log("");
  console.log("play");
  c.send({ type: "qa_build_play", game_uuid: GAME });
  const playing = await c.await("qa_build_playing", 10000);
  check("play acknowledged", playing !== null);
  await sleep(2500);
  s = await status(c);
  check("status reads running while the game is alive", s && s.state === "running", s && s.state);

  // ---- 7. a running game blocks an update and is never killed
  console.log("");
  console.log("update while running");
  check("build 2 registered", (await registerBuild(BUILD2)).status === 200);
  c.send({ type: "qa_build_update", game_uuid: GAME });
  await c.await("qa_build_started", 10000);
  const blocked = await c.await("qa_build_result", 60000);
  check("update on a running game is refused", blocked && blocked.state === "game_running", blocked);
  s = await status(c);
  check("the game is still running (it was never killed)", s && s.state === "running", s && s.state);
  check("the installed build is untouched",
    JSON.parse(fs.readFileSync(INSTALLS_FILE, "utf8")).installs
      .find((r) => r.game_uuid === GAME).build_uuid === BUILD1.build_uuid);

  console.log("  ..  waiting for the game to exit on its own");
  for (let i = 0; i < 60; i++) {
    await sleep(2000);
    s = await status(c);
    if (s && s.state !== "running") break;
  }
  check("the game exited normally", s && s.state !== "running", s && s.state);
  check("a newer authorized build reads update_available",
    s && s.state === "update_available", s && s.state);

  // ---- 8. update
  console.log("");
  console.log("update");
  c.send({ type: "qa_build_update", game_uuid: GAME });
  await c.await("qa_build_started", 10000);
  const updated = await c.await("qa_build_result", 180000);
  check("update completed", updated && updated.state === "updated", updated);
  const rec2 = JSON.parse(fs.readFileSync(INSTALLS_FILE, "utf8")).installs
    .find((r) => r.game_uuid === GAME);
  check("the record now names the new build", rec2 && rec2.build_uuid === BUILD2.build_uuid, rec2 && rec2.build_uuid);
  check("the new package's bytes are on disk", rec2 && rec2.sha256 === BUILD2.sha256);
  check("the previous install was cleaned up",
    !fs.existsSync(path.join(LIB_ROOT, "VIRULE QA", ".previous-" + GAME)));
  s = await status(c);
  check("status reads installed and current", s && s.state === "installed", s && s.state);

  // ---- 9. the operation survives the browser closing
  console.log("");
  console.log("browser close during an operation");
  c.send({ type: "qa_build_remove", game_uuid: GAME });
  await c.await("qa_build_removed", 30000);
  c.end();
  const c2 = await connect();
  await c2.next();
  c2.send({ type: "qa_build_install", game_uuid: GAME });
  await c2.await("qa_build_started", 10000);
  c2.end();                       // the page goes away mid-install
  console.log("  ..  page disconnected; the client should finish alone");
  await sleep(15000);
  const c3 = await connect();
  await c3.next();
  const after = await status(c3);
  check("the install finished with no page connected",
    after && (after.state === "installed" || after.state === "update_available"), after && after.state);
  check("the returning page sees the installed build",
    fs.existsSync(gameExe));
  c = c3;

  // ---- 10. remove
  console.log("");
  console.log("remove");
  const marker = path.join(LIB_ROOT, "a-tester-file-that-must-survive.txt");
  fs.writeFileSync(marker, "not VIRULE's to delete");
  c.send({ type: "qa_build_remove", game_uuid: GAME });
  const removed = await c.await("qa_build_removed", 60000);
  check("remove acknowledged", removed !== null);
  check("the managed game directory is gone", !fs.existsSync(gameDir));
  check("the tester's library root still exists", fs.existsSync(LIB_ROOT));
  check("an unrelated file in the library root survived", fs.existsSync(marker));
  check("the managed install record was dropped",
    !JSON.parse(fs.readFileSync(INSTALLS_FILE, "utf8")).installs.some((r) => r.game_uuid === GAME));
  s = await status(c);
  check("status returns to not_installed", s && s.state === "not_installed", s && s.state);

  // ---- 11. authorization is the server's, not the page's
  console.log("");
  console.log("authorization cannot be asserted by the page");
  check("roster cleared", (await publishRoster("")).status === 200);
  await sleep(16000);
  s = await status(c);
  check("a revoked tester is no longer offered the build",
    s && (s.state === "unauthorized" || s.state === "no_build"), s && s.state);
  c.send({ type: "qa_build_install", game_uuid: GAME });
  await c.await("qa_build_started", 10000);
  const refused = await c.await("qa_build_result", 60000);
  check("and an install is refused outright",
    refused && (refused.state === "not_authorized" || refused.state === "no_build"), refused);
  check("nothing was installed", !fs.existsSync(gameDir));

  c.end();

  console.log("");
  console.log(`${pass} passed, ${fail} failed`);
  console.log("");
  console.log("SYNTHETIC KV RECORDS TO DELETE:");
  console.log("  qarel1:" + org + ":" + tester);
  console.log("  qainv1:" + token);
  console.log("  qaacc1:" + GAME);
  console.log("  qacur1:" + GAME);
  console.log("  qabld1:" + BUILD1.build_uuid);
  console.log("  qabld1:" + BUILD2.build_uuid);
}

main()
  .catch((e) => { console.error("harness error:", e.message); fail++; })
  .finally(() => {
    restore();
    fs.rmSync(LIB_ROOT, { recursive: true, force: true });
    console.log("");
    console.log("restored the real credential and client state; removed the test library root");
    process.exit(fail === 0 ? 0 : 1);
  });
