// End-to-end usage check-in test: the client's REAL manifest request
// (src/shared/manifest_request.hpp, through tests\usage\usage_tests.exe)
// against the REAL VIRULE service code (VIRULE_BACKEND, in this process
// behind a local HTTP server).
//
//   tests\usage\run_tests.bat            builds the exe, then runs this
//   node tools\usage_checkin_test.mjs <path to usage_tests.exe>
//
// Unlike the bridge harnesses this starts NO client and never touches port
// 47612, so it is safe to run with the resident client installed.
//
// Covers: a client on record with no Admin use and no batch, the same row
// later gaining Admin use, the previous-key link, delivery + acknowledgement, a lost acknowledgement (retained,
// re-sent, stored once), a service error (retained; still "reached"), a
// service that predates the check-in (falls back to the plain GET), no
// pending batches (a plain GET, nothing else), an unreachable service
// (retained; counted only for scheduled checks) and the persisted
// update-health record across all of them.

import { execFile } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const here = path.dirname(fileURLToPath(import.meta.url));
const exe = process.argv[2];
if (!exe || !fs.existsSync(exe)) {
  console.error("usage: node tools/usage_checkin_test.mjs <usage_tests.exe>");
  process.exit(2);
}
const backendTools = path.resolve(here, "..", "..", "..", "VIRULE_BACKEND", "tools", "local_worker.mjs");
if (!fs.existsSync(backendTools)) {
  console.error("VIRULE_BACKEND not found beside the VIRULE workspace: " + backendTools);
  process.exit(2);
}
const { startLocalWorker } = await import(pathToFileURL(backendTools).href);
const local = await startLocalWorker();

let pass = 0, fail = 0;
const check = (name, cond, extra) => {
  if (cond) { pass++; console.log("ok   " + name); }
  else { fail++; console.log("FAIL " + name + " :: " + JSON.stringify(extra ?? null)); }
};

// The local "update service": the real Worker, plus switches for the ways a
// real exchange goes wrong between the two machines.
const mode = { kind: "normal" };
const seen = [];
const server = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks).toString("utf8");
  seen.push({ method: req.method, bytes: body.length });
  if (mode.kind === "error") { res.statusCode = 500; res.end("{}"); return; }
  if (mode.kind === "old" && req.method !== "GET") { res.statusCode = 405; res.end("{}"); return; }
  const answer = await local.call(req.method, "https://virule.app/client/admin-manifest.json",
    req.method === "GET" ? undefined : body);
  let text = answer.text;
  if (mode.kind === "lost-ack" && answer.body && "ack" in answer.body) {
    // The service stored the batch; the acknowledgement never arrived.
    const { ack, ...rest } = answer.body;
    void ack;
    text = JSON.stringify(rest);
  }
  res.statusCode = answer.status;
  res.setHeader("content-type", "application/json");
  res.end(text);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = `http://127.0.0.1:${server.address().port}/client/admin-manifest.json`;

const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "virule-checkin-test-"));
const spool = path.join(sandbox, "usage");
const health = path.join(sandbox, "client", "update_health.json");
// Async on purpose: the server above lives in this process, so a blocking
// launch would leave the exe talking to a server that cannot answer.
const execFileAsync = promisify(execFile);
const run = async (...args) => (await execFileAsync(exe, args, { encoding: "utf8" })).stdout.trim();
const fields = (line) => Object.fromEntries(line.split(" ").map((kv) => kv.split("=")));
const seed = (n) => run("seed", spool, String(n));
const request = async (target = url, scheduled = "1", admin = "-", mode = "") =>
  fields(await run("request", target, spool, health, scheduled, admin, mode));
const readHealth = () => { try { return JSON.parse(fs.readFileSync(health, "utf8")); } catch { return null; } };
const events = () => local.count("SELECT COUNT(*) n FROM usage_events");
const [clientKey, rekeyedKey] = (await run("identity")).split(" ");
const installRow = (key) => local.sqlite.prepare("SELECT * FROM usage_installs WHERE client_key = ?").get(key);

const realError = console.error;
console.error = () => {};

// 0. A machine with no usable identity: the check is the plain GET it has
//    always been, and nothing is recorded about it.
let r = await request(url, "1", "-", "anon");
check("no identity: one plain GET, manifest read, nothing on record",
  r.offered === "0" && r.answered === "1" && r.status === "200" && r.version !== "" && r.seen === "0" &&
  seen.length === 1 && seen[0].method === "GET" && local.count("SELECT COUNT(*) n FROM usage_installs") === 0, { r, seen });

// 1. A CLIENT WITH NO ADMIN USE AT ALL: no batch exists, the Admin was never
//    opened (here: not even installed). The check still identifies it.
seen.length = 0;
r = await request();
check("no batch, no Admin: still ONE request, a POST, and the manifest is read",
  r.offered === "0" && r.answered === "1" && r.version !== "" && seen.length === 1 && seen[0].method === "POST", { r, seen });
check("the installation is on record from the check-in alone", r.seen === "1" && r.linked === "0" &&
  !!installRow(clientKey) && installRow(clientKey).client_version === "0.8.6" &&
  installRow(clientKey).admin_version === "" && installRow(clientKey).checkins === 1 &&
  installRow(clientKey).install_id === "0123456789abcdef0123456789abcdef", installRow(clientKey));
check("it recorded no events", events() === 0, events());
check("contact recorded", readHealth()?.last_contact_utc > 0 && readHealth()?.failed_attempts === 0, readHealth());
const firstSeen = installRow(clientKey).first_seen_utc;
await new Promise((res) => setTimeout(res, 1100));
r = await request(url, "1", "0.1.1-alpha.40");
check("a later check-in: same row, first seen kept, last seen advanced, Admin now installed",
  local.count("SELECT COUNT(*) n FROM usage_installs") === 1 && installRow(clientKey).first_seen_utc === firstSeen &&
  installRow(clientKey).last_seen_utc > firstSeen && installRow(clientKey).checkins === 2 &&
  installRow(clientKey).admin_version === "0.1.1-alpha.40", installRow(clientKey));

// 2. Delivery and acknowledgement.
await seed(5);
seen.length = 0;
r = await request();
check("pending batch rides ONE request, a POST",
  seen.length === 1 && seen[0].method === "POST" && seen[0].bytes > 0, seen);
check("acknowledged batch is deleted locally",
  r.offered === "1" && r.answered === "1" && r.delivered === "1" && r.remaining === "0", r);
check("manifest still read from the same answer", r.version !== "", r);
check("5 events stored for this client", events() === 5 &&
  local.count("SELECT COUNT(*) n FROM usage_events WHERE client_key = ?", clientKey) === 5, events());
check("Admin use lands on the SAME installation row (client -> Admin user)",
  local.count("SELECT COUNT(*) n FROM usage_installs") === 1 && installRow(clientKey).first_seen_utc === firstSeen &&
  installRow(clientKey).workspace_id !== "", installRow(clientKey));

// 3. The acknowledgement is lost: retained, re-sent, stored once.
await seed(3);
mode.kind = "lost-ack";
r = await request();
check("lost acknowledgement: the batch is kept", r.answered === "1" && r.delivered === "0" && r.remaining === "1", r);
check("the service had already stored it", events() === 8, events());
mode.kind = "normal";
r = await request();
check("re-sent at the next check and now deleted", r.delivered === "1" && r.remaining === "0", r);
check("no duplicate rows from the retry", events() === 8, events());

// 4. A service error is still contact, and nothing is lost.
await seed(2);
mode.kind = "error";
const contactBefore = readHealth().last_contact_utc;
await new Promise((res) => setTimeout(res, 1100));
r = await request();
check("service error: no manifest, batch kept", r.answered === "0" && r.reached === "1" && r.remaining === "1", r);
check("a service error is NOT a connectivity failure",
  readHealth().failed_attempts === 0 && readHealth().last_contact_utc > contactBefore, readHealth());

// 5. Storage failing behind a healthy manifest: the update check is unharmed.
mode.kind = "normal";
local.controls.failDb = true;
r = await request();
local.controls.failDb = false;
check("storage failure: manifest still answered, batch kept",
  r.answered === "1" && r.version !== "" && r.delivered === "0" && r.remaining === "1", r);

// 6. A service that predates the check-in refuses the POST: fall back to GET.
mode.kind = "old";
seen.length = 0;
r = await request();
check("older service: POST refused, plain GET still gets the manifest",
  r.answered === "1" && r.version !== "" && r.delivered === "0" && r.remaining === "1" &&
  seen.map((s) => s.method).join(",") === "POST,GET", { r, seen });

// 7. Unreachable service: retained, and only scheduled checks count.
const dead = "http://127.0.0.1:1/client/admin-manifest.json";
r = await request(dead, "0");
check("unreachable: nothing reached, batch kept", r.answered === "0" && r.reached === "0" && r.status === "0" && r.remaining === "1", r);
check("an unscheduled failure is not an attempt", readHealth().failed_attempts === 0, readHealth());
await request(dead, "1");
await request(dead, "1");
await request(dead, "1");
check("three scheduled failures are three attempts", readHealth().failed_attempts === 3, readHealth());
const frozen = readHealth().last_contact_utc;
check("last contact is unchanged by failures", frozen > 0 && frozen >= contactBefore, readHealth());

// 8. Connectivity returns: delivery resumes and the record clears.
mode.kind = "normal";
r = await request();
check("service back: the retained batch is delivered", r.delivered === "1" && r.remaining === "0", r);
check("exactly the 2 retained events arrived, once", events() === 10, events());
check("a successful contact clears the failed attempts",
  readHealth().failed_attempts === 0 && readHealth().last_contact_utc >= frozen, readHealth());

// 9. The Admin replaces the machine key on its first run: the new key's
//    check-in names the old one until the service has it.
mode.kind = "error";
r = await request(url, "1", "0.1.1-alpha.40", "rekey");
check("re-keyed, service failing: the link is offered and stays pending", r.linked === "1" && r.seen === "0", r);
mode.kind = "normal";
r = await request(url, "1", "0.1.1-alpha.40", "rekey");
check("re-keyed: the new key is linked to the key it replaced",
  r.linked === "1" && r.seen === "1" && !!installRow(rekeyedKey) &&
  installRow(rekeyedKey).previous_client_key === clientKey, installRow(rekeyedKey));
r = await request(url, "1", "0.1.1-alpha.40", "rekey");
check("once landed, the link is no longer sent", r.linked === "0" && r.seen === "1" &&
  installRow(rekeyedKey).previous_client_key === clientKey, r);

console.error = realError;
server.close();
local.cleanup();
fs.rmSync(sandbox, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
