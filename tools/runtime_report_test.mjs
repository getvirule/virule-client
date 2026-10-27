// End-to-end runtime report test: the Client's REAL runtime report
// (src/client/runtime_report.hpp, one real cycle through
// tests\runtime_report\runtime_report_tests.exe) against the REAL VIRULE
// service code (VIRULE_BACKEND, the Worker in this process over the real
// identity migrations).
//
//   tests\runtime_report\run_tests.bat            builds the exe, then runs this
//   node tools\runtime_report_test.mjs <path to runtime_report_tests.exe>
//
// Starts NO client and never touches port 47612.
//
// Covers: the Client's signed report for an evaluator's assignment, made on
// a machine the service bound to that evaluator, is accepted and kept as the
// Client observed it (running, then not running); the same bytes for another
// evaluator, a tampered state or an unbound machine are refused; an older
// observation never replaces a newer one.

import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const here = path.dirname(fileURLToPath(import.meta.url));
const exe = process.argv[2];
if (!exe || !fs.existsSync(exe)) {
  console.error("usage: node tools/runtime_report_test.mjs <runtime_report_tests.exe>");
  process.exit(2);
}
const backend = path.resolve(here, "..", "..", "..", "VIRULE_BACKEND", "tools");
if (!fs.existsSync(path.join(backend, "local_worker.mjs"))) {
  console.error("VIRULE_BACKEND not found beside the VIRULE workspace: " + backend);
  process.exit(2);
}
const { startLocalWorker } = await import(pathToFileURL(path.join(backend, "local_worker.mjs")).href);
const { accountRowsSql, phcHash, signInDesktop } = await import(pathToFileURL(path.join(backend, "desktop_identity.mjs")).href);
const local = await startLocalWorker();
const { identity, env } = local;

let pass = 0, fail = 0;
const out = console.log;
const check = (name, cond, extra) => {
  if (cond) { pass++; out("ok   " + name); }
  else { fail++; out("FAIL " + name + " :: " + JSON.stringify(extra ?? null)?.slice(0, 500)); }
};
console.error = () => {};
console.log = () => {};

const ORIGIN = "https://virule-api-staging.heath-michaels9441.workers.dev";
const ON = { VIRULE_ENV: "staging", ASSIGNMENT_EXPIRY: "on" };
const transport = async (method, url, { headers = {}, body } = {}) => {
  const r = await local.worker.fetch(new Request(url, { method, headers, body }), { ...env, ...ON }, {});
  const buf = Buffer.from(await r.arrayBuffer());
  let j = null; try { j = JSON.parse(buf.toString("utf8")); } catch { /* not JSON */ }
  return { status: r.status, body: j, bytes: buf, headers: r.headers, setCookies: r.headers.getSetCookie() };
};
const password = "correct horse battery staple " + randomBytes(4).toString("hex");
const phc = await phcHash(password);
async function person(name, capabilities) {
  const email = `${name}@runtime.virule.test`;
  const id = randomBytes(16).toString("hex");
  for (const sql of accountRowsSql({ id, email, displayName: name, phc, capabilities })) identity.exec(sql);
  const s = await signInDesktop({ transport, origin: ORIGIN, email, password });
  s.id = id;
  return s;
}
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const md5 = (b) => createHash("md5").update(b).digest("hex");
const hex = () => randomBytes(16).toString("hex");
const run = promisify(execFile);
/** One real cycle of the Client: its KEY and POST lines. */
async function cycle(seed, assignment, evaluator, running) {
  const { stdout } = await run(exe, ["cycle", seed, assignment, evaluator, running ? "1" : "0"]);
  const lines = stdout.split(/\r?\n/);
  const key = lines.find((l) => l.startsWith("KEY "))?.slice(4);
  const posts = lines.filter((l) => l.startsWith("POST ")).map((l) => {
    const rest = l.slice(5);
    const sp = rest.indexOf(" ");
    return { path: rest.slice(0, sp), body: rest.slice(sp + 1) };
  });
  return { key, posts };
}
const send = (who, p) => who.apiRaw("POST", p.path, { headers: { "content-type": "application/json" }, body: p.body });
const row = (a, key) => identity.prepare("SELECT * FROM evaluation_assignment_machines WHERE assignment_id = ? AND machine_key = ?").get(a, key);

try {
  const dev = await person("dev", ["developer"]);
  const ev = await person("ev", ["evaluator"]);
  const other = await person("other", ["evaluator"]);
  const G = hex();
  await dev.api("POST", "/v1/evaluations/purchases", {
    idempotency_key: randomBytes(16).toString("base64url"), game_uuid: G, quantity: 1,
    game: { title: "Runtime", description: "A game.", genres: ["puzzle"], content_warnings: ["none"], steam_app_id: "480" },
    acceptance: { terms_url: "https://virule.app/terms/", terms_version: "2026-08-27", privacy_url: "https://virule.app/privacy/",
      privacy_version: "2026-10-01", accepted_at: new Date().toISOString(), context: "evaluation_purchase" },
  });
  const pkg = randomBytes(4096);
  const opened = await dev.api("POST", `/v1/evaluations/games/${G}/uploads`, {
    build_uuid: hex(), built_utc: new Date().toISOString(), file_count: 1, content_bytes: pkg.length - 8,
    package_bytes: pkg.length, package_sha256: sha256(pkg), launch_exe: "Game.exe", part_bytes: 32 * 1024 * 1024,
  });
  await dev.apiRaw("PUT", `/v1/evaluations/uploads/${opened.body.session_id}/parts/1`, {
    headers: { "x-virule-part-sha256": sha256(pkg), "x-virule-part-md5": md5(pkg) }, body: pkg,
  });
  await dev.api("POST", `/v1/evaluations/uploads/${opened.body.session_id}/complete`);
  await ev.api("POST", "/v1/assignments/preferences", { preferred_genres: ["puzzle", "board-game", "educational", "experimental", "party-game"], excluded_genres: [], excluded_warnings: [] });
  const offer = (await ev.api("POST", "/v1/assignments/offers/open")).body.offer;
  const A = (await ev.api("POST", `/v1/assignments/offers/${offer.id}/accept`)).body.assignment.id;
  check("setup: the evaluator holds an assignment", /^[0-9a-f]{32}$/.test(A ?? ""));

  const seed = randomBytes(32).toString("hex");
  const first = await cycle(seed, A, ev.id, true);
  check("the Client's cycle produced one report", first.posts.length === 1 && /^[0-9a-f]{64}$/.test(first.key ?? ""), first);
  check("an unbound machine's report is refused (401)", (await send(ev, first.posts[0])).status === 401);
  check("...and nothing is kept", !row(A, first.key));
  const bound = await ev.api("POST", "/v1/assignments/credential", { machine_key: first.key });
  check("the service binds the machine to the evaluator", bound.status === 201);
  const ok1 = await send(ev, first.posts[0]);
  check("the Client's running report is accepted", ok1.status === 200 && ok1.body?.ok === true, ok1.body);
  check("the service keeps it as the Client observed it: running", row(A, first.key)?.report_running === 1, row(A, first.key));
  check("another evaluator cannot send it (404, not theirs)", (await send(other, first.posts[0])).status === 404);
  const tampered = { ...first.posts[0], body: first.posts[0].body.replace('"running":true', '"running":false') };
  check("a tampered state does not verify (401)", (await send(ev, tampered)).status === 401);
  await new Promise((r) => setTimeout(r, 1100));
  const second = await cycle(seed, A, ev.id, false);
  check("a later not-running report is accepted and replaces it", (await send(ev, second.posts[0])).status === 200 && row(A, first.key).report_running === 0);
  check("the older running observation sent again changes nothing", (await send(ev, first.posts[0])).status === 200 && row(A, first.key).report_running === 0);
  const forOther = await cycle(seed, A, other.id, true);
  check("a report naming another evaluator does not verify for this one (401)", (await send(ev, forOther.posts[0])).status === 401);
} catch (e) {
  fail++;
  out("FAIL (exception) " + (e instanceof Error ? e.stack : String(e)));
}
local.cleanup();
out(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
