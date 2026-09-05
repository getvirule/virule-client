// P3 ARP contamination regression (2026-09-05): a SANDBOXED Virule-Setup
// run must never touch the REAL machine registrations.
//
// The incident: takeover_test scenario 5 spawned the real Virule-Setup.exe
// with only LOCALAPPDATA redirected at a throwaway tree. The filesystem
// world was sandboxed; HKCU was not. Setup's registration step stamped the
// sandbox paths into the real Apps & Features entry
// (HKCU\...\Uninstall\ViruleClient), and the sandboxed client's identity
// refresh later "healed" DisplayVersion on that same real entry. The fix is
// paths::environment_redirected(): every machine-registration WRITE (the
// uninstall entry, virule://, the DisplayVersion refresh) refuses when the
// env-resolved local appdata is not the OS-known per-user folder.
//
// This harness replays the WORST CASE on purpose: it runs Setup exactly the
// forgetful way (LOCALAPPDATA redirected, no suppression flags of any kind)
// and proves the real registry survives byte-identical.
//
//   1. snapshot the real ARP entry and the real virule:// command;
//   2. run Virule-Setup.exe end to end against a local manifest server,
//      sandboxed via LOCALAPPDATA only;
//   3. wait until Setup passes its registration step (the sandbox install
//      exists and the setup log records the refusal breadcrumb);
//   4. assert the real ARP entry and virule:// are byte-identical to the
//      snapshots and reference nothing under the sandbox;
//   5. kill every sandbox-spawned process and remove the sandbox.
//
// Like takeover_test, a running real client is asked to exit by Setup's
// stop_running_client (it is an on-demand process that virule:// or Setup
// restarts at any time); this harness never launches real binaries itself.
//
// Run: node tools/arp_isolation_test.mjs      (builds must exist already)

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLIENT_EXE = path.join(repo, "build", "Release", "x64", "virule-client.exe");
const SETUP_EXE = path.join(repo, "build", "Release", "x64", "Virule-Setup.exe");
// os.tmpdir, never the Dropbox-synced repo tree (sync-client lock races).
const SANDBOX = path.join(os.tmpdir(), "virule-arp-isolation-sandbox");

const ARP_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ViruleClient";
const PROTO_KEY = "HKCU\\Software\\Classes\\virule";

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function regDump(key) {
  try {
    return execFileSync("reg.exe", ["query", key, "/s"], { encoding: "utf8" });
  } catch { return null; } // absent is a legitimate real state
}

function killSandboxProcesses() {
  const root = SANDBOX.replace(/'/g, "''");
  const ps = `Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like '${root}*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`;
  try {
    execFileSync("powershell.exe", ["-NoProfile", "-Command", ps], { stdio: "pipe" });
  } catch { /* nothing to kill */ }
}

async function main() {
  if (!fs.existsSync(CLIENT_EXE) || !fs.existsSync(SETUP_EXE)) {
    console.error("builds missing (build\\Release\\x64); build first");
    process.exit(2);
  }
  fs.rmSync(SANDBOX, { recursive: true, force: true });
  fs.mkdirSync(SANDBOX, { recursive: true });

  const arpBefore = regDump(ARP_KEY);
  const protoBefore = regDump(PROTO_KEY);

  const clientBytes = fs.readFileSync(CLIENT_EXE);
  const sha = crypto.createHash("sha256").update(clientBytes).digest("hex");
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/manifest.json")) {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({
        version: "0.0.1",
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

  console.log("sandboxed Setup, the forgetful-harness worst case (no suppression flags)");
  const setup = spawn(SETUP_EXE, [
    `--manifest-url=http://127.0.0.1:${server.address().port}/manifest.json`,
    "--dev-unsigned",
  ], { env: { ...process.env, LOCALAPPDATA: SANDBOX }, stdio: "ignore" });
  setup.on("error", () => {});

  // Registration is Setup step 6, after the install placement and before
  // the client start; the refusal breadcrumb in the sandboxed setup log is
  // the proof the guard (not a crash) is what kept the registry clean.
  const setupLog = path.join(SANDBOX, "VIRULE", "client", "logs", "virule-setup.log");
  const installedExe = path.join(SANDBOX, "Programs", "VIRULE", "virule-client.exe");
  let breadcrumb = false;
  for (let i = 0; i < 240 && !breadcrumb; i++) {
    await sleep(500);
    try {
      breadcrumb = fs.readFileSync(setupLog, "utf8")
        .includes("machine registrations skipped");
    } catch { /* not yet */ }
  }
  check("client installed into the sandbox", fs.existsSync(installedExe));
  check("setup log records the registration refusal", breadcrumb);

  // Let the Setup-started sandbox client reach its own (refused) virule://
  // self-registration before judging the registry.
  await sleep(5000);

  const arpAfter = regDump(ARP_KEY);
  const protoAfter = regDump(PROTO_KEY);
  check("real ARP entry byte-identical", arpAfter === arpBefore,
    arpAfter === arpBefore ? "" : `now:\n${arpAfter ?? "ABSENT"}`);
  check("real ARP entry references no sandbox path",
    arpAfter === null || !arpAfter.toLowerCase().includes(SANDBOX.toLowerCase()));
  check("real virule:// registration byte-identical", protoAfter === protoBefore,
    protoAfter === protoBefore ? "" : `now:\n${protoAfter ?? "ABSENT"}`);

  // Teardown: Setup (still holding its takeover watch) and the sandbox
  // client are throwaway processes of a throwaway world.
  try { setup.kill(); } catch { /* already gone */ }
  killSandboxProcesses();
  server.close();
  for (let i = 0; i < 10; i++) {
    await sleep(600);
    try {
      fs.rmSync(SANDBOX, { recursive: true, force: true });
      break;
    } catch { /* retry */ }
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
