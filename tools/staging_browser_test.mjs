// VIRULE STAGING browser journey test.
//
// The staging environment's whole point is that a person opens ONE URL and
// uses VIRULE normally. This drives that journey in a REAL browser (Microsoft
// Edge, the one browser the product lists as validated) against the REAL
// staging services, and asserts the environment never leaks.
//
// The journey it drives is the BOOTSTRAP one, the hard case:
//
//   1. open the staging URL on a machine with no VIRULE client   -> Get VIRULE
//   2. Get VIRULE -> the offer; Download offers the STAGING Setup asset and
//      records the browser-owned INSTALL_ADMIN intent
//   3. the client appears (as it would once Setup had run) and the OPEN page
//      CONTINUES THE RECORDED INTENT BY ITSELF, with no further click. That is
//      the product's "the original intent survives Setup" behaviour, and it is
//      why there is no second button to press here
//   4. the BROWSER IS CLOSED mid-install. The client must finish the staging
//      install on its own and launch the Admin
//   5. a fresh page reports the installed state
//   6. every request the pages made went to the staging origin; not one went
//      to virule.app or api.virule.app
//
// Sandboxed: the client is spawned with LOCALAPPDATA pointed at a throwaway
// tree and --no-register, so the owner's own VIRULE installation and the real
// Apps & Features entry are untouched. Only processes running from inside the
// OS temp directory are ever killed.
//
// playwright-core is not a dependency of this repo; it is already installed in
// the site repo, and this resolves it from there by explicit path rather than
// adding a dependency to the client for one test.
//
// Run:  node tools/staging_browser_test.mjs
//       node tools/staging_browser_test.mjs --headed   (watch it)

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.dirname(here);
const viruleRoot = path.dirname(repo);
const siteRepo = path.join(viruleRoot, "v1_mvp_site");

const require_ = createRequire(path.join(siteRepo, "package.json"));
let chromium;
try {
  ({ chromium } = require_("playwright-core"));
} catch {
  console.error("playwright-core is not installed in " + siteRepo);
  console.error("Install it there, or run tools/staging_env_test.mjs instead.");
  process.exit(2);
}

const STAGING_BASE = "https://virule-api-staging.heath-michaels9441.workers.dev";
const STAGING_REPO = "getvirule/virule-staging-releases";
const STAGING_HOST = "virule-api-staging.heath-michaels9441.workers.dev";
const STAGING_CLIENT = path.join(repo, "build", "Release", "x64", "staging", "virule-client.exe");
const SANDBOX = path.join(os.tmpdir(), "virule-staging-browser-test");
const PENDING_INTENT_KEY = "virule.pending";
const PORT = 47612;

const HEADED = process.argv.includes("--headed");

let pass = 0, fail = 0;
const check = (name, ok, detail = "") => {
  if (ok) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? "  (" + detail + ")" : ""}`); }
};
const info = (m) => console.log(`  --    ${m}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const ARP_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ViruleClient";
const readRealArp = () => {
  try { return execFileSync("reg.exe", ["query", ARP_KEY, "/s"], { encoding: "utf8" }); }
  catch { return null; }
};

function processPaths(name) {
  try {
    const out = execFileSync("powershell", ["-NoProfile", "-Command",
      `Get-Process -Name '${name}' -ErrorAction SilentlyContinue | ` +
      `Select-Object -ExpandProperty Path`], { encoding: "utf8" });
    return out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  } catch { return []; }
}

// Kills VIRULE processes running from inside the OS temp directory and NOTHING
// else. An interrupted run can leave a sandboxed client holding the bridge
// port, and it would then answer this run's pages with the previous run's
// state. Never kills by name alone: the owner's own installation, wherever it
// is, must be untouchable.
function killSandboxProcesses() {
  const tmp = os.tmpdir().toLowerCase();
  let killed = 0;
  for (const name of ["virule", "virule-client", "ViruleAdminHost", "Virule-Setup"]) {
    for (const p of processPaths(name)) {
      if (!p.toLowerCase().startsWith(tmp)) continue;
      try {
        execFileSync("powershell", ["-NoProfile", "-Command",
          `Get-Process -Name '${name}' -ErrorAction SilentlyContinue | ` +
          `Where-Object { $_.Path -eq '${p.replace(/'/g, "''")}' } | Stop-Process -Force`],
          { stdio: "ignore" });
        killed++;
      } catch {}
    }
  }
  if (killed) info(`stopped ${killed} leftover sandbox process(es)`);
}

// Asks whatever holds the bridge port to exit. Non-destructive: the client is
// an on-demand process that virule:// or Setup restarts at any time.
function shutdownWhateverHoldsThePort() {
  return new Promise((resolve) => {
    const socket = net.connect(PORT, "127.0.0.1", () => {
      socket.write([
        "GET /v1 HTTP/1.1", `Host: 127.0.0.1:${PORT}`,
        "Upgrade: websocket", "Connection: Upgrade",
        `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString("base64")}`,
        "Sec-WebSocket-Version: 13", "", "",
      ].join("\r\n"));
      setTimeout(() => {
        const body = Buffer.from('{"type":"shutdown"}', "utf8");
        const mask = crypto.randomBytes(4);
        const masked = Buffer.from(body);
        for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];
        try {
          socket.write(Buffer.concat([Buffer.from([0x81, 0x80 | body.length]), mask, masked]));
        } catch {}
        setTimeout(() => { try { socket.destroy(); } catch {} resolve(); }, 900);
      }, 500);
    });
    socket.on("error", () => resolve());
    setTimeout(() => { try { socket.destroy(); } catch {} resolve(); }, 4000);
  });
}

let clientProc = null;
function startClient(root) {
  clientProc = spawn(STAGING_CLIENT, ["--no-register"], {
    env: { ...process.env, LOCALAPPDATA: root }, stdio: "ignore",
  });
  return new Promise((resolve) => setTimeout(resolve, 2500));
}

const bodyText = (page) => page.evaluate(() => document.body.innerText).catch(() => "");

async function waitForText(page, texts, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const body = await bodyText(page);
    for (const t of texts) if (body.includes(t)) return t;
    if (Date.now() >= deadline) return null;
    await sleep(500);
  }
}

const isRunningFrom = (name, root) =>
  processPaths(name).some((p) => p.toLowerCase().startsWith(root.toLowerCase()));

async function main() {
  console.log("VIRULE STAGING browser journey test");
  console.log(`  staging url : ${STAGING_BASE}`);
  console.log(`  browser     : Microsoft Edge${HEADED ? " (headed)" : " (headless)"}`);
  console.log(`  sandbox     : ${SANDBOX}`);
  console.log("");

  if (!fs.existsSync(STAGING_CLIENT)) {
    console.error(`missing staging client: ${STAGING_CLIENT}`);
    process.exit(2);
  }
  killSandboxProcesses();
  await shutdownWhateverHoldsThePort();
  fs.rmSync(SANDBOX, { recursive: true, force: true });
  const root = path.join(SANDBOX, "journey");
  fs.mkdirSync(root, { recursive: true });
  const arpSnapshot = readRealArp();

  // THE LOCAL NETWORK ACCESS GATE. The page probes ws://127.0.0.1:47612, and
  // current Chromium gates a public page reaching a loopback address behind a
  // permission ("Your browser may ask for permission", as the site's own copy
  // says). A real user answers that prompt; a headless run has nobody to answer
  // it. This is a HARNESS accommodation, not a product difference: production
  // behaves exactly the same way, and the QA steps say so.
  const browser = await chromium.launch({
    channel: "msedge",
    headless: !HEADED,
    args: ["--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessSendPreflights,PrivateNetworkAccessRespectPreflightResults"],
  });

  const hosts = new Set();
  const manifestReads = [];
  const anchorClicks = [];
  async function newTrackedContext() {
    const ctx = await browser.newContext({ acceptDownloads: true });
    try { await ctx.grantPermissions(["local-network-access"], { origin: STAGING_BASE }); }
    catch { /* older browser: the launch flag covers it */ }

    // WHICH URL THE PRODUCT ACTUALLY CHOSE.
    //
    // The Setup offer is a plain cross-origin anchor click: the site sets an
    // href and clicks it, and the asset's own attachment disposition is what
    // turns the navigation into a download. That means neither observation
    // point is dependable here. `page.on("request")` does not see it, because
    // the browser process owns the navigation; a page-side record does not
    // survive it, because the navigation can reset the page's world; and a
    // headless `download` event did not fire reliably either.
    //
    // An exposed binding is recorded on THIS side of the wire the moment the
    // click happens, so nothing the browser does afterwards can erase it. It
    // observes the product's own decision directly, which is the thing under
    // test.
    await ctx.exposeBinding("__viruleRecordAnchorClick", (_source, href) => {
      anchorClicks.push(href);
    });
    await ctx.addInitScript(() => {
      // `click` is defined on HTMLElement.prototype, not on
      // HTMLAnchorElement.prototype, so that is where the hook belongs.
      const original = HTMLElement.prototype.click;
      HTMLElement.prototype.click = function () {
        try {
          if (this instanceof HTMLAnchorElement && this.href) {
            window.__viruleRecordAnchorClick(this.href);
          }
        } catch {}
        return original.apply(this, arguments);
      };
    });
    const p = await ctx.newPage();
    p.on("request", (r) => { try { hosts.add(new URL(r.url()).host); } catch {} });
    p.on("response", (r) => {
      if (r.url().includes("/client/admin-manifest.json")) manifestReads.push(r.url());
    });
    return { ctx, page: p };
  }

  let { ctx: context, page } = await newTrackedContext();

  try {
    // -----------------------------------------------------------------
    console.log("1. the staging URL, on a machine with no VIRULE client");
    await page.goto(STAGING_BASE + "/", { waitUntil: "domcontentloaded", timeout: 60000 });
    const first = await waitForText(page, ["Get VIRULE"], 25000);
    check("the page offers Get VIRULE", first === "Get VIRULE", await bodyText(page));

    // -----------------------------------------------------------------
    console.log("2. Get VIRULE offers the STAGING Setup");
    await page.getByRole("button", { name: "Get VIRULE" }).click();
    const offer = await waitForText(page,
      ["Install VIRULE to continue.", "Having trouble installing."], 30000);
    check("the page reaches the install offer", offer === "Install VIRULE to continue.",
      offer || await bodyText(page));
    // A DOM click, not a synthesized mouse click. Playwright's mouse click on
    // this particular button does not activate its React handler in headless
    // Edge (it activates Get VIRULE above just fine); a DOM click activates
    // exactly the handler a user's click activates, which is what is under
    // test here. What IS being asserted is the URL the product chooses, not
    // the button's hit box.
    await page.getByRole("button", { name: "Download" }).waitFor({ timeout: 30000 });
    await page.evaluate(() => {
      const btn = [...document.querySelectorAll("button")]
        .find((el) => el.textContent.trim() === "Download");
      if (btn) btn.click();
    });
    await sleep(2500);

    const setupClicks = anchorClicks.filter((u) => u.includes("Virule-Setup.exe"));
    check("Download offers a Virule-Setup.exe", setupClicks.length > 0,
      anchorClicks.join(", ") || "no anchor click was observed");
    check("the offered Setup is the STAGING asset",
      setupClicks.some((u) =>
        u.includes(STAGING_REPO) && u.includes("client-staging/Virule-Setup.exe")),
      setupClicks.join(", "));
    check("no production Setup asset was offered",
      !setupClicks.some((u) => u.includes("getvirule/virule-client/")), setupClicks.join(", "));

    const intent = await page.evaluate(
      (k) => { try { return localStorage.getItem(k); } catch { return null; } },
      PENDING_INTENT_KEY);
    check("the browser recorded its INSTALL_ADMIN intent",
      typeof intent === "string" && intent.includes("INSTALL_ADMIN"), intent || "none");

    // -----------------------------------------------------------------
    console.log("3. the client appears; the OPEN page continues the intent by itself");
    await startClient(root);
    // No click here, deliberately. The recorded intent is what continues the
    // journey, which is exactly the property Setup has to preserve.
    const continued = await waitForText(page,
      ["Installing VIRULE", "Updating VIRULE", "Something went wrong."], 120000);
    check("the page continued the recorded intent with no further click",
      continued === "Installing VIRULE" || continued === "Updating VIRULE",
      continued || await bodyText(page));

    // -----------------------------------------------------------------
    console.log("4. the browser closes mid-install; the client must finish alone");
    await context.close();
    context = null;
    info("browser context closed while the staging Admin install was in flight");

    const adminExe = path.join(root, "Programs", "VIRULE", "Admin", "virule.exe");
    const relFile = path.join(root, "Programs", "VIRULE", "Admin", "installed-release.json");
    let installed = false;
    const deadline = Date.now() + 25 * 60 * 1000;
    while (Date.now() < deadline) {
      if (fs.existsSync(adminExe) && fs.existsSync(relFile)) { installed = true; break; }
      await sleep(3000);
    }
    check("the client finished the install with no browser open", installed, adminExe);

    if (installed) {
      const installedVersion = JSON.parse(fs.readFileSync(relFile, "utf8")).version;
      const served = await (await fetch(STAGING_BASE + "/client/admin-manifest.json",
        { cache: "no-store" })).json();
      check("the installed version is the STAGING manifest's version",
        installedVersion === served.version,
        `installed=${installedVersion} staging=${served.version}`);
      const bytes = fs.readFileSync(adminExe);
      check("the installed Admin is a STAGING build",
        bytes.includes(Buffer.from(STAGING_HOST, "utf16le")) &&
        !bytes.includes(Buffer.from("api.virule.app", "utf16le")));
      let launched = false;
      for (let i = 0; i < 60; i++) {
        if (isRunningFrom("virule", root)) { launched = true; break; }
        await sleep(1000);
      }
      check("the Admin launched automatically after the fresh install", launched);
      killSandboxProcesses();
      await sleep(1500);
    }

    // -----------------------------------------------------------------
    console.log("5. a fresh page reports the installed state");
    ({ ctx: context, page } = await newTrackedContext());
    await page.goto(STAGING_BASE + "/", { waitUntil: "domcontentloaded", timeout: 60000 });
    // The installed states are "Open" (a button), "Currently open" (the quiet
    // resolved state for an Admin that is already running) and "Update".
    // "Get VIRULE" here would mean the page did not see the install at all.
    const settled = await waitForText(page,
      ["Currently open", "Update", "Open", "Get VIRULE"], 40000);
    check("the page reports VIRULE as installed",
      settled === "Open" || settled === "Currently open" || settled === "Update",
      settled || await bodyText(page));

    // -----------------------------------------------------------------
    console.log("6. the journey never left staging");
    check("the pages read the Admin manifest same-origin from staging",
      manifestReads.length > 0 && manifestReads.every((u) => u.startsWith(STAGING_BASE)),
      manifestReads.join(", ") || "never fetched");
    const prodHosts = [...hosts].filter((h) =>
      h === "virule.app" || h === "www.virule.app" || h === "api.virule.app");
    check("the pages contacted no production VIRULE host", prodHosts.length === 0,
      prodHosts.join(", "));
    info(`hosts contacted: ${[...hosts].join(", ")}`);
    check("the real Apps & Features entry is unchanged", readRealArp() === arpSnapshot);
  } finally {
    if (context) { try { await context.close(); } catch {} }
    try { await browser.close(); } catch {}
    await shutdownWhateverHoldsThePort();
    if (clientProc) { try { clientProc.kill(); } catch {} }
    killSandboxProcesses();
  }

  console.log("");
  console.log(`  ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("HARNESS ERROR:", e); process.exit(1); });
