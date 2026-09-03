// virule:// ROUTING REGRESSION.
//
// THE DEFECT THIS EXISTS FOR: the homepage's generic wake (virule://open)
// reached VIRULE Admin, which treated every virule:// launch as QA and, with
// QA TEST MODE on, showed an expired QA invitation screen. A generic wake
// must NEVER produce a QA surface, in either component, ever again.
//
// Two components implement the same grammar in two repositories (the VIRULE
// Client's src/shared/protocol_reg.hpp and the Admin's src/cli/main.cpp
// qa_protocol namespace). This checks the ROUTING SOURCE of both: that only
// the QA namespace can reach QA verification, that the wake grammar is
// identical on both sides, and that the Admin no longer takes the protocol
// registration back when the client is installed.
//
//   node tools/protocol_routing_test.mjs

import { readFileSync } from "node:fs";

const CLIENT_HEADER =
  "D:/Dropbox/Dropbox/development/VIRULE/virule-client/src/shared/protocol_reg.hpp";
const CLIENT_MAIN =
  "D:/Dropbox/Dropbox/development/VIRULE/virule-client/src/client/main.cpp";
const ADMIN_MAIN =
  "D:/Dropbox/Dropbox/development/VIRULE/v2_mvp/src/cli/main.cpp";

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

const clientHeader = readFileSync(CLIENT_HEADER, "utf8");
const clientMain = readFileSync(CLIENT_MAIN, "utf8");
const adminMain = readFileSync(ADMIN_MAIN, "utf8");

/* Pull one C++ function body out by name (brace-matched). */
function body(src, signatureFragment) {
  const at = src.indexOf(signatureFragment);
  if (at < 0) return null;
  const open = src.indexOf("{", at);
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") {
      depth--;
      if (depth === 0) return src.slice(open, i + 1);
    }
  }
  return null;
}

const normalize = (s) => s.replace(/\s+/g, " ").trim();

console.log("A. the wake grammar is one grammar, implemented twice");
{
  const clientWake = body(clientHeader, "bool is_wake_url(");
  const adminWake = body(adminMain, "bool is_wake_url(");
  check("client implements is_wake_url", clientWake !== null);
  check("Admin implements is_wake_url", adminWake !== null);
  check(
    "both wake implementations are identical",
    clientWake !== null && adminWake !== null &&
      normalize(clientWake) === normalize(adminWake),
    "the two components would disagree about what a wake is",
  );

  const clientToken = body(clientHeader, "parse_qa_verify_token(");
  const adminToken = body(adminMain, "parse_verify_token(");
  check(
    "both parse the same QA verify prefix",
    clientToken !== null && adminToken !== null &&
      clientToken.includes('"virule://qa/verify/"') &&
      adminToken.includes('"virule://qa/verify/"'),
  );
  check(
    "both require 64 lowercase hex",
    clientToken !== null && adminToken !== null &&
      clientToken.includes("0123456789abcdef") &&
      adminToken.includes("0123456789abcdef") &&
      clientToken.includes("!= 64") === adminToken.includes("!= 64"),
  );
}

console.log("B. Admin routing: a generic wake can never reach QA");
{
  const wakeAt = adminMain.indexOf("if (qa_protocol::is_wake_url(protocol_url))");
  const qaAt = adminMain.indexOf("if (qa_protocol::is_qa_url(protocol_url))");
  const verifyAt = adminMain.indexOf("return run_qa_verify_mode(protocol_url);");
  check("Admin dispatches on the wake grammar", wakeAt > 0);
  check("Admin dispatches on the QA namespace", qaAt > 0);
  check(
    "the wake branch is decided BEFORE QA",
    wakeAt > 0 && qaAt > wakeAt,
    "a wake could otherwise fall into QA",
  );
  check(
    "QA verification is reachable only inside the QA-namespace branch",
    verifyAt > qaAt && verifyAt > 0 && qaAt > 0,
  );
  check(
    "the wake branch runs the no-op wake, not QA",
    adminMain.includes("return run_protocol_wake();"),
  );
  const wakeBody = body(adminMain, "int run_protocol_wake(");
  check("the wake path exists", wakeBody !== null);
  check(
    "the wake path touches nothing QA",
    wakeBody !== null &&
      !/qa_verify|qa_access_service|qa_test_mode|redeem|qa_tester/.test(wakeBody),
    "the wake must not read QA state at all, test mode included",
  );
  check(
    "an unknown virule:// grammar is rejected with no action",
    /Unknown grammar[\s\S]{0,200}return 0;/.test(adminMain),
  );
}

console.log("C. the installed client is the canonical virule:// handler");
{
  const reg = body(adminMain, "void register_protocol(");
  check("Admin register_protocol exists", reg !== null);
  check(
    "the Admin prefers the installed client",
    reg !== null && reg.includes("client_installed(&client)"),
  );
  check(
    "the Admin only heals a registration that is not already the client's",
    reg !== null && reg.includes("if (!registered_to(client.wstring()))"),
    "re-claiming on every launch is what caused the misroute",
  );
  check(
    "the Admin registers itself only when no client is installed",
    reg !== null &&
      reg.indexOf("GetModuleFileNameW") > reg.indexOf("client_installed"),
  );
}

console.log("D. the client routes on the same grammar, in the same order");
{
  const wakeAt = clientMain.indexOf("if (vclient::protocol_reg::is_wake_url(protocol_url))");
  const qaAt = clientMain.indexOf("} else if (vclient::protocol_reg::is_qa_url(protocol_url))");
  check("the client dispatches on the wake grammar", wakeAt > 0);
  check("the client dispatches on the QA namespace", qaAt > 0);
  check("the wake branch is decided BEFORE QA", wakeAt > 0 && qaAt > wakeAt);
  check(
    "a QA token is only parsed inside the QA-namespace branch",
    qaAt > 0 && clientMain.indexOf("parse_qa_verify_token(protocol_url)") > qaAt,
  );
  check(
    "anything else is rejected with no action",
    clientMain.includes("rejected virule:// input"),
  );
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
