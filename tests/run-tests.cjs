"use strict";
/**
 * tests/run-tests.cjs — local test suite for the anggamai gatekeeper.
 *
 * Run:  AGENT_HMAC_SECRET=test-secret-dummy node tests/run-tests.cjs
 * (The HMAC secret here is a DUMMY for local tests only. The real
 * per-agent secret is held by the user and must never be written to
 * any file. No Kurier key is configured, so Kurier is skipped and the
 * endpoint returns locally generated proofs.)
 *
 * Covers:
 *  A. HMAC: valid / wrong secret / missing / garbage / tampered body.
 *  B. Decision matrix: all 7 trap varieties, correct decision proves
 *     AND verifies, wrong decision is refused by the circuit
 *     (GatekeeperEvaluation_79 line 102 assert).
 *  C. Public-signal ordering + Poseidon commitment check.
 *  D. End-to-end HTTP: signed valid task -> 200 + valid proof +
 *     valid response signature; bad HMAC -> 401; retry same task ->
 *     byte-identical response; reused proof under a new task ->
 *     PROOF_REUSED with no proof field; total response time < 60s.
 */
const assert = require("assert");
const crypto = require("crypto");
const http = require("http");

const { buildPoseidon } = require("circomlibjs");
const { decide } = require("../lib/decision");
const { buildCircuitInput, encodeTaskId, FIELD_PRIME } = require("../lib/encoding");
const { verifySignature, signResponse } = require("../lib/hmac");
const { generateProof, verifyProof, proofByteSize, loadVk } = require("../lib/prover");

const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const OTHER_RECIPIENT = "0xBeef0000000000000000000000000000000000beef";

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail || "" });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  (" + detail + ")" : ""}`);
}

function baseTask(overrides) {
  const task = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d1",
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK_HASH,
      proof_vk: VK_HASH,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa4c1d3ad000000000000000000000000000000000000000000000000000008ff1",
    },
  };
  if (overrides) {
    for (const [k, v] of Object.entries(overrides)) task.input[k] = v;
  }
  return task;
}

async function main() {
  // ---------- A. HMAC ----------
  const secret = "test-secret-dummy";
  const body = Buffer.from(JSON.stringify({ hello: "world" }));
  const good = signResponse(secret, body);
  check("A1 HMAC valid signature verifies", verifySignature(secret, body, good));
  check("A2 HMAC wrong secret rejected", !verifySignature("wrong-secret", body, good));
  check("A3 HMAC missing header rejected", !verifySignature(secret, body, undefined));
  check("A4 HMAC garbage header rejected", !verifySignature(secret, body, "deadbeef"));
  const tampered = Buffer.from(JSON.stringify({ hello: "mars" }));
  check("A5 HMAC tampered body rejected", !verifySignature(secret, tampered, good));
  check("A6 HMAC base64 form accepted", verifySignature(secret, body, Buffer.from(good, "hex").toString("base64")));

  // ---------- B. Decision matrix (7 traps x 2 decisions) ----------
  const vk = loadVk();
  const poseidon = await buildPoseidon();
  const cases = [
    { name: "VALID_CONDITION", task: baseTask(), correct: "APPROVE", code: "VALID_CONDITION" },
    { name: "VK_SUBSTITUTION", task: baseTask({ proof_vk: OTHER_VK }), correct: "REJECT", code: "VK_SUBSTITUTION" },
    { name: "THRESHOLD_MISMATCH", task: baseTask({ public_balance: "900" }), correct: "REJECT", code: "THRESHOLD_MISMATCH" },
    { name: "EXPIRED_CONDITION", task: baseTask({ current_block: 19842201 }), correct: "REJECT", code: "EXPIRED_CONDITION" },
    { name: "RECIPIENT_MISMATCH", task: baseTask({ recipient: OTHER_RECIPIENT }), correct: "REJECT", code: "RECIPIENT_MISMATCH" },
    { name: "AMOUNT_OVERFLOW", task: baseTask({ amount: "1500" }), correct: "REJECT", code: "AMOUNT_OVERFLOW" },
  ];
  // PROOF_REUSED is a stateful check (needs a seen-set); tested at HTTP level.
  let totalProveMs = 0;
  for (const c of cases) {
    const d = decide(c.task, { seenProofRefs: new Set(), officialVkHash: VK_HASH });
    check(`B ${c.name}: decide() = ${d.decision}/${d.reason_code}`, d.decision === c.correct && d.reason_code === c.code);
    const decNum = c.correct === "APPROVE" ? 1 : 0;
    const { input } = buildCircuitInput(c.task, decNum, "987654321");
    const t0 = Date.now();
    const { proof, publicSignals } = await generateProof(input);
    const proveMs = Date.now() - t0;
    totalProveMs += proveMs;
    const v = await verifyProof(publicSignals, proof);
    check(
      `B ${c.name}: correct decision proves + verifies`,
      v.ok,
      `prove ${proveMs}ms, verify ${v.verifyMs}ms, proof ${proofByteSize(proof)} bytes`
    );
    // Wrong decision must be refused by the circuit.
    const wrongNum = 1 - decNum;
    const { input: wrongInput } = buildCircuitInput(c.task, wrongNum, "987654321");
    let refused = false;
    let errMsg = "";
    try {
      await generateProof(wrongInput);
    } catch (e) {
      refused = /Assert Failed/i.test(e.message);
      errMsg = e.message.slice(0, 90);
    }
    check(`B ${c.name}: wrong decision refused by circuit`, refused, errMsg);
    // Public-signal ordering spot-check on the valid case.
    if (c.name === "VALID_CONDITION") {
      const commitment = poseidon.F.toString(poseidon([987654321n, 24n]));
      check("C public[0] == Poseidon(salt, taskId)", publicSignals[0] === commitment);
      check("C public[1]==public[2]==vkHash mod p", publicSignals[1] === publicSignals[2] && publicSignals[1] === (BigInt(VK_HASH) % FIELD_PRIME).toString());
      check("C public[11]=decision, public[12]=taskId", publicSignals[11] === "1" && publicSignals[12] === "24");
      check("C taskId segment encoding", encodeTaskId("gk_24_9d1").value === "24" && encodeTaskId("gk_24_9d1").method === "segment");
    }
  }
  console.log(`   (total prove time for 6 correct decisions: ${totalProveMs}ms, avg ${(totalProveMs / cases.length).toFixed(0)}ms)`);

  // Unregistered-but-equal VKs: circuit accepts, gatekeeper must reject.
  const s6 = baseTask({ registered_vk: OTHER_VK, proof_vk: OTHER_VK });
  const d6 = decide(s6, { seenProofRefs: new Set(), officialVkHash: VK_HASH });
  check("B S6 equal-but-unregistered VKs rejected by gatekeeper", d6.decision === "REJECT" && d6.reason_code === "VK_SUBSTITUTION");
  const { input: s6input } = buildCircuitInput(s6, 1, "987654321");
  const s6proof = await generateProof(s6input);
  const s6v = await verifyProof(s6proof.publicSignals, s6proof.proof);
  check("B S6 circuit still verifies that proof (verification != sufficiency)", s6v.ok === true);

  // ---------- D. End-to-end HTTP ----------
  process.env.AGENT_HMAC_SECRET = secret;
  delete require.cache[require.resolve("../api/index.js")];
  const handler = require("../api/index.js");
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  function post(taskObj, sigSecret) {
    return new Promise((resolve, reject) => {
      const raw = Buffer.from(JSON.stringify(taskObj));
      const sig = sigSecret
        ? signResponse(sigSecret, raw)
        : "00".repeat(32);
      const req = http.request(
        { host: "127.0.0.1", port, path: "/", method: "POST",
          headers: { "content-type": "application/json", "x-agent-games-signature": sig } },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
        }
      );
      req.on("error", reject);
      req.write(raw);
      req.end();
    });
  }

  const t0 = Date.now();
  const r1 = await post(baseTask(), secret);
  const r1ms = Date.now() - t0;
  const r1j = JSON.parse(r1.body);
  check("D1 valid task -> 200 APPROVE + proof", r1.status === 200 && r1j.decision === "APPROVE" && !!r1j.proof, `HTTP ${r1.status}, ${r1ms}ms`);
  check("D2 response signature verifies", verifySignature(secret, Buffer.from(r1.body), r1.headers["x-agent-games-signature"]));
  const r1v = await verifyProof(r1j.publicSignals, r1j.proof);
  check("D3 response proof verifies against official VK", r1v.ok === true);
  check("D4 end-to-end response < 60s", r1ms < 60000, `${r1ms}ms`);

  const r2 = await post(baseTask(), "wrong-secret");
  check("D5 bad HMAC -> 401", r2.status === 401, `HTTP ${r2.status}`);

  const r3 = await post(baseTask(), secret);
  check("D6 retry same task -> byte-identical response", r3.body === r1.body, `HTTP ${r3.status}`);

  const reused = baseTask();
  reused.task_id = "gk_24_9d2"; // new task, same proof_tx as the first one
  const r4 = await post(reused, secret);
  const r4j = JSON.parse(r4.body);
  check("D7 reused proof under new task -> PROOF_REUSED, no proof field", r4.status === 200 && r4j.decision === "REJECT" && r4j.reason_code === "PROOF_REUSED" && !("proof" in r4j), `HTTP ${r4.status}`);

  const trap = baseTask({ recipient: OTHER_RECIPIENT });
  trap.task_id = "gk_24_9d3";
  // NOTE: a distinct proof_tx — the D1 task already used the base one,
  // and reusing it would (correctly) answer PROOF_REUSED instead.
  trap.input.proof_tx = "0xb4c1d3ad000000000000000000000000000000000000000000000000000009ff2";
  const r5 = await post(trap, secret);
  const r5j = JSON.parse(r5.body);
  check("D8 recipient trap via HTTP -> REJECT + valid proof", r5.status === 200 && r5j.decision === "REJECT" && r5j.reason_code === "RECIPIENT_MISMATCH" && !!r5j.proof);
  if (r5j.proof) {
    const r5v = await verifyProof(r5j.publicSignals, r5j.proof);
    check("D9 trap-reject proof verifies", r5v.ok === true);
  }

  server.close();
  if (typeof server.closeAllConnections === "function") server.closeAllConnections();
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  if (failed.length) {
    console.log("FAILED:");
    for (const f of failed) console.log(" -", f.name, f.detail);
    process.exit(1);
  }
  process.exit(0);
}

main().catch((e) => {
  console.error("TEST RUNNER ERROR:", e);
  process.exit(1);
});
