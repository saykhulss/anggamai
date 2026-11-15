"use strict";
/**
 * api/index.js — Proof Gatekeeper agent endpoint (anggamai).
 *
 * Vercel serverless function (also runnable standalone:
 * `node api/index.js` serves on PORT, default 3000).
 *
 * Request flow (per the official Builder Field Guide):
 *   1. Read the RAW body. Verify `x-agent-games-signature` (HMAC-SHA256)
 *      against the raw body BEFORE parsing anything. Bad/missing
 *      signature -> 401, no work done.
 *   2. Parse the task envelope. Unknown type -> signed 200 ack
 *      (tolerates preflight/health probes whose format is unpublished).
 *   3. Idempotency: task_id already in the response cache -> return the
 *      cached body byte-identical (platform retries).
 *   4. Deterministic decision checklist (lib/decision.js).
 *   5. PROOF_REUSED -> respond decision only, no proof (scoring
 *      excludes these from the proof bonus).
 *   6. Otherwise generate the Groth16 proof for the decision. If the
 *      circuit refuses (decision != verdict), try the opposite
 *      decision once — the circuit is the referee — and log the
 *      disagreement. If both fail, fail closed (REJECT, no proof).
 *   7. Verify the proof locally (snarkjs) before answering.
 *   8. Kurier (only when KURIER_API_KEY is set): submit the proof and
 *      poll to Finalized within the remaining budget; include the
 *      jobId/status/txHash in the response.
 *   9. Respond with the decision + proof, signed with
 *      `x-agent-games-signature` over the raw response body, inside
 *      the 60s window (fail closed on any timeout/uncertainty).
 *
 * Environment:
 *   AGENT_HMAC_SECRET  (required) per-agent 32-byte secret from registration
 *   KURIER_API_KEY     (optional) Kurier mainnet API key (kurier.xyz)
 *   REGISTERED_VK_HASH (optional) official gatekeeper vkHash; defaults
 *                      to the value in circuits/circuit-info.json
 *   STATE_FILE         (optional) path for the seen-set JSON store
 *   PROOF_TIMEOUT_MS   (optional) cap for one proof generation, default 45000
 *
 * The HMAC secret and Kurier key are NEVER written to any file by this
 * code. Local tests use dummy values via the same variables.
 */
const http = require("http");
const path = require("path");
const fs = require("fs");

const { verifySignature, signResponse } = require("../lib/hmac");
const { decide } = require("../lib/decision");
const { buildCircuitInput } = require("../lib/encoding");
const { generateProof, verifyProof, proofByteSize } = require("../lib/prover");
const kurier = require("../lib/kurier");
const { Store } = require("../lib/store");

const ROOT = path.join(__dirname, "..");
const GATEKEEPER_TYPE = "agent-games.proof-gatekeeper.v1";

const HMAC_SECRET =
  process.env.AGENT_HMAC_SECRET || process.env.AGENT_GAMES_HMAC_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const PROOF_TIMEOUT_MS = parseInt(process.env.PROOF_TIMEOUT_MS || "45000", 10);

let officialVkHash = process.env.REGISTERED_VK_HASH || "";
if (!officialVkHash) {
  try {
    const info = JSON.parse(
      fs.readFileSync(path.join(ROOT, "circuits", "circuit-info.json"), "utf8")
    );
    officialVkHash = info.circuits.gatekeeper.vkHash;
  } catch (_) {
    officialVkHash = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
  }
}

const store = new Store(
  process.env.STATE_FILE || path.join(ROOT, "data", "state.json")
);

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendSigned(res, status, obj, secret) {
  const body = JSON.stringify(obj);
  const sig = signResponse(secret, body);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": sig,
  });
  res.end(body);
  return body;
}

function parseDeadline(task, receivedAt) {
  // Platform window is 60s; keep a 3s margin for sending the response.
  let deadline = receivedAt + 55000;
  const d = task && (task.deadline_at || task.deadlineAt);
  if (d) {
    const parsed = Date.parse(d);
    if (!Number.isNaN(parsed)) deadline = Math.min(deadline, parsed - 3000);
  }
  return deadline;
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Try to prove `decision`; on circuit refusal, try the opposite once. */
async function proveDecision(task, decision, deadlineMs) {
  const attempt = async (dec) => {
    const { input } = buildCircuitInput(task, dec === "APPROVE" ? 1 : 0);
    const budget = Math.max(1000, deadlineMs - Date.now());
    return withTimeout(
      generateProof(input),
      Math.min(PROOF_TIMEOUT_MS, budget),
      "proof generation"
    );
  };
  try {
    const r = await attempt(decision);
    return { ...r, decisionUsed: decision, checklistDisagreed: false };
  } catch (e) {
    if (!/Assert Failed|line: 102/i.test(e.message)) throw e;
    // Circuit refused: the checklist disagrees with the circuit.
    // The circuit is the referee — try the opposite decision once.
    const opposite = decision === "APPROVE" ? "REJECT" : "APPROVE";
    console.warn(
      `[gatekeeper] checklist said ${decision} but circuit refused; trying ${opposite}`
    );
    const r = await attempt(opposite);
    return { ...r, decisionUsed: opposite, checklistDisagreed: true };
  }
}

async function handleTask(rawBody, req) {
  const receivedAt = Date.now();
  const secret = HMAC_SECRET;
  const signature = req.headers["x-agent-games-signature"];

  // (1) HMAC first — before parsing.
  if (!secret) {
    return { status: 500, body: { error: "server misconfigured: no HMAC secret" } };
  }
  if (!verifySignature(secret, rawBody, signature)) {
    return { status: 401, body: { error: "invalid signature" } };
  }

  let task;
  try {
    task = JSON.parse(rawBody.toString("utf8"));
  } catch (_) {
    return { status: 400, body: { error: "invalid JSON" } };
  }

  // (2a) Preflight probe (platform save-time check): the platform POSTs a
  // signed {"type": "agent-games.preflight.v1", ...} and requires a signed
  // { ok: true, protocolVersion: "v1" } response. Anything else fails the
  // endpoint save with "The endpoint must return signed protocol-v1 JSON."
  if (task.type === "agent-games.preflight.v1") {
    return { status: 200, body: { ok: true, protocolVersion: "v1" } };
  }

  // (2) Unknown envelope type: signed ack (preflight/health tolerance).
  if (task.type && task.type !== GATEKEEPER_TYPE) {
    return { status: 200, body: { status: "ok", agent: "anggamai" } };
  }
  if (!task.input) {
    return { status: 400, body: { error: "missing task input" } };
  }

  const taskId = task.task_id || task.taskId || "";
  const proofTx = task.input.proof_tx ?? task.input.proofTx ?? null;
  const deadlineMs = parseDeadline(task, receivedAt);

  // (3) Idempotency: byte-identical replay for retries.
  if (taskId) {
    const cached = store.getCachedResponse(taskId);
    if (cached) {
      console.log(`[gatekeeper] ${taskId} replay (cached)`);
      return { status: 200, body: cached, raw: true };
    }
  }

  // (4) Deterministic decision.
  const { decision, reason_code } = decide(task, {
    seenProofRefs: store.seenProofRefs,
    officialVkHash,
  });
  console.log(`[gatekeeper] ${taskId} decision=${decision} reason=${reason_code}`);

  const finish = (status, obj) => {
    const body = JSON.stringify(obj);
    store.record(taskId, proofTx, body);
    return { status, body: obj };
  };

  // (5) Reused proof: decision only, no proof.
  if (reason_code === "PROOF_REUSED") {
    return finish(200, { decision, reason_code, proof_tx: proofTx });
  }

  // (6) Generate the proof for the decision.
  let proved;
  try {
    proved = await proveDecision(task, decision, deadlineMs);
  } catch (e) {
    console.error(`[gatekeeper] ${taskId} proof failed:`, e.message);
    // Fail closed: REJECT without a proof.
    return finish(200, {
      decision: "REJECT",
      reason_code,
      proof_tx: proofTx,
      error: "proof_generation_failed",
    });
  }
  if (proved.checklistDisagreed) {
    console.warn(
      `[gatekeeper] ${taskId} CHECKLIST/CIRCUIT DISAGREEMENT — used ${proved.decisionUsed}`
    );
  }

  // (7) Verify the proof locally before answering.
  const local = await verifyProof(proved.publicSignals, proved.proof);
  if (!local.ok) {
    console.error(`[gatekeeper] ${taskId} local proof verification FAILED`);
    return finish(200, {
      decision: "REJECT",
      reason_code,
      proof_tx: proofTx,
      error: "proof_verification_failed",
    });
  }

  // (8) Kurier: submit + poll to Finalized within the remaining budget.
  let kurierResult = null;
  if (KURIER_API_KEY) {
    try {
      kurierResult = await kurier.submitAndFinalize(
        KURIER_API_KEY,
        {
          proof: proved.proof,
          publicSignals: proved.publicSignals,
          vkHash: officialVkHash,
        },
        deadlineMs
      );
      console.log(
        `[gatekeeper] ${taskId} kurier job ${kurierResult.jobId} status=${kurierResult.status} tx=${kurierResult.txHash}`
      );
    } catch (e) {
      console.error(`[gatekeeper] ${taskId} kurier error:`, e.message);
      kurierResult = { status: "error", error: e.message };
    }
  }

  const finalDecision =
    proved.checklistDisagreed && proved.decisionUsed !== decision
      ? proved.decisionUsed
      : decision;
  const finalReason =
    proved.checklistDisagreed && proved.decisionUsed !== decision
      ? proved.decisionUsed === "APPROVE"
        ? "VALID_CONDITION"
        : reason_code
      : reason_code;

  return finish(200, {
    decision: finalDecision,
    reason_code: finalReason,
    proof_tx: proofTx,
    proof: proved.proof,
    publicSignals: proved.publicSignals,
    proof_bytes: proofByteSize(proved.proof),
    kurier: kurierResult,
  });
}

async function handler(req, res) {
  try {
    if (req.method === "GET") {
      return sendSigned(res, 200, {
        status: "ok",
        agent: "anggamai",
        track: "proof-gatekeeper",
      }, HMAC_SECRET);
    }
    if (req.method !== "POST") {
      res.writeHead(405);
      return res.end();
    }
    const rawBody = await readRawBody(req);
    const out = await handleTask(rawBody, req);
    if (out.raw) {
      // Cached body: re-signing is deterministic, so bytes stay identical.
      const sig = signResponse(HMAC_SECRET, out.body);
      res.writeHead(out.status, {
        "content-type": "application/json",
        "x-agent-games-signature": sig,
      });
      return res.end(out.body);
    }
    return sendSigned(res, out.status, out.body, HMAC_SECRET);
  } catch (e) {
    console.error("[gatekeeper] unhandled error:", e);
    try {
      return sendSigned(res, 500, { error: "internal_error" }, HMAC_SECRET);
    } catch (_) {
      res.writeHead(500);
      return res.end();
    }
  }
}

// Vercel: raw body (HMAC is computed over the unparsed bytes).
handler.config = { api: { bodyParser: false } };
module.exports = handler;
module.exports.config = handler.config;

if (require.main === module) {
  const port = parseInt(process.env.PORT || "3000", 10);
  http.createServer(handler).listen(port, () => {
    console.log(`anggamai gatekeeper listening on http://127.0.0.1:${port}`);
    console.log(`HMAC secret configured: ${HMAC_SECRET ? "yes" : "NO — set AGENT_HMAC_SECRET"}`);
    console.log(`Kurier key configured: ${KURIER_API_KEY ? "yes" : "no (proofs returned locally only)"}`);
  });
}
