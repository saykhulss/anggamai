"use strict";
/**
 * prover.js — Groth16 proof generation + verification (snarkjs 0.7.6).
 *
 * The tournament circuit (gatekeeper.wasm / gatekeeper_final.zkey) is
 * Groth16/BN128, compiled with Circom 2.x. It enforces:
 *   decision == computed verdict
 * i.e. APPROVE (decision=1) is provable only when every check passes,
 * and REJECT (decision=0) only when at least one fails. A wrong
 * decision cannot even build a witness — fullProve throws
 * "Assert Failed. Error in template GatekeeperEvaluation_79 line: 102".
 *
 * Public signals (13), in order:
 *   [0] commitment = Poseidon(salt, taskId)
 *   [1] registeredVkHash  [2] proofVkHash  [3] minimum
 *   [4] publicBalance     [5] expiryBlock  [6] currentBlock
 *   [7] recipient         [8] conditionRecipient
 *   [9] amount            [10] maxTransfer
 *   [11] decision         [12] taskId
 * (Order verified empirically in tests/sanity-prove: public[0] equals
 * Poseidon([salt, taskId]) and the rest match the inputs.)
 */
const path = require("path");
const fs = require("fs");
const snarkjs = require("snarkjs");

const ROOT = path.join(__dirname, "..");
const WASM_PATH = path.join(ROOT, "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(ROOT, "circuits", "gatekeeper_final.zkey");
const VK_PATH = path.join(ROOT, "circuits", "verification_key.json");

let vkCache = null;
function loadVk() {
  if (!vkCache) {
    vkCache = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
  }
  return vkCache;
}

/**
 * Generate a Groth16 proof for the given circuit inputs.
 * @returns {Promise<{proof: object, publicSignals: string[], proveMs: number}>}
 * @throws if the witness cannot be built (decision disagrees with the
 *         task fields — the circuit refusing is the expected signal).
 */
async function generateProof(circuitInput) {
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH
  );
  return { proof, publicSignals, proveMs: Date.now() - t0 };
}

/** Locally verify a proof against the tournament verification key. */
async function verifyProof(publicSignals, proof) {
  const vk = loadVk();
  const t0 = Date.now();
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  return { ok, verifyMs: Date.now() - t0 };
}

/** Proof size in bytes when serialised (informational). */
function proofByteSize(proof) {
  return Buffer.byteLength(JSON.stringify(proof));
}

module.exports = {
  WASM_PATH,
  ZKEY_PATH,
  VK_PATH,
  loadVk,
  generateProof,
  verifyProof,
  proofByteSize,
};
