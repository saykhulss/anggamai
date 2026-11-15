"use strict";
/**
 * encoding.js — map a Proof Gatekeeper task envelope to circuit inputs.
 *
 * Circuit inputs (verified by probing gatekeeper.wasm, 2026-11-15):
 *   taskId, minimum, publicBalance, expiryBlock, currentBlock,
 *   recipient, conditionRecipient, amount, maxTransfer,
 *   registeredVkHash, proofVkHash, salt, decision
 * Each is a single BN254 field element. The witness calculator reduces
 * every value modulo the field prime, so a full 256-bit hash is passed
 * as its decimal string and reduced deterministically.
 *
 * ASSUMPTIONS (not published by the platform — confirm on first Practice):
 *  A1. taskId: the envelope task_id looks like "gk_<N>_<suffix>".
 *      The numeric middle segment N is used as the field element.
 *      (Evidence: the sample task_id is "gk_24_9d1" and the published
 *      Poseidon check uses taskId=24.) If the id has no such segment,
 *      fall back to keccak256(task_id) mod FIELD_PRIME.
 *  A2. Hex values (vk hashes, addresses) are passed as BigInt(hex)
 *      decimal strings; the witness calculator reduces mod p.
 */

const crypto = require("crypto");

// BN254 scalar field prime (Fr). Verified empirically 2026-11-15:
// BigInt(vkHash) % this == publicSignals[1] of a generated proof.
// Hex: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

/** Parse a task_id like "gk_24_9d1" -> "24". Returns null if no segment. */
function parseTaskId(taskId) {
  if (typeof taskId !== "string") return null;
  const m = taskId.match(/^gk_(\d+)_/);
  if (m) return m[1];
  // Bare numeric id.
  if (/^\d+$/.test(taskId)) return taskId;
  return null;
}

/** Fallback taskId encoding: keccak256(task_id) mod FIELD_PRIME. */
function hashTaskId(taskId) {
  const { keccak256 } = require("js-sha3");
  const digest = keccak256(taskId);
  return (BigInt("0x" + digest) % FIELD_PRIME).toString();
}

/** task_id string -> circuit field element (decimal string). */
function encodeTaskId(taskId) {
  const parsed = parseTaskId(taskId);
  if (parsed !== null) return { value: parsed, method: "segment" };
  return { value: hashTaskId(taskId), method: "keccak256-mod-p" };
}

/** 0x-hex string (or decimal string) -> field element decimal string. */
function encodeField(value) {
  if (typeof value === "number") return BigInt(value).toString();
  const s = String(value).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s).toString();
  if (/^\d+$/.test(s)) return s;
  throw new Error(`Cannot encode field value: ${value}`);
}

/** Random private salt: 31 random bytes as a field element string. */
function randomSalt() {
  const buf = crypto.randomBytes(31);
  return (BigInt("0x" + buf.toString("hex")) % FIELD_PRIME).toString();
}

/**
 * Build the 13 circuit inputs for one task + decision.
 * decision: 1 = APPROVE, 0 = REJECT.
 * salt: optional override (tests); otherwise random.
 */
function buildCircuitInput(task, decision, salt) {
  const input = task.input || task;
  const taskId = encodeTaskId(task.task_id || task.taskId);
  return {
    input: {
      taskId: taskId.value,
      minimum: encodeField(input.minimum),
      publicBalance: encodeField(input.public_balance ?? input.publicBalance),
      expiryBlock: encodeField(input.expiry_block ?? input.expiryBlock),
      currentBlock: encodeField(input.current_block ?? input.currentBlock),
      recipient: encodeField(input.recipient),
      conditionRecipient: encodeField(
        input.condition_recipient ?? input.conditionRecipient
      ),
      amount: encodeField(input.amount),
      maxTransfer: encodeField(input.max_transfer ?? input.maxTransfer),
      registeredVkHash: encodeField(
        input.registered_vk ?? input.registeredVkHash
      ),
      proofVkHash: encodeField(input.proof_vk ?? input.proofVkHash),
      salt: salt || randomSalt(),
      decision: decision ? "1" : "0",
    },
    taskIdEncoding: taskId.method,
  };
}

module.exports = {
  FIELD_PRIME,
  parseTaskId,
  hashTaskId,
  encodeTaskId,
  encodeField,
  randomSalt,
  buildCircuitInput,
};
