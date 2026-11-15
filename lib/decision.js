"use strict";
/**
 * decision.js — deterministic Proof Gatekeeper decision checklist.
 *
 * Pure function of the task envelope + seen proof references + the
 * official registered vkHash. No crypto, no I/O: the same input always
 * produces the same output (the platform scores decisions independently,
 * so the decision must be deterministic).
 *
 * Check order (first failure wins; single-trap tasks are the norm, so
 * order only matters if a task carries two traps at once):
 *   0. proof reference already seen under a DIFFERENT task id
 *      -> REJECT PROOF_REUSED (no proof is generated for these)
 *   1. proof VK != registered VK            -> REJECT VK_SUBSTITUTION
 *   2. registered VK != official vkHash     -> REJECT VK_SUBSTITUTION
 *      (equal-but-unregistered hashes: the circuit accepts them, the
 *      gatekeeper must not — "verification is necessary, not
 *      sufficient". Closest official reason code is VK_SUBSTITUTION.)
 *   3. public balance < minimum             -> REJECT THRESHOLD_MISMATCH
 *   4. recipient != condition recipient     -> REJECT RECIPIENT_MISMATCH
 *   5. current block >= expiry block        -> REJECT EXPIRED_CONDITION
 *      (fail closed: at the expiry block the window is treated as over)
 *   6. amount > max transfer                -> REJECT AMOUNT_OVERFLOW
 *   else                                    -> APPROVE VALID_CONDITION
 *
 * Retry/idempotency is handled by the caller: if task_id is already in
 * the response cache, the cached response is returned verbatim and this
 * function is never called.
 */

function normalizeHex(v) {
  return String(v).trim().toLowerCase();
}

function toBigInt(v) {
  const s = String(v).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  return BigInt(s);
}

/**
 * @param {object} task  task envelope (type/task_id/input as on the event page)
 * @param {object} opts  { seenProofRefs: Set<string>, officialVkHash: string }
 * @returns {{decision: "APPROVE"|"REJECT", reason_code: string}}
 */
function decide(task, opts) {
  const input = task.input || task;
  const seen = opts.seenProofRefs || new Set();
  const officialVk = opts.officialVkHash
    ? normalizeHex(opts.officialVkHash)
    : null;

  const proofTx = input.proof_tx ?? input.proofTx ?? null;
  if (proofTx && seen.has(String(proofTx))) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  }

  const registeredVk = normalizeHex(
    input.registered_vk ?? input.registeredVkHash
  );
  const proofVk = normalizeHex(input.proof_vk ?? input.proofVkHash);

  if (proofVk !== registeredVk) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  }
  if (officialVk && registeredVk !== officialVk) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  }

  const minimum = toBigInt(input.minimum);
  const balance = toBigInt(input.public_balance ?? input.publicBalance);
  if (balance < minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  }

  const recipient = normalizeHex(input.recipient);
  const conditionRecipient = normalizeHex(
    input.condition_recipient ?? input.conditionRecipient
  );
  if (recipient !== conditionRecipient) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  }

  const expiry = toBigInt(input.expiry_block ?? input.expiryBlock);
  const current = toBigInt(input.current_block ?? input.currentBlock);
  if (current >= expiry) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  }

  const amount = toBigInt(input.amount);
  const cap = toBigInt(input.max_transfer ?? input.maxTransfer);
  if (amount > cap) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  }

  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

module.exports = { decide };
