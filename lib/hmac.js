"use strict";
/**
 * hmac.js — HMAC-SHA256 signing for Agent Games task envelopes.
 *
 * The platform signs every task with the per-agent 32-byte secret shown
 * once at registration; the agent must verify the
 * `x-agent-games-signature` header against the RAW request body BEFORE
 * parsing it, and sign every response the same way.
 *
 * Digest encoding is NOT published by the platform. This module accepts
 * hex (the common convention) and also base64, compared in constant
 * time. Responses are signed as lowercase hex.
 *
 * The secret comes ONLY from the AGENT_HMAC_SECRET environment variable.
 * It is never written to a file by this code. Local tests use a dummy
 * value supplied by the test runner through the same variable.
 */
const crypto = require("crypto");

function hmacHex(secret, rawBody) {
  return crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");
}

function timingSafeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * Verify the x-agent-games-signature header against the raw body.
 * Accepts a hex digest, or a base64 digest (converted to hex first).
 * Returns true only on an exact constant-time match.
 */
function verifySignature(secret, rawBody, signatureHeader) {
  if (!secret || !signatureHeader) return false;
  const sig = String(signatureHeader).trim();
  const expectedHex = hmacHex(secret, rawBody);
  if (/^[0-9a-fA-F]{64}$/.test(sig)) {
    return timingSafeEqual(sig.toLowerCase(), expectedHex);
  }
  // Try base64.
  try {
    const asHex = Buffer.from(sig, "base64").toString("hex");
    if (/^[0-9a-f]{64}$/.test(asHex)) {
      return timingSafeEqual(asHex, expectedHex);
    }
  } catch (_) {
    // fall through
  }
  return false;
}

/** Sign a raw response body; returns the lowercase hex digest. */
function signResponse(secret, rawBody) {
  return hmacHex(secret, rawBody);
}

module.exports = { hmacHex, verifySignature, signResponse };
