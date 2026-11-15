"use strict";
/**
 * kurier.js — zkVerify proof submission via Kurier (Horizen Labs REST API).
 *
 * Docs: https://docs.zkverify.io/overview/getting-started/kurier
 * Mainnet:  https://api.kurier.xyz/api/v1   (Swagger: /docs)
 * Testnet:  https://api-testnet.kurier.xyz/api/v1
 *
 * API key: sign up at https://kurier.xyz (mainnet) or
 * https://testnet.kurier.xyz (testnet) and generate a key from the
 * dashboard. No payment step is documented for obtaining a key;
 * usage is tracked per key and rate limits can be raised via Discord.
 * (Whether a paid tier exists for high volume is NOT stated in the
 * docs — see README. No key is held by this repo; the key comes from
 * the KURIER_API_KEY environment variable.)
 *
 * Endpoints used:
 *   POST /register-vk/{key}
 *        {proofType:"groth16", proofOptions:{library:"snarkjs",curve:"bn128"}, vk}
 *        -> {vkHash, ...}   (once per verification key)
 *   POST /submit-proof/{key}
 *        {proofType:"groth16", vkRegistered:true,
 *         proofOptions:{library:"snarkjs",curve:"bn128"},
 *         proofData:{proof, publicSignals, vk: vkHash}}
 *        -> {jobId, optimisticVerify:"success"}
 *   GET  /job-status/{key}/{jobId}
 *        -> {jobId, status, statusId, txHash, blockHash, ...}
 *        statuses: Queued, Valid, Submitted, IncludedInBlock,
 *        Finalized, Failed (plus aggregation statuses if chainId set).
 *
 * Flow for one decision: submit-proof, then poll job-status every
 * 5s until Finalized (or Failed, or the caller's deadline). The
 * worked example in the docs finalised in ~16s.
 *
 * The Builder Field Guide's security section says "the verification
 * reached a finalized state before approval" — i.e. the agent should
 * have its proof finalised before it answers APPROVE. In practice the
 * 60s response window bounds this: if Finalized is not reached by the
 * deadline, the endpoint still answers with the locally verified
 * proof plus the pending Kurier job reference, so the platform can
 * confirm finalisation itself. That trade-off is documented in the
 * README; it is strictly better than timing out (-2) or answering
 * without a proof (-2).
 */
const API_URL = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (_) {
    data = { raw: text };
  }
  if (!res.ok) {
    const err = new Error(`Kurier POST ${res.status}: ${text.slice(0, 300)}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function getJson(url) {
  const res = await fetch(url);
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (_) {
    data = { raw: text };
  }
  if (!res.ok) {
    const err = new Error(`Kurier GET ${res.status}: ${text.slice(0, 300)}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

/** Register a verification key once; returns the Kurier response. */
async function registerVk(apiKey, vkJson) {
  return postJson(`${API_URL}/register-vk/${apiKey}`, {
    proofType: "groth16",
    proofOptions: { library: "snarkjs", curve: "bn128" },
    vk: vkJson,
  });
}

/** Submit a proof; returns {jobId, optimisticVerify}. */
async function submitProof(apiKey, { proof, publicSignals, vkHash }) {
  return postJson(`${API_URL}/submit-proof/${apiKey}`, {
    proofType: "groth16",
    vkRegistered: true,
    proofOptions: { library: "snarkjs", curve: "bn128" },
    proofData: { proof, publicSignals, vk: vkHash },
  });
}

/** One job-status read. */
async function jobStatus(apiKey, jobId) {
  return getJson(`${API_URL}/job-status/${apiKey}/${jobId}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Submit a proof and poll until Finalized / Failed / deadline.
 * @param {number} deadlineMs  absolute epoch ms to stop polling.
 * @returns {Promise<{jobId, status, txHash, blockHash, finalized: boolean, polls: number, elapsedMs: number}>}
 */
async function submitAndFinalize(
  apiKey,
  { proof, publicSignals, vkHash },
  deadlineMs
) {
  const t0 = Date.now();
  const submitted = await submitProof(apiKey, { proof, publicSignals, vkHash });
  const jobId = submitted.jobId;
  if (submitted.optimisticVerify !== "success") {
    throw new Error(
      `Kurier optimisticVerify != success: ${JSON.stringify(submitted).slice(0, 300)}`
    );
  }
  let polls = 0;
  let last = null;
  while (Date.now() < deadlineMs) {
    last = await jobStatus(apiKey, jobId);
    polls++;
    if (last.status === "Finalized") {
      return {
        jobId,
        status: "Finalized",
        txHash: last.txHash || null,
        blockHash: last.blockHash || null,
        finalized: true,
        polls,
        elapsedMs: Date.now() - t0,
      };
    }
    if (last.status === "Failed") {
      return {
        jobId,
        status: "Failed",
        txHash: last.txHash || null,
        blockHash: last.blockHash || null,
        finalized: false,
        polls,
        elapsedMs: Date.now() - t0,
      };
    }
    await sleep(5000);
  }
  return {
    jobId,
    status: (last && last.status) || "Unknown",
    txHash: (last && last.txHash) || null,
    blockHash: (last && last.blockHash) || null,
    finalized: false,
    polls,
    elapsedMs: Date.now() - t0,
    timedOut: true,
  };
}

module.exports = {
  API_URL,
  registerVk,
  submitProof,
  jobStatus,
  submitAndFinalize,
};
