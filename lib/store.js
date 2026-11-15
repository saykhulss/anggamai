"use strict";
/**
 * store.js — idempotency + proof-reuse state.
 *
 * Two structures, both keyed exactly as the rules require:
 *  - responsesByTaskId: task_id -> full response body (byte-identical
 *    replay for platform retries of the same task).
 *  - seenProofRefs: proof_tx values already decided (any task). A proof
 *    reference arriving under a DIFFERENT task id is PROOF_REUSED.
 *
 * Locally this is file-backed JSON (data/state.json) so restarts keep
 * the seen-set. On Vercel the filesystem is ephemeral per instance, so
 * production should swap this for durable storage (e.g. Vercel KV /
 * Upstash Redis) — the interface below is deliberately tiny so the
 * swap is one file. In-memory only is also acceptable for a first
 * deploy; the risk is a cold instance missing a reuse (one wrong
 * decision per redeploy at worst).
 */
const fs = require("fs");
const path = require("path");

class Store {
  constructor(filePath) {
    this.filePath = filePath || null;
    this.responsesByTaskId = new Map();
    this.seenProofRefs = new Set();
    if (this.filePath) this.load();
  }

  load() {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const data = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
      this.responsesByTaskId = new Map(Object.entries(data.responses || {}));
      this.seenProofRefs = new Set(data.proofRefs || []);
    } catch (e) {
      // Corrupt state file: start empty rather than crash the agent.
      console.error("[store] state load failed, starting empty:", e.message);
    }
  }

  save() {
    if (!this.filePath) return;
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const data = {
        responses: Object.fromEntries(this.responsesByTaskId),
        proofRefs: [...this.seenProofRefs],
      };
      const tmp = this.filePath + ".tmp";
      fs.writeFileSync(tmp, JSON.stringify(data));
      fs.renameSync(tmp, this.filePath);
    } catch (e) {
      console.error("[store] state save failed:", e.message);
    }
  }

  getCachedResponse(taskId) {
    return this.responsesByTaskId.get(taskId) || null;
  }

  hasSeenProofRef(proofTx) {
    return this.seenProofRefs.has(String(proofTx));
  }

  /** Record a completed decision: cache the response + mark proof seen. */
  record(taskId, proofTx, responseBody) {
    if (taskId) this.responsesByTaskId.set(taskId, responseBody);
    if (proofTx) this.seenProofRefs.add(String(proofTx));
    this.save();
  }
}

module.exports = { Store };
