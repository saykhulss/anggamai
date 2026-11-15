# anggamai — Proof Gatekeeper agent (zkVerify Agent Games, Season 01)

A local build of the Proof Gatekeeper agent endpoint for the zkVerify
Agent Games competition (21 Oct – 21 Nov 2026). The agent is already
registered on agentgames.zkverify.io (handle `peksq9tw`, agent name
`anggamai`, Proof Gatekeeper track only). This repo is the **local
build + test** step: it proves the endpoint logic, the circuit, and the
decision rules work. **Deployment is a separate step** (Vercel
serverless layout is prepared: `api/index.js` + `vercel.json`).

No real secrets, no real funds, no live submissions anywhere in this
repo. Tests use a dummy HMAC secret and no Kurier key.

## What the agent does

The platform POSTs a signed JSON task envelope to the agent's public
HTTPS endpoint. The agent must, within 60 seconds:

1. Verify the HMAC-SHA256 in `x-agent-games-signature` against the
   **raw** request body, before parsing anything (bad signature → 401).
2. Decide deterministically: APPROVE only when every check passes,
   otherwise REJECT with the matching `reason_code`.
3. Generate a Groth16 proof of that decision with the tournament's
   own circuit (snarkjs 0.7.6) and include it in the response.
4. Sign the response with `x-agent-games-signature` over the raw
   response body. Fail closed (REJECT) on any timeout or uncertainty.

Scoring (official): correct decision +12 either way; wrong APPROVE
−6; wrong REJECT −3; timeout −2; provable task answered without a
valid proof −2; reliability bonus +0..+5 pro-rated by the share of
provable tasks whose proof verified.

## Files

| File | What it is |
|---|---|
| `api/index.js` | HTTP handler (Vercel serverless; also standalone via `node api/index.js`, PORT default 3000) |
| `lib/decision.js` | Deterministic decision checklist (pure function, no I/O) |
| `lib/encoding.js` | Task envelope → circuit inputs (field encoding, taskId parsing, salt) |
| `lib/hmac.js` | HMAC-SHA256 verify/sign (hex, base64 also accepted on verify) |
| `lib/prover.js` | snarkjs Groth16 prove/verify against the tournament circuit |
| `lib/kurier.js` | Kurier client: register-vk, submit-proof, job-status polling |
| `lib/store.js` | Idempotency: response cache by task_id + seen proof references |
| `circuits/` | Official artifacts: `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json`, `circuit-info.json` |
| `scripts/probe-signals.mjs` | Independent WASM probe that found the 13 input signal names |
| `tests/run-tests.cjs` | Full local test suite (`npm test`) |

## Quick start (local)

```bash
npm install
# dummy secret for local tests only — the real secret is never in this repo
AGENT_HMAC_SECRET=test-secret-dummy npm test
AGENT_HMAC_SECRET=test-secret-dummy PORT=3000 node api/index.js
```

Environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `AGENT_HMAC_SECRET` | yes | Per-agent 32-byte secret issued once at registration. Tests use a dummy. |
| `KURIER_API_KEY` | no | Kurier mainnet API key (kurier.xyz). Without it, proofs are returned locally only (no on-chain submission). |
| `REGISTERED_VK_HASH` | no | Official gatekeeper vkHash; defaults to `circuits/circuit-info.json`. |
| `STATE_FILE` | no | Seen-set JSON path; defaults to `data/state.json`. |
| `PROOF_TIMEOUT_MS` | no | Cap for one proof generation; default 45000. |

## Request / response schema (implemented)

Task envelope (from the official event page):

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_24_9d1",
  "mode": "competition",
  "issued_at": "<issued-at>",
  "deadline_at": "<deadline-at>",
  "input": {
    "registered_vk": "0x7d3a...f291",
    "proof_vk": "0xa4c1...b8ff",
    "minimum": "1000",
    "public_balance": "1460",
    "expiry_block": 19842201,
    "current_block": 19832000,
    "recipient": "0xDe42...9f01",
    "condition_recipient": "0xDe42...9f01",
    "amount": "500",
    "max_transfer": "1000",
    "proof_tx": "0xa4c1...8ff1"
  }
}
```

Response (decision + the documented fields, plus the proof):

```json
{
  "decision": "APPROVE",
  "reason_code": "VALID_CONDITION",
  "proof_tx": "0xa4c1...8ff1",
  "proof": { "pi_a": ["…","…","1"], "pi_b": [[…],[…],["1"]], "pi_c": ["…","…","1"], "protocol": "groth16", "curve": "bn128" },
  "publicSignals": ["<commitment>", "<registeredVkHash>", "<proofVkHash>", "1000", "1460", "19842201", "19832000", "<recipient>", "<conditionRecipient>", "500", "1000", "1", "24"],
  "proof_bytes": 722,
  "kurier": { "jobId": "…", "status": "Finalized", "txHash": "0x…" }
}
```

`proof` / `publicSignals` are omitted for `PROOF_REUSED` (the
tournament excludes those from the proof bonus). `kurier` is `null`
when no Kurier key is configured. Every response carries
`x-agent-games-signature` (HMAC-SHA256 hex over the raw body).

## Decision checklist (first failure wins)

| # | Check | Fail → reason_code |
|---|---|---|
| 0 | proof reference seen under a *different* task id | `PROOF_REUSED` (no proof generated) |
| 1 | proof VK ≠ registered VK | `VK_SUBSTITUTION` |
| 2 | registered VK ≠ official vkHash from `/api/circuit-info` | `VK_SUBSTITUTION` |
| 3 | public balance < minimum | `THRESHOLD_MISMATCH` |
| 4 | recipient ≠ condition recipient | `RECIPIENT_MISMATCH` |
| 5 | current block ≥ expiry block | `EXPIRED_CONDITION` |
| 6 | amount > max transfer | `AMOUNT_OVERFLOW` |
| — | all pass | `APPROVE` / `VALID_CONDITION` |

Retries of the same `task_id` return the cached response
byte-identical (idempotency key), they are never re-decided. A
proof reference is recorded as seen for every completed decision.

Check 2 is the "verification is necessary, not sufficient" case: the
circuit accepts two *equal* VK hashes even when neither is the
registered one, so the gatekeeper must compare against the official
hash off-circuit (verified in the test suite as case S6).

## Circuit verification (measured 2026-11-15)

Downloaded from the official site; sizes and hashes match the
published values:

| File | Bytes | SHA-256 |
|---|---|---|
| `gatekeeper.wasm` | 1,755,820 | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | 309,750 | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |

`/api/circuit-info` (saved as `circuits/circuit-info.json`):
gatekeeper vkHash
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
(Steal-the-VFY `vfyPolicy` vkHash is also in that file.)

Verification key exported with snarkjs 0.7.6: protocol groth16,
curve bn128, **13 public inputs**, witness size 647, Circom 2.

**Input signal names** — the site does not publish them. They were
found independently by probing the WASM (`scripts/probe-signals.mjs`:
Circom 2 resolves inputs by FNV-1a hash of the name;
`getInputSignalSize` returns 1 for a real signal, 0 otherwise):
`taskId, minimum, publicBalance, expiryBlock, currentBlock,
recipient, conditionRecipient, amount, maxTransfer, registeredVkHash,
proofVkHash, salt, decision` — 13/13 found, 0/20 decoy names matched,
total input size 13. `salt` is the only private input.

**Public-signal order** (verified empirically, not assumed):
`[0]` commitment `= Poseidon(salt, taskId)`,
`[1]` registeredVkHash, `[2]` proofVkHash, `[3]` minimum,
`[4]` publicBalance, `[5]` expiryBlock, `[6]` currentBlock,
`[7]` recipient, `[8]` conditionRecipient, `[9]` amount,
`[10]` maxTransfer, `[11]` decision, `[12]` taskId.
Checked: `Poseidon([987654321, 24]) =
4538591768452999874275481926009620849813943225939850916630922448132760538048`
equals `publicSignals[0]` of the valid-approve proof; the other
signals equal the inputs (hex values reduced mod the BN254 field
prime).

**Circuit behaviour** (matches the published write-ups): the circuit
enforces `decision == computed verdict`. A wrong decision cannot even
build a witness — `fullProve` throws `Assert Failed. Error in template
GatekeeperEvaluation_79 line: 102`. Measured locally: proof
generation ~305–1,164 ms (cold ~1.1 s, warm ~0.4 s), verification
~19–113 ms, proof ~719–724 bytes JSON. All well inside the 60 s
window.

## Kurier findings (docs.zkverify.io, read 2026-11-15)

Kurier is Horizen Labs' REST service for submitting proofs to
zkVerify. Mainnet `https://api.kurier.xyz/api/v1` (Swagger at
`/docs`); testnet `https://api-testnet.kurier.xyz/api/v1`.

- **API key:** sign up at https://kurier.xyz (mainnet) or
  https://testnet.kurier.xyz (testnet) and generate a key from the
  dashboard. **No payment step is documented for obtaining a key**;
  usage is tracked per key and rate limits can be raised via Discord.
  Whether a paid tier exists for high volume is *not stated* in the
  docs — the key itself is free to create (account signup only).
  No key is held by this repo.
- **Endpoints:**
  - `POST /register-vk/{key}` — `{proofType:"groth16",
    proofOptions:{library:"snarkjs",curve:"bn128"}, vk}` → `{vkHash}`
    (once per verification key).
  - `POST /submit-proof/{key}` — `{proofType:"groth16",
    vkRegistered:true, proofOptions:{library:"snarkjs",curve:"bn128"},
    proofData:{proof, publicSignals, vk: vkHash}}` →
    `{jobId, optimisticVerify:"success"}`.
  - `GET /job-status/{key}/{jobId}` → `{jobId, status, statusId,
    txHash, blockHash, …}`; statuses Queued → Valid → Submitted →
    IncludedInBlock → Finalized (or Failed). Poll every 5 s. The
    docs' worked example finalised in ~16 s.
- **Must the agent submit + poll to Finalized before responding?**
  The field guide's security section says "the verification reached
  a finalized state before approval". Read strictly, the agent
  submits its proof to Kurier and waits for Finalized before
  answering APPROVE. This implementation does exactly that when
  `KURIER_API_KEY` is set, within the remaining response budget
  (proof ~1 s + Kurier ~16 s typical ≪ 60 s). If Finalized is *not*
  reached by the deadline, the endpoint still answers with the
  locally verified proof plus the pending Kurier job reference, so
  the platform can confirm finalisation itself — strictly better
  than timing out (−2) or answering without a proof (−2). Without a
  key, Kurier is skipped and proofs are returned locally only.
- **zkVerifyJS alternative** (direct chain interaction) needs a seed
  phrase and a funded account (tVFY for fees) — not used here; that
  path is out of scope for this free-only build.

## Known unknowns — confirm on first Practice dispatch

These are **assumptions, not published facts**. The Practice endpoint
is the place to confirm each one (10 free dispatches/hour/agent):

1. **taskId encoding.** The envelope `task_id` is a string like
   `"gk_24_9d1"` but the circuit takes a field element. Implemented:
   parse the numeric middle segment (`gk_<N>_<suffix>` → `N`).
   Evidence: the sample id contains `24` and the published Poseidon
   check uses `taskId=24`. Fallback (untested against the platform):
   `keccak256(task_id) mod FIELD_PRIME`. If Practice shows a
   taskId mismatch, switch the encoding.
2. **Response proof field names.** The event page's "expected
   response shape" shows only `decision`, `reason_code`, `proof_tx`.
   The guide says to include the proof, but no field names are
   published. Implemented as `proof` (snarkjs object) +
   `publicSignals` (array), matching snarkjs/Kurier conventions.
3. **HMAC digest encoding.** Not published. Implemented: verify
   accepts lowercase hex or base64; responses are signed as
   lowercase hex.
4. **Preflight format.** Not published. Implemented: `GET /`
   returns a signed health JSON; an unknown-type POST returns a
   signed `{"status":"ok"}` ack.
5. **On-chain confirmation of the *incoming* proof.** The build
   checklist says to call zkVerifyJS to confirm the task's proof is
   on-chain with a matching VK. The trap varieties are all
   detectable from the envelope alone, so the decision does not
   depend on it; this build does not perform the lookup (no Kurier
   key / funded account locally). Before production, decide whether
   to enforce it (fail-closed: a lookup outage would flip APPROVEs
   to REJECTs) or keep it advisory.

## Test report

Run `npm test` (dummy HMAC secret, no Kurier key). Results from
2026-11-15 (see `tests/run-tests.cjs` for the cases):

- **HMAC (6 checks):** valid verifies; wrong secret / missing /
  garbage / tampered body rejected; base64 form accepted.
- **Decision matrix (6 trap varieties × correct + wrong decision):**
  every correct decision proves and verifies OK (prove 305–1,164 ms,
  verify 19–113 ms, proof 719–724 bytes); every wrong decision is
  refused by the circuit (`GatekeeperEvaluation_79 line: 102`).
  `PROOF_REUSED` is covered at HTTP level (D7).
- **S6 (equal-but-unregistered VKs):** circuit still verifies the
  proof; the gatekeeper rejects it — verification ≠ sufficiency.
- **Public signals:** commitment = Poseidon(salt, taskId) confirmed;
  ordering confirmed; vkHash mod-p confirmed.
- **End-to-end HTTP:** valid task → 200 APPROVE + verifying proof in
  412 ms; bad HMAC → 401; retry → byte-identical response; reused
  proof under a new task → PROOF_REUSED with no proof field;
  recipient trap → REJECT + verifying proof.
- **Total: 39/39 checks passed** (first run was 36/38: a wrong
  BN254 prime literal in the test and a reused `proof_tx` in the
  D8 test case — both test bugs, fixed; the endpoint code was
  already correct).

## Deployment checklist (not done here)

- [ ] Create a Vercel account (sign up with GitHub `saykhulss`) and
  deploy this repo (`vercel --prod`); note the public HTTPS URL.
- [ ] Set `AGENT_HMAC_SECRET` (the real per-agent secret, held by the
  user — enter it in the Vercel dashboard, never in chat or git)
  and `KURIER_API_KEY` (from kurier.xyz) as Vercel env vars.
- [ ] Register/update the endpoint URL on the agent's Agent Games
  settings page; wait for the health check to pass.
- [ ] Run the Practice task (dashboard → Practice → Dispatch) and
  confirm assumptions 1–4 above against a real task.
- [ ] Replace the file-backed seen-set with durable storage
  (Vercel KV / Upstash) — serverless instances are ephemeral, so a
  cold instance could miss a reuse.
- [ ] Watch round windows (16:00–02:00 IST = 17:30–03:30 WIB);
  the endpoint must stay up; free-tier sleeping loses tasks.

## Security notes

- The real per-agent HMAC secret is held by the user only. It must
  never be committed, pasted in chat, or written to any file. Tests
  use `test-secret-dummy`.
- No Kurier key, seed phrase, private key, or wallet is in this repo.
- The endpoint never spends anything: proof generation and local
  verification are free; Kurier submission uses the key's quota only.
