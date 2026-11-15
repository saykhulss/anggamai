// Probe the gatekeeper WASM for input signal names (independent verification).
// Circom 2 WASM resolves input signals by FNV-1a hash of the name;
// getInputSignalSize(hMSB, hLSB) returns the signal size, or < 0 when absent.
import fs from "fs";
import { WitnessCalculatorBuilder } from "circom_runtime";

// fnvHash, copied verbatim from circom_runtime/js/utils.js (FNV-1a 64-bit).
function fnvHash(str) {
  const uint64_max = BigInt(2) ** BigInt(64);
  let hash = BigInt("0xCBF29CE484222325");
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str[i].charCodeAt(0));
    hash *= BigInt(0x100000001B3);
    hash %= uint64_max;
  }
  let shash = hash.toString(16);
  let n = 16 - shash.length;
  shash = "0".repeat(n).concat(shash);
  return shash;
}

const wasm = fs.readFileSync("circuits/gatekeeper.wasm");
const wc = await WitnessCalculatorBuilder(wasm, { sanityCheck: false });
const ex = wc.instance.exports;

console.log("circom version:", ex.getVersion());
console.log("total input size (getInputSize):", ex.getInputSize());
console.log("witness size:", ex.getWitnessSize());

const claimed = [
  "taskId", "minimum", "publicBalance", "expiryBlock", "currentBlock",
  "recipient", "conditionRecipient", "amount", "maxTransfer",
  "registeredVkHash", "proofVkHash", "salt", "decision",
];
const decoys = [
  "nonsense", "vkHash", "proof", "sender", "balance", "task_id",
  "public_balance", "vk", "nonce", "commitment", "output", "action",
  "registered_vk", "proof_vk", "expiry_block", "current_block",
  "max_transfer", "condition_recipient", "publicBalance2", "TaskId",
];

function probe(name) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  const size = ex.getInputSignalSize(hMSB, hLSB);
  return size;
}

console.log("\n--- claimed signal names ---");
let found = 0;
for (const n of claimed) {
  const s = probe(n);
  console.log(`${n}: ${s < 0 ? "NOT FOUND" : "size=" + s}`);
  if (s >= 0) found++;
}
console.log(`claimed found: ${found}/${claimed.length}`);

console.log("\n--- decoy names (should all be NOT FOUND) ---");
let decoyHits = 0;
for (const n of decoys) {
  const s = probe(n);
  if (s >= 0) { console.log(`${n}: size=${s}  <-- UNEXPECTED`); decoyHits++; }
}
console.log(`decoy hits: ${decoyHits}/${decoys.length}`);
