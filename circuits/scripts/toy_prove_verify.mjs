// P0 capstone: toy zk-SNARK end-to-end.
//
// Usage:  node scripts/toy_prove_verify.mjs [--assert] [--keep]
//
// Pipeline (all local, all deterministic, no network after install):
//   1. compile toy_entropy_audit.circom (circom WASM)   -> toy.r1cs + toy.wasm
//   2. compute witness (Poseidon nullifier via circomlib)
//   3. Powers-of-Tau (bn128, 12) + Beacon contribution  -> pot12_final.ptau
//   4. Groth16 phase-2 setup + contribution             -> toy.zkey
//   5. prove  -> proof.json + public.json
//   6. verify -> assertion / exit code
//
// Everything runs in circuits/build/toy; artifacts are removed unless --keep.

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const BUILD = join(ROOT, "build", "toy");
const BIN = join(ROOT, "node_modules", ".bin");

const keep = process.argv.includes("--keep");
const assertMode = process.argv.includes("--assert");

function sh(bin, args, cwd = BUILD) {
  // Invoke the Node CLI entry points directly (no shell), so the
  // space-containing repo path ("Obsidian Vault") never hits cmd.exe
  // quoting. circom -> circom2/cli.js, snarkjs -> snarkjs/build/cli.cjs
  let entry;
  if (bin === "circom") {
    entry = join(ROOT, "node_modules", "circom2", "cli.js");
  } else if (bin === "snarkjs") {
    entry = join(ROOT, "node_modules", "snarkjs", "build", "cli.cjs");
  } else {
    throw new Error(`unknown tool: ${bin}`);
  }
  return execFileSync(process.execPath, [entry, ...args],
                      { cwd, stdio: "pipe" }).toString();
}

function step(label) {
  console.log(`\n=== ${label} ===`);
}

mkdirSync(BUILD, { recursive: true });

// ---------------------------------------------------------------------------
// 1. Compile the toy circuit.
// ---------------------------------------------------------------------------
step("Compiling toy_entropy_audit.circom (circom2 WASM)");
// circom2's WASM sandbox requires RELATIVE paths and maps "." via the
// preopen chain; running from ROOT with repo-relative paths keeps the
// whole input/output set inside the single mapped root.
mkdirSync(BUILD, { recursive: true });
sh("circom", [
  "toy_entropy_audit.circom",
  "--r1cs",
  "--wasm",
  "--sym",
  "-l",
  "node_modules",
  "-o",
  join("build", "toy").replaceAll("\\", "/"),
], ROOT);

// ---------------------------------------------------------------------------
// 2. Generate a valid witness.
//    secret + node_secret are the private witness; window_id is the public
//    input. The nullifier is a public OUTPUT the circuit computes itself
//    (Poseidon(secret, node_secret, window_id)), so the witness stays
//    trivially consistent with the constraints.
// ---------------------------------------------------------------------------
step("Building witness inputs");
const secret = "12345678901234567890";         // hardened entropy seed
const nodeSecret = "98765432109876543210";      // node keying material
const windowId = "42";                          // the "valid window" gate

const input = {
  window_id: windowId,
  secret,
  node_secret: nodeSecret,
};
writeFileSync(join(BUILD, "input.json"), JSON.stringify(input, null, 2));

const wasmDir = join(BUILD, "toy_entropy_audit_js");
const witness = join(BUILD, "witness.wtns");
step("Generating witness");
execFileSync(
  process.execPath,
  [join(wasmDir, "generate_witness.js"), join(wasmDir, "toy_entropy_audit.wasm"),
   join(BUILD, "input.json"), witness],
  { stdio: "pipe" }
);

// ---------------------------------------------------------------------------
// 3. Powers of Tau (tiny, bn128, 12 constraints) + deterministic beacon.
// ---------------------------------------------------------------------------
step("Powers of Tau (deterministic)");
sh("snarkjs", ["powersoftau", "new", "bn128", "12", "pot12_0000.ptau", "-v"]);
sh("snarkjs", ["powersoftau", "contribute", "pot12_0000.ptau", "pot12_0001.ptau",
               "--name=PEM toy", "-v", "-e=toy-seed-0000"]);
sh("snarkjs", ["powersoftau", "beacon", "pot12_0001.ptau", "pot12_beacon.ptau",
               "010203040506070809", "10", "-n=PEM-Beacon"]);
sh("snarkjs", ["powersoftau", "prepare", "phase2", "pot12_beacon.ptau",
               "pot12_final.ptau", "-v"]);

// ---------------------------------------------------------------------------
// 4. Groth16 phase-2 setup.
// ---------------------------------------------------------------------------
step("Groth16 setup");
sh("snarkjs", ["groth16", "setup", "toy_entropy_audit.r1cs", "pot12_final.ptau",
               "toy_0000.zkey"]);
sh("snarkjs", ["zkey", "contribute", "toy_0000.zkey", "toy.zkey",
               "--name=PEM", "-v", "-e=toy-phase2-seed"]);
sh("snarkjs", ["zkey", "export", "verificationkey", "toy.zkey",
               "verification_key.json"]);

// ---------------------------------------------------------------------------
// 5. Prove + 6. Verify.
// ---------------------------------------------------------------------------
step("Proving");
sh("snarkjs", ["groth16", "prove", "toy.zkey", "witness.wtns", "proof.json",
               "public.json"]);

step("Verifying");
const verifyOut = sh("snarkjs", ["groth16", "verify", "verification_key.json",
                                 "public.json", "proof.json"]);
console.log(verifyOut.trim());

const ok = verifyOut.includes("OK");
console.log(`\nPUBLIC INPUTS: ${verifyOut.match(/\[\s*[^\]]*\]/)?.[0] ?? ""}`);
console.log(`RESULT: ${ok ? "PASS" : "FAIL"}`);

if (!keep) {
  rmSync(BUILD, { recursive: true, force: true });
}

if (assertMode && !ok) {
  process.exit(1);
}
process.exit(ok ? 0 : 1);