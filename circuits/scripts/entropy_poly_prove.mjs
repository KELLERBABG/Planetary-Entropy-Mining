// Real entropy-gate zk-SNARK end-to-end.
//
// Usage:  node scripts/entropy_poly_prove.mjs [--assert] [--keep] [--out <dir>]
//
// Pipeline (all local, all deterministic, no network after install):
//   1. compile circuits/entropy_audit_poly.circom (circom WASM)  -> r1cs/wasm/sym
//   2. generate the witness from cli/zk_witness.py input.json
//   3. Powers-of-Tau (bn128, power 14) + beacon contribution
//   4. Groth16 phase-2 setup + contribution + verification key
//   5. prove  -> proof.json + public.json
//   6. verify -> assertion / exit code
//   7. export  -> Verifier.sol (real Groth16 pairing verifier) + calldata
//
// Artifacts live in circuits/build/poly; removed unless --keep.
// `--out` copies the exported verifier + calldata fixtures to a directory
// (used by the Foundry integration and the Python twin test fixtures).

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, copyFileSync, rmSync, existsSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const BUILD = join(ROOT, "build", "poly");

const keep = process.argv.includes("--keep");
const assertMode = process.argv.includes("--assert");
const outIdx = process.argv.indexOf("--out");
const OUT_DIR = outIdx >= 0 ? process.argv[outIdx + 1] : null;

function sh(bin, args, cwd = BUILD) {
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
// 1. Compile the entropy-gate circuit.
// ---------------------------------------------------------------------------
step("Compiling entropy_audit_poly.circom (circom2 WASM)");
sh("circom", [
  "entropy_audit_poly.circom",
  "--r1cs", "--wasm", "--sym",
  "-l", "node_modules",
  "-o", join("build", "poly").replaceAll("\\", "/"),
], ROOT);

// ---------------------------------------------------------------------------
// 2. Build the witness (real pipeline data via the Python builder).
// ---------------------------------------------------------------------------
step("Building witness inputs");
execFileSync("py", ["-m", "cli.zk_witness", "--out",
                    join(BUILD, "input.json")],
             { stdio: "inherit" });

const wasmDir = join(BUILD, "entropy_audit_poly_js");
const witness = join(BUILD, "witness.wtns");
step("Generating witness");
execFileSync(
  process.execPath,
  [join(wasmDir, "generate_witness.js"),
   join(wasmDir, "entropy_audit_poly.wasm"),
   join(BUILD, "input.json"), witness],
  { stdio: "inherit" }
);

// ---------------------------------------------------------------------------
// 3. Powers of Tau (bn128, power 14) + deterministic beacon.
//    Power 14 supports 2^14 = 16384 constraints; the entropy-gate circuit
//    needs ~ (64+256+256+3) * ~2 + poseidon constraints, well under that.
// ---------------------------------------------------------------------------
step("Powers of Tau (deterministic)");
sh("snarkjs", ["powersoftau", "new", "bn128", "14", "pot14_0000.ptau", "-v"]);
sh("snarkjs", ["powersoftau", "contribute", "pot14_0000.ptau", "pot14_0001.ptau",
               "--name=PEM entropy", "-v", "-e=entropy-seed-0000"]);
sh("snarkjs", ["powersoftau", "beacon", "pot14_0001.ptau", "pot14_beacon.ptau",
               "010203040506070809", "10", "-n=PEM-Beacon"]);
sh("snarkjs", ["powersoftau", "prepare", "phase2", "pot14_beacon.ptau",
               "pot14_final.ptau", "-v"]);

// ---------------------------------------------------------------------------
// 4. Groth16 phase-2 setup.
// ---------------------------------------------------------------------------
step("Groth16 setup");
sh("snarkjs", ["groth16", "setup", "entropy_audit_poly.r1cs", "pot14_final.ptau",
               "entropy_0000.zkey"]);
sh("snarkjs", ["zkey", "contribute", "entropy_0000.zkey", "entropy.zkey",
               "--name=PEM", "-v", "-e=entropy-phase2-seed"]);
sh("snarkjs", ["zkey", "export", "verificationkey", "entropy.zkey",
               "verification_key.json"]);

// ---------------------------------------------------------------------------
// 5. Prove + 6. Verify.
// ---------------------------------------------------------------------------
step("Proving");
sh("snarkjs", ["groth16", "prove", "entropy.zkey", "witness.wtns",
               "proof.json", "public.json"]);

step("Verifying");
const verifyOut = sh("snarkjs", ["groth16", "verify", "verification_key.json",
                                 "public.json", "proof.json"]);
console.log(verifyOut.trim());
const ok = verifyOut.includes("OK");
console.log(`RESULT: ${ok ? "PASS" : "FAIL"}`);

// ---------------------------------------------------------------------------
// 7. Export the real Solidity verifier + calldata for the settlement layer.
// ---------------------------------------------------------------------------
if (ok) {
  step("Exporting Solidity verifier");
  sh("snarkjs", ["zkey", "export", "solidityverifier", "entropy.zkey",
                 "EntropyVerifier.sol"]);
  sh("snarkjs", ["zkey", "export", "soliditycalldata", "public.json",
                 "proof.json", "calldata.txt"]);
  console.log("Exported EntropyVerifier.sol + calldata.txt");

  if (OUT_DIR) {
    mkdirSync(OUT_DIR, { recursive: true });
    copyFileSync(join(BUILD, "EntropyVerifier.sol"),
                 join(OUT_DIR, "EntropyVerifier.sol"));
    copyFileSync(join(BUILD, "calldata.txt"), join(OUT_DIR, "calldata.txt"));
    copyFileSync(join(BUILD, "public.json"), join(OUT_DIR, "public.json"));
    copyFileSync(join(BUILD, "proof.json"), join(OUT_DIR, "proof.json"));
    copyFileSync(join(BUILD, "input.json"), join(OUT_DIR, "input.json"));
    console.log(`Copied artifacts -> ${OUT_DIR}`);
  }
}

if (!keep) {
  rmSync(BUILD, { recursive: true, force: true });
}

if (assertMode && !ok) {
  process.exit(1);
}
process.exit(ok ? 0 : 1);