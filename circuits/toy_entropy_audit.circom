// Toy zk-SNARK circuit for the Planetary Entropy Audit (P0 capstone).
//
// Proves, in zero knowledge:
//   "I know a hardened-entropy secret and a node secret such that the
//    nullifier commitment for this valid window equals the public value —
//    without revealing the secret or the node secret."
//
// Signal layout:
//   public  window_id  (capture window epoch — the "time T")
//   public  nullifier  (OUTPUT: Poseidon(secret, node_secret, window_id))
//   private secret     (the hardened entropy seed of this capture)
//   private node_secret (per-node keying material)
//
// The nullifier is a public OUTPUT computed by the circuit, so a verifier
// learns only "some node holding entropy opened nullifier N in a valid
// window" — no location, no capture bytes, no secret. The prover's witness
// (secret, node_secret) is kept private.
//
// (1) window_id == 42 is a placeholder for the real "NIST SP 800-90B
//     min-entropy >= threshold" gate; the full circuit adds the polynomial
//     hardening + entropy-threshold constraints.
// (2) nullifier = Poseidon(secret, node_secret, window_id): a field-native
//     ZK-friendly commitment (the same construction used in mixers). Being
//     an output, it is computed by the circuit itself and needs no
//     JS-side hash, so the witness is always consistent with the circuit.

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template EntropyAuditToy() {
    // Public inputs.
    signal input window_id;
    // Private witness.
    signal input secret;
    signal input node_secret;
    // Public output: the commitment.
    signal output nullifier;

    // (1) Valid-window gate (toy: window must be 42).
    signal validWindow <== window_id - 42;
    validWindow === 0;

    // (2) Commit.
    component c = Poseidon(3);
    c.inputs[0] <== secret;
    c.inputs[1] <== node_secret;
    c.inputs[2] <== window_id;
    nullifier <== c.out;
}

component main = EntropyAuditToy();