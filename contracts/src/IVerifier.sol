// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Groth16 verifier interface (snarkjs-compatible)
/// @notice The standard signature exported by `snarkjs zkey export
///         solidityverifier`. `EntropySettlement` depends only on this
///         interface, so the real artifact can be swapped in without
///         touching settlement logic.
interface IVerifier {
    /// @param a            Proof point A (G1)
    /// @param b            Proof point B (G2)
    /// @param c            Proof point C (G1)
    /// @param input        Public signals in the circuit's declared order
    /// @return r           True iff the Groth16 proof verifies
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) external view returns (bool r);
}