// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "./IVerifier.sol";

/// @title Reference Groth16 verifier (toy entropy-audit circuit layout)
/// @notice Drop-in stand-in for `snarkjs zkey export solidityverifier`
///         output. Implements the *signal-layout* contract that the toy
///         circuit (circuits/toy_entropy_audit.circom) enforces, so the
///         settlement flow is fully testable without the toolchain:
///           - public signals are exactly [window_id, nullifier]
///           - the valid-window gate (window_id == 42) holds
///           - the proof points must be non-zero field elements
///         Replace this file with the export of the real artifact to get
///         full cryptographic verification; no other contract changes.
contract Verifier is IVerifier {
    /// @dev The toy circuit's hard-coded valid window.
    uint256 internal constant VALID_WINDOW = 42;

    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) external pure override returns (bool) {
        // Signal layout: [window_id, nullifier].
        if (input.length != 2) {
            return false;
        }
        if (input[0] != VALID_WINDOW) {
            return false;
        }
        // Structural sanity: no zero group elements in the proof.
        if (a[0] == 0 && a[1] == 0) {
            return false;
        }
        if (c[0] == 0 && c[1] == 0) {
            return false;
        }
        for (uint256 i = 0; i < 2; i++) {
            if (b[i][0] == 0 && b[i][1] == 0) {
                return false;
            }
        }
        return true;
    }
}