// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "./IVerifier.sol";

/// @title Entropy settlement: proof verification + atomic payment
/// @notice The on-chain end of the Planetary Entropy Audit pipeline.
///
/// A claimant attests a captured entropy window by submitting a Groth16
/// proof (toy circuit: "valid window + nullifier commitment") together with
/// the public nullifier. Settlement rules:
///
///   1. The nullifier must not have been spent before (anti-double-mint —
///      the on-chain counterpart of the identity-layer nullifier).
///   2. The proof must verify against the public signals.
///   3. `msg.value` must cover `price`; the surplus is refunded.
///
/// State changes happen *before* the external transfer (checks-effects-
/// interactions), so a malicious claimant contract cannot re-enter.
contract EntropySettlement {
    IVerifier public immutable verifier;

    /// @notice Wei required to settle one certificate.
    uint256 public price;

    /// @notice Paid out to the node that mined the entropy window.
    address public immutable payee;

    /// @notice nullifier -> already settled?
    mapping(uint256 => bool) public spent;

    event Settled(address indexed claimant, uint256 nullifier, uint256 amount);
    event PriceChanged(uint256 oldPrice, uint256 newPrice);

    error NotPaid(uint256 required, uint256 received);
    error AlreadySpent(uint256 nullifier);
    error InvalidProof();

    constructor(address verifier_, address payee_, uint256 price_) {
        require(verifier_ != address(0), "zero verifier");
        require(payee_ != address(0), "zero payee");
        verifier = IVerifier(verifier_);
        payee = payee_;
        price = price_;
    }

    /// @notice Set a new settlement price (operator).
    function setPrice(uint256 newPrice) external {
        require(msg.sender == payee, "only payee");
        emit PriceChanged(price, newPrice);
        price = newPrice;
    }

    /// @notice Verify a Groth16 proof and (atomically) release payment.
    /// @param a,b,c   Proof points.
    /// @param input   Public signals — the toy circuit's layout is
    ///                [window_id, nullifier]; the verifier enforces the
    ///                window gate, so the only input we trust to bind the
    ///                payment is the nullifier.
    /// @return nullifierClaimed The committed nullifier the payment settled.
    function settle(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) external payable returns (uint256 nullifierClaimed) {
        if (msg.value < price) {
            revert NotPaid(price, msg.value);
        }
        nullifierClaimed = input[input.length - 1];
        if (spent[nullifierClaimed]) {
            revert AlreadySpent(nullifierClaimed);
        }
        if (!verifier.verifyProof(a, b, c, input)) {
            revert InvalidProof();
        }
        // Effects before interactions.
        spent[nullifierClaimed] = true;
        emit Settled(msg.sender, nullifierClaimed, price);

        (bool ok,) = payee.call{value: price}("");
        require(ok, "payee transfer failed");

        uint256 surplus = msg.value - price;
        if (surplus > 0) {
            (bool okRefund,) = msg.sender.call{value: surplus}("");
            require(okRefund, "refund failed");
        }
        return nullifierClaimed;
    }
}