// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {EntropySettlement} from "../src/EntropySettlement.sol";
import {Verifier} from "../src/Verifier.sol";

/// @dev A valid proof for the toy circuit layout (window_id = 42).
///      The reference Verifier only checks structure, not group math, so
///      any non-zero points satisfy it when the window gate passes.
contract EntropySettlementTest is Test {
    EntropySettlement internal settlement;
    Verifier internal verifier;
    address internal payee = makeAddr("payee");
    address internal claimant = makeAddr("claimant");
    uint256 internal constant PRICE = 1 ether;

    function setUp() public {
        verifier = new Verifier();
        settlement = new EntropySettlement(address(verifier), payee, PRICE);
    }

    function _validInput(uint256 nullifier)
        internal
        pure
        returns (uint256[] memory)
    {
        uint256[] memory input = new uint256[](2);
        input[0] = 42; // valid window gate
        input[1] = nullifier;
        return input;
    }

    function _validProof()
        internal
        pure
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c)
    {
        a = [uint256(1), uint256(2)];
        // G2 points: two 2-tuples (explicit casts for fixed-size arrays).
        b = [
            [uint256(3), uint256(4)],
            [uint256(5), uint256(6)]
        ];
        c = [uint256(7), uint256(8)];
    }

    function test_SettleTransfersPriceToPayee() public {
        uint256 nullifier = 12345;
        vm.deal(claimant, PRICE);
        vm.prank(claimant);
        uint256 paid = settlement.settle{value: PRICE}(
            _validProof0(), _validProof1(), _validProof2(),
            _validInput(nullifier)
        );
        assertEq(paid, nullifier);
        assertEq(payee.balance, PRICE);
        assertTrue(settlement.spent(nullifier));
    }

    function test_RejectSecondSettleSameNullifier() public {
        uint256 nullifier = 99;
        vm.deal(claimant, 2 * PRICE);
        vm.startPrank(claimant);
        settlement.settle{value: PRICE}(
            _validProof0(), _validProof1(), _validProof2(),
            _validInput(nullifier)
        );
        vm.expectRevert(abi.encodeWithSelector(
            EntropySettlement.AlreadySpent.selector, nullifier));
        settlement.settle{value: PRICE}(
            _validProof0(), _validProof1(), _validProof2(),
            _validInput(nullifier)
        );
        vm.stopPrank();
    }

    function test_RevertWhenUnderpaid() public {
        uint256 nullifier = 7;
        vm.deal(claimant, PRICE - 1);
        vm.prank(claimant);
        vm.expectRevert(abi.encodeWithSelector(
            EntropySettlement.NotPaid.selector, PRICE, PRICE - 1));
        settlement.settle{value: PRICE - 1}(
            _validProof0(), _validProof1(), _validProof2(),
            _validInput(nullifier)
        );
    }

    function test_RevertWhenInvalidWindow() public {
        uint256[] memory input = new uint256[](2);
        input[0] = 41; // wrong window
        input[1] = 5;
        vm.deal(claimant, PRICE);
        vm.prank(claimant);
        vm.expectRevert(EntropySettlement.InvalidProof.selector);
        settlement.settle{value: PRICE}(
            _validProof0(), _validProof1(), _validProof2(), input
        );
    }

    function test_RevertWhenWrongInputLength() public {
        uint256[] memory input = new uint256[](1);
        input[0] = 42;
        vm.deal(claimant, PRICE);
        vm.prank(claimant);
        vm.expectRevert(EntropySettlement.InvalidProof.selector);
        settlement.settle{value: PRICE}(
            _validProof0(), _validProof1(), _validProof2(), input
        );
    }

    function test_RefundSurplus() public {
        uint256 nullifier = 42_000;
        uint256 overpay = PRICE + 0.5 ether;
        vm.deal(claimant, overpay);
        vm.prank(claimant);
        settlement.settle{value: overpay}(
            _validProof0(), _validProof1(), _validProof2(),
            _validInput(nullifier)
        );
        assertEq(payee.balance, PRICE);
        assertEq(claimant.balance, overpay - PRICE);
    }

    function test_OnlyPayeeCanChangePrice() public {
        vm.prank(payee);
        settlement.setPrice(2 ether);
        assertEq(settlement.price(), 2 ether);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert("only payee");
        settlement.setPrice(3 ether);
    }

    // -- helpers: unpack the tuple from _validProof() ----------------------

    function _validProof0() internal pure returns (uint256[2] memory) {
        (uint256[2] memory a,,) = _validProof();
        return a;
    }

    function _validProof1() internal pure returns (uint256[2][2] memory) {
        (, uint256[2][2] memory b,) = _validProof();
        return b;
    }

    function _validProof2() internal pure returns (uint256[2] memory) {
        (, , uint256[2] memory c) = _validProof();
        return c;
    }
}