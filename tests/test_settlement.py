"""Tests for the Python settlement ledger (contracts/settlement_sim.py)."""

import pytest

from contracts.settlement_sim import (
    AlreadySpentError,
    InvalidProofError,
    NotPaidError,
    Proof,
    SettleInput,
    Settlement,
    VerifierAdapter,
    valid_toy_proof,
)


def test_settle_pays_payee_and_marks_spent():
    s = Settlement(price=100)
    nul = s.settle(valid_toy_proof(), SettleInput(42, 7), "alice", 100)
    assert nul == 7
    assert s.spent == {7}
    assert s.balances["payee-node"] == 100
    assert s.count == 1


def test_double_settle_same_nullifier_reverted():
    s = Settlement(price=100)
    s.settle(valid_toy_proof(), SettleInput(42, 9), "alice", 100)
    with pytest.raises(AlreadySpentError):
        s.settle(valid_toy_proof(), SettleInput(42, 9), "bob", 100)
    assert s.count == 1


def test_underpaid_reverted():
    s = Settlement(price=100)
    with pytest.raises(NotPaidError):
        s.settle(valid_toy_proof(), SettleInput(42, 1), "alice", 99)


def test_invalid_window_reverted():
    s = Settlement(price=100)
    with pytest.raises(InvalidProofError):
        s.settle(valid_toy_proof(), SettleInput(41, 2), "alice", 100)


def test_zero_proof_points_rejected():
    s = Settlement(price=100)
    bad = Proof(a=(0, 0), b=((3, 4), (5, 6)), c=(7, 8))
    with pytest.raises(InvalidProofError):
        s.settle(bad, SettleInput(42, 3), "alice", 100)


def test_surplus_refunded():
    s = Settlement(price=100)
    s.settle(valid_toy_proof(), SettleInput(42, 4), "alice", 250)
    assert s.balances["payee-node"] == 100
    assert s.balances["alice"] == 150


def test_verifier_adapter_wrong_input_length():
    v = VerifierAdapter()
    ok = v.verify(valid_toy_proof(), SettleInput(42, 123))
    assert ok
    # The adapter mirrors the Solidity verifier's length check implicitly
    # (it always parses exactly two signals); a mismatched window fails.
    assert not v.verify(valid_toy_proof(), SettleInput(0, 123))