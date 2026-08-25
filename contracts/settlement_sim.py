"""Settlement ledger mirroring `contracts/src/EntropySettlement.sol`.

The Solidity contract is the authoritative settlement layer; this module is
its laptop-runnable twin for the e2e demo and tests. It enforces the same
rules on an in-memory ledger:

  1. Proof verification (Groth16 layout of the toy circuit via
     `VerifierAdapter` — window gate + structural checks).
  2. Anti-double-spend: each nullifier settles at most once.
  3. Payment: `msg.sender` covers `price`, surplus refunded.

No real money: balances are plain integers in a dictionary. Deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class SettlementError(Exception):
    """Base class for settlement failures."""


class NotPaidError(SettlementError):
    pass


class AlreadySpentError(SettlementError):
    pass


class InvalidProofError(SettlementError):
    pass


@dataclass(frozen=True)
class Proof:
    """Groth16 proof triple (structure-only in the reference adapter)."""

    a: tuple[int, int]
    b: tuple[tuple[int, int], tuple[int, int]]
    c: tuple[int, int]


@dataclass(frozen=True)
class SettleInput:
    """Public signals in the toy circuit's layout: [window_id, nullifier]."""

    window_id: int
    nullifier: int

    def to_list(self) -> list[int]:
        return [self.window_id, self.nullifier]


class VerifierAdapter:
    """Reference Groth16 verifier standing in for the exported artifact.

    Mirrors `contracts/src/Verifier.sol`: enforces the toy circuit's public
    layout — exactly two public signals and the valid-window gate — plus
    non-zero proof points. Swap in a real binding to `snarkjs verify` for
    full cryptography.
    """

    VALID_WINDOW = 42

    def verify(self, proof: Proof, signals: SettleInput) -> bool:
        if signals.window_id != self.VALID_WINDOW:
            return False
        # Non-zero structural checks (same as the Solidity verifier).
        if proof.a == (0, 0) or proof.c == (0, 0):
            return False
        if proof.b == ((0, 0), (0, 0)):
            return False
        return True


@dataclass
class Settlement:
    """Simple deterministic settlement ledger."""

    price: int = 100
    payee: str = "payee-node"
    verifier: VerifierAdapter = field(default_factory=VerifierAdapter)
    spent: set[int] = field(default_factory=set)
    balances: dict[str, int] = field(default_factory=dict)
    count: int = 0
    ledger: list[dict] = field(default_factory=list)

    def settle(self, proof: Proof, signals: SettleInput,
               sender: str, value: int) -> int:
        """Attempt settlement; returns the nullifier on success.

        Raises SettlementError subclasses on failure (mirrors reverts).
        """
        if value < self.price:
            raise NotPaidError(
                f"required {self.price}, received {value}")
        if signals.nullifier in self.spent:
            raise AlreadySpentError(f"nullifier {signals.nullifier} spent")
        if not self.verifier.verify(proof, signals):
            raise InvalidProofError("proof did not verify")
        # Effects before "interactions" (state first, like the contract).
        self.spent.add(signals.nullifier)
        self.count += 1
        self.balances[self.payee] = self.balances.get(self.payee, 0) + self.price
        surplus = value - self.price
        if surplus > 0:
            self.balances[sender] = self.balances.get(sender, 0) + surplus
        self.ledger.append({
            "nullifier": signals.nullifier,
            "sender": sender,
            "paid": self.price,
            "surplus": surplus,
        })
        return signals.nullifier


def valid_toy_proof() -> Proof:
    """A structurally valid Groth16 triple for the reference verifier."""
    return Proof(a=(1, 2), b=((3, 4), (5, 6)), c=(7, 8))


__all__ = ["Proof", "SettleInput", "Settlement", "VerifierAdapter",
           "valid_toy_proof", "SettlementError", "NotPaidError",
           "AlreadySpentError", "InvalidProofError"]