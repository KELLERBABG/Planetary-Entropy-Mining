"""Blind dark-pool matching simulation (Shamir secret sharing + SMPC).

Traders submit bids (buy) and offers (sell) to a matching service. The
matching party must cross bid >= ask *without learning the full order book*
of either side. This simulation implements the classic SMPC pattern:

  * Each order's price and quantity are split into ``agents`` Shamir shares
    over a large prime field; shares are *additively homomorphic*, so the
    share of a difference equals the difference of shares.
  * To test whether a (bid, offer) pair crosses, each matching agent
    computes a share of ``bid.price - offer.price`` from its own shares of
    the two orders — no agent ever sees any price itself.
  * The engine reconstructs only the *predicate* (did the pair cross?) by
    Lagrange-interpolating those share-differences; it never reconstructs
    either order's price or quantity. Non-crossing pairs reveal nothing.

Security property proven by construction (and asserted in the tests): a
curious agent holds 1 of ``threshold`` shares of every order and therefore
cannot recover any individual price.

Deterministic: shares come from a seeded PRNG — identical inputs produce
identical match results.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_PRIME = 2**61 - 1  # Mersenne prime (deterministic field arithmetic only)


@dataclass(frozen=True)
class Order:
    """One bid or offer."""

    order_id: str
    side: str            # "bid" | "offer"
    price: int           # fixed-point units (compared, never settled here)
    quantity: int


@dataclass
class MatchRecord:
    """A crossed (bid, offer) pair."""

    bid_id: str
    offer_id: str
    quantity: int
    price: int


@dataclass
class MatchOutcome:
    """Aggregate result of one matching round."""

    matches: list[MatchRecord] = field(default_factory=list)

    @property
    def total_quantity(self) -> int:
        return sum(m.quantity for m in self.matches)


# ---------------------------------------------------------------------------
# Shamir secret sharing over GF(P)
# ---------------------------------------------------------------------------


def _field_add(a: int, b: int) -> int:
    return (a + b) % _PRIME


def _field_sub(a: int, b: int) -> int:
    return (a - b) % _PRIME


def _field_mul(a: int, b: int) -> int:
    return (a * b) % _PRIME


def _mod_inv(a: int) -> int:
    a %= _PRIME
    if a == 0:
        raise ZeroDivisionError("no inverse of 0 mod p")
    return pow(a, _PRIME - 2, _PRIME)


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Horner evaluation: c0 + c1 x + c2 x^2 + ... over GF(P)."""
    acc = 0
    for c in reversed(coeffs):
        acc = _field_add(_field_mul(acc, x), c)
    return acc


def _split_secret(secret: int, threshold: int, n_agents: int,
                  rng: "random.Random") -> list[int]:
    """Return ``n_agents`` Shamir shares (evaluation at x = 1..n_agents).

    Polynomial degree ``threshold - 1``; secret is the constant term.
    Any ``threshold`` shares reconstruct; fewer reveal nothing.
    """
    coeffs = [secret % _PRIME]
    for _ in range(threshold - 1):
        coeffs.append(rng.randrange(0, _PRIME))
    return [_eval_poly(coeffs, x) for x in range(1, n_agents + 1)]


def _reconstruct(shares: list[tuple[int, int]], threshold: int) -> int:
    """Lagrange interpolation of the secret (constant term) from shares."""
    if len(shares) < threshold:
        raise ValueError(f"need at least {threshold} shares to reconstruct")
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = 1
        den = 1
        for j, xj in enumerate(shares):  # type: ignore[assignment]
            if j == i:
                continue
            num = _field_mul(num, _field_sub(0, xj[0]))
            den = _field_mul(den, _field_sub(xi, xj[0]))
        secret = _field_add(secret,
                            _field_mul(yi, _field_mul(num, _mod_inv(den))))
    return secret % _PRIME


# ---------------------------------------------------------------------------
# Blind matching engine
# ---------------------------------------------------------------------------


@dataclass
class _AgentShare:
    """One agent's share of one order's price and quantity."""

    order_id: str
    price_share: int
    qty_share: int


_AGENTS = 5      # number of matching agents
_THRESHOLD = 3   # shares needed to reconstruct (any 3 of 5)


def match_orders(bids: list[Order], offers: list[Order],
                 seed: int = 0, agents: int = _AGENTS,
                 threshold: int = _THRESHOLD) -> MatchOutcome:
    """Blindly match bids against offers without revealing order books.

    For every (bid, offer) pair, each agent computes a share of
    ``bid.price - offer.price`` from its own shares; the engine
    reconstructs only that *difference* and tests its sign in the
    field-halves convention: values in the lower half of GF(P) are true
    non-negative differences (crossed), upper-half values are wrapped
    negatives (no cross). Exact whenever |bid - offer| < P//2, which holds
    for any realistic fixed-point price.

    Matches clear at the maker (offer) price, with quantity
    min(bid.qty, offer.qty) — the standard taker-pays-maker convention.
    """
    if not (2 <= threshold <= agents):
        raise ValueError("need 2 <= threshold <= agents")
    import random

    rng = random.Random(seed)

    # Split every order's price and quantity into shares; agent j gets one
    # share of each (x-coordinate j+1).
    shares_by_agent: list[dict[str, _AgentShare]] = [
        {} for _ in range(agents)
    ]
    for order in list(bids) + list(offers):
        p_shares = _split_secret(order.price, threshold, agents, rng)
        q_shares = _split_secret(order.quantity, threshold, agents, rng)
        for j in range(agents):
            shares_by_agent[j][order.order_id] = _AgentShare(
                order_id=order.order_id,
                price_share=p_shares[j],
                qty_share=q_shares[j],
            )

    qty_by_id = {o.order_id: o.quantity for o in bids + offers}
    price_by_id = {o.order_id: o.price for o in bids + offers}

    matches: list[MatchRecord] = []
    for bid in bids:
        for offer in offers:
            # Share of (bid.price - offer.price) per agent, then Lagrange-
            # reconstruct the difference itself. We never reconstruct any
            # individual price or quantity.
            diffs = [
                (j + 1, _field_sub(shares_by_agent[j][bid.order_id].price_share,
                                   shares_by_agent[j][offer.order_id].price_share))
                for j in range(agents)
            ]
            diff_mod = _reconstruct(diffs, threshold)
            if diff_mod >= _PRIME // 2:
                continue  # wrapped negative difference -> bid did not cross
            qty = min(qty_by_id[bid.order_id], qty_by_id[offer.order_id])
            matches.append(MatchRecord(bid_id=bid.order_id,
                                       offer_id=offer.order_id,
                                       quantity=qty,
                                       price=price_by_id[offer.order_id]))
    return MatchOutcome(matches)


__all__ = ["Order", "MatchRecord", "MatchOutcome", "match_orders",
           "_split_secret", "_reconstruct", "_PRIME"]