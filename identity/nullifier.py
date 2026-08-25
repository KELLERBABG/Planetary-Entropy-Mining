"""Deterministic identity nullifiers.

A nullifier proves "this node already registered signal W in window T"
without revealing *which* node or *which* signal — the anti-double-mining
primitive of the Planetary Entropy Audit.

Design (per AGENTS.md):
  nullifier = HMAC-BLAKE2b(key = per-node secret,
                           msg = SHA-256(extracted_seed_bytes) · window_id)
             → truncated to 32 bytes.

Key properties (all proven in tests):
  * Same node + same signal + same window -> identical nullifier.
  * Same node + same signal + *different* window -> different nullifier
    (a window can only be mined once).
  * Different nodes + same signal + same window -> different nullifiers
    (nodes cannot impersonate each other).
  * The nullifier does not reveal the seed bytes (keyed PRF).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

_SERVER_CONTEXT = b"PEM-nullifier-v1"
_HASH_LEN = 32


@dataclass(frozen=True)
class NullifierKey:
    """Per-node secret keying material."""

    node_id: bytes
    key_material: bytes


def random_nullifier_key(node_id: str | bytes) -> NullifierKey:
    """Create a fresh per-node key (for the simulator / test harness).

    A real node would derive this from a hardware secret; here it is
    generated deterministically from the node id for reproducibility via
    SHA-256 so no randomness is injected into tests.
    """
    nid = node_id.encode() if isinstance(node_id, str) else bytes(node_id)
    material = hashlib.sha256(nid).digest()
    return NullifierKey(node_id=nid, key_material=material)


def nullifier(seed: bytes, key: NullifierKey, window_id: str | bytes) -> bytes:
    """Deterministic nullifier for (signal seed, node, window)."""
    wid = window_id.encode() if isinstance(window_id, str) else bytes(window_id)
    digest = hashlib.sha256(seed).digest()
    return hmac.new(key.key_material, _SERVER_CONTEXT + digest + wid,
                    hashlib.blake2b).digest()[: _HASH_LEN]


def verify_nullifier(seed: bytes, key: NullifierKey, window_id: str | bytes,
                     expected: bytes) -> bool:
    """Constant-time compare of a nullifier against an expected value."""
    return hmac.compare_digest(nullifier(seed, key, window_id), expected)


__all__ = ["NullifierKey", "random_nullifier_key", "nullifier", "verify_nullifier"]