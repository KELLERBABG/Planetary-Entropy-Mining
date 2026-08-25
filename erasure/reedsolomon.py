"""Systematic Reed-Solomon erasure coding over GF(256).

Splits ``data`` into ``k`` equal-length blocks and produces ``n >= k``
shards such that *any* ``k`` of the ``n`` shards reconstruct the original
bytes — the standard "any k of n" property required for DTN store-and-forward
delivery where some shards may be lost or delayed.

Design (textbook RS as an evaluation code, reusing ``hardening.gf256``):

  * Message blocks are evaluations P(x_1)..P(x_k) of a degree-(k-1)
    polynomial P at k distinct nonzero field points x_i = i+1.
  * Shard m (0-based) stores P(x_{m+1}). The first ``k`` shards therefore
    equal the raw data blocks (*systematic*); the remaining ``n-k`` are
    parity computed by Lagrange interpolation::

        P(x_m) = sum_i L_i(x_m) * block_i,   L_i(x) = prod_{t ne i} (x - x_t)/(x_i - x_t)

  * Reconstruction from any k shards with indices S: the same Lagrange
    formula evaluated at the original points x_1..x_k recovers the blocks::

        block_i = sum_{m in S} L'_m(x_i) * shard_m,   L'_m over points {x_s : s in S}

  * Every arithmetic operation is GF(256) with the AES polynomial (0x11B),
    the single field implementation shared with the hardening module.

Layout: each shard encodes a 4-byte big-endian original-length header
followed by the (zero-padded to a multiple of ``k``) payload, so
``decode(encode(data)) == data`` exactly and partial trailing zero bytes
are never confused with payload. Deterministic for identical input.

API::

    encode(data: bytes, k: int, n: int) -> list[Shard]
    decode(shards: Sequence[Shard], k: int, n: int | None = None) -> bytes
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from functools import lru_cache

from hardening.gf256 import gf_div, gf_mul

_HEADER = struct.Struct(">I")
_MAX_SHARDS = 255  # GF(256) has 255 nonzero, distinct evaluation points.


@dataclass(frozen=True)
class Shard:
    """One erasure-coded shard: its 0-based index and payload bytes."""

    index: int
    data: bytes

    def __len__(self) -> int:
        return len(self.data)

    def __bytes__(self) -> bytes:
        return self.data


# ---------------------------------------------------------------------------
# Lagrange basis machinery (cached per index set — pure field algebra).
# ---------------------------------------------------------------------------


@lru_cache(maxsize=64)
def _lagrange_matrix(src_idx: tuple[int, ...],
                     dst_idx: tuple[int, ...]) -> tuple[tuple[int, ...], ...]:
    """Matrix M with M[d][s] = L_s(x_{d+1}), L_s over points {x_s+1}.

    src_idx: the "known" shard indices (points at which values are given).
    dst_idx: the indices at which to re-evaluate the interpolated
             polynomial. Returns a len(dst) x len(src) matrix.
    """
    src_pts = [i + 1 for i in src_idx]
    dst_pts = [j + 1 for j in dst_idx]
    rows = []
    for y in dst_pts:
        row = []
        for i, xi in enumerate(src_pts):
            num = 1
            den = 1
            for j, xj in enumerate(src_pts):
                if j == i:
                    continue
                num = _fmult(num, y, xj)
                den = gf_mul(den, _fsub(xi, xj))
            row.append(gf_div(num, den))
        rows.append(tuple(row))
    return tuple(rows)


def _fmult(acc: int, y: int, xj: int) -> int:
    """acc * (y + xj) over GF(256) — subtraction equals addition (XOR)."""
    return gf_mul(acc, (y ^ xj))


def _fsub(a: int, b: int) -> int:
    """a - b over GF(256) == a ^ b."""
    return a ^ b


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _check_params(k: int, n: int, *, decode: bool = False) -> None:
    if not isinstance(k, int) or not isinstance(n, int):
        raise TypeError("k and n must be ints")
    if k < 1 or n < k:
        raise ValueError(f"need 1 <= k <= n (got k={k}, n={n})")
    if n > _MAX_SHARDS:
        raise ValueError(f"n > {_MAX_SHARDS} not representable in GF(256)")


def encode(data: bytes, k: int, n: int) -> list[Shard]:
    """Split and erasure-code ``data`` into ``n`` shards (any k suffices).

    The payload is length-prefixed so ``decode`` restores exactly the input
    bytes. First ``k`` shards are systematic (the raw blocks).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    _check_params(k, n)
    payload = bytes(data)
    padded = _pad_payload(payload, k)
    block_len = len(padded) // k
    blocks = [padded[i * block_len:(i + 1) * block_len]
              for i in range(k)]

    src = tuple(range(k))
    dst = tuple(range(n))
    mat = _lagrange_matrix(src, dst)
    shards: list[Shard] = []
    for m in range(n):
        row = mat[m]
        out = bytearray(block_len)
        for j in range(block_len):
            acc = 0
            for i in range(k):
                acc ^= gf_mul(row[i], blocks[i][j])
            out[j] = acc
        shards.append(Shard(m, _HEADER.pack(len(payload)) + bytes(out)))
    return shards


def decode(shards: list[Shard] | tuple[Shard, ...], k: int,
           n: int | None = None) -> bytes:
    """Reconstruct the original bytes from any ``>= k`` shards.

    Args:
        shards: received shards (indices must be distinct).
        k: number of data blocks the message was split into.
        n: total shards produced by ``encode`` (inferred from the maximum
           received index when omitted — do not omit when shards are not
           contiguous).
    """
    if not shards:
        raise ValueError("no shards supplied")
    for s in shards:
        if not isinstance(s, Shard):
            raise TypeError("shards must be Shard instances")
    indices = [s.index for s in shards]
    if len(set(indices)) != len(indices):
        raise ValueError("duplicate shard indices")
    if any(i < 0 or i >= _MAX_SHARDS for i in indices):
        raise ValueError("shard index out of range [0, 255]")
    n_all = n if n is not None else max(indices) + 1
    _check_params(k, n_all)
    if len(shards) < k:
        raise ValueError(f"need at least k={k} shards, got {len(shards)}")

    # Re-evaluate the interpolated polynomial at the original data points.
    src = tuple(indices)
    dst = tuple(range(k))
    mat = _lagrange_matrix(src, dst)

    # Decode + strip the 4-byte length header per shard.
    bodies = [bytes(s.data) for s in shards]
    if any(len(b) < _HEADER.size for b in bodies):
        raise ValueError("shard too short (missing length header)")
    lengths = {_HEADER.unpack(b[:_HEADER.size])[0] for b in bodies}
    if len(lengths) != 1:
        raise ValueError("inconsistent length headers across shards")
    orig_len = lengths.pop()
    if orig_len == 0:
        return b""  # encoded empty payload — nothing to reconstruct
    block_len = len(bodies[0]) - _HEADER.size
    if block_len == 0:
        raise ValueError("empty shard body")

    blocks_out = [bytearray(block_len) for _ in range(k)]
    for i in range(k):
        row = mat[i]
        for j in range(block_len):
            acc = 0
            for m, s in enumerate(shards):
                acc ^= gf_mul(row[m], bodies[m][_HEADER.size + j])
            blocks_out[i][j] = acc
    joined = b"".join(bytes(b) for b in blocks_out)
    if orig_len > len(joined):
        raise ValueError("reconstructed payload shorter than length header")
    return joined[:orig_len]


def _pad_payload(payload: bytes, k: int) -> bytes:
    """Return payload padded to a multiple of k (zero-pad at the end)."""
    rem = (-len(payload)) % k
    return payload + b"\x00" * rem


__all__ = ["Shard", "encode", "decode"]