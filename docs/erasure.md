# Erasure coding (`erasure/`)

Systematic Reed-Solomon erasure coding over GF(256), reusing the field
arithmetic from `hardening/gf256.py` (AES polynomial 0x11B, generator 3) —
there is exactly one field implementation in the repo.

## API

```python
from erasure import encode, decode, Shard

shards = encode(data, k=4, n=8)     # 8 shards; any 4 reconstruct
assert decode(shards[:4], k=4, n=8) == data
assert decode(shards[3:7], k=4, n=8) == data
```

- `encode(data: bytes, k: int, n: int) -> list[Shard]`
- `decode(shards, k: int, n: int | None = None) -> bytes`

The first `k` shards are **systematic**: they contain the raw data blocks.
The remaining `n - k` are parity computed by Lagrange interpolation, so a
receiver needs only any `k` of the `n` shards (the DTN delivery case where
some shards are lost or delayed).

## Design

- Message bytes are padded to a multiple of `k` and split into `k` blocks.
- Block values are treated as evaluations `P(x_1)..P(x_k)` of a degree
  `k-1` polynomial `P` over GF(256) at points `x_i = i + 1`.
- Shard `m` stores `P(x_{m+1})`; reconstruction from any `k` shards is a
  second Lagrange pass back at the original `x_1..x_k`.
- Each shard carries a 4-byte big-endian original-length header so
  `decode(encode(data)) == data` exactly and trailing zero bytes are never
  confused with padding.
- Lagrange basis matrices are `lru_cache`d per index set (pure field
  algebra, deterministic).
- `n <= 255` (only 255 nonzero field points exist).

## Guarantees (proven in `tests/test_erasure.py`)

- Round-trip: `decode(encode(data, k, n), k, n) == data` for many `(k, n)`.
- Any-k-of-n: every subset of exactly `k` shards reconstructs the message.
- Systematic property: shard `i < k` is the raw block `i`.
- Determinism: identical input produces byte-identical shards.
- Corruption: a corrupted shard included in reconstruction yields a
  mismatch (erasure codes detect but do not correct) — the pipeline drops
  bad shards and uses any `k` *good* ones.
- Validation: `k < 1`, `n < k`, `n > 255`, zero/duplicate shards and
  inconsistent length headers all raise `ValueError`.

## Integration

`cli/e2e.py` uses `encode(packet, 2, 4)` to shard the onion-wrapped
certificate, ships each shard as a DTN bundle, and calls
`decode(received, 2, 4)` on arrival.