# Networking layer (`net/`)

Three deterministic simulations — no sockets, no hardware: Sphinx-style
onion framing, a DTN mesh, and blind dark-pool SMPC matching.

## `net/sphinx.py` — layered onion framing

Transport-privacy primitive of the audit. A sender wraps a payload in `n`
layers of X25519 + AES-GCM (one per route hop). A hop can peel only the
layer addressed to it and learns only the next-hop *tag* — a keyed HMAC
handle — never the destination identity, the payload, or the rest of the
route.

```python
from net.sphinx import create_route, wrap, unwrap, OnionNode

route = create_route(3, ["mix-a", "mix-b", "mix-c"], seed="r")
packet = wrap(cert_bytes, route, seed="w")
# hop by hop:
res = unwrap(packet, OnionNode(route[0]))   # not final -> res.next_packet
```

Properties (proven in `tests/test_sphinx.py`):
- Only the addressed hop can open its layer (`WrongHopError` otherwise).
- Intermediate hops never see the payload; each layer's tag differs
  (per-hop mixing).
- Replay protection per `(session, seq)` (`ReplayError`) and strict per-
  session ordering (`OutOfOrderError`).
- Deterministic: same seed -> byte-identical packets.
- Tampering with any layer fails authentication.

## `net/dtn.py` — DTN mesh simulation

Store-and-forward delivery across a mesh with *intermittent* links. Each
link follows a deterministic up/down schedule (seeded). Nodes buffer
bundles until a shortest-path next hop is available on the current up-graph
and forward one hop per step; TTLs age and expire bundles.

```python
from net.dtn import Topology, Bundle, simulate

topo = Topology(["sender", "r1", "r2", "receiver"], seed=11,
                connect_prob=0.9, up_fraction=0.6, period=6)
res = simulate(topo, [Bundle("sender", "receiver", 0, shard.data, 200)],
               steps=200)
res.delivered_sequences("sender", "receiver")   # {0}
```

Properties (proven in `tests/test_dtn.py`):
- Deterministic topology and schedules for a given seed.
- Delivery over direct, multihop, and intermittently-down paths.
- Dedupe on `(src, seq)` prevents loops and duplicate deliveries.
- TTL expiry drops bundles and reports the count.
- Delivery records carry arrival step, hop count, and the path taken.

## `net/darkpool.py` — blind dark-pool matching (SMPC)

Traders submit bids and offers; a matching engine crosses `bid >= offer`
without any party learning the other's order book. Each order's price and
quantity are split into Shamir shares (threshold `t` of `n` agents) over
GF(2^61-1). The crossing predicate is reconstructed from shares of
`bid.price - offer.price` using the field-halves convention — the engine
never reconstructs any individual price.

```python
from net.darkpool import Order, match_orders

out = match_orders(bids, offers, seed=13)
```

Properties (proven in `tests/test_darkpool.py`):
- Any `t` shares reconstruct a secret; fewer reveal nothing.
- Shares are additively homomorphic (share of difference = difference of
  shares) — the basis of the blind predicate.
- Crossing semantics: matches only when `bid.price >= offer.price`.
- Matched quantity = `min(bid.qty, offer.qty)`; price clears at the maker
  (offer) price.
- Deterministic for a given seed.

## Integration

`cli/e2e.py` chains all three: wrap the certificate (onion), shard the
packet (erasure/), ship shards as DTN bundles, unwrap at the destination,
then blind-match certificates against buyers and settle.