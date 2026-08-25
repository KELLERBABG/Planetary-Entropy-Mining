"""Deterministic DTN (delay-tolerant network) mesh simulation.

Simulates store-and-forward delivery of sharded entropy bundles across a
mesh of nodes with *intermittent* links: a link between two nodes is up or
down per a deterministic schedule derived from a seed (reproducible tests).
Nodes buffer bundles while no route to the destination is available and
forward them as soon as a functional next hop appears.

Design:
  * `Topology` owns the node set and the per-link up/down schedules.
  * `Bundle` is an immutable (src, dst, ttl, payload) unit; bundles carry a
    sequence number per origin so receivers can detect gaps.
  * Per-node buffers deduplicate on (src, seq), which both prevents loops
    (a bundle is forwarded at most once per (src, seq)) and duplicate
    deliveries.
  * `simulate(topology, bundles, steps)` advances time in discrete steps.
    At each step links are refreshed from their deterministic schedules,
    then every node forwards its buffered bundles over any currently-up
    link that makes progress toward the destination (BFS shortest path on
    the *current* up-graph). Deliveries are recorded with the arrival step,
    hop count and the actual path taken.
  * Delivery guarantee: a bundle whose TTL covers the latency of a route
    that is up at some point within its TTL is delivered. Because all
    links share the same up/down phase windows, the connected component
    of the up-graph is stable, so enough steps always deliver.

No real sockets: every node is an in-memory object; everything is
deterministic for a given seed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

_DEFAULT_BUNDLE_LIMIT = 10_000  # per-node buffer cap (simulation safety)


@dataclass(frozen=True)
class Bundle:
    """One store-and-forward payload unit."""

    src: str
    dst: str
    seq: int
    payload: bytes
    ttl: int = 30  # steps before the bundle expires

    def __len__(self) -> int:
        return len(self.payload)


@dataclass(frozen=True)
class LinkState:
    """Deterministic on/off schedule for one directed link."""

    a: str
    b: str
    up_windows: tuple[tuple[int, int], ...]

    def is_up(self, t: int) -> bool:
        return any(lo <= t < hi for lo, hi in self.up_windows)


@dataclass
class DeliveryRecord:
    """Recorded successful delivery of a bundle."""

    bundle: Bundle
    arrived_at: int
    hops: int
    path: tuple[str, ...]


@dataclass
class _BufferEntry:
    """A bundle plus the bookkeeping accumulated on its way here."""

    bundle: Bundle
    hops: int
    path: tuple[str, ...]


class Topology:
    """Set of nodes plus deterministic link schedules."""

    def __init__(self, nodes: Sequence[str], seed: int = 0,
                 connect_prob: float = 0.7, up_fraction: float = 0.6,
                 period: int = 10) -> None:
        """Build a random mesh with per-link up/down schedules.

        All links share the same period and phase, so the up-graph at any
        step is a stable subgraph of the mesh.

        Args:
            nodes: node ids.
            seed: RNG seed (deterministic mesh + schedules).
            connect_prob: probability a directed pair gets a link at all.
            up_fraction: fraction of each period the link is scheduled up.
            period: link-state period in steps (same phase for all links).
        """
        self.nodes = list(nodes)
        self.links: dict[tuple[str, str], LinkState] = {}
        self._build(seed, connect_prob, up_fraction, period)

    def _build(self, seed: int, connect_prob: float, up_fraction: float,
               period: int) -> None:
        import random

        rng = random.Random(seed)
        up_len = max(1, int(round(up_fraction * period)))
        for i, a in enumerate(self.nodes):
            for j, b in enumerate(self.nodes):
                if i == j:
                    continue
                if rng.random() < connect_prob:
                    # Stable schedule: up for the first `up_len` steps of
                    # every period, down for the rest. Deterministic.
                    windows = tuple((start, start + up_len)
                                    for start in range(0, 10_000, period))
                    self.links[(a, b)] = LinkState(a=a, b=b,
                                                   up_windows=windows)

    def is_up(self, a: str, b: str, t: int) -> bool:
        ks = self.links.get((a, b))
        return bool(ks and ks.is_up(t))

    def neighbors_up(self, node: str, t: int) -> list[str]:
        return [b for (a, b) in self.links
                if a == node and self.is_up(a, b, t)]


class Node:
    """A DTN store-and-forward router."""

    def __init__(self, node_id: str, capacity: int = _DEFAULT_BUNDLE_LIMIT) -> None:
        self.node_id = node_id
        self.capacity = capacity
        self.buffer: dict[tuple[str, int], _BufferEntry] = {}
        self.received: list[DeliveryRecord] = []

    def accept(self, bundle: Bundle, arrived_at: int, hops: int,
               path: tuple[str, ...]) -> bool:
        """Store a bundle; returns False if a dup, buffer full, or delivered."""
        if bundle.dst == self.node_id:
            self.received.append(DeliveryRecord(bundle, arrived_at, hops, path))
            self.buffer.pop((bundle.src, bundle.seq), None)
            return True
        key = (bundle.src, bundle.seq)
        if key in self.buffer:
            return False
        if len(self.buffer) >= self.capacity:
            return False
        self.buffer[key] = _BufferEntry(bundle=bundle, hops=hops, path=path)
        return True

    def __repr__(self) -> str:
        return f"Node({self.node_id})"


@dataclass
class SimulationResult:
    """Outcome of one simulate() run."""

    deliveries: list[DeliveryRecord] = field(default_factory=list)
    dropped: int = 0
    steps: int = 0

    def delivered_sequences(self, src: str, dst: str) -> set[int]:
        return {d.bundle.seq for d in self.deliveries
                if d.bundle.src == src and d.bundle.dst == dst}


def _shortest_next(up: dict[str, set[str]], src: str, dst: str) -> str | None:
    """Next hop on the shortest up-graph path (BFS); None if unreachable."""
    if src == dst:
        return dst
    prev: dict[str, str | None] = {src: None}
    queue = [src]
    for cur in queue:
        if cur == dst:
            break
        for nxt in sorted(up.get(cur, ())):
            if nxt not in prev:
                prev[nxt] = cur
                queue.append(nxt)
    if dst not in prev:
        return None
    cur: str = dst
    while prev[cur] != src:  # type: ignore[operator]
        cur = prev[cur]  # type: ignore[assignment]
    return cur


def simulate(topology: Topology, bundles: Sequence[Bundle], steps: int = 60,
             node_capacity: int = _DEFAULT_BUNDLE_LIMIT) -> SimulationResult:
    """Run the DTN simulation for ``steps`` discrete time steps.

    At each step:
      1. Links refresh per their deterministic schedules.
      2. Every node forwards buffered bundles one hop toward the destination
         on the current shortest-path (BFS) up-graph.
      3. TTLs decrement; expired bundles are dropped and counted.
    """
    nodes = {n: Node(n, capacity=node_capacity) for n in topology.nodes}
    for b in bundles:
        if b.src not in nodes or b.dst not in nodes:
            raise ValueError(f"bundle references unknown node "
                             f"({b.src}->{b.dst})")
        nodes[b.src].buffer[(b.src, b.seq)] = _BufferEntry(bundle=b,
                                                           hops=0,
                                                           path=(b.src,))
    total_per_dst: dict[str, int] = {}
    for b in bundles:
        total_per_dst[b.dst] = total_per_dst.get(b.dst, 0) + 1

    result = SimulationResult()
    for t in range(steps):
        up: dict[str, set[str]] = {n: set(topology.neighbors_up(n, t))
                                   for n in topology.nodes}
        for node in list(nodes.values()):
            for key, entry in list(node.buffer.items()):
                b = entry.bundle
                if b.dst == node.node_id:
                    continue
                nxt = _shortest_next(up, node.node_id, b.dst)
                if nxt is None or nxt == node.node_id:
                    continue
                target = nodes[nxt]
                delivered = target.accept(b, t, entry.hops + 1,
                                          entry.path + (nxt,))
                if delivered:
                    node.buffer.pop(key, None)
        # Age buffers: drop expired, decrement the rest.
        for node in nodes.values():
            expired = [k for k, e in node.buffer.items() if e.bundle.ttl <= 0]
            result.dropped += len(expired)
            for k in expired:
                node.buffer.pop(k, None)
            for k, e in list(node.buffer.items()):
                node.buffer[k] = _BufferEntry(
                    bundle=Bundle(e.bundle.src, e.bundle.dst, e.bundle.seq,
                                  e.bundle.payload, e.bundle.ttl - 1),
                    hops=e.hops, path=e.path)
        # Early exit once every destination node has all its bundles.
        if all(len(nodes[dst].received) >= total for dst, total
               in total_per_dst.items()):
            break
    for node in nodes.values():
        result.deliveries.extend(node.received)
    result.steps = steps
    return result


__all__ = ["Bundle", "LinkState", "Topology", "Node", "simulate",
           "SimulationResult", "DeliveryRecord"]