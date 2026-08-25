"""Tests for Sphinx-style onion framing (net/sphinx.py)."""

import pytest

from net.sphinx import (
    HopKey,
    OnionNode,
    OutOfOrderError,
    ReplayError,
    Route,
    WrongHopError,
    create_route,
    wrap,
)

TAG_LEN = 32

ROUTE = create_route(3, ["alice", "bob", "carol"], seed="route-seed")


def _peel_all(packet: bytes, route: Route):
    """Deliver an onion layer by layer; returns the final payload."""
    nodes = [OnionNode(hop) for hop in route.hops]
    cur = packet
    final_payload = None
    for _i, node in enumerate(nodes):
        res = node.recv(cur)
        if res.final:
            final_payload = res.payload
            break
        assert res.next_packet is not None
        # The revealed tag is the *inner* packet's public tag — the handle
        # the next hop checks. The payload and route beyond stay hidden.
        assert res.next_tag == res.next_packet[:TAG_LEN]
        cur = res.next_packet
    return final_payload


def test_three_hop_delivery_round_trip():
    payload = b"secret entropy certificate shard"
    packet = wrap(payload, ROUTE, seed="round-trip")
    got = _peel_all(packet, ROUTE)
    assert got == payload


def test_wrong_hop_key_fails():
    packet = wrap(b"payload", ROUTE, seed="wrong-hop")
    stranger = OnionNode(HopKey.generate("mallory", seed="mallory-seed"))
    with pytest.raises(WrongHopError):
        stranger.recv(packet)


def test_intermediate_hop_does_not_see_payload():
    packet = wrap(b"top secret payload", ROUTE, seed="privacy")
    hop0 = OnionNode(ROUTE[0])
    res = hop0.recv(packet)
    assert not res.final
    assert res.payload is None
    assert res.session is not None
    # The tag of the next packet differs from the outer tag (mixing).
    assert res.next_tag != packet[:TAG_LEN]


def test_replay_rejected():
    packet = wrap(b"replay me", ROUTE, seed="replay")
    hop0 = OnionNode(ROUTE[0])
    hop0.recv(packet)
    with pytest.raises(ReplayError):
        hop0.recv(packet)


def test_out_of_order_rejected():
    first = wrap(b"first", ROUTE, seed="order-session", seq=1)
    second = wrap(b"second", ROUTE, seed="order-session", seq=2)
    hop0 = OnionNode(ROUTE[0])
    hop0.recv(first)
    hop0.recv(second)
    # Re-delivering seq=1 after seq=2 is a sequence violation.
    with pytest.raises(OutOfOrderError):
        hop0.recv(first)


def test_deterministic_wrap():
    a = wrap(b"same", ROUTE, seed="det")
    b = wrap(b"same", ROUTE, seed="det")
    assert a == b


def test_tamper_detection():
    packet = bytearray(wrap(b"integrity", ROUTE, seed="tamper"))
    packet[100] ^= 0x01
    hop0 = OnionNode(ROUTE[0])
    with pytest.raises((WrongHopError, ValueError)):
        hop0.recv(bytes(packet))


def test_empty_route_rejected():
    with pytest.raises(ValueError):
        wrap(b"x", Route(tuple()))


def test_wrap_requires_bytes():
    with pytest.raises(TypeError):
        wrap("not bytes", ROUTE)  # type: ignore[arg-type]