"""Tests for the DTN mesh simulation (net/dtn.py)."""

import pytest

from net.dtn import Bundle, LinkState, Topology, simulate

# ---------------------------------------------------------------------------
# Deterministic schedules
# ---------------------------------------------------------------------------


def test_link_schedule_deterministic():
    ls = LinkState("a", "b", up_windows=((0, 3), (10, 13)))
    assert ls.is_up(0) and ls.is_up(2)
    assert not ls.is_up(3)
    assert not ls.is_up(5)
    assert ls.is_up(10) and not ls.is_up(13)


def test_topology_is_deterministic():
    t1 = Topology(["n0", "n1", "n2"], seed=7)
    t2 = Topology(["n0", "n1", "n2"], seed=7)
    t3 = Topology(["n0", "n1", "n2"], seed=8)
    assert t1.links.keys() == t2.links.keys()
    assert t1.links.keys() != t3.links.keys()


# ---------------------------------------------------------------------------
# Store-and-forward delivery
# ---------------------------------------------------------------------------


def test_direct_delivery_when_link_up():
    topo = Topology(["src", "dst"], seed=0, connect_prob=1.0, up_fraction=1.0)
    bundle = Bundle(src="src", dst="dst", seq=0, payload=b"hello", ttl=10)
    res = simulate(topo, [bundle], steps=10)
    assert res.delivered_sequences("src", "dst") == {0}
    rec = res.deliveries[0]
    assert rec.hops == 1
    assert rec.path == ("src", "dst")


def test_undelivered_when_never_connected():
    topo = Topology(["src", "solo"], seed=0, connect_prob=0.0)
    bundle = Bundle(src="src", dst="solo", seq=0, payload=b"x", ttl=100)
    res = simulate(topo, [bundle], steps=50)
    assert res.deliveries == []


def test_multihop_store_and_forward():
    # Line: a -- b -- c, all links always up (drop the direct a<->c link
    # so the *only* path is the 2-hop one through b).
    topo = Topology(["a", "b", "c"], seed=0, connect_prob=1.0, up_fraction=1.0)
    topo.links.pop(("a", "c"), None)
    topo.links.pop(("c", "a"), None)
    bundle = Bundle(src="a", dst="c", seq=0, payload=b"bundle", ttl=50)
    res = simulate(topo, [bundle], steps=20)
    assert res.delivered_sequences("a", "c") == {0}
    rec = res.deliveries[0]
    assert rec.hops == 2
    assert rec.path == ("a", "b", "c")


def test_delivery_with_intermittent_links():
    # All links up only during the first half of each period; a bundle with
    # a big TTL must still get through once a window opens.
    topo = Topology(["a", "b", "c"], seed=0, connect_prob=1.0,
                    up_fraction=0.5, period=10)
    bundle = Bundle(src="a", dst="c", seq=0, payload=b"slow", ttl=100)
    res = simulate(topo, [bundle], steps=60)
    assert res.delivered_sequences("a", "c") == {0}


def test_multiple_bundles_all_delivered():
    topo = Topology(["a", "b", "c", "d"], seed=3, connect_prob=0.9,
                    up_fraction=0.7, period=6)
    bundles = [
        Bundle(src="a", dst="d", seq=i, payload=f"p{i}".encode(), ttl=200)
        for i in range(8)
    ]
    res = simulate(topo, bundles, steps=200)
    assert res.delivered_sequences("a", "d") == set(range(8))


def test_no_duplicate_deliveries():
    topo = Topology(["a", "b", "c"], seed=1, connect_prob=1.0,
                    up_fraction=1.0, period=5)
    bundle = Bundle(src="a", dst="c", seq=0, payload=b"once", ttl=100)
    res = simulate(topo, [bundle], steps=40)
    # Exactly one delivery record for the bundle.
    assert len(res.deliveries) == 1


def test_ttl_expiry_drops_bundles():
    topo = Topology(["a", "b"], seed=0, connect_prob=0.0)  # never connected
    bundle = Bundle(src="a", dst="b", seq=0, payload=b"doomed", ttl=2)
    res = simulate(topo, [bundle], steps=10)
    assert res.deliveries == []
    assert res.dropped >= 1


def test_unknown_node_rejected():
    topo = Topology(["a", "b"], seed=0)
    with pytest.raises(ValueError):
        simulate(topo, [Bundle(src="a", dst="ghost", seq=0, payload=b"")], steps=1)


def test_deterministic_across_seeds():
    bundles = [Bundle(src="a", dst="d", seq=i, payload=b"x", ttl=100)
               for i in range(5)]
    topo = Topology(["a", "b", "c", "d"], seed=42, connect_prob=0.8,
                    up_fraction=0.6, period=8)
    r1 = simulate(topo, bundles, steps=120)
    r2 = simulate(topo, bundles, steps=120)
    assert [d.arrived_at for d in r1.deliveries] == \
           [d.arrived_at for d in r2.deliveries]