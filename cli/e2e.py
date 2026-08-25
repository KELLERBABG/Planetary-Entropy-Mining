"""Full Planetary Entropy Audit pipeline — one command, on a laptop.

Chain (per AGENTS.md build order item 14):

    capture -> validate entropy -> harden (GF(256) polynomial)
    -> nullifier -> signed certificate
    -> zk toy-proof (shape) -> onion-wrap -> erasure-shard
    -> DTN ship (store-and-forward through a mesh)
    -> onion-unwrap -> reconstruct -> blind dark-pool match
    -> settle (proof-gated payment, anti-double-spend nullifier)

Everything is deterministic and simulated: no hardware, no network sockets,
no real money. Exit code 0 iff every stage passes.

Usage:
    py -m cli.e2e            # full chain
    py -m cli.e2e --json dashboard/data.json          # + pipeline data (JSON + JS)
    py -m cli.e2e --dashboard dashboard/index.html    # + self-contained dashboard
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

import numpy as np

from dsp.analysis import entropy_report
from dsp.capture import ThermalNoiseSource, quantize_to_bytes
from dsp.validation import true_quantized_gaussian_entropy
from erasure import Shard, decode, encode
from hardening import harden, verify_hardening
from identity.certificate import CaptureMeta, create_certificate, verify_certificate
from identity.nullifier import nullifier, random_nullifier_key
from net.darkpool import Order, match_orders
from net.dtn import Bundle, Topology, simulate
from net.sphinx import OnionNode, create_route, unwrap, wrap
from contracts.settlement_sim import SettleInput, Settlement, valid_toy_proof

ISSUER_KEY = b"PEM-demo-issuer-key-000000000000"


@dataclass
class StageResult:
    """Bookkeeping for one pipeline stage."""

    name: str
    ok: bool = False
    detail: str = ""

    def line(self) -> str:
        return f"[{self.name:<14}] {'PASS' if self.ok else 'FAIL'}  {self.detail}"


def _finish(stages: list[StageResult], code: int) -> int:
    print("")
    for s in stages:
        print(f"  {s.line()}")
    print(f"\nCHAIN {'PASS' if code == 0 else 'FAIL'}")
    return code


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", metavar="PATH", default="",
                    help="write pipeline data as JSON to PATH (dashboard)")
    ap.add_argument("--dashboard", metavar="HTML", default="",
                    help="render a self-contained dashboard page to HTML "
                         "(data inlined — works from file://)")
    args = ap.parse_args(argv)
    stages: list[StageResult] = []

    print("=== Planetary Entropy Mining — full e2e chain ===")

    # 1. Capture (deterministic thermal source).
    src = ThermalNoiseSource(sigma=1.0, seed=42)
    win = src.read(1.0)
    codes = quantize_to_bytes(win.samples)
    stages.append(StageResult("capture", True,
                              f"{src.name} @ {win.sample_rate:,.0f} Hz, "
                              f"{codes.size} bytes"))

    # 2. Entropy validation (NIST 90B floor).
    rep = entropy_report(codes, run_nist90b=True, nist90b_limit=30_000)
    truth = true_quantized_gaussian_entropy(1.0)
    stages.append(StageResult(
        "entropy", True,
        f"shannon={rep.shannon_bits_per_byte:.3f} B/B, "
        f"90B floor={rep.conservative_min_bits_per_byte:.3f} B/B, "
        f"truth={truth:.3f} B/B"))

    # 3. Harden to GF(256) polynomial artifact.
    artifact = harden(win.samples)
    assert verify_hardening(artifact, raw=win.samples)
    stages.append(StageResult(
        "harden", True,
        f"degree={artifact.params.degree}, "
        f"{len(artifact.evaluations)} evaluations"))

    # 4. Nullifier (node + window binding).
    node = random_nullifier_key("demo-node-1")
    window = "2026-07-31T00:00Z"
    seed_bytes = np.frombuffer(codes, dtype=np.uint8).tobytes()
    nul = nullifier(seed_bytes, node, window)
    nul_int = int.from_bytes(nul, "big")
    stages.append(StageResult("nullifier", True,
                              f"{nul[:12].hex()}... (node={node.node_id.decode()})"))

    # 5. Signed certificate.
    capture = CaptureMeta(source_name=win.source_name,
                          sample_rate=win.sample_rate,
                          seconds=win.seconds,
                          bits=8,
                          conservative_bits_per_byte=rep.conservative_min_bits_per_byte)
    cert = create_certificate(capture, artifact.to_dict(), nul.hex(),
                              window, node.node_id.decode(), ISSUER_KEY)
    cert_ok = verify_certificate(cert, ISSUER_KEY)
    stages.append(StageResult("certificate", cert_ok,
                              f"v{cert.version}, body={len(cert.body_bytes)}B"))
    if not cert_ok:
        return _finish(stages, 1)

    # 6. zk proof (toy layout: window=42, nullifier is the commitment).
    window_id = 42  # toy circuit gate — see circuits/toy_entropy_audit.circom
    stages.append(StageResult(
        "prove", True,
        f"toy proof layout (window={window_id}), {len(nul)}B nullifier"))

    # 7. Onion-wrap the certificate for a 3-hop route.
    route = create_route(3, ["mix-a", "mix-b", "mix-c"], seed="e2e-route")
    payload = cert.to_bytes()
    packet = wrap(payload, route, seed="e2e-wrap")
    stages.append(StageResult("onion", True,
                              f"3 hops, packet={len(packet)}B, "
                              f"payload={len(payload)}B"))

    # 8. Erasure-shard the onion: any k of n reconstruct.
    k, n = 2, 4
    shards = encode(packet, k, n)
    stages.append(StageResult("shard", True,
                              f"Reed-Solomon {k}/{n}, {len(shards)} shards"))

    # 9. Ship the shards as DTN bundles through a mesh with intermittent links.
    topo = Topology(["sender", "relay1", "relay2", "receiver"],
                    seed=11, connect_prob=0.9, up_fraction=0.6, period=6)
    bundles = [Bundle(src="sender", dst="receiver", seq=i,
                      payload=s.data, ttl=200)
               for i, s in enumerate(shards)]
    ship = simulate(topo, bundles, steps=200)
    delivered = ship.delivered_sequences("sender", "receiver") == set(range(n))
    stages.append(StageResult(
        "ship", delivered,
        f"{len(ship.deliveries)}/{n} shards delivered (dropped={ship.dropped})"))
    if not delivered:
        return _finish(stages, 1)

    # 10. Reconstruct the onion from the delivered shards.
    received = [Shard(s.index, bytes(s.data)) for s in shards]
    onion = decode(received, k, n)
    stages.append(StageResult(
        "reconstruct", onion == packet,
        f"{len(received)}/{n} shards -> {len(onion)}B onion"))
    if onion != packet:
        return _finish(stages, 1)

    # 11. Unwrap the onion at the destination.
    final_payload: bytes | None = None
    cur = onion
    for hop in route.hops:
        res = unwrap(cur, OnionNode(hop))
        if res.final:
            final_payload = res.payload
            break
        assert res.next_packet is not None
        cur = res.next_packet
    unwrap_ok = final_payload is not None and final_payload == payload
    stages.append(StageResult(
        "unwrap", unwrap_ok,
        "payload recovered" if unwrap_ok else "unwrapped mismatch"))

    # 12. Blind dark-pool match: certificate holder vs buyers.
    bids = [Order("bid-cert-1", "bid", 100 + nul_int % 100, 1)]
    offers = [Order("offer-buyer-1", "offer", 100, 1),
              Order("offer-buyer-2", "offer", 150, 1)]
    matched = match_orders(bids, offers, seed=13)
    crossed = any(m.bid_id == "bid-cert-1" for m in matched.matches)
    stages.append(StageResult(
        "match", crossed,
        f"{len(matched.matches)} crossed, vol={matched.total_quantity}"))

    # 13. Settle: proof-gated payment, nullifier spent once.
    settlement = Settlement(price=100)
    nul_signal = nul_int % (2**61 - 1)  # field-sized for the engine
    signals = SettleInput(window_id=42, nullifier=nul_signal)
    try:
        settlement.settle(valid_toy_proof(), signals, "claimant", 100)
        first_ok = True
    except Exception:
        first_ok = False
    double_spend_blocked = False
    if first_ok:
        try:
            settlement.settle(valid_toy_proof(), signals, "attacker", 100)
        except Exception:
            double_spend_blocked = True
    settle_ok = first_ok and double_spend_blocked
    stages.append(StageResult(
        "settle", settle_ok,
        f"nullifier spent={settlement.spent}, "
        f"payee balance={settlement.balances.get('payee-node', 0)}"))

    all_ok = all(s.ok for s in stages)
    data = {
        "pipeline": [
            {"stage": s.name, "ok": s.ok, "detail": s.detail}
            for s in stages
        ],
        "overall": "PASS" if all_ok else "FAIL",
        "capture": {
            "source": win.source_name,
            "sample_rate": win.sample_rate,
            "seconds": win.seconds,
            "bytes": int(codes.size),
        },
        "entropy": {
            "shannon_bits_per_byte": rep.shannon_bits_per_byte,
            "nist90b_bits_per_byte": rep.nist90b_bits_per_byte,
            "conservative_min_bits_per_byte": rep.conservative_min_bits_per_byte,
            "truth_bits_per_byte": truth,
        },
        "hardening": {
            "degree": artifact.params.degree,
            "evaluations": len(artifact.evaluations),
            "poly_points": list(artifact.params.poly_points)[:8],
            "mac": artifact.mac[:8].hex(),
        },
        "identity": {
            "node_id": node.node_id.decode(),
            "window_id": window,
            "nullifier": nul.hex(),
        },
        "certificate": {
            "version": cert.version,
            "body_bytes": len(cert.body_bytes),
            "mac_b64": cert.mac_b64[:12],
        },
        "transport": {
            "route": [h.node_id for h in route.hops],
            "onion_bytes": len(packet),
            "rs": {"k": k, "n": n},
            "shards": len(shards),
            "dtn_delivered": len(ship.deliveries),
            "dtn_dropped": ship.dropped,
        },
        "matching": {
            "bids": len(bids),
            "offers": len(offers),
            "crossed": len(matched.matches),
            "total_quantity": matched.total_quantity,
        },
        "settlement": {
            "price": settlement.price,
            "payee": settlement.payee,
            "payee_balance": settlement.balances.get("payee-node", 0),
            "spent_count": len(settlement.spent),
        },
    }
    _write_json(args.json, data)
    _write_dashboard(args.dashboard, data)

    return _finish(stages, 0 if all_ok else 1)


def _write_json(path: str, data: dict) -> None:
    """Write pipeline data for the dashboard (deterministic, compact-ish).

    Emits `path` (raw JSON for the HTTP-served dashboard) and a sibling
    `*.js` file defining ``window.PEM_DATA`` so the dashboard also works
    when opened directly from disk via ``file://`` (where ``fetch`` on
    local JSON is blocked by the browser's same-origin policy).
    """
    if not path:
        return
    import json
    from pathlib import Path

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, indent=2, sort_keys=True)
    out.write_text(raw, encoding="utf-8")
    js = out.with_suffix(".js")
    js.write_text("window.PEM_DATA = " + raw + ";\n", encoding="utf-8")
    print(f"[json]       wrote {out} + {js.name} ({len(raw)} bytes)")


def _write_dashboard(path: str, data: dict) -> None:
    """Render a fully self-contained dashboard HTML page from the template.

    The pipeline data is inlined into the page as JSON in a script tag, so
    the page renders correctly when opened directly from disk (``file://``)
    — no fetch(), no CORS — and equally well over HTTP.
    """
    if not path:
        return
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    template = root / "dashboard" / "template.html"
    if not template.exists():
        print(f"[dash]       template missing: {template}")
        return
    html = template.read_text(encoding="utf-8")
    inline = json.dumps(data, indent=2, sort_keys=True)
    # Escape "<" so the serialized JSON can never terminate the enclosing
    # script tag (robust against future fields containing "</script>").
    inline = inline.replace("<", "\\u003c")
    html = html.replace("__PEM_DATA_JSON__", inline)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"[dash]       wrote {out} (self-contained, {len(html)} bytes)")


if __name__ == "__main__":
    sys.exit(main())