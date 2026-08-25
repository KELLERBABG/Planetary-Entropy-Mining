"""Build the input witness for the real entropy-gate zk circuit.

The circuit `circuits/entropy_audit_poly.circom` proves:

    "the 256-bin histogram of 2^16 quantized samples has a most-common
     count <= 2048 (per-symbol min-entropy >= 5 bits), bound to a 64-byte
     GF(256) polynomial commitment and a Poseidon nullifier over
     (secret, node_secret, polynomial fold)."

This module derives a *real* satisfying witness from the same deterministic
capture pipeline the certificate uses, so the e2e proof is over genuine
pipeline data (not hand-picked numbers). It writes `input.json` in the
shape the circuit's generated witness calculator expects.

Usage:
    py -m cli.zk_witness --out circuits/build/poly/input.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

from dsp.capture import ThermalNoiseSource, quantize_to_bytes
from hardening import extract_seed, harden

NSAMPLES = 65536
NPOLY = 64


def build_input() -> dict:
    """Deterministic witness for the entropy-gate circuit.

    Uses the same seeded thermal source + hardening as `cli/e2e.py`, so the
    proof is bound to a real certificate's polynomial artifact.
    """
    src = ThermalNoiseSource(sigma=1.0, seed=42)
    win = src.read(NSAMPLES / src.sample_rate + 0.01)
    codes = np.asarray(quantize_to_bytes(win.samples), dtype=np.uint8)[:NSAMPLES]

    counts = np.bincount(codes, minlength=256).tolist()
    max_count = int(max(counts))
    # Circuit gate: max_count * 2^5 <= 65536  (5-bit per-symbol floor).
    assert max_count * 2 ** 5 <= NSAMPLES, "thermal source passes the gate"

    artifact = harden(win.samples)
    evals = list(bytearray(artifact.evaluations))
    assert len(evals) == NPOLY

    seed_int = int.from_bytes(extract_seed(win.samples), "big") % (2 ** 248)
    node_secret = int.from_bytes(b"demo-node-1" * 4, "big") % (2 ** 248)

    return {
        "secret": str(seed_int),
        "node_secret": str(node_secret),
        "p": [str(v) for v in evals],
        "counts": [str(v) for v in counts],
        "max_count": str(max_count),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="circuits/build/poly/input.json")
    args = ap.parse_args(argv)

    import json

    data = build_input()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[zk] witness written to {out} "
          f"(max_count={data['max_count']}, p_len={len(data['p'])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())