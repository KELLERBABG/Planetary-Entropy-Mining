"""End-to-end P0 pipeline demo.

Runs the full **verifyable software** chain on a laptop, no hardware:

    capture -> entropy validation -> harden (GF(256) polynomial)
           -> nullifier -> signed certificate -> (optional) zk proof

Usage:
    py -m cli.demo                 # full demo (incl. zk proof if toolchain present)
    py -m cli.demo --quick         # Python-only core, skips the JS zk stage
    py -m cli.demo --no-zk         # alias for --quick

Exit code 0 on success.  Everything is deterministic (seeded).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

from dsp.capture import ThermalNoiseSource, quantize_to_bytes
from dsp.validation import true_quantized_gaussian_entropy
from dsp.analysis import entropy_report
from hardening import harden
from identity.certificate import CaptureMeta, create_certificate, verify_certificate
from identity.nullifier import nullifier, random_nullifier_key

ISSUER_KEY = b"PEM-demo-issuer-key-000000000000"


def _run_zk_stage(quick: bool) -> bool:
    """Run the circom2 + snarkjs toy proof pipeline if available."""
    if quick:
        print("  [zk] skipped (--quick)")
        return True
    node_modules = Path(__file__).resolve().parent.parent / "circuits" / "node_modules"
    if not (node_modules / "circom2").exists():
        print("  [zk] skipped (run `cd circuits && npm install` first)")
        return True
    print("  [zk] compiling + proving + verifying toy entropy-audit circuit...")
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        print("  [zk] skipped (node not found)")
        return True
    script = Path(__file__).resolve().parent.parent / "circuits" / "scripts" / "toy_prove_verify.mjs"
    try:
        subprocess.run([node, str(script), "--assert"], check=True,
                       cwd=script.parent.parent, capture_output=True, text=True)
        print("  [zk] PASS (snarkjs verify OK)")
        return True
    except FileNotFoundError:
        print("  [zk] skipped (node not found)")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [zk] FAILED: {e.stderr[-400:]}")
        return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true",
                    help="skip the JS zk stage (Python-only P0 core)")
    args = ap.parse_args(argv)

    print("=== Planetary Entropy Mining — P0 e2e demo ===")

    # 1. Capture (deterministic thermal source).
    src = ThermalNoiseSource(sigma=1.0, seed=42)
    win = src.read(1.0)
    codes = quantize_to_bytes(win.samples)
    print(f"[1] capture    : {src.name} @ {src.sample_rate:,.0f} Hz, "
          f"{win.seconds}s -> {codes.size} bytes")

    # 2. Validate entropy (NIST 90B floor).
    rep = entropy_report(codes, run_nist90b=True, nist90b_limit=30_000)
    truth = true_quantized_gaussian_entropy(1.0)
    print(f"[2] entropy    : shannon={rep.shannon_bits_per_byte:.3f} B/B, "
          f"90B floor={rep.conservative_min_bits_per_byte:.3f} B/B, "
          f"truth={truth:.3f} B/B")

    # 3. Harden to GF(256) polynomial artifact.
    artifact = harden(win.samples)
    print(f"[3] harden     : degree={artifact.params.degree}, "
          f"{len(artifact.evaluations)} evaluations, mac={artifact.mac[:8].hex()}…")

    # 4. Nullifier (node + window binding).
    node = random_nullifier_key("demo-node-1")
    window = "2026-07-31T00:00Z"
    nul = nullifier(np.frombuffer(codes, dtype=np.uint8).tobytes(), node, window)
    print(f"[4] nullifier  : {nul[:16].hex()}… (node={node.node_id.decode()})")

    # 5. Signed certificate.
    capture = CaptureMeta(
        source_name=win.source_name,
        sample_rate=win.sample_rate,
        seconds=win.seconds,
        bits=8,
        conservative_bits_per_byte=rep.conservative_min_bits_per_byte,
    )
    cert = create_certificate(capture, artifact.to_dict(), nul.hex(),
                              window, node.node_id.decode(), ISSUER_KEY)
    ok = verify_certificate(cert, ISSUER_KEY)
    print(f"[5] certificate: version={cert.version}, body={len(cert.body_bytes)}B, "
          f"mac-b64={cert.mac_b64[:12]}…, verify={ok}")
    if not ok:
        print("FAIL: certificate verification")
        return 1

    # 6. Optional zk proof.
    if not _run_zk_stage(args.quick):
        return 1

    print("PIPELINE PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())