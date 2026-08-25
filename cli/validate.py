"""Entropy validation report entry point.

Usage:
    py -m cli.validate                 # quick (2s windows, 20k symbol cap)
    py -m cli.validate --full          # NIST-recommended sizes (slow)
    py -m cli.validate --seconds 10 --limit 200000

Writes docs/entropy_validation_report.md and exits non-zero on failure so CI
can gate on it. No hardware, no network — everything is deterministic.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dsp.capture import SOURCE_REGISTRY
from dsp.validation import validate_sources


def _build_sources(seeds: dict[str, int] | None = None) -> list:
    seeds = seeds or {"thermal": 0, "rf_ionospheric": 1, "seismic": 2}
    sources = []
    for name, cls in SOURCE_REGISTRY.items():
        try:
            if name == "rf_ionospheric":
                # Keep the 2 MSps SDR fast for validation.
                sources.append(cls(seed=seeds[name], sample_rate=200_000))
            else:
                sources.append(cls(seed=seeds[name]))
        except TypeError:
            sources.append(cls(seed=seeds[name]))
    return sources


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seconds", type=float, default=3.0)
    ap.add_argument("--limit", type=int, default=50_000,
                    help="Symbol cap for the NIST 90B estimators")
    ap.add_argument("--full", action="store_true",
                    help="Use NIST-recommended sizes (slower)")
    args = ap.parse_args(argv)

    if args.full:
        args.seconds = max(args.seconds, 5.0)
        args.limit = max(args.limit, 200_000)

    sources = _build_sources()
    report = validate_sources(sources, seconds=args.seconds,
                              nist90b_limit=args.limit)

    lines = report.summary_lines()
    print("\n".join(lines))

    docs = Path("docs")
    docs.mkdir(exist_ok=True)
    out = docs / "entropy_validation_report.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nReport written to {out}")

    return 0 if report.all_pass else 1


if __name__ == "__main__":
    sys.exit(main())