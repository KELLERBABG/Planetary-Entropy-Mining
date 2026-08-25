"""Entropy validation: cross-check estimators against known source truth.

The thermal source is defined as N(0, sigma^2); after the 8-bit midtread
quantizer `quantize_to_bytes` the *exact* output distribution is computable
from the normal CDF (each of the 256 bins gets ``p = Phi(edge_hi) -
Phi(edge_lo)``). That gives an honest ground-truth byte entropy that the
estimators must approximate — not a hand-waved bound.

RF / seismic sources are colored and bursty; no closed form exists, so the
validation asserts the structural invariants: the conservative 90B floor
never exceeds the histogram min-entropy, which never exceeds Shannon
entropy, and all estimators land in plausible ranges for an entropy-rich
source.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from .analysis import entropy_report
from .capture import EntropySource, quantize_to_bytes


@dataclass
class SourceValidation:
    """Validation result for one entropy source."""

    source_name: str
    n_bytes: int
    shannon_bits_per_byte: float
    min_hist_bits_per_byte: float
    nist90b_bits_per_byte: float
    conservative_bits_per_byte: float
    ground_truth_bits_per_byte: float | None = None
    truth_tolerance_bits: float = 0.15
    order_ok: bool = False
    truth_ok: bool | None = None

    @property
    def passes(self) -> bool:
        if not self.order_ok:
            return False
        if self.ground_truth_bits_per_byte is not None:
            return bool(self.truth_ok)
        return True


@dataclass
class ValidationReport:
    """Aggregate validation across all simulated sources."""

    seconds: float
    bits: int
    sources: list[SourceValidation] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return bool(self.sources) and all(s.passes for s in self.sources)

    def summary_lines(self) -> list[str]:
        lines = [f"Entropy validation report ({self.seconds}s windows, "
                 f"{self.bits}-bit quantizer)"]
        lines.append("-" * 88)
        for s in self.sources:
            truth = (f"{s.ground_truth_bits_per_byte:.3f}"
                     if s.ground_truth_bits_per_byte is not None else "-")
            ok = str(bool(s.passes))
            lines.append(
                f"  {s.source_name:<14} n={s.n_bytes:<8}"
                f" shannon={s.shannon_bits_per_byte:5.3f}"
                f" min-hist={s.min_hist_bits_per_byte:5.3f}"
                f" 90B={s.nist90b_bits_per_byte:5.3f}"
                f" conservative={s.conservative_bits_per_byte:5.3f}"
                f" truth={truth} pass={ok}")
        lines.append("-" * 88)
        lines.append(f"OVERALL: {'PASS' if self.all_pass else 'FAIL'}")
        return lines


def true_quantized_gaussian_entropy(sigma: float, bits: int = 8) -> float:
    """Shannon entropy (bits/byte) of the exact quantizer output for
    N(0, sigma^2), assuming the midtread quantizer in `quantize_to_bytes`.

    The quantizer maps x to bin
        floor((x - median)/scale * 2^(bits-1)) + 2^(bits-1)
    with scale = 4*std (std -> sigma for the true source) and clamps to
    [0, 2^bits - 1]. Bin edges in standard units are sigma-invariant:
        z_edge(k) = (k - 2^(bits-1)) / 2^(bits-1) * 4
    (bin width = 8/2^bits in z units), so the result is the SAME for every
    positive sigma: the entropy of the standardized Gaussian quantized at
    +-4 sigma, which is ~7.0468 bits/byte for 8 bits (a bell shape over
    +-4 sigma cannot fill all 256 bins uniformly). Probabilities come from
    the normal CDF Phi.
    """
    if sigma is None or sigma <= 0.0:
        return 0.0  # degenerate source: every sample quantizes to one bin
    levels = 2 ** bits
    width = 8.0 * sigma / levels
    edges = sigma * (-4.0 + width * np.arange(levels + 1) / sigma)
    p = np.diff(0.5 * (1.0 + np.vectorize(math.erf)(edges / (sigma * math.sqrt(2.0)))))
    # Clamp captures both tails into the extreme bins.
    p[0] += 0.5 * (1.0 + math.erf(edges[0] / (sigma * math.sqrt(2.0))))
    p[-1] += 0.5 * (1.0 - math.erf(edges[-1] / (sigma * math.sqrt(2.0))))
    p = np.clip(p, 1e-300, 1.0)
    return float(-(p * np.log2(p)).sum())


def validate_sources(sources: list[EntropySource], seconds: float = 3.0,
                     bits: int = 8, nist90b_limit: int = 50_000,
                     truth_tolerance_bits: float = 0.15) -> ValidationReport:
    """Capture, quantify and entropy-validate every source.

    The thermal source carries an exact ground truth (see
    :func:`true_quantized_gaussian_entropy`); RF and seismic are validated
    for structural invariants only.
    """
    report = ValidationReport(seconds=seconds, bits=bits)
    for src in sources:
        win = src.read(seconds)
        codes = quantize_to_bytes(win.samples, bits=bits)
        rep = entropy_report(codes, bits=bits, run_nist90b=True,
                             nist90b_limit=nist90b_limit)
        order_ok = (
            rep.nist90b_bits_per_bit <= rep.min_entropy_histogram_bits_per_bit + 1e-9
            and rep.min_entropy_histogram_bits_per_bit <= rep.shannon_bits_per_bit + 1e-9
        )
        ground_truth = None
        truth_ok = None
        if src.name == "thermal":
            ground_truth = true_quantized_gaussian_entropy(src.sigma, bits=bits)
            truth_ok = abs(rep.shannon_bits_per_byte - ground_truth) <= truth_tolerance_bits
        report.sources.append(SourceValidation(
            source_name=src.name,
            n_bytes=int(rep.n_bytes),
            shannon_bits_per_byte=rep.shannon_bits_per_byte,
            min_hist_bits_per_byte=rep.min_entropy_histogram_bits_per_byte,
            nist90b_bits_per_byte=rep.nist90b_bits_per_byte,
            conservative_bits_per_byte=rep.conservative_min_bits_per_byte,
            ground_truth_bits_per_byte=ground_truth,
            truth_tolerance_bits=truth_tolerance_bits,
            order_ok=order_ok,
            truth_ok=truth_ok,
        ))
    return report


__all__ = ["SourceValidation", "ValidationReport",
           "true_quantized_gaussian_entropy", "validate_sources"]