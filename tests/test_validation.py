"""Tests for the entropy validation cross-checks (dsp/validation)."""

import numpy as np
import pytest

from dsp.capture import RFNoiseSource, SeismicNoiseSource, SOURCE_REGISTRY, ThermalNoiseSource
from dsp.validation import (
    ValidationReport,
    true_quantized_gaussian_entropy,
    validate_sources,
)


def test_true_quantized_gaussian_entropy_values():
    # The quantizer rescales by 4*std, so the *standardized* Gaussian is
    # quantized at +/-4 sigma with bin width 1/32 in z-units for every
    # positive sigma: H = h(N(0,1)) + log2(32) ~ 2.047 + 5 = 7.0468 bits/byte.
    # A bell shape over +/-4 sigma cannot fill all 256 bins uniformly, so
    # the exact truth is ~7.047, NOT 8.
    h = true_quantized_gaussian_entropy(1.0)
    assert abs(h - 7.0468) < 1e-3
    # Sigma-invariant: the bin edges in z-units do not depend on sigma.
    assert abs(true_quantized_gaussian_entropy(0.01) - h) < 1e-12
    assert abs(true_quantized_gaussian_entropy(100.0) - h) < 1e-12
    # Degenerate source (sigma == 0 or None) collapses to a single bin.
    assert true_quantized_gaussian_entropy(0.0) == 0.0
    assert true_quantized_gaussian_entropy(None) == 0.0


def test_thermal_shannon_matches_true_distribution():
    # Empirical Shannon entropy of a quantized thermal capture must match the
    # analytic ground truth from the normal CDF.
    sigma = 1.0
    src = ThermalNoiseSource(sigma=sigma, seed=11)
    samples = src.read(4.0).samples
    codes = np.clip(np.floor((samples) / (4.0 * sigma) * 128.0) + 128.0,
                    0, 255).astype(np.uint8)
    counts = np.bincount(codes, minlength=256)
    p = counts / counts.sum()
    empirical = float(-(p[p > 0] * np.log2(p[p > 0])).sum())
    truth = true_quantized_gaussian_entropy(sigma)
    assert abs(empirical - truth) < 0.05


def test_validate_sources_report_structure():
    sources = [ThermalNoiseSource(seed=1),
               RFNoiseSource(seed=2, sample_rate=200_000),
               SeismicNoiseSource(seed=3)]
    report = validate_sources(sources, seconds=1.0, nist90b_limit=5_000)
    assert isinstance(report, ValidationReport)
    assert {s.source_name for s in report.sources} == \
        {"thermal", "rf_ionospheric", "seismic"}
    for s in report.sources:
        assert s.n_bytes > 0
        assert np.isfinite(s.shannon_bits_per_byte)
        assert s.passes, f"{s.source_name} failed validation"
    assert report.all_pass


def test_validate_sources_thermal_ground_truth():
    src = ThermalNoiseSource(sigma=1.0, seed=5)
    report = validate_sources([src], seconds=2.0, nist90b_limit=5_000)
    s = report.sources[0]
    assert s.ground_truth_bits_per_byte is not None
    assert abs(s.shannon_bits_per_byte - s.ground_truth_bits_per_byte) <= 0.15


def test_validate_sources_uses_registry():
    names = sorted(SOURCE_REGISTRY)
    assert names == ["rf_ionospheric", "seismic", "thermal"]