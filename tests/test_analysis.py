"""Tests for the signal processing / entropy estimation chain (dsp/analysis)."""

import numpy as np
import pytest

from dsp.analysis import (
    EntropyReport,
    SpectralAnalysis,
    analyze_capture_window,
    entropy_report,
    min_entropy_histogram_bits,
    noise_floor,
    shannon_entropy_bytes,
    spectral_analysis,
)
from dsp.capture import RFNoiseSource, ThermalNoiseSource, quantize_to_bytes

RNG = np.random.default_rng(7)


# ---------------------------------------------------------------------------
# Shannon / histogram entropy
# ---------------------------------------------------------------------------

def test_shannon_uniform_bytes_is_8_bits():
    data = RNG.integers(0, 256, size=100_000).astype(np.uint8)
    h = shannon_entropy_bytes(data)
    assert 7.99 < h <= 8.0


def test_shannon_constant_is_zero():
    assert shannon_entropy_bytes(np.full(1000, 5, dtype=np.uint8)) == 0.0


def test_shannon_empty_is_zero():
    assert shannon_entropy_bytes(np.zeros(0, dtype=np.uint8)) == 0.0


def test_min_entropy_histogram_constant_zero():
    assert min_entropy_histogram_bits(np.full(5000, 9, dtype=np.uint8)) == 0.0


def test_min_entropy_histogram_biased_stream():
    # 90% zeros: -log2(0.9) / 8 per bit.
    data = (RNG.random(100_000) < 0.9).astype(np.uint8)
    h = min_entropy_histogram_bits(data)
    expected = -np.log2(0.9) / 8
    assert abs(h - expected) < 0.001


def test_min_entropy_histogram_uniform_near_one():
    data = RNG.integers(0, 256, size=1_000_000).astype(np.uint8)
    h = min_entropy_histogram_bits(data)
    # Expected shortfall ~ sqrt(2 ln(256) / n) / ln(2) ~ 0.008 for n = 1M.
    assert h > 1.0 - 0.02


# ---------------------------------------------------------------------------
# Spectral analysis / noise floor
# ---------------------------------------------------------------------------

def test_noise_floor_white_noise_is_finite_and_repeatable():
    a = ThermalNoiseSource(sigma=1.0, seed=1).read(1.0).samples
    b = ThermalNoiseSource(sigma=1.0, seed=1).read(1.0).samples
    f1, f2 = noise_floor(a, 48_000.0), noise_floor(b, 48_000.0)
    assert abs(f1 - f2) < 1e-9
    assert np.isfinite(f1)


def test_spectral_analysis_white_noise_flat_spectrum():
    src = ThermalNoiseSource(sigma=1.0, seed=3)
    win = src.read(1.0)
    spec = spectral_analysis(win.samples, src.sample_rate)
    assert isinstance(spec, SpectralAnalysis)
    assert spec.freqs.size == spec.psd_db.size
    band = spec.psd_db[spec.freqs > 1000.0]
    spread = np.percentile(band, 90) - np.percentile(band, 10)
    assert spread < 12.0  # no strong coloring for white noise


def test_spectral_analysis_detects_tone():
    t = np.arange(48_000) / 48_000.0
    sig = np.sin(2 * np.pi * 10_000.0 * t) * 5.0 + RNG.normal(size=48_000)
    spec = spectral_analysis(sig, 48_000.0)
    assert spec.peak_hz is not None
    assert abs(spec.peak_hz - 10_000.0) < 100.0
    assert spec.peak_excess_db > 6.0


def test_spectral_analysis_rf_bandwidth_bounded():
    src = RFNoiseSource(seed=4, sample_rate=200_000)
    win = src.read(0.5)
    spec = spectral_analysis(win.samples, src.sample_rate)
    assert spec.bandwidth_hz < src.sample_rate / 2.0
    # Power concentration: >= 70% of power inside the 20 kHz observation
    # band, >= 95% below 60 kHz (transition band + burst sidebands).
    pw = 10.0 ** (spec.psd_db / 10.0)
    cdf = np.cumsum(pw) / np.sum(pw)
    frac_in_band = cdf[np.searchsorted(spec.freqs, src.bandwidth)] - 0.0
    frac_below = cdf[np.searchsorted(spec.freqs, 60_000)] - 0.0
    assert frac_in_band >= 0.7
    assert frac_below >= 0.95


def test_spectral_analysis_rejects_empty():
    with pytest.raises(ValueError):
        spectral_analysis(np.zeros(0), 48_000.0)


# ---------------------------------------------------------------------------
# Full report + 90B cross-check
# ---------------------------------------------------------------------------

def test_entropy_report_constant_stream():
    rep = entropy_report(np.full(20_000, 3, dtype=np.uint8))
    assert isinstance(rep, EntropyReport)
    assert rep.shannon_bits_per_byte == 0.0
    assert rep.conservative_min_bits_per_byte < 1e-6


def test_entropy_report_uniform_stream_near_8_bits():
    data = RNG.integers(0, 256, size=1_000_000).astype(np.uint8)
    rep = entropy_report(data, nist90b_limit=50_000)
    assert rep.shannon_bits_per_byte > 7.99
    assert rep.min_entropy_histogram_bits_per_byte > 7.9
    # 90B is conservative on short samples; individual estimators exceed
    # 0.9/bit at 200k symbols (tested in test_nist800_90b.py).
    assert rep.nist90b_bits_per_byte > 7.0
    assert rep.conservative_min_bits_per_byte == rep.nist90b_bits_per_byte


def test_cross_check_conservative_order():
    # For a good source: 90B <= histogram min-entropy <= Shannon.
    src = ThermalNoiseSource(sigma=1.0, seed=5)
    codes = quantize_to_bytes(src.read(2.0).samples)
    rep = entropy_report(codes, nist90b_limit=100_000)
    assert rep.min_entropy_histogram_bits_per_bit <= rep.shannon_bits_per_bit + 1e-9
    assert rep.nist90b_bits_per_bit <= rep.min_entropy_histogram_bits_per_bit + 1e-9


def test_analyze_capture_window_end_to_end():
    src = ThermalNoiseSource(sigma=1.0, seed=6)
    win = src.read(0.5)
    spec, rep = analyze_capture_window(win.samples, src.sample_rate,
                                       nist90b_limit=20_000)
    assert np.isfinite(spec.noise_floor_db)
    # 8-bit quantization of a unit Gaussian spans ~6-7 bits/byte; the 90B
    # suite is deliberately conservative on small samples, so use a wide,
    # correct-by-construction bound here (tight bounds live in the probe).
    assert 4.0 < rep.conservative_min_bits_per_byte <= 8.0
    assert rep.min_entropy_histogram_bits_per_byte <= rep.shannon_bits_per_byte + 1e-9
