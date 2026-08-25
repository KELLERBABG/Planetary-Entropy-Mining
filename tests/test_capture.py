"""Tests for the simulated entropy capture sources."""

import numpy as np
import pytest

from dsp.capture import (
    RFNoiseSource,
    SeismicNoiseSource,
    SOURCE_REGISTRY,
    ThermalNoiseSource,
    quantize_to_bytes,
)


def test_thermal_statistics_match_ground_truth():
    src = ThermalNoiseSource(sigma=2.0, seed=42)
    win = src.read(1.0)
    assert win.samples.size == int(src.sample_rate)
    assert np.abs(np.mean(win.samples)) < 0.05
    assert np.abs(np.std(win.samples) - 2.0) < 0.1


def test_thermal_entropy_ground_truth_is_positive_and_finite():
    src = ThermalNoiseSource(sigma=1.0)
    h = src.expected_entropy_bits_per_sample()
    assert 0.5 < h < 6.0  # sigma=1 -> ~2.05 bits


def test_sources_are_deterministic_per_seed():
    a = ThermalNoiseSource(seed=7).read(0.5).samples
    b = ThermalNoiseSource(seed=7).read(0.5).samples
    c = ThermalNoiseSource(seed=8).read(0.5).samples
    assert np.array_equal(a, b)
    assert not np.array_equal(a, c)


def test_rf_source_bursts_change_statistics():
    quiet = RFNoiseSource(burst_rate=0.0, seed=3, sample_rate=100_000).read(2.0).samples
    busy = RFNoiseSource(burst_rate=20.0, seed=3, sample_rate=100_000).read(2.0).samples
    assert np.std(busy) > np.std(quiet)


def test_rf_is_band_limited():
    src = RFNoiseSource(seed=4, sample_rate=100_000)
    win = src.read(0.5)
    freqs = np.fft.rfftfreq(win.samples.size, 1.0 / src.sample_rate)
    psd = np.abs(np.fft.rfft(win.samples)) ** 2
    in_band = np.sum(psd[freqs < src.bandwidth])
    out_band = np.sum(psd[freqs >= src.bandwidth * 2.0])
    assert in_band > out_band * 100


def test_seismic_events_present():
    src = SeismicNoiseSource(event_rate=10.0, seed=5)
    win = src.read(2.0)
    assert np.max(np.abs(win.samples)) > 3.0


def test_quantize_to_bytes_shape_and_range():
    samples = np.random.default_rng(0).normal(size=1000)
    codes = quantize_to_bytes(samples, bits=8)
    assert codes.shape == samples.shape
    assert codes.dtype == np.uint8
    assert codes.min() >= 0 and codes.max() <= 255
    assert codes.max() - codes.min() > 200  # uses full range


def test_registry_contains_all_sources():
    assert set(SOURCE_REGISTRY) == {"thermal", "rf_ionospheric", "seismic"}


@pytest.mark.parametrize("cls", [ThermalNoiseSource, RFNoiseSource, SeismicNoiseSource])
def test_all_sources_read_window(cls):
    src = cls(seed=11, sample_rate=100_000) if cls is RFNoiseSource else cls(seed=11)
    win = src.read(0.25)
    assert win.samples.size > 0
    assert win.source_name == src.name
    assert win.metadata
