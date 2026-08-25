"""Tests for the NIST SP 800-90B min-entropy estimators.

Two tiers:
- default (fast): deterministic per-test RNGs, sanity checks at modest sizes;
  the zero-detection cases keep a tight (0) bound and the MCV bias cases a
  tight statistical bound, so correctness is still exercised.
- @pytest.mark.slow: rigorous statistical validation at full recommended
  sizes (200k symbols / 1M bits). Run with `py -m pytest -m slow`.
"""

import math
import zlib

import numpy as np
import pytest

from dsp.nist800_90b import (
    _pfunc,
    _pq_func,
    _search_for_p,
    collision,
    compression,
    estimate_min_entropy,
    lag_prediction,
    lrs,
    lz78y,
    markov,
    mcv,
    multi_mcw,
    multi_mmc_prediction,
    t_tuple,
)

SYMBOL_ESTS = [mcv, t_tuple, lrs, lz78y, multi_mcw,
               lag_prediction, multi_mmc_prediction]
BINARY_ESTS = [collision, markov, compression]


def _seed(seed: object) -> int:
    """Stable int seed from an int or a label (estimator names, etc.)."""
    if isinstance(seed, int):
        return seed
    return zlib.crc32(str(seed).encode("utf-8"))


def _random_bits(n: int, seed: object = 2024) -> np.ndarray:
    return (np.random.default_rng(_seed(seed)).random(n) < 0.5).astype(np.uint8)


def _random_bytes(n: int, seed: object = 2024) -> np.ndarray:
    return np.random.default_rng(_seed(seed)).integers(0, 256, size=n).astype(np.uint8)


# ---------------------------------------------------------------------------
# Probability machinery
# ---------------------------------------------------------------------------

def test_pq_func_known_values():
    assert abs(_pq_func(0.5) - 2.5) < 1e-9
    assert abs(_pq_func(1.0) - 2.0) < 1e-9


def test_pq_func_numerically_stable_near_one():
    # Previously overflowed (math.exp(z), z = 1/(1-p)) for p > 1 - 1/709.
    assert abs(_pq_func(1.0 - 1e-12) - 2.0) < 1e-6
    assert abs(_pq_func(1.0 - 1e-6) - 2.0) < 0.05


def test_pq_func_monotone_decreasing():
    xs = np.linspace(0.5, 1.0, 50)
    vals = [_pq_func(x) for x in xs]
    assert all(vals[i] >= vals[i + 1] - 1e-9 for i in range(len(vals) - 1))


def test_pfunc_and_search():
    # pfunc -> 1 as p -> 0 (10-iteration fixed point, per reference).
    assert abs(_pfunc(1e-6, 1, 1000) - 1.0) < 1e-3
    assert _pfunc(0.5, 1, 1000) < 0.5
    xs = np.linspace(0.05, 0.95, 19)
    vals = [_pfunc(x, 3, 5000) for x in xs]
    assert all(vals[i] >= vals[i + 1] - 1e-9 for i in range(len(vals) - 1))
    # Random binary data: r ~ 2*log2(N), so P_local lands near 0.43.
    p = _search_for_p(21, 1_000_000)
    assert 0.35 < p < 0.5
    # Deterministic data: r = N, P_local saturates near 1.
    p = _search_for_p(50_000, 50_000)
    assert p > 0.99


# ---------------------------------------------------------------------------
# Fast defaults: estimator sanity on random data (deterministic per-test RNG)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("est", SYMBOL_ESTS)
def test_random_bytes_sanity(est):
    h = est(_random_bytes(8_000, seed=est.__name__), 8)
    # Every estimator must recognise high-entropy streams at 8k symbols.
    # Bounds are deliberately loose here; tight ones live in the slow tier.
    assert 0.5 <= h <= 1.0, f"{est.__name__} = {h}"


@pytest.mark.parametrize("est", BINARY_ESTS)
def test_random_bits_sanity(est):
    h = est(_random_bits(16_000, seed=est.__name__))
    assert 0.5 <= h <= 1.0, f"{est.__name__} = {h}"


@pytest.mark.parametrize("est", SYMBOL_ESTS)
def test_constant_bytes_zero_entropy(est):
    h = est(np.full(10_000, 42, dtype=np.uint8), 8)
    assert h < 1e-6, f"{est.__name__} = {h}"


@pytest.mark.parametrize("est", BINARY_ESTS)
def test_constant_bits_zero_entropy(est):
    h = est(np.zeros(10_000, dtype=np.uint8))
    assert h < 1e-6, f"{est.__name__} = {h}"


def test_markov_detects_alternating_pattern():
    bits = (np.arange(50_000) % 2).astype(np.uint8)
    assert markov(bits) < 0.01


def test_mcv_detects_biased_source():
    # 90% zeros: min entropy of the byte stream ~ -log2(0.9)/8 bit.
    data = (np.random.default_rng(7).random(100_000) < 0.9).astype(np.uint8)
    h = mcv(data, 8)
    expected = -math.log2(0.9) / 8
    assert abs(h - expected) < 0.01


def test_mcv_detects_biased_binary():
    bits = (np.random.default_rng(8).random(200_000) < 0.9).astype(np.uint8)
    h = mcv(bits, 1)
    assert abs(h - (-math.log2(0.9))) < 0.01


# ---------------------------------------------------------------------------
# Full suite entry point (fast structural checks)
# ---------------------------------------------------------------------------

def test_estimate_min_entropy_small_random_bytes():
    res = estimate_min_entropy(_random_bytes(8_000, seed=1).tobytes(),
                               bits_per_symbol=8)
    assert res["bits_per_symbol"] == 8
    assert res["n_symbols"] == 8_000
    assert set(res["estimators"]) == {"mcv", "t_tuple", "lrs", "lz78y",
                                      "multi_mcw", "lag_prediction",
                                      "multi_mmc_prediction"}
    assert res["min_entropy_per_bit"] == min(res["estimators"].values())


def test_estimate_min_entropy_accepts_bytes_and_array():
    arr = _random_bytes(2_000, seed=2)
    same = estimate_min_entropy(arr.tobytes(), bits_per_symbol=8)
    res = estimate_min_entropy(arr, bits_per_symbol=8)
    assert same["min_entropy_per_bit"] == res["min_entropy_per_bit"]


def test_estimate_min_entropy_respects_limit():
    res = estimate_min_entropy(_random_bytes(20_000, seed=3),
                               bits_per_symbol=8, limit=10_000)
    assert res["n_symbols"] == 10_000


def test_estimate_min_entropy_rejects_bad_symbol_length():
    with pytest.raises(ValueError):
        estimate_min_entropy(b"x", bits_per_symbol=4)


def test_estimate_min_entropy_rejects_empty():
    with pytest.raises(ValueError):
        estimate_min_entropy(b"")


# ---------------------------------------------------------------------------
# Slow tier: rigorous statistical validation at full recommended sizes
# ---------------------------------------------------------------------------

@pytest.mark.slow
@pytest.mark.parametrize("est", SYMBOL_ESTS)
def test_random_bytes_near_one_bit_per_bit(est):
    h = est(_random_bytes(200_000, seed=est.__name__), 8)
    assert 0.9 <= h <= 1.0, f"{est.__name__} = {h}"


# The NIST compression test (6.3.6, Maurer with 6-bit symbols) is inherently
# conservative: on 1M truly random bits it lands in ~0.86-0.90 (verified
# bit-identical against the dj-on-github reference port), so its threshold is
# 0.85 while collision/markov hold the 0.9 bound.
BINARY_SLOW_FLOOR = {"collision": 0.9, "markov": 0.9, "compression": 0.85}


@pytest.mark.slow
@pytest.mark.parametrize("est", BINARY_ESTS)
def test_random_bits_near_one_bit(est):
    h = est(_random_bits(1_000_000, seed=est.__name__))
    assert BINARY_SLOW_FLOOR[est.__name__] <= h <= 1.0, f"{est.__name__} = {h}"


@pytest.mark.slow
def test_estimate_min_entropy_random_bytes():
    res = estimate_min_entropy(_random_bytes(200_000, seed="full").tobytes(),
                               bits_per_symbol=8)
    assert res["bits_per_symbol"] == 8
    assert res["n_symbols"] == 200_000
    assert res["min_entropy_per_bit"] >= 0.9
    assert set(res["estimators"]) == {"mcv", "t_tuple", "lrs", "lz78y",
                                      "multi_mcw", "lag_prediction",
                                      "multi_mmc_prediction"}
    assert res["min_entropy_per_bit"] == min(res["estimators"].values())


@pytest.mark.slow
def test_estimate_min_entropy_random_bits():
    # Structural smoke at 200k bits: the tight 0.9/0.9/0.85 bounds live in the
    # per-estimator slow tests at NIST's recommended 1M-bit size. At 200k bits
    # NIST's own conservative tests land lower on this fixed stream (collision
    # ~0.845, compression ~0.868), so the aggregate floor here is loose.
    # (Regression: array input used to be double-unpacked, collapsing the
    # stream to 0.033 — fixed in dsp/nist800_90b.estimate_min_entropy.)
    res = estimate_min_entropy(_random_bits(200_000, seed="bits"),
                               bits_per_symbol=1)
    assert res["bits_per_symbol"] == 1
    assert res["min_entropy_per_bit"] >= 0.8
    assert "collision" in res["estimators"]
    assert "markov" in res["estimators"]
    assert "compression" in res["estimators"]


@pytest.mark.slow
def test_estimate_min_entropy_constant_is_zero():
    res = estimate_min_entropy(np.full(50_000, 7, dtype=np.uint8))
    assert res["min_entropy_per_bit"] < 1e-6