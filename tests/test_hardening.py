"""Tests for GF(256) arithmetic and the polynomial hardening module."""

import numpy as np
import pytest

from hardening.gf256 import (
    gf_add,
    gf_div,
    gf_mul,
    gf_poly_eval,
    gf_poly_eval_array,
    gf_pow,
)
from hardening.polynomial import (
    HardenConfig,
    HardenedEntropy,
    extract_seed,
    harden,
    polynomial_embed,
    verify_hardening,
)

# ---------------------------------------------------------------------------
# GF(256) field arithmetic (AES polynomial 0x11B)
# ---------------------------------------------------------------------------

def test_gf_mul_known_values():
    # Spot checks against the standard AES GF(256) tables.
    assert gf_mul(0x57, 0x83) == 0xC1
    assert gf_mul(0x53, 0xCA) == 0x01
    assert gf_mul(1, 1) == 1
    assert gf_mul(0, 42) == 0


def test_gf_mul_commutative_and_associative():
    rng = np.random.default_rng(1)
    a = int(rng.integers(0, 256))
    b = int(rng.integers(0, 256))
    c = int(rng.integers(0, 256))
    assert gf_mul(a, b) == gf_mul(b, a)
    assert gf_mul(gf_mul(a, b), c) == gf_mul(a, gf_mul(b, c))


def test_gf_div_is_inverse_of_mul():
    rng = np.random.default_rng(2)
    for _ in range(20):
        a = int(rng.integers(0, 256))
        b = int(rng.integers(1, 256))
        assert gf_mul(gf_div(a, b), b) == a


def test_gf_div_zero_raises():
    with pytest.raises(ZeroDivisionError):
        gf_div(5, 0)


def test_gf_pow_is_cycle_255():
    # a^255 = 1 for every nonzero a (Fermat in GF(256)).
    rng = np.random.default_rng(3)
    for _ in range(10):
        a = int(rng.integers(1, 256))
        assert gf_pow(a, 255) == 1


def test_gf_poly_eval_matches_array():
    coeffs = (np.arange(1, 33) * 7 % 256).astype(np.uint8)
    xs = np.arange(1, 20, dtype=np.uint8)
    single = np.array([gf_poly_eval(coeffs, int(x)) for x in xs], dtype=np.uint8)
    vec = gf_poly_eval_array(coeffs, xs)
    assert np.array_equal(single, vec)


def test_gf_poly_eval_constant_poly():
    coeffs = np.array([9, 0, 0, 0], dtype=np.uint8)
    for x in (0, 1, 2, 3):
        assert gf_poly_eval(coeffs, x) == 9


# ---------------------------------------------------------------------------
# Hardening: extraction, polynomial embedding, artifacts
# ---------------------------------------------------------------------------

def test_extract_seed_deterministic_and_sensitive():
    raw = np.arange(1000, dtype=np.uint8)
    a = extract_seed(raw)
    b = extract_seed(raw)
    c = extract_seed(raw + 1)
    assert a == b
    assert a != c


def test_polynomial_embed_pads_and_truncates():
    coeffs = polynomial_embed(b"\x01\x02\x03", degree=5)
    assert coeffs.tolist() == [1, 2, 3, 0, 0, 0]
    long = polynomial_embed(bytes(range(100)), degree=7)
    assert len(long) == 8
    assert long[:8].tolist() == list(range(8))


def test_harden_artifact_deterministic():
    raw = np.random.default_rng(4).normal(size=5000)
    artifact = harden(raw)
    assert isinstance(artifact, HardenedEntropy)
    assert len(artifact.evaluations) == len(artifact.params.poly_points)
    assert artifact.params.degree == 31
    assert len(artifact.mac) == 32  # blake2b digest
    assert artifact.seed_len == 32


def test_harden_verify_round_trip():
    raw = np.random.default_rng(5).normal(size=5000)
    artifact = harden(raw)
    assert verify_hardening(artifact, raw=raw)
    assert verify_hardening(artifact, seed=extract_seed(raw, artifact.params))
    assert verify_hardening(artifact)  # MAC-only check


def test_verify_rejects_corrupted_eval_or_raw():
    raw = np.random.default_rng(6).normal(size=5000)
    artifact = harden(raw)
    bad_eval = bytearray(artifact.evaluations)
    bad_eval[0] ^= 0xFF
    artifact.evaluations = bad_eval
    assert not verify_hardening(artifact, raw=raw)
    artifact.evaluations = bytearray(artifact.evaluations)
    assert not verify_hardening(artifact, raw=raw + 0.01)


def test_harden_config_validation():
    with pytest.raises(ValueError):
        HardenConfig(degree=0)
    with pytest.raises(ValueError):
        HardenConfig(degree=10, poly_points=(1, 2, 3))  # too few points


def test_artifact_serialization_round_trip():
    raw = np.random.default_rng(7).normal(size=5000)
    artifact = harden(raw)
    d = artifact.to_dict()
    restored = HardenedEntropy.from_dict(d)
    assert restored.params == artifact.params
    assert bytes(restored.evaluations) == bytes(artifact.evaluations)
    assert restored.mac == artifact.mac
    assert verify_hardening(restored, raw=raw)


def test_harden_different_raw_gives_different_artifact():
    a = harden(np.random.default_rng(8).normal(size=5000))
    b = harden(np.random.default_rng(9).normal(size=5000))
    assert bytes(a.evaluations) != bytes(b.evaluations)
    assert a.mac != b.mac