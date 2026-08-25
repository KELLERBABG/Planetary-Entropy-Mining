"""Noise hardening: transform raw entropy bytes into a verifiable polynomial.

Design (simple, per AGENTS.md "start simple: cryptographic extraction +
redundancy"):
  1. Extract unbiased seed material from the quantized noise stream with a
     keyed BLAKE2b extractor (the stream may contain bursts / stamps from
     the simulation, so a keyed extractor separates the noise entropy from
     any structure).
  2. Build a redundancy-protected polynomial representation over GF(256):
     the seed bytes become the coefficients p(x) (degree d, d+1 coeffs),
     and the hardened artifact stores `n_points > d+1` evaluations
     y_i = p(alpha^i). The surplus evaluations are the redundancy that lets
     the erasure-coding module later reconstruct the seed with < 100% of
     the points.
  3. `verify_hardening` recomputes the evaluations from the seed and checks
     both the keyed MAC and the polynomial values, so a corrupted hardened
     blob is rejected and a modified seed no longer validates.

The artifact is a *commitment* to the hardened entropy: the seed is derived
deterministically from the raw noise, the polynomial is a deterministic
function of the seed, and the stored evaluations bind both.

Everything is deterministic for a given seed. No real money / keys.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

import numpy as np

from .gf256 import gf_poly_eval_array

_KEY_LEN = 32      # BLAKE2b key length
_SALT_LEN = 16
_DEFAULT_DEGREE = 31          # 32 coefficients = 32 seed bytes
# 64 distinct, nonzero GF(256) evaluation points (the field elements 1..64)
# → 2x redundancy vs the 32 polynomial coefficients. Points are constrained
# to be distinct and nonzero so any degree+1 of them uniquely determine the
# polynomial (required later by the erasure-coding / reconstruction stage).
_POLY_POINTS: tuple[int, ...] = tuple(range(1, 65))


@dataclass
class HardenConfig:
    """Parameter set that must be serialised into every certificate."""

    key_id: int = 1
    degree: int = _DEFAULT_DEGREE
    extract_salt: bytes = b""
    poly_points: tuple[int, ...] = _POLY_POINTS

    def __post_init__(self) -> None:
        if self.extract_salt == b"":
            self.extract_salt = bytes(range(_SALT_LEN))
        if self.degree < 1:
            raise ValueError("degree must be >= 1")
        if len(self.poly_points) <= self.degree:
            raise ValueError("need at least degree+1 evaluation points "
                             "(redundancy requires more)")


@dataclass
class HardenedEntropy:
    """Result of hardening: polynomial evaluations + MAC + params."""

    params: HardenConfig
    evaluations: bytearray      # len(poly_points) evaluations y_i = p(alpha^i)
    mac: bytes
    seed_len: int

    def to_dict(self) -> dict:
        return {
            "params": {
                "key_id": self.params.key_id,
                "degree": self.params.degree,
                "extract_salt": self.params.extract_salt.hex(),
                "poly_points": list(self.params.poly_points),
            },
            "evaluations": bytes(self.evaluations).hex(),
            "mac": self.mac.hex(),
            "seed_len": self.seed_len,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HardenedEntropy":
        p = d["params"]
        return cls(
            params=HardenConfig(
                key_id=p["key_id"],
                degree=p["degree"],
                extract_salt=bytes.fromhex(p["extract_salt"]),
                poly_points=tuple(p["poly_points"]),
            ),
            evaluations=bytearray(bytes.fromhex(d["evaluations"])),
            mac=bytes.fromhex(d["mac"]),
            seed_len=d["seed_len"],
        )


def _keyed_extract(raw: np.ndarray, salt: bytes, key: bytes,
                   out_len: int = 32) -> bytes:
    """Keyed BLAKE2b extractor: raw noise bytes -> uniform seed bytes."""
    h = hashlib.blake2b(digest_size=out_len, key=key, salt=salt)
    h.update(bytes(np.asarray(raw, dtype=np.uint8).tobytes()))
    return h.digest()


def extract_seed(raw: np.ndarray, config: HardenConfig | None = None,
                 server_key: bytes | None = None) -> bytes:
    """Deterministic seed extraction for a configured pipeline."""
    config = config or HardenConfig()
    key = server_key or b"PEM-hardening-key-v1"[: _KEY_LEN]
    return _keyed_extract(raw, config.extract_salt, key)


def polynomial_embed(seed: bytes, degree: int) -> np.ndarray:
    """Map seed bytes to GF(256) polynomial coefficients (zero-padded)."""
    coeffs = np.zeros(degree + 1, dtype=np.uint8)
    b = np.frombuffer(seed, dtype=np.uint8)
    coeffs[: min(len(b), degree + 1)] = b[: degree + 1]
    return coeffs


def harden(raw: np.ndarray, config: HardenConfig | None = None,
           server_key: bytes | None = None) -> HardenedEntropy:
    """Harden a raw noise window into the polynomial artifact.

    p(x) = seed[0] + seed[1]*x + ... over GF(256); evaluation points are a
    superset of the generator powers alpha^i. Only the evaluations (and a
    MAC) are stored — never the seed bytes themselves.
    """
    config = config or HardenConfig()
    key = server_key or b"PEM-hardening-key-v1"[: _KEY_LEN]
    seed = extract_seed(raw, config, key)
    coeffs = polynomial_embed(seed, config.degree)
    pts = np.asarray(config.poly_points, dtype=np.uint8)
    evals = bytearray(gf_poly_eval_array(coeffs, pts))
    mac = hmac.new(key, b"hardening-v1" + bytes(evals), hashlib.sha256).digest()
    return HardenedEntropy(params=config, evaluations=evals, mac=mac,
                           seed_len=len(seed))


def verify_hardening(artifact: HardenedEntropy, raw: np.ndarray | None = None,
                     seed: bytes | None = None,
                     server_key: bytes | None = None) -> bool:
    """Verify a hardened artifact against its seed (or raw bytes).

    1. MAC over the stored evaluations must validate.
    2. If a seed (or raw) is supplied, the recomputed polynomial evaluations
       must match the stored ones exactly.
    """
    key = server_key or b"PEM-hardening-key-v1"[: _KEY_LEN]
    expected_mac = hmac.new(key, b"hardening-v1" + bytes(artifact.evaluations),
                            hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, artifact.mac):
        return False
    if raw is not None:
        seed = extract_seed(raw, artifact.params, key)
    if seed is not None:
        coeffs = polynomial_embed(seed, artifact.params.degree)
        pts = np.asarray(artifact.params.poly_points, dtype=np.uint8)
        evals = gf_poly_eval_array(coeffs, pts)
        if not np.array_equal(evals, np.frombuffer(artifact.evaluations,
                                                   dtype=np.uint8)):
            return False
    return True


__all__ = ["HardenConfig", "HardenedEntropy", "harden", "verify_hardening",
           "extract_seed", "polynomial_embed"]