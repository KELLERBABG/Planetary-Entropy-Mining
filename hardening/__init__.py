"""Noise hardening: entropy -> GF(256) polynomial commitment."""

from .gf256 import (
    gf_add,
    gf_div,
    gf_mul,
    gf_poly_eval,
    gf_poly_eval_array,
    gf_pow,
)
from .polynomial import (
    HardenConfig,
    HardenedEntropy,
    extract_seed,
    harden,
    polynomial_embed,
    verify_hardening,
)

__all__ = [
    "gf_add", "gf_div", "gf_mul", "gf_pow",
    "gf_poly_eval", "gf_poly_eval_array",
    "HardenConfig", "HardenedEntropy",
    "extract_seed", "harden", "polynomial_embed", "verify_hardening",
]