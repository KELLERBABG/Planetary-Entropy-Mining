"""GF(256) field arithmetic with the AES polynomial (0x11B).

Implements addition (XOR), multiplication, division and the classic
log/antilog tables using primitive element 3. Used by the hardening
(polynomial) and erasure-coding modules so the whole pipeline shares one
field implementation. Deterministic, no dependencies beyond numpy.
"""

from __future__ import annotations

import numpy as np

_MOD = 0x11B
# PRIMITIVE element of GF(256)* with polynomial 0x11B. Element 2 has order
# only 51 (2^51 = 1) — using it silently builds tables covering a 51-element
# subgroup, corrupting all multiplication. Element 3 spans the full group of
# order 255 (as in the standard AES S-box tables).
_GEN = 3


def _xtime(v: int) -> int:
    """Multiply by x (2) in GF(256): shift left, reduce mod 0x11B."""
    v <<= 1
    if v & 0x100:
        v ^= _MOD
    return v & 0xFF


# Build the antilog table with the correct generator 3:
#   gen^i = (gen^(i-1) * gen) = 2*(gen^(i-1)) ^ gen^(i-1)   (field mul by 3)
_ALOG_INT = [0] * 256
_ALOG_INT[0] = 1
for _i in range(1, 256):
    _ALOG_INT[_i] = _xtime(_ALOG_INT[_i - 1]) ^ _ALOG_INT[_i - 1]
_ALOG = np.asarray(_ALOG_INT, dtype=np.uint8)
_LOG = np.zeros(256, dtype=np.uint8)
for _i in range(255):
    _LOG[_ALOG_INT[_i]] = _i
# log(0) is undefined; point it somewhere harmless and guard at use sites.
_LOG[0] = 0


def gf_add(a: int, b: int) -> int:
    return (a & 0xFF) ^ (b & 0xFF)


def gf_mul(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    if a == 0 or b == 0:
        return 0
    return int(_ALOG[(int(_LOG[a]) + int(_LOG[b])) % 255])


def gf_div(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return int(_ALOG[(int(_LOG[a]) - int(_LOG[b])) % 255])


def gf_pow(a: int, n: int) -> int:
    a &= 0xFF
    n %= 255
    if a == 0:
        return 0 if n != 0 else 1
    return int(_ALOG[(int(_LOG[a]) * n) % 255])


def gf_poly_eval(coeffs: np.ndarray, x: int) -> int:
    """Evaluate a polynomial over GF(256) at point x (Horner).

    `coeffs` are low-to-high: p(x) = c0 + c1*x + c2*x^2 + ... Horner must
    therefore iterate from the *highest* coefficient downwards.
    """
    result = 0
    for c in reversed(np.asarray(coeffs, dtype=np.uint8)):
        result = gf_add(gf_mul(result, x), int(c))
    return result


def gf_poly_eval_array(coeffs: np.ndarray, xs: np.ndarray) -> np.ndarray:
    """Evaluate the polynomial at many points (Horner, highest coeff first)."""
    coeffs = np.asarray(coeffs, dtype=np.uint8)
    xs = np.asarray(xs, dtype=np.uint8)
    result = np.zeros(xs.size, dtype=np.uint8)
    for c in reversed(coeffs):
        # result = result * xs + c over GF(256)
        mul = np.zeros(xs.size, dtype=np.uint8)
        both = (result != 0) & (xs != 0)
        if both.any():
            mul[both] = _ALOG[
                (np.int64(_LOG[result[both]]) + np.int64(_LOG[xs[both]])) % 255
            ]
        result = (mul ^ int(c)) & 0xFF
    return result


__all__ = ["gf_add", "gf_mul", "gf_div", "gf_pow", "gf_poly_eval",
           "gf_poly_eval_array"]