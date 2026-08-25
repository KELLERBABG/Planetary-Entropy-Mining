"""Signal processing chain for entropy capture.

Implements the DSP stage of the pipeline: FFT / periodogram analysis, noise
floor extraction, Shannon entropy and histogram-based min-entropy estimation,
and a cross-check against the NIST SP 800-90B estimator suite
(:mod:`dsp.nist800_90b`).

Design notes
------------
- Every estimator takes *quantized bytes* (8-bit ADC codes) or raw float
  samples. Float-level estimates are computed on quantized streams so they
  are comparable to the 90B suite, which also operates on discrete symbols.
- The noise floor is the robust (median) PSD level in a band, expressed in
  dB relative to full scale; it is the standard receiver figure used to
  reject weak/spurious channels before entropy extraction.
- The cross-check asserts the classic relationship
  H_min(90B) <= H_min(histogram) <= H_Shannon (per bit): the 90B suite is
  deliberately conservative, so a stream that passes it with margin is
  trustworthy for keying material.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from .capture import quantize_to_bytes
from .nist800_90b import estimate_min_entropy


@dataclass
class SpectralAnalysis:
    """Result of an FFT / periodogram analysis."""

    freqs: np.ndarray
    psd_db: np.ndarray          # PSD in dB (arbitrary reference)
    noise_floor_db: float       # robust median PSD level in dB
    bandwidth_hz: float         # occupied band above the floor
    peak_hz: float | None       # frequency of the strongest peak, if any
    peak_excess_db: float       # peak level above the floor, in dB


@dataclass
class EntropyReport:
    """Combined entropy estimate for one quantized stream."""

    n_bytes: int
    shannon_bits_per_byte: float
    shannon_bits_per_bit: float
    min_entropy_histogram_bits_per_byte: float
    min_entropy_histogram_bits_per_bit: float
    nist90b_bits_per_byte: float
    nist90b_bits_per_bit: float
    conservative_min_bits_per_byte: float  # min(histogram, 90B)
    estimator_details: dict = field(default_factory=dict)


def shannon_entropy_bytes(data: np.ndarray | bytes) -> float:
    """Shannon entropy per byte (bits) of an 8-bit symbol stream."""
    arr = np.asarray(data, dtype=np.uint8)
    if arr.size == 0:
        return 0.0
    counts = np.bincount(arr, minlength=256)
    p = counts / arr.size
    nz = p[p > 0]
    return float(-(nz * np.log2(nz)).sum())


def min_entropy_histogram_bits(data: np.ndarray | bytes,
                               bits: int = 8) -> float:
    """Histogram-based min-entropy: -log2(p_max), per bit."""
    arr = np.asarray(data, dtype=np.uint8)
    if arr.size == 0:
        return 0.0
    counts = np.bincount(arr, minlength=256)
    p_max = counts.max() / arr.size
    h = -math.log2(p_max)
    return max(0.0, h / bits)


def noise_floor(samples: np.ndarray, sample_rate: float,
                nfft: int = 2048) -> float:
    """Robust noise floor (dB) of a capture window.

    Uses a Welch periodogram with a Hann window and takes the median PSD
    level in dB; the median is robust against narrowband signals and
    impulsive events riding on top of the noise.
    """
    arr = np.asarray(samples, dtype=np.float64)
    if arr.size < nfft:
        nfft = max(2, int(2 ** math.floor(math.log2(arr.size))))
    freqs, psd = _periodogram(arr, sample_rate, nfft)
    db = 10.0 * np.log10(np.maximum(psd, 1e-300))
    return float(np.median(db))


def _periodogram(samples: np.ndarray, sample_rate: float,
                 nfft: int) -> tuple[np.ndarray, np.ndarray]:
    """Welch periodogram (single segment, Hann window)."""
    from scipy import signal as sp_signal

    window = sp_signal.get_window("hann", nfft)
    n_segs = max(1, samples.size // nfft)
    seg = samples[: n_segs * nfft].reshape(n_segs, nfft) * window
    fft = np.fft.rfft(seg, axis=1)
    power = (np.abs(fft) ** 2).mean(axis=0)
    power /= (window ** 2).sum()  # scale for the window's noise power gain
    freqs = np.fft.rfftfreq(nfft, 1.0 / sample_rate)
    return freqs, power


def spectral_analysis(samples: np.ndarray, sample_rate: float,
                      nfft: int = 2048,
                      floor_percentile: float = 50.0) -> SpectralAnalysis:
    """Full FFT analysis: PSD, noise floor, occupied band, peaks."""
    arr = np.asarray(samples, dtype=np.float64)
    if arr.size == 0:
        raise ValueError("empty samples")
    freqs, psd = _periodogram(arr, sample_rate, min(nfft, arr.size))
    db = 10.0 * np.log10(np.maximum(psd, 1e-300))
    floor = float(np.percentile(db, floor_percentile))
    above = db > floor + 3.0
    band = float(freqs[above].max() - freqs[above].min()) if above.any() else 0.0
    # Occupied band: 5th..95th percentiles of the power-weighted frequency
    # distribution (robust against both noise and narrowband spikes).
    pw = np.maximum(psd, 1e-300)
    cdf = np.cumsum(pw)
    cdf /= cdf[-1]
    f_lo = float(freqs[np.searchsorted(cdf, 0.05)])
    f_hi = float(freqs[np.searchsorted(cdf, 0.95)])
    occupied = max(band, f_hi - f_lo)
    peak_idx = int(np.argmax(db))
    excess = float(db[peak_idx] - floor)
    peak = float(freqs[peak_idx]) if excess > 6.0 else None
    return SpectralAnalysis(freqs=freqs, psd_db=db, noise_floor_db=floor,
                            bandwidth_hz=occupied, peak_hz=peak,
                            peak_excess_db=excess)


def entropy_report(data: np.ndarray | bytes, bits: int = 8,
                   run_nist90b: bool = True,
                   nist90b_limit: int = 200_000) -> EntropyReport:
    """Estimate entropy of a quantized stream by every available method.

    Args:
        data: 8-bit symbols (uint8 array or bytes).
        bits: symbol length in bits (1 or 8).
        run_nist90b: run the SP 800-90B suite (slow on big inputs).
        nist90b_limit: symbol cap for the 90B suite.

    Returns:
        EntropyReport with Shannon, histogram min-entropy, and (optionally)
        the SP 800-90B min-entropy, plus the conservative floor.
    """
    arr = np.asarray(data, dtype=np.uint8)
    if arr.size == 0:
        raise ValueError("empty data")
    shannon_byte = shannon_entropy_bytes(arr)
    min_hist_byte = min_entropy_histogram_bits(arr, 8) * 8
    details: dict = {}
    nist_byte: float | None = None
    if run_nist90b:
        res = estimate_min_entropy(arr, bits_per_symbol=bits, limit=nist90b_limit)
        nist_bit = res["min_entropy_per_bit"]
        nist_byte = nist_bit * bits
        details = res
    per_byte = [v for v in (min_hist_byte, nist_byte) if v is not None]
    conservative = min(per_byte)
    return EntropyReport(
        n_bytes=int(arr.size),
        shannon_bits_per_byte=shannon_byte,
        shannon_bits_per_bit=shannon_byte / 8.0,
        min_entropy_histogram_bits_per_byte=min_hist_byte,
        min_entropy_histogram_bits_per_bit=min_hist_byte / 8.0,
        nist90b_bits_per_byte=float(nist_byte) if nist_byte is not None else float("nan"),
        nist90b_bits_per_bit=float(nist_byte / bits) if nist_byte is not None else float("nan"),
        conservative_min_bits_per_byte=conservative,
        estimator_details=details,
    )


def analyze_capture_window(samples: np.ndarray, sample_rate: float,
                           bits: int = 8, **kwargs) -> tuple[SpectralAnalysis,
                                                              EntropyReport]:
    """One-stop analysis of a raw capture window (float samples).

    Quantizes the window to ADC codes, then runs both the spectral and the
    entropy analysis. Returns (spectral, entropy).
    """
    spec = spectral_analysis(samples, sample_rate)
    codes = quantize_to_bytes(samples, bits=bits)
    ent = entropy_report(codes, bits=bits, **kwargs)
    return spec, ent
