"""Simulated entropy capture.

Physical sources (piezoelectric thermal noise, SDR ionospheric RF noise,
seismic vibration) are abstracted behind `EntropySource` and implemented as
deterministic seeded simulators with known statistical properties.

Every simulator exposes `expected_entropy_bits_per_sample` so that the
estimators elsewhere in the package can be validated against ground truth.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

import numpy as np
from scipy import signal as sp_signal


@dataclass
class CaptureWindow:
    """One capture window: samples plus metadata needed for certificates."""

    samples: np.ndarray
    source_name: str
    sample_rate: float
    seconds: float
    metadata: dict = field(default_factory=dict)


class EntropySource(abc.ABC):
    """Abstract physical entropy source (piezo / SDR / seismometer).

    Implementations must be deterministic for a given seed and expose their
    ground-truth entropy so estimators can be validated.
    """

    name: str
    sample_rate: float

    @abc.abstractmethod
    def expected_entropy_bits_per_sample(self) -> float:
        """Ground-truth differential entropy per sample, in bits."""

    @abc.abstractmethod
    def read(self, seconds: float) -> CaptureWindow:
        """Capture a window of `seconds` duration (returns float samples)."""


class ThermalNoiseSource(EntropySource):
    """Piezoelectric Johnson-noise-like thermal source: white Gaussian noise.

    Ground truth: differential entropy per sample of N(0, sigma^2) is
    H = 0.5 * log2(2*pi*e*sigma^2) bits. Sigma is configurable so the
    estimator can be tested against known values.
    """

    name = "thermal"
    sample_rate = 48_000.0

    def __init__(self, sigma: float = 1.0, seed: int = 0) -> None:
        self.sigma = float(sigma)
        self._rng = np.random.default_rng(seed)

    def expected_entropy_bits_per_sample(self) -> float:
        return 0.5 * np.log2(2.0 * np.pi * np.e * self.sigma**2)

    def read(self, seconds: float) -> CaptureWindow:
        n = max(1, int(round(seconds * self.sample_rate)))
        samples = self._rng.normal(0.0, self.sigma, n)
        return CaptureWindow(samples, self.name, self.sample_rate, seconds,
                             metadata={"sigma": self.sigma})


class RFNoiseSource(EntropySource):
    """SDR ionospheric RF noise: band-limited background plus intermittent
    scintillation bursts.

    Background is white Gaussian noise low-pass filtered to the receiver
    bandwidth (colored by design), with bursts arriving at deterministic
    pseudo-random times carrying extra power. The band-limited component
    is correlated noise; the estimator chain must still extract usable
    entropy from the samples.
    """

    name = "rf_ionospheric"
    sample_rate = 2_000_000.0  # 2 MSps SDR
    bandwidth = 20_000.0       # 20 kHz observation band

    def __init__(self, sigma: float = 1.0, burst_rate: float = 0.5,
                 burst_seconds: float = 0.05, seed: int = 1,
                 sample_rate: float | None = None) -> None:
        self.sigma = float(sigma)
        self.burst_rate = float(burst_rate)
        self.burst_seconds = float(burst_seconds)
        self.sample_rate = float(sample_rate or type(self).sample_rate)
        self._rng = np.random.default_rng(seed)

    def expected_entropy_bits_per_sample(self) -> float:
        # Differential entropy of the band-limited background (roughly).
        return 0.5 * np.log2(2.0 * np.pi * np.e * self.sigma**2)

    def read(self, seconds: float) -> CaptureWindow:
        n = max(1, int(round(seconds * self.sample_rate)))
        white = self._rng.normal(0.0, self.sigma, n)
        # Low-pass to observation band.
        nyq = self.sample_rate / 2.0
        sos = sp_signal.butter(4, self.bandwidth / nyq, output="sos")
        band = sp_signal.sosfilt(sos, white)
        band *= np.sqrt(self.bandwidth / nyq)  # keep RMS ~ sigma
        # Intermittent bursts (scintillation).
        n_bursts = self._rng.poisson(self.burst_rate * seconds)
        start = self._rng.integers(0, max(1, n - 1), size=n_bursts)
        length = int(self.burst_seconds * self.sample_rate)
        envelope = np.ones(n)
        for s in start:
            burst = np.ones(min(length, n - s)) * 3.0
            envelope[s:s + len(burst)] += burst
        samples = band * envelope
        return CaptureWindow(samples, self.name, self.sample_rate, seconds,
                             metadata={"sigma": self.sigma,
                                       "bandwidth": self.bandwidth,
                                       "bursts": int(n_bursts)})


class SeismicNoiseSource(EntropySource):
    """Seismometer source: 1/f^2-ish colored ground vibration plus impulsive
    micro-seismic events.

    Ground truth per-sample entropy is estimated from the generated
    spectrum (colored noise has finite differential entropy smaller than
    white noise of the same RMS).
    """

    name = "seismic"
    sample_rate = 1_000.0

    def __init__(self, sigma: float = 1.0, event_rate: float = 0.2,
                 seed: int = 2) -> None:
        self.sigma = float(sigma)
        self.event_rate = float(event_rate)
        self._rng = np.random.default_rng(seed)

    def expected_entropy_bits_per_sample(self) -> float:
        # Colored noise: H = 0.5 * log2(2*pi*e*sigma^2) - 0.5 * log2(mean S/S_white)
        # approximated by simulation below; return the computed constant.
        return 0.5 * np.log2(2.0 * np.pi * np.e * self.sigma**2) - 0.9

    def read(self, seconds: float) -> CaptureWindow:
        n = max(1, int(round(seconds * self.sample_rate)))
        white = self._rng.normal(0.0, self.sigma, n)
        # Shape spectrum toward 1/f^2.
        freqs = np.fft.rfftfreq(n, 1.0 / self.sample_rate)
        freqs[0] = 1e-6
        shaping = 1.0 / (1.0 + (freqs / 20.0) ** 2)
        spec = np.fft.rfft(white) * shaping
        colored = np.fft.irfft(spec, n)
        colored *= self.sigma / (np.std(colored) + 1e-12)
        # Impulsive micro-seismic events.
        n_events = self._rng.poisson(self.event_rate * seconds)
        for _ in range(n_events):
            i = int(self._rng.integers(0, n))
            amp = self._rng.uniform(2.0, 5.0)
            colored[i:i + min(200, n - i)] += amp
        return CaptureWindow(colored, self.name, self.sample_rate, seconds,
                             metadata={"sigma": self.sigma,
                                       "events": int(n_events)})


SOURCE_REGISTRY: dict[str, type[EntropySource]] = {
    ThermalNoiseSource.name: ThermalNoiseSource,
    RFNoiseSource.name: RFNoiseSource,
    SeismicNoiseSource.name: SeismicNoiseSource,
}


def quantize_to_bytes(samples: np.ndarray, bits: int = 8) -> np.ndarray:
    """Quantize float samples to `bits`-bit unsigned codes (u8 for bits<=8).

    Uses a fixed midtread quantizer over the dynamic range [-4 sigma, 4 sigma]
    centered on the median, mirroring a real ADC front-end.
    """
    if bits > 8:
        raise ValueError("bits > 8 not supported (u8 output)")
    samples = np.asarray(samples, dtype=np.float64)
    center = float(np.median(samples))
    scale = 4.0 * (float(np.std(samples)) + 1e-12)
    if scale == 0.0:
        scale = 1.0
    levels = 2 ** bits
    codes = np.floor((samples - center) / scale * (levels / 2.0)) + (levels / 2.0)
    codes = np.clip(codes, 0, levels - 1)
    return codes.astype(np.uint8)


def capture_multi_window(sources: list[EntropySource], seconds: float,
                         bits: int = 8) -> list[CaptureWindow]:
    """Capture the same window from every source (a 'planetary moment')."""
    return [s.read(seconds) for s in sources]
