"""NIST SP 800-90B entropy estimators (Section 6.3, non-IID track).

Implements the ten min-entropy estimators from NIST SP 800-90B
(Turan et al., 2018): Most Common Value, Collision, Markov, Compression,
t-Tuple, Longest Repeated Substring (LRS), LZ78Y, Multi Most Common Value
(MultiMCW), Lag Prediction and MultiMMC Prediction, following the reference
formulas used by the NIST Entropy Assessment C++ package and its published
Python port (dj-on-github/SP800_90b_tests). See docs/nist800_90b.md for
derivation, notes and validation results.

Conventions: symbols are L-bit values; every estimator returns min-entropy
**per bit** (per-symbol estimate divided by symbol length). Binary-only
estimators (collision, markov, compression) are defined for 1-bit symbols.
"""

from __future__ import annotations

import heapq
import math
from collections import deque
from typing import Optional

import numpy as np

# ---------------------------------------------------------------------------
# Shared probability machinery (reference formulas).
# ---------------------------------------------------------------------------


def _upper_incomplete_gamma_3(z: float) -> float:
    """Gamma(3, z) = integral_z^inf t^2 e^-t dt, closed form for k=3."""
    return math.exp(-z) * (z * z + 2.0 * z + 2.0)


def _pq_func(p: float) -> float:
    """Expected collision distance E[T] for a binary source with P(1)=p.

    Used by the reference 90B toolchain to map the observed mean collision
    distance x_bar' to a probability. Decreasing on [0.5, 1]: pq(0.5) = 2.5
    (maximally random), pq(1) = 2 (deterministic).
    """
    q = 1.0 - p
    if q <= 0.0:
        return 2.0
    # Closed form of the reference formula (SP 800-90B 6.3.3): substituting
    # Gamma(3, z)*exp(z)/z^3 = (z^2 + 2z + 2)/z^3 with z = 1/(1-p) collapses
    # the cancelling pair of terms to 2 + 2q - 2q^2. The naive math.exp(z)
    # form overflows for p > 1 - 1/709 and loses ~9 digits to cancellation
    # before that (constant streams drive the binary search to p ~ 0.999).
    # Verified: pq(0.5) = 2.5, pq(1) = 2, monotone decreasing on [0.5, 1].
    return 2.0 + 2.0 * q - 2.0 * q * q


def _pfunc(p: float, r: int, n: int) -> float:
    """P(a run of >= r correct predictions occurs) for P(correct)=p.

    Equation (6.3.x) of SP 800-90B as used by the reference code; the binary
    search target is 0.99 (probability 'unlikely' to be exceeded by chance).
    """
    p = float(p)
    q = 1.0 - p
    x = 0.0
    for _ in range(10):
        x = 1.0 + q * (p ** r) * (x ** (r + 1.0))
    result = (1.0 - p * x) / ((r + 1.0 - r * x) * q)
    try:
        result = result / (x ** (n + 1))
    except OverflowError:
        result = 0.0
    if not (0.0 <= result <= 1.0):  # NaN / divergence guard
        result = 0.0
    return result


def _search_for_p(r: int, n: int) -> float:
    """Binary search on [0, 1] for p with _pfunc(p, r, n) = 0.99."""
    lo, hi = 0.0, 1.0
    p = 0.0
    for _ in range(1000):
        mid = (lo + hi) / 2.0
        cand = _pfunc(mid, r, n)
        if 0.99 - 1e-9 < cand < 0.99 + 1e-9:
            return mid
        if cand > 0.99:
            lo = mid
        else:
            hi = mid
        p = mid
    return p


def _conf_upper(p_hat: float, n: int) -> float:
    """2.576-sigma upper confidence bound on a probability estimate."""
    if p_hat <= 0.0:
        return 0.0
    return p_hat + 2.576 * math.sqrt((p_hat * (1.0 - p_hat)) / max(1, n - 1))


def _clamp_pu(p: float) -> float:
    return min(1.0, max(0.0, p))


def _prob_to_min_entropy(pu: float, bits_per_symbol: int) -> float:
    return max(0.0, min(1.0, -math.log2(pu) / bits_per_symbol))


def _longest_run(flags: np.ndarray) -> int:
    """Length of the longest run of True values."""
    run = best = 0
    for ok in flags:
        run = run + 1 if ok else 0
        if run > best:
            best = run
    return best


def _prediction_pu(p_global: float, n_pred: int, r: int,
                   bits_per_symbol: int, p0_fallback: float) -> float:
    """Combine global success rate and run length into the p_u bound used by
    the four prediction-based estimators (6.3.4/6.3.8/6.3.9/6.3.10)."""
    if p_global == 0.0:
        p_prime = 1.0 - p0_fallback ** (1.0 / n_pred)
    else:
        p_prime = _clamp_pu(_conf_upper(p_global, n_pred))
    p_local = _search_for_p(r, n_pred)
    return max(p_prime, p_local, 1.0 / (2 ** bits_per_symbol))


# ---------------------------------------------------------------------------
# Estimators. All take symbols: np.ndarray of symbol values.
# ---------------------------------------------------------------------------


def mcv(symbols: np.ndarray, bits_per_symbol: int) -> float:
    """6.3.1 Most Common Value."""
    n = symbols.size
    if n < 2:
        return 0.0
    counts = np.bincount(symbols.astype(np.int64), minlength=0)
    p_hat = float(counts.max()) / n
    pu = _clamp_pu(p_hat + 2.576 * math.sqrt(p_hat * (1.0 - p_hat) / (n - 1.0)))
    return _prob_to_min_entropy(pu, bits_per_symbol)


def collision(bits: np.ndarray) -> float:
    """6.3.3 Collision test (binary)."""
    n = bits.size
    if n < 3:
        return 1.0
    t_vals: list[int] = []
    i = 1  # 1-based, per reference algorithm
    while i <= n - 2:
        if bits[i - 1] == bits[i]:
            j = i + 1
        else:
            j = i + 2
        t_vals.append(j - i + 1)
        i = j + 1
    v = len(t_vals)
    x_bar = float(sum(t_vals)) / v
    sq = sum((t - x_bar) ** 2 for t in t_vals)
    sigma_hat = math.sqrt(sq / (v - 1.0)) if v > 1 else 0.0
    x_bar_prime = x_bar - 2.576 * (sigma_hat / math.sqrt(v))
    # pq is decreasing on [0.5, 1]: larger x_bar' (fewer collisions) -> p -> 0.5.
    lo, hi = 0.5, 1.0
    p = 0.5
    for _ in range(1000):
        mid = (lo + hi) / 2.0
        cand = _pq_func(mid)
        if abs(cand - x_bar_prime) < 1e-10:
            p = mid
            break
        if cand > x_bar_prime:
            lo = mid
        else:
            hi = mid
        p = mid
    if p < 0.5:
        p = 1.0 - p
    return _prob_to_min_entropy(p, 1)


def markov(bits: np.ndarray) -> float:
    """6.3.5 Markov test (binary)."""
    n = bits.size
    if n < 2:
        return 1.0
    b = bits.astype(np.int64)
    p0 = float(np.count_nonzero(b == 0)) / n
    p1 = 1.0 - p0
    c00 = int(np.count_nonzero((b[:-1] == 0) & (b[1:] == 0)))
    c01 = int(np.count_nonzero((b[:-1] == 0) & (b[1:] == 1)))
    c10 = int(np.count_nonzero((b[:-1] == 1) & (b[1:] == 0)))
    c11 = int(np.count_nonzero((b[:-1] == 1) & (b[1:] == 1)))
    s0 = c00 + c01
    s1 = c10 + c11
    p00 = c00 / s0 if s0 else 0.0
    p01 = c01 / s0 if s0 else 0.0
    p10 = c10 / s1 if s1 else 0.0
    p11 = c11 / s1 if s1 else 0.0
    p_seq = [
        p0 * p00 ** 127,
        p0 * p01 ** 64 * p10 ** 63,
        p0 * p01 * p11 ** 126,
        p1 * p10 * p00 ** 126,
        p1 * p10 ** 64 * p01 ** 63,
        p1 * p11 ** 127,
    ]
    p_max = max(p_seq)
    if p_max <= 0.0:
        return 1.0
    return _prob_to_min_entropy(p_max, 128)  # per 128-symbol sequence


def compression(bits: np.ndarray, d: int = 1000) -> float:
    """6.3.6 Compression test (binary; Maurer-style dictionary distance)."""
    b = 6
    n = bits.size
    blocks = n // b
    if blocks <= d + 1:
        return 1.0  # insufficient data
    s_prime = np.packbits(bits[: blocks * b].reshape(-1, 6), axis=1).reshape(-1) >> (8 - b)
    s_prime = [int(v) for v in s_prime]
    v = blocks - d
    dictionary = [0] * (2 ** b + 1)
    for i in range(d):
        dictionary[s_prime[i]] = i + 1  # 1-based positions
    dist = np.zeros(v, dtype=np.float64)
    for i in range(d, blocks):
        val = s_prime[i]
        if dictionary[val] != 0:
            dist[i - d] = (i + 1) - dictionary[val]
            dictionary[val] = i + 1
        else:
            dictionary[val] = i + 1
            dist[i - d] = i + 1
    dlog = np.log2(np.maximum(dist, 1.0))
    x_bar = float(dlog.mean())
    sigma_hat = 0.5907 * math.sqrt(max(0.0, float((dlog ** 2).mean()) - x_bar ** 2))
    x_bar_prime = x_bar - (2.576 * sigma_hat) / math.sqrt(v)
    # Reference ranges (SP 800-90B 6.3.6 / NIST ea_non_iid C++, as ported in
    # dj-on-github/SP800_90b_tests):
    #   term 1: u = 1..v,        weight v,       factor z^2  (u1)
    #   term 2: u = d+1..d+v-1,  weights v-1..1, factor z^2  (coeff . s2[:v-1])
    #   term 3: u = d+1..d+v,    weight 1,       factor z    (s2)
    # The first series runs over 1..v — NOT 1..d. Truncating u1 at d dropped
    # the geometric tail and biased the min-entropy estimate low <0.9/bit on
    # random streams (Flaky suite failure).
    u1 = np.arange(1, v + 1, dtype=np.float64)
    u2 = np.arange(d + 1, v + d + 1, dtype=np.float64)
    coeff = np.arange(v - 1, 0, -1, dtype=np.float64)

    def g(z: float) -> float:
        s1 = np.log2(u1) * ((1.0 - z) ** (u1 - 1.0))
        s2 = np.log2(u2) * ((1.0 - z) ** (u2 - 1.0))
        return (v * z * z * s1.sum()
                + z * z * float(np.dot(coeff, s2[:v - 1]))
                + z * float(s2.sum())) / v

    lo, hi = 2.0 ** -b, 1.0
    p = lo
    for _ in range(200):
        mid = (lo + hi) / 2.0
        q = (1.0 - mid) / (2.0 ** b - 1.0)
        cand = g(mid) + (2.0 ** b - 1.0) * g(q)
        if abs(cand - x_bar_prime) < 1e-9:
            p = mid
            break
        if cand > x_bar_prime:
            lo = mid
        else:
            hi = mid
        p = mid
    return _prob_to_min_entropy(p, b)


def _max_tuple_count(symbols: np.ndarray, t: int, bits_per_symbol: int) -> int:
    """Max occurrence count of any t-tuple in `symbols`.

    Uses a sliding integer key when the tuple fits in 62 bits (O(1) per
    position), byte-string keys otherwise.
    """
    n = symbols.size
    if t > n:
        return 0
    b = bits_per_symbol
    if t * b <= 62:
        mask = (1 << (t * b)) - 1
        counts: dict[int, int] = {}
        key = 0
        for i in range(n):
            key = ((key << b) | int(symbols[i])) & mask
            if i >= t - 1:
                counts[key] = counts.get(key, 0) + 1
        return max(counts.values())
    raw = symbols.tobytes()
    counts = {}
    for i in range(n - t + 1):
        key = raw[i:i + t]
        counts[key] = counts.get(key, 0) + 1
    return max(counts.values())


def t_tuple(symbols: np.ndarray, bits_per_symbol: int, threshold: int = 35,
            max_t: int = 62) -> float:
    """6.3.7 t-Tuple test."""
    n = symbols.size
    if n < threshold:
        return 1.0
    t_max = 0
    for t in range(1, min(n, max_t) + 1):
        if _max_tuple_count(symbols, t, bits_per_symbol) >= threshold:
            t_max = t
        else:
            break
    if t_max < 1:
        t_max = 1
    p_max = 0.0
    for i in range(1, t_max + 1):
        qi = _max_tuple_count(symbols, i, bits_per_symbol)
        pi = qi / (n - i + 1.0)
        p_max = max(p_max, pi ** (1.0 / i))
    pu = _clamp_pu(_conf_upper(p_max, n))
    return _prob_to_min_entropy(pu, bits_per_symbol)


def lrs(symbols: np.ndarray, bits_per_symbol: int, threshold: int = 35,
        max_v: int = 62) -> float:
    """6.3.9 Longest Repeated Substring test."""
    n = symbols.size
    if n < threshold:
        return 1.0
    # u: smallest tuple length with max count < threshold.
    u = 1
    while u < min(n, max_v):
        if _max_tuple_count(symbols, u, bits_per_symbol) < threshold:
            break
        u += 1
    # v: smallest tuple length with max count == 1 (all tuples unique).
    v = u
    while v < min(n, max_v):
        if _max_tuple_count(symbols, v, bits_per_symbol) == 1:
            break
        v += 1
    p_max = 0.0
    for w in range(u, v + 1):
        b = bits_per_symbol
        counts: dict[int, int] = {}
        mask = (1 << (w * b)) - 1 if w * b <= 62 else 0
        if w * b <= 62:
            key = 0
            for i in range(n):
                key = ((key << b) | int(symbols[i])) & mask
                if i >= w - 1:
                    counts[key] = counts.get(key, 0) + 1
        else:
            raw = symbols.tobytes()
            counts = {}
            for i in range(n - w + 1):
                key = raw[i:i + w]
                counts[key] = counts.get(key, 0) + 1
        total = sum(1 if c == 2 else 3 if c == 3 else c * (c - 1) // 2
                    for c in counts.values() if c >= 2)
        pairs = (n - w + 1) * (n - w) / 2.0
        if pairs > 0:
            p_max = max(p_max, (total / pairs) ** (1.0 / w))
    pu = _clamp_pu(_conf_upper(p_max, n))
    return _prob_to_min_entropy(pu, bits_per_symbol)


def lz78y(symbols: np.ndarray, bits_per_symbol: int, b: int = 16) -> float:
    """6.3.8 LZ78Y dictionary prediction test.

    Context indexing follows the reference port (1-based): at step i the
    dictionary counts (context = symbols[i-j-1 .. i-2], next = symbols[i-1])
    pairs and predicts symbols[i] from contexts ending at i-1.
    """
    n = symbols.size
    if n <= b + 2:
        return 1.0
    n_pred = n - b - 1
    s = symbols.astype(np.uint8)
    max_dict = 65536
    d: dict[bytes, dict[int, int]] = {}
    dict_size = 0
    correct = np.zeros(n_pred, dtype=bool)
    for i in range(b + 2, n + 1):  # 1-based
        for j in range(b, 0, -1):
            ctx = s[i - j - 2:i - 2].tobytes()
            nxt = int(s[i - 2])
            sub = d.get(ctx)
            if sub is None:
                if dict_size < max_dict:
                    d[ctx] = {nxt: 1}
                    dict_size += 1
                continue
            sub[nxt] = sub.get(nxt, 0) + 1
        prediction: Optional[int] = None
        best_count = 0
        for j in range(b, 0, -1):
            ctx = s[i - j - 1:i - 1].tobytes()
            sub = d.get(ctx)
            if sub is None:
                continue
            y = max(sub, key=lambda k: (sub[k], k))
            if sub[y] > best_count:
                best_count = sub[y]
                prediction = y
        if prediction is not None and prediction == int(s[i - 1]):
            correct[i - b - 2] = True
    c = int(correct.sum())
    p_global = c / n_pred
    r = _longest_run(correct) + 1
    pu = _prediction_pu(p_global, n_pred, r, bits_per_symbol, p0_fallback=0.001)
    return _prob_to_min_entropy(pu, bits_per_symbol)


class _SlidingMostFrequent:
    """Most frequent symbol in a sliding window, ties broken by recency.

    Lazy max-heap of (-count, -last_seen, symbol): O(log d) per update where
    d is the number of distinct symbols currently in the window.

    NOTE: the queue must be plain (no maxlen) — eviction is done manually
    here so the evicted symbol's count is decremented. A ``deque(maxlen=size)``
    evicts silently on append, leaving stale counts that corrupt `top()`.
    """

    __slots__ = ("window", "counts", "last_seen", "heap", "size")

    def __init__(self, size: int) -> None:
        self.window: deque[int] = deque()
        self.counts: dict[int, int] = {}
        self.last_seen: dict[int, int] = {}
        self.heap: list[tuple[int, int, int]] = []
        self.size = size

    def push(self, sym: int, pos: int) -> None:
        if len(self.window) == self.size:
            old = self.window.popleft()
            c = self.counts.get(old, 0) - 1
            if c <= 0:
                self.counts.pop(old, None)
            else:
                self.counts[old] = c
        self.window.append(sym)
        self.counts[sym] = self.counts.get(sym, 0) + 1
        self.last_seen[sym] = pos
        heapq.heappush(self.heap, (-self.counts[sym], -pos, sym))

    def top(self) -> Optional[int]:
        while self.heap:
            neg_c, neg_pos, sym = self.heap[0]
            if (self.counts.get(sym) == -neg_c
                    and self.last_seen.get(sym) == -neg_pos):
                return sym
            heapq.heappop(self.heap)
        return None


def multi_mcw(symbols: np.ndarray, bits_per_symbol: int) -> float:
    """6.3.4 Multi Most Common Value (partial collection) test.

    Window sizes are powers of two up to min(4096, n//2) (the official
    parameter set). Predictions start once the largest window is full.
    """
    n = symbols.size
    if n < 4:
        return 1.0
    max_win = min(4096, max(2, n // 2))
    wins: list[int] = []
    w = 1
    while w <= max_win:
        wins.append(w)
        w *= 2
    n_pred = n - max_win - 1
    if n_pred <= 0:
        return 1.0
    trackers = [_SlidingMostFrequent(w) for w in wins]
    for t in trackers:
        t.push(int(symbols[0]), 0)
    scoreboard = [0] * len(wins)
    winner = 0
    correct = np.zeros(n_pred, dtype=bool)
    for i in range(1, n):
        mfs = [t.top() for t in trackers]
        prediction = mfs[winner]
        if prediction is not None and prediction == int(symbols[i]):
            idx = i - max_win - 1
            if 0 <= idx < n_pred:
                correct[idx] = True
        for j, t in enumerate(trackers):
            if t.top() == int(symbols[i]):
                scoreboard[j] += 1
                if scoreboard[j] >= scoreboard[winner]:
                    winner = j
        for t in trackers:
            t.push(int(symbols[i]), i)
    c = int(correct.sum())
    p_global = c / n_pred
    r = _longest_run(correct) + 1
    pu = _prediction_pu(p_global, n_pred, r, bits_per_symbol, p0_fallback=0.01)
    return _prob_to_min_entropy(pu, bits_per_symbol)


def lag_prediction(symbols: np.ndarray, bits_per_symbol: int, d: int = 128) -> float:
    """6.3.10 Lag Prediction test (vectorized).

    scoreboard[k] = number of matches at lag k seen so far; the winner lag is
    the one with the largest scoreboard, ties broken toward the largest lag.
    Since packed = count*(d+1) + lag orders exactly by (count, lag), a single
    maximum-scan over the packed values reproduces the sequential winner
    trajectory.
    """
    n = symbols.size
    if n < 3:
        return 1.0
    d = min(d, n - 1)
    s = symbols.astype(np.int64)
    packed = np.zeros(n, dtype=np.int64)
    for k in range(1, d + 1):
        matches = s[k:] == s[:-k]
        counts = np.cumsum(matches, dtype=np.int64)
        window = counts[:n - k - 1] * (d + 1) + k
        np.maximum(packed[k + 1:], window, out=packed[k + 1:])
    winner = np.maximum(1, packed[1:] % (d + 1)).astype(np.int64)
    idx = np.arange(1, n) - winner
    valid = idx >= 0
    correct = np.zeros(n - 1, dtype=bool)
    safe = idx[valid]
    correct[valid] = s[safe] == s[np.arange(1, n)[valid]]
    n_pred = n - 1
    c = int(correct.sum())
    p_global = c / n_pred
    r = _longest_run(correct) + 1
    pu = _prediction_pu(p_global, n_pred, r, bits_per_symbol, p0_fallback=0.01)
    return _prob_to_min_entropy(pu, bits_per_symbol)


def multi_mmc_prediction(symbols: np.ndarray, bits_per_symbol: int,
                         d: int = 16, max_entries: int = 50000) -> float:
    """6.3.9 MultiMMC Prediction test (order-d context models).

    For each context length k the model stores counts of (context, next)
    pairs; the predictor for length k is the symbol most often seen after the
    current k-symbol context (ties -> larger symbol), and the winning context
    length adapts via scoreboard. (The published Python port's update is
    context-blind; this follows the spec's described intent.)
    """
    n = symbols.size
    if n < 3:
        return 1.0
    d = min(d, n - 2)
    n_pred = n - 2
    models: list[dict[bytes, dict[int, int]]] = [{} for _ in range(d + 1)]
    entries = [0] * (d + 1)
    scoreboard = [0] * (d + 1)
    winner = 1
    s = symbols.astype(np.uint8)
    subpredict: list[Optional[int]] = [None] * (d + 1)
    correct = np.zeros(n_pred, dtype=bool)
    for i in range(2, n):
        for k in range(1, d + 1):
            if k < i - 1:
                ctx = s[i - k - 2:i - 2].tobytes()
                y = int(s[i - 2])
                m = models[k]
                sub = m.get(ctx)
                if sub is None:
                    if entries[k] < max_entries:
                        m[ctx] = {y: 1}
                        entries[k] += 1
                else:
                    sub[y] = sub.get(y, 0) + 1
        for k in range(1, d + 1):
            if k < i - 1:
                ctx = s[i - k - 1:i - 1].tobytes()
                m = models[k]
                sub = m.get(ctx)
                subpredict[k] = max(sub, key=lambda y: (sub[y], y)) if sub else None
            else:
                subpredict[k] = None
        if subpredict[winner] is not None and subpredict[winner] == int(s[i - 1]):
            correct[i - 2] = True
        for k in range(1, d + 1):
            if subpredict[k] == int(s[i - 1]):
                scoreboard[k] += 1
                if scoreboard[k] >= scoreboard[winner]:
                    winner = k
    c = int(correct.sum())
    p_global = c / n_pred
    r = _longest_run(correct) + 1
    pu = _prediction_pu(p_global, n_pred, r, bits_per_symbol, p0_fallback=0.001)
    return _prob_to_min_entropy(pu, bits_per_symbol)


# ---------------------------------------------------------------------------
# Public entry point.
# ---------------------------------------------------------------------------

BINARY_ESTIMATORS = ("collision", "markov", "compression")
SYMBOL_ESTIMATORS = ("mcv", "t_tuple", "lrs", "lz78y", "multi_mcw",
                     "lag_prediction", "multi_mmc_prediction")


def estimate_min_entropy(data: bytes | np.ndarray, bits_per_symbol: int = 8,
                         limit: int = 1_000_000) -> dict:
    """Run the full SP 800-90B suite and return per-bit min-entropy results.

    Args:
        data: raw bytes (or uint8 array) captured from a noise source.
        bits_per_symbol: symbol length in bits (1 or 8 supported).
        limit: maximum number of symbols to analyse. NIST recommends
            >= 1M samples; the cap keeps runtime sane on a laptop.

    Returns:
        dict with 'estimators' {name: entropy_per_bit}, 'min_entropy_per_bit',
        'n_symbols', 'bits_per_symbol'.
    """
    if bits_per_symbol == 1:
        if isinstance(data, (bytes, bytearray, memoryview)):
            # Packed byte stream: each byte carries 8 bits.
            symbols = np.unpackbits(np.frombuffer(bytes(data), dtype=np.uint8))
        else:
            # Already a 0/1 array of bit symbols — use directly. (Passing raw
            # bytes through `bytes(arr)` would re-encode each 0/1 element as a
            # full byte and double-unpack it into 8 bits, corrupting the stream.)
            symbols = np.asarray(data, dtype=np.uint8)
            if symbols.size and symbols.max() > 1:
                raise ValueError(
                    "bits_per_symbol=1 with an array requires 0/1 bit symbols "
                    "(pass packed bytes instead)")
    elif bits_per_symbol == 8:
        if isinstance(data, (bytes, bytearray, memoryview)):
            symbols = np.frombuffer(bytes(data), dtype=np.uint8)
        else:
            symbols = np.asarray(data, dtype=np.uint8)
    else:
        raise ValueError("bits_per_symbol must be 1 or 8")
    if symbols.size == 0:
        raise ValueError("empty data")
    if symbols.size > limit:
        symbols = symbols[:limit]
    results: dict[str, float] = {}
    if bits_per_symbol == 1:
        results["collision"] = collision(symbols)
        results["markov"] = markov(symbols)
        results["compression"] = compression(symbols)
    results["mcv"] = mcv(symbols, bits_per_symbol)
    results["t_tuple"] = t_tuple(symbols, bits_per_symbol)
    results["lrs"] = lrs(symbols, bits_per_symbol)
    results["lz78y"] = lz78y(symbols, bits_per_symbol)
    results["multi_mcw"] = multi_mcw(symbols, bits_per_symbol)
    results["lag_prediction"] = lag_prediction(symbols, bits_per_symbol)
    results["multi_mmc_prediction"] = multi_mmc_prediction(symbols, bits_per_symbol)
    results = {k: float(max(0.0, min(1.0, v))) for k, v in results.items()}
    return {
        "estimators": results,
        "min_entropy_per_bit": min(results.values()),
        "n_symbols": int(symbols.size),
        "bits_per_symbol": int(bits_per_symbol),
    }
