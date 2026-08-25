# PROJECT STATUS — Planetary Entropy Mining
> Handoff document. Updated: 2026-07-31 (after NIST 90B debug session).

---

## 1. State of the project

**P0 (MVP) core is complete and green.** The NIST SP 800-90B suite was found
failing during the last session; **three issues were root-caused, fixed and
documented** (see §4). The default test suite is `93/93` passing.

Deliverable ordering per `AGENTS.md` / `DEVELOPMENT_PLAN.md`:

| # | Item | Status | Location |
|---|------|--------|----------|
| 1 | Repo bootstrap (pyproject, pytest, scripts) | ✅ done | `pyproject.toml`, `scripts/test.ps1` |
| 2 | Entropy capture sim (thermal/RF/seismic, deterministic) | ✅ done | `dsp/capture.py` |
| 3 | Signal processing & entropy estimators | ✅ done | `dsp/analysis.py`, `dsp/nist800_90b.py` |
| 4 | Entropy validation vs ground truth | ✅ done | `dsp/validation.py`, `docs/entropy_validation_report.md` |
| 5 | Hardening (GF(256) polynomial commitment) | ✅ done | `hardening/` |
| 6 | Deterministic nullifier (per node/window) | ✅ done | `identity/nullifier.py` |
| 7 | Certificate schema (versioned, signed) | ✅ done | `identity/certificate.py` |
| 8 | Toy zk circuit (circom + snarkjs) | ✅ done (P0 capstone = **toy**) | `circuits/` |
| 9 | **Erasure coding (Reed-Solomon n/k)** | ❌ **TODO** | — |
| 10 | **Sphinx-style onion framing (X25519+AES-GCM)** | ❌ **TODO** | — |
| 11 | **DTN mesh simulation** | ❌ **TODO** | — |
| 12 | **Dark pool SMPC matching sim** | ❌ **TODO** | — |
| 13 | **Solidity settlement contracts (Foundry)** | ❌ **TODO** | — |
| 14 | **e2e demo: capture→harden→prove→onion→shard→ship→match→settle** | 🔶 partial | `cli/demo.py` (P0 chain only) |
| 15 | Dashboard | ❌ optional (P2) | — |

**Overall: ~60%** — all P0 engineering is done and verified; P1/P2 are the
remaining work. Nothing in the repo requires hardware; everything is simulated
with deterministic seeds.

---

## 2. How to run

```powershell
# Full default test suite (fast — excludes the 1M-bit slow tier)
py -m pytest -q

# Slow tier (NIST recommended sizes: 200k symbols / 1M bits; takes minutes)
py -m pytest -m slow -q

# Everything (fast + slow)
py -m pytest -m "" -q

# One-command local verification (tests + validation report + demo)
powershell -File scripts/test.ps1

# P0 end-to-end demo (Python-only, skips JS zk)
py -m cli.demo --quick

# Full demo incl. circom/snarkjs toy proof (after `cd circuits && npm install`)
py -m cli.demo

# Entropy validation report (writes docs/entropy_validation_report.md)
py -m cli.validate
```

Environment notes:
- Windows, `py` launcher (plain `python` is the MS Store alias and does not work).
- NumPy ≥ 1.26; Python ≥ 3.11.
- `circuits/` needs `npm install` for the zk stage; `--quick` skips it.

---

## 3. Repository map

```
dsp/          capture sim, analysis, NIST SP 800-90B estimators, validation
hardening/    GF(256) + polynomial commitment (HardenConfig, HardenedEntropy)
identity/     nullifier (HMAC-BLAKE2b) + signed certificate schema
circuits/     circom toy entropy-audit circuit + snarkjs prove/verify script
cli/          validate.py (entropy report), demo.py (P0 e2e)
tests/        pytest suite (one file per module)
docs/         nist800_90b.md, entropy_validation_report.md, PROJECT_STATUS.md
scripts/      test.ps1 (one-command CI-ish local run)
```

---

## 4. Last session: what was wrong and what was fixed

The NIST 90B test suite was failing. Three issues were root-caused and fixed
(details in `docs/nist800_90b.md`, findings 4–6):

1. **`_SlidingMostFrequent` eviction corruption (MultiMCW, §6.3.4)**
   - `deque(maxlen=size)` evicted silently on append → the manual `popleft`
     was dead code → evicted symbols' counts never decremented → wrong modes.
   - `multi_mcw` scored 0.756 on random data instead of ≈1.0.
   - **Fix:** unbounded deque, explicit evict-before-append. Now 0.983; a burst
     test `[A,A,A,B,B]` in a size-3 window correctly returns B.

2. **`estimate_min_entropy` double-unpacked 1-bit arrays**
   - `bytes(arr)` on a 0/1 ndarray encoded each bit as a full byte, then
     `np.unpackbits` expanded it ×8 → 200k random bits became 1.6M bits of
     `00000000`/`10000000` groups → aggregate min-entropy collapsed to 0.033
     (every individual estimator was healthy).
   - **Fix:** 1-bit arrays are used directly; arrays containing values > 1 now
     raise `ValueError`. Packed-bytes input still uses `unpackbits`.
   - Regression guard: 60-symbol input must report `n_symbols == 60`, not 480.

3. **`compression` slow-tier bound calibrated (NIST §6.3.6)**
   - Verified our `G()` is numerically identical to the official
     `dj-on-github/SP800_90b_tests` reference (|Δ| ≤ 1e-16) and returns the
     same value (0.8605 = 0.8605) on the failing seed.
   - NIST's 6-bit Maurer test is inherently conservative: 0.856–0.903 on 1M
     random bits across six seeds.
   - **Fix:** slow-tier floor for `compression` = 0.85 (collision/markov keep
     0.9). `BINARY_SLOW_FLOOR` in `tests/test_nist800_90b.py`.

---

## 5. What has to be done next (items 9–15)

Follow `AGENTS.md` build order. Each item = **code + tests + runnable demo**,
tests first, deterministic seeds, document in `docs/`.

### 9. Erasure coding — `erasure/` (P1)
- Reed-Solomon n/k sharding. Reuse `hardening/gf256.py` (generator 3, AES
  polynomial 0x11B) — do NOT write a second GF implementation.
- API sketch: `encode(data: bytes, k: int, n: int) -> list[Shard]`,
  `decode(shards, k) -> bytes` (reconstruct from any k of n).
- Tests: encode→corrupt→decode round-trip; fewer than k shards fails;
  deterministic output for identical input.

### 10. Sphinx-style onion framing — `net/sphinx.py` (P1)
- Layered X25519 + AES-GCM over a **fixed 3-hop route** (simulated; no real
  sockets), per-hop mixing of sender/receiver identity.
- API sketch: `create_route(n_hops)`, `wrap(payload, route) -> packet`,
  `unwrap(packet, hop_key, hop_index)`.
- Tests: 3-hop route end-to-end; wrong hop key fails; replay/order protection.

### 11. DTN mesh simulation — `net/dtn.py` (P1)
- Deterministic simulated nodes with intermittent links, store-and-forward
  bundles, delivery guarantees under link failures.
- API sketch: `Topology(nodes, links, failure_seed)`, `Bundle`,
  `Node.send/recv`, `simulate(steps) -> delivery_stats`.
- Tests: delivery under N link failures; no loops; deterministic across
  identical seeds.

### 12. Dark pool SMPC matching sim — `darkpool/` (P2)
- Shamir secret sharing + blind matching of bids/offers; prove no party learns
  the full order book.
- Tests: prices match only when a bid/offer cross; none learns the other's
  book; deterministic.

### 13. Settlement contracts — `contracts/` (P2)
- Solidity: proof verification + payment. Foundry tests (`forge test`).
- Needs a proof artifact contract interface compatible with the toy circuit
  output (see `circuits/`).

### 14. e2e demo (P1 capstone)
- Extend `cli/demo.py` (or add `cli/e2e.py`) to one command:
  `capture → harden → prove → onion → shard → ship → match → settle`.
- `scripts/test.ps1` already calls `py -m cli.demo --quick` — keep that green.

### 15. Dashboard (P2, optional)
- Plain HTML/JS or Vite+React to visualize certificates and matching.

### Cross-cutting
- After each item: `py -m pytest` green, short doc in `docs/`, scope
  guardrails respected (no hardware, no real money/keys, no mainnet).
- `docs/nist800_90b.md` references the reference port used for validation —
  keep that provenance note if new estimator work happens.

---

## 6. Gotchas for the next session

- **No git repo** — `git status` fails with "not a git repository". If version
  control is wanted, `git init` first (and add a proper `.gitignore` check —
  one exists but the repo was never initialized).
- **Plain `python` is broken** on this machine (MS Store alias) — always use
  `py`.
- The slow tier takes **minutes** (pure-Python estimator loops): run it in the
  background with `-m slow` separately from the fast default run.
- The reference implementations (`dj-on-github/SP800_90b_tests`) have their own
  bugs (e.g. `multi_mcw`'s `correct[i - w[1]]` array overflow at large sizes) —
  use them for formula cross-checks only, not as executable golds.
- Temp/scratch files were cleaned; `scripts/` currently holds only `test.ps1`.