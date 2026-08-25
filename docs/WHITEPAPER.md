# Planetary Entropy Mining — Technical Whitepaper

**Version 1.0 — 2026-07-31**

> **Abstract.** Planetary Entropy Mining is a verifiable-entropy infrastructure
> that converts environmental noise (thermal, ionospheric RF, seismic) into
> cryptographic certificates of "real physical activity at time T", transports
> them unlinkably through a delay-tolerant mesh, matches them blindly against
> emission-buying bids, and settles atomically against a proof-gated payment
> contract. This whitepaper specifies the complete protocol as implemented in
> the reference codebase (all-simulated, deterministic, laptop-runnable) and
> states the security properties each module actually proves.

---

## 1. Introduction

A carbon-credit-like token is only worth what its provenance can prove. Today,
emission certificates are issued by centralized registries; their audit trail
is paperwork. Planetary Entropy Mining attempts the inverse construction:
instead of trusting an issuer, ground every certificate in a *physical
measurement* that any verifier can check — a window of environmental noise so
entropy-rich that it cannot be precomputed, plus a zero-knowledge proof that
the measurement was honestly produced at the claimed time, without revealing
where the measuring node is.

The system is modular; each stage is a replaceable component with a precise
interface. The reference codebase implements every stage as a **deterministic
simulation** (no hardware, no sockets, no real money) so the protocol can be
specified, tested, and audited on a laptop. The cryptographic core — GF(256)
field arithmetic, X25519/AES-GCM onion layers, Shamir secret sharing — is
real; only the physical sources and the settlement ledger are simulated.

## 2. Threat model & design goals

### 2.1 Adversary

- **A-1 Curious mix node.** A node on the transport path tries to learn where
  a certificate came from or what it contains.
- **A-2 Double-miner.** A node tries to register the same physical signal
  twice, or relay another node's signal as its own.
- **A-3 Curious market participant.** A trader in the dark pool tries to learn
  the full order book (others' prices or quantities).
- **A-4 Double-spender / re-player.** A claimant tries to settle the same
  certificate twice against the settlement contract.
- **A-5 Network adversary.** Links are intermittent; some shards are lost,
  reordered, or corrupted. Delivery must still succeed when enough shards
  arrive intact.

### 2.2 Goals

| Goal | Mechanism | Where proven |
|------|-----------|--------------|
| Location-blind proof | zk-SNARK over hardened entropy + nullifier | `circuits/`, `identity/` |
| Anti-double-mining | deterministic per-node-per-window nullifier | `identity/nullifier.py` |
| Transport unlinkability | layered onion encryption with per-hop tag mixing | `net/sphinx.py` |
| Data-loss resilience | Reed-Solomon any-k-of-n sharding | `erasure/` |
| Intermittent-link delivery | DTN store-and-forward with TTL | `net/dtn.py` |
| Order-book privacy | Shamir share-only matching predicate | `net/darkpool.py` |
| Atomic settle + anti-double-spend | proof-gated payment contract, spent-nullifier set | `contracts/` |
| Verification without trust | every module ships pytest/Foundry tests | repository test suite |

### 2.3 Non-goals (explicit)

- Real hardware capture (piezo/SDR) — only seeded simulators with known
  statistical ground truth.
- Real network sockets — the DTN is an in-memory discrete-time simulation.
- Real financial settlement — the ledger is a deterministic in-memory model;
  the Solidity contract is the authoritative spec.
- Lattice assumption claims — "lattice-style" hardening here means a
  polynomial commitment over GF(256), not a post-quantum OWF.

## 3. System architecture

```
        physical reality (simulated): thermal / RF / seismic -> ADC (8-bit)
        capture window -> [2] entropy estimation (NIST SP 800-90B)
        -> [3] hardening (GF(256) polynomial commitment) -> [4] nullifier
        -> [5] certificate -> [6] zk-SNARK proof (toy) -> [7] onion wrap
        -> [8] RS shard (k/n) -> [9] DTN mesh delivery -> [10] reconstruct
        -> [11] unwrap -> [12] blind dark-pool match -> [13] atomic settle
```

## 4. Stage-by-stage specification

### 4.1 Entropy capture (simulated) — `dsp/capture.py`

Three sources implement the `EntropySource` interface; each is a seeded PRNG
with a **documented ground-truth entropy** so estimators can be validated:

| Source      | Model                          | Ground truth                              |
|-------------|--------------------------------|-------------------------------------------|
| `thermal`   | white Gaussian N(0, σ²)        | H = ½·log₂(2πeσ²) bits/sample             |
| `rf_ionospheric` | band-limited Gaussian + bursts | ½·log₂(2πeσ²) background (approx.)        |
| `seismic`   | 1/f² colored noise + impulses  | H = ½·log₂(2πeσ²) − 0.9 (approx.)         |

Quantization uses a fixed midtread 8-bit ADC model over ±4σ (dynamic range
centered on the median) — the exact output distribution is computable from
the normal CDF, giving a closed-form `true_quantized_gaussian_entropy` used
as the validation target (§4.2).

### 4.2 Entropy estimation — `dsp/analysis.py`, `dsp/nist800_90b.py`

For each quantized byte stream the estimator chain computes:

- **Shannon entropy** per byte from the empirical histogram.
- **Histogram min-entropy** = −log₂(p_max) per byte.
- **NIST SP 800-90B** min-entropy from all ten Section 6.3 estimators
  (MCV, collision, Markov, compression, t-tuple, LRS, LZ78Y, MultiMCW,
  Lag, MultiMMC), cross-checked numerically against the published reference
  port (|Δ| ≤ 1e-16 on the validated formulas).

The report's `conservative_min_bits_per_byte = min(histogram, 90B)` is the
floor a certificate uses. Validation asserts the ordering
`H_90B ≤ H_hist ≤ H_Shannon` and, for thermal, agreement with the exact
quantizer truth within tolerance. The port's historical bugs (`multi_mcw`
eviction, double-unpacking, compression floor calibration) were root-caused
and regression-tested; details in `docs/nist800_90b.md`.

### 4.3 Hardening — `hardening/`

Raw noise → a verifiable GF(256) polynomial artifact:

1. **Keyed extraction.** A BLAKE2b-based extractor maps the quantized stream
   to a 32-byte seed (keyed so simulator structure cannot leak in).
2. **Polynomial embedding.** The seed becomes the degree-31 coefficients of
   `p(x) = c0 + c1·x + ... + c31·x^31` over GF(256) (AES polynomial 0x11B,
   generator 3 — the standard AES table construction).
3. **Commitment.** The artifact stores 64 evaluations `p(a^i)` at distinct
   nonzero points (2× redundancy vs. 32 coefficients) plus an HMAC. Only the
   evaluations are stored — never the seed — so the artifact is a commitment
   to the hardened entropy.

`verify_hardening` recomputes evaluations from a candidate seed/raw and
checks the MAC. The 32-coefficient/64-point layout means any 33 evaluations
recover the polynomial — the same field machinery powers Reed-Solomon
sharding (§4.8), reusing one GF(256) implementation for the whole pipeline.

### 4.4 Nullifier — `identity/nullifier.py`

```
nullifier = HMAC-BLAKE2b(key = per-node secret,
                         msg = SHA-256(seed) || window_id)[:32]
```

Properties (tested):
- same node + same signal + same window → identical nullifier;
- different window → different nullifier (a window is mined once);
- different nodes → different nullifiers (no impersonation);
- nullifier hides the seed (keyed PRF), and the zk circuit (§4.6) commits to
  it, so it doubles as the anti-double-mining and the anti-double-spend
  witness.

### 4.5 Certificate — `identity/certificate.py`

Version-1 schema, canonical JSON (sorted keys, compact separators ⇒
byte-identical for identical inputs), HMAC-SHA256 signed over the body.
Fields: version, node_id, window_id, capture metadatum (source, sample rate,
seconds, bits, conservative min-entropy, entropy digest), hardened artifact,
nullifier. Verification checks the MAC and schema invariants.

### 4.6 zk-SNARK — `circuits/toy_entropy_audit.circom`

A Groth16 toy circuit over BN128 proving, in zero knowledge:

> "I know a hardened-entropy secret and a node secret whose Poseidon
> commitment equals the public nullifier for the valid window T."

- public: `window_id`, `nullifier` (output)
- private: `secret`, `node_secret` (the witness, never revealed)
- valid-window gate: `window_id == 42` (placeholder for the real
  "90B min-entropy ≥ threshold" constraint)

The real Groth16 pipeline (compile → witness → powers-of-tau with
deterministic beacon → phase-2 setup → prove → verify) runs via
`circuits/scripts/toy_prove_verify.mjs`; the settlement flow's e2e demo uses
the same public-signal layout. The full hardening+entropy-threshold circuit
is future work (§9).

### 4.7 Sphinx-style onion framing — `net/sphinx.py`

Layered X25519 + AES-GCM over a **fixed** route; each hop's layer is
addressed by a keyed tag (HMAC over the ephemeral public key), mirroring
Sphinx's tag-lookup table. Layer plaintext: magic ‖ final-flag ‖ session ‖
sequence ‖ length ‖ body.

Per-hop guarantees (tests):
- only the addressed hop opens its layer (`WrongHopError` otherwise);
- an intermediate hop learns only the *next hop's tag* — never the payload,
  the destination, or the rest of the route (tag != next-hop tag ⇒ mixing);
- per-node `(session, seq)` guard rejects replays (`ReplayError`) and out-
  of-order delivery (`OutOfOrderError`);
- any byte tampering fails AES-GCM authentication;
- identical seed → byte-identical packets (deterministic demos).

### 4.8 Erasure coding — `erasure/`

Systematic Reed-Solomon over the same GF(256): message bytes pad to a
multiple of *k*, split into *k* blocks interpreted as evaluations of a
degree-(k−1) polynomial at points 1..k; shard *m* stores the evaluation at
point m+1 plus a 4-byte length header. Any *k* of *n* shards reconstruct the
exact original (length header disambiguates trailing zero padding).

Tests exhaustively enumerate all C(n,k) subsets for small (k,n) and assert
round-trips, the systematic property (shards 0..k−1 are the raw blocks), and
parameter validation (n ≤ 255 field points, k ≥ 1, k ≤ n).

### 4.9 DTN mesh — `net/dtn.py`

Deterministic discrete-time store-and-forward. Each directed link has an
up/down schedule (same period/phase ⇒ stable connected subgraphs). Nodes
buffer bundles; each step, every buffered bundle advances one hop along the
current-shortest BFS path to its destination, deduplicated on `(src, seq)`
(loop prevention), and TTLs expire un-deliverable bundles (counted as drops).
Delivery records carry arrival step, hop count, and the actual path — the
e2e demo delivers 4/4 RS shards across a 4-node mesh with 0.6 up-fraction.

### 4.10 Dark pool SMPC matching — `net/darkpool.py`

Order prices and quantities are split into Shamir shares over the Mersenne
prime 2^61 − 1 (threshold t-of-n agents). Shares are additively homomorphic,
so each agent computes a share of `bid.price − offer.price` from its own
shares of the two orders. The engine Lagrange-reconstructs only that
*difference* and applies the field-half convention — values `< P/2` are true
non-negative differences (crossed), values `≥ P/2` are wrapped negatives (no
cross). It **never reconstructs any individual price or quantity**, so no
party learns the order book (a single curious agent holds 1<t shares of every
value and gains no information). Matches clear at the maker (offer) price
with min(bid.qty, offer.qty).

### 4.11 Settlement — `contracts/`

The Solidity `EntropySettlement` is the authoritative logic:

1. `msg.value >= price`, else revert `NotPaid`;
2. nullifier not already `spent`, else revert `AlreadySpent`;
3. `IVerifier.verifyProof(a, b, c, input)` holds, else revert `InvalidProof`;
4. mark spent + emit `Settled`, then pay `payee` and refund surplus —
   state changes precede external calls (checks-effects-interactions ⇒
   reentrancy-safe).

`Verifier.sol` implements the toy circuit's public-signal layout
(`[window_id, nullifier]`, `window_id == 42`, non-zero proof points); the
exported real Groth16 verifier is a drop-in (`snarkjs zkey export
solidityverifier`). `contracts/settlement_sim.py` is a pure-Python twin of
the same rules so the laptop e2e demo runs the identical logic. Foundry
tests cover settle, surplus refund, double-spend rejection, underpay,
invalid proof, and price ownership.

## 5. End-to-end pipeline

`cli/e2e.py` chains all thirteen stages with deterministic seeds; every stage
is scored PASS/FAIL and the exit code gates CI (also wired into
`scripts/test.ps1`). The same run optionally emits `dashboard/data.json`,
`data.js`, and a fully self-contained `dashboard/index.html` (data inlined —
renders from `file://` with no server, no CORS).

## 6. Security-property summary (as actually proven)

| Property | Module | Test evidence |
|----------|--------|---------------|
| GF(256) field arithmetic correct (AES tables, generator 3) | `hardening/gf256.py` | known-answer tests, commutativity/associativity, a^255 = 1 |
| Estimator ordering H_90B >= H_hist >= H_Shannon | `dsp/` | validation suite vs closed-form quantizer truth |
| Hardening commitment verifiable, corruption-detecting | `hardening/` | verify round-trip, flipped-byte rejected |
| Nullifier deterministic / window-bound / node-bound | `identity/` | same-signal/window/node matrix |
| Certificate byte-determinism + MAC | `identity/` | serialization round-trip |
| Onion: wrong-hop, payload privacy, replay, ordering, tamper | `net/sphinx.py` | 9 tests |
| RS: any-k-of-n exact reconstruction, systematic, deterministic | `erasure/` | full C(n,k) subset scan |
| DTN: delivery under intermittent links, no dup, TTL drop | `net/dtn.py` | 11 tests |
| Dark pool: share round-trip, additive homomorphism, blind crossing | `net/darkpool.py` | 9 tests |
| Settlement: atomic pay-once-per-nullifier | `contracts/` | 7 Python tests + Foundry suite |
| Dashboard: deterministic, valid embedded JSON, script-tag safe | `cli/e2e.py` | 5 tests |
| **Whole chain** | `cli/e2e.py` | 13/13 stages PASS |

## 7. Parametrization reference

| Parameter | Value | Meaning |
|-----------|-------|---------|
| GF(256) polynomial | 0x11B, generator 3 | AES field |
| Hardening degree | 31 (32 coeffs), 64 points | 2x redundancy |
| Nullifier | HMAC-BLAKE2b, 32-byte output | anti-double-mine |
| Onion | X25519 + AES-GCM, 32B tag/32B eph/12B nonce/layer | 3-hop route |
| RS | (k=2, n=4) in e2e; n <= 255, k <= n general | any-k-of-n |
| DTN | 4-node mesh, 0.9 connect, 0.6 up, period 6, TTL 200 | e2e demo |
| Shamir | GF(2^61-1), threshold 3 of 5 agents | dark pool |
| Settlement price | 100 (sim) | payee-funded unit |

## 8. Repository layout

```
dsp/          capture sim, FFT/noise floor, Shannon/90B estimators, validation
hardening/    GF(256) + polynomial commitment
identity/     nullifier + signed certificate schema
erasure/      systematic Reed-Solomon n/k
net/          sphinx.py / dtn.py / darkpool.py (simulations)
circuits/     circom toy proof + snarkjs pipeline
contracts/    Solidity settlement + Foundry tests + Python twin
cli/          demo.py (P0) - e2e.py (full chain, --json/--dashboard)
dashboard/    template.html -> generated self-contained index.html + data
tests/        pytest suite (one file per module)
docs/         this whitepaper, module docs, NIST report, status
```

## 9. Limitations & roadmap

Honest limitations of the current implementation:

1. **Toy zk circuit.** The Groth16 circuit proves commitment structure and
   the `window_id` gate, not yet the full "90B min-entropy >= threshold over
   the hardened polynomial" statement. The real circuit is the primary next
   engineering item; the interfaces (circuit public signals, verifier ABI)
   already match.
2. **Reference verifier.** `contracts/src/Verifier.sol` checks the public
   layout, not pairing math; swap in the `snarkjs`-exported verifier for the
   cryptographic guarantee (documented, one-file change). `forge test` was
   not runnable on this machine (Foundry absent); the Python twin is green.
3. **Simulated physics.** "Ground truth" entropies come from closed-form /
   modeled sources; real piezo/SDR validation is a hardware project outside
   this repo's scope (AGENTS.md guardrail).
4. **DTN scale.** Deterministic schedules and synchronous steps bound the
   simulation to laptop-scale tests; asynchronous real routing is future work.
5. **No formal proofs.** Properties are machine-checked by tests (multiple
   seeds, exhaustive subsets), not mechanically verified; a formalization
   (e.g., in Lean/Isabelle) is a research-scale item.

Roadmap priorities after this whitepaper: real entropy-gate circuit -> real
Groth16 verifier wiring -> DTN asynchronous mode -> multi-node e2e federation
-> formal property verification.

## 10. References

- NIST SP 800-90B — *Recommendation for the Entropy Sources Used for Random
  Bit Generation* (Turan et al., 2018).
- Reference port used for estimator cross-checks:
  `dj-on-github/SP800_90b_tests` (formula-only; its `multi_mcw` overflow bug
  is documented in `docs/nist800_90b.md`).
- Sphinx: Danezis & Goldberg, *Sphinx: A Compact and Provably Secure Mix
  Format* (2009).
- Shamir, *How to Share a Secret* (1979). Groth16: Groth, *On the Size of
  Pairing-Based Non-interactive Arguments* (2016).
