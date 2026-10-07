# AGENTS.md — Planetary Entropy Mining: Working Plan for AI Assistants

This is the operational plan for how to approach this project. The long-term vision
is in `DEVELOPMENT_PLAN.md`. This file governs day-to-day engineering.

## 1. Scope Guardrails

We build **verifiable software** for the Planetary Entropy Mining system. Physical
hardware (piezo, SDR, RF) is abstracted behind interfaces and simulated — nothing
in the repo may require hardware to run. We do NOT build: real SDR drivers, meteor
scatter, GPU proof generation, real carbon registry integrations.

Deliverable ordering (per DEVELOPMENT_PLAN.md "Recommended MVP"):
- **P0 (MVP):** entropy capture (simulated) → signal processing → entropy estimation
  → hardening → nullifier → zk-SNARK proof → signed certificate.
- **P1:** erasure-coded shard distribution, onion (Sphinx-style) framing, DTN mesh
  simulation.
- **P2:** SMPC dark pool matching simulation, atomic settlement contracts, dashboard.

## 2. Tech Stack Decisions (locked unless a task says otherwise)

| Area | Choice | Why |
|------|--------|-----|
| DSP / entropy / simulations | Python (numpy, scipy) | Fastest iteration; NIST STS + Dieharder bindings available |
| Erasure coding | Python `reedsolo` or hand-rolled Reed-Solomon | Small, testable |
| zk-SNARKs | Circom + snarkjs | Standard toolchain |
| Smart contracts | Solidity + Foundry | Testable, local |
| Networking sim | Python (simulated nodes, no real sockets) | Deterministic tests |
| Dashboard | Plain HTML/JS or Vite+React (later) | Defer until P2 |
| CLI | Python `click`/`argparse`, one demo entrypoint | e2e demos |

Core library code may be ported to Rust later ("no dynamic allocation" claim) —
only as a follow-up optimization, never blocking MVP.

## 3. Repository Layout

```
docs/          research notes, specs, NIST test reports
dsp/           capture sim, FFT, noise floor, entropy estimators (NIST SP 800-90B)
hardening/     noise → polynomial hardening
identity/      deterministic nullifiers
erasure/       Reed-Solomon n/k sharding
circuits/      circom circuits + snarkjs scripts
net/           DTN mesh + onion framing simulations
contracts/     Solidity settlement contracts (Foundry)
cli/           end-to-end demo entrypoints
```

## 4. Build Order (each item = code + tests + runnable demo)

1. **Repo bootstrap:** layout, `pyproject.toml`, test runner (pytest), CI-ish local script.
2. **Entropy capture sim:** interface `EntropySource` + simulated thermal/RF/seismic noise
   generators with known statistical properties (so estimators can be validated against truth).
3. **Signal processing:** FFT → noise floor extraction → min-entropy/Shannon estimation,
   cross-checked against NIST SP 800-90B estimators.
4. **Entropy validation:** run NIST STS on captured streams; produce a report in `docs/`.
5. **Hardening:** map raw noise into a lattice-style polynomial representation with
   verifiable structure (start simple: cryptographic extraction + redundancy).
6. **Nullifier:** deterministic per-node-per-window HMAC/BLAKE3 nullifier; tests prove
   same signal twice → same nullifier, different nodes → different nullifiers.
7. **Certificate schema:** versioned format (capture metadata, entropy digest, nullifier,
   hardening params) + serialize/verify round-trip tests.
8. **zk circuit (P0 capstone):** Circom circuit proving "valid entropy measurement at time T
   without location" — start with a minimal toy circuit, then the real one. e2e demo:
   capture → proof → verify.
9. **Erasure coding:** n/k sharding + reconstruction + corruption tests.
10. **Sphinx framing:** layered onion encryption over a fixed route (X25519 + AES-GCM);
    mixing of sender/receiver identity per hop; test with 3-hop route.
11. **DTN mesh sim:** deterministic simulated nodes with intermittent links, store-and-forward
    bundles, delivery guarantees under link failures.
12. **Dark pool sim:** Shamir secret sharing + blind matching of bids/offers; prove no
    party learns order books.
13. **Settlement contracts:** Solidity — proof verification + payment; Foundry tests.
14. **e2e demo:** one CLI command: capture → harden → prove → onion → shard → ship → match → settle.
15. **Dashboard (P2, optional):** visualize certificates and matching.

## 5. Working Agreement (rules for every session)

- **Tests first, always.** Every module ships with pytest (or Foundry) tests. Run the full
  suite before calling a task done. Test command: `pytest` at repo root (add `make test`/script).
- **No hardware required.** SDR/piezo only exist as interfaces + simulators.
- **Minimal dependencies.** Prefer stdlib + numpy/scipy; add a dependency only if it
  replaces 100+ lines of error-prone code.
- **Keep every demo runnable.** At each milestone the e2e demo must run on a laptop.
- **Deterministic seeds** for all simulators (tests must be reproducible).
- **Document as we go:** each module gets a short doc in `docs/`; NIST test results recorded.
- **Never touch real money/keys.** No mainnet deployment, no real secrets in code.
- **Follow the guardrails:** if a task seems to require hardware/GPU/registry partnership,
  stop and ask — don't silently expand scope.
- **Check both files on entry:** re-read AGENTS.md and DEVELOPMENT_PLAN.md when starting a session.

## 6. Definition of Done

A task is done when: code exists, tests pass (`pytest`/`forge test`), the relevant demo
runs, docs/notes updated, and scope guardrails respected. If blocked, leave a clear
status note in the session and stop at the guardrail instead of hacking around it.
