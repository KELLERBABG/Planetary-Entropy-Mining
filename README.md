# Planetary Entropy Mining

Harvest environmental entropy (thermal, RF, seismic noise) into cryptographically
verified certificates: simulated capture -> SP 800-90B entropy estimation ->
lattice-style hardening -> deterministic nullifiers -> zk-SNARK proofs ->
erasure-coded onion-framed transport through a DTN mesh -> blind dark-pool
matching -> atomic settlement.

Everything runs on a laptop. No hardware, no network sockets, no real money:
physical sources exist only as seeded simulators with known statistical truth,
so every estimator can be validated.

See `AGENTS.md` (working agreement), `DEVELOPMENT_PLAN.md` (long-term vision),
and `docs/PROJECT_STATUS.md` (current status + what's next).

## Layout

| Path | Contents |
|------|----------|
| `dsp/` | capture simulators, FFT/noise-floor analysis, entropy estimators (NIST SP 800-90B), validation suite |
| `hardening/` | noise-to-polynomial hardening with verifiable structure |
| `identity/` | deterministic nullifiers, certificate schema + MAC signing |
| `erasure/` | hand-rolled Reed-Solomon GF(256) n/k sharding |
| `net/` | Sphinx-style onion framing, DTN mesh simulation, dark pool simulation |
| `circuits/` | Circom zk circuits + snarkjs scripts |
| `contracts/` | Solidity settlement contracts (Foundry) |
| `cli/` | end-to-end demo entrypoint |
| `docs/` | module docs, NIST report, architecture |

## Quickstart

```powershell
py -m pip install -e ".[dev]"
py -m pytest                          # fast suite (slow NIST 90B tier excluded)
py -m pytest -m ""                    # full suite incl. rigorous 90B validation
py -m cli.validate                    # entropy validation report -> docs/
# zk-SNARK P0 capstone (JavaScript toolchain):
#   cd circuits && npm install        # one-time (circom2 + snarkjs + circomlib)
node circuits/scripts/toy_prove_verify.mjs --assert   # compile -> prove -> verify
```

## Module status (truthful)

| # | Module | Status |
|---|--------|--------|
| 1 | Repo bootstrap | done |
| 2 | Entropy capture sim | done |
| 3 | Signal processing + estimation | done |
| 4 | Entropy validation + report | done |
| 5 | Hardening (GF(256) polynomial) | done |
| 6 | Nullifier | done |
| 7 | Certificate schema | done |
| 8 | zk circuit + e2e proof (toy, Groth16) | done |
| 9 | Erasure coding | next (uses hardening GF(256)) |
| 10 | Sphinx framing | next |
| 11 | DTN mesh | next |
| 12 | Dark pool | next |
| 13 | Settlement contracts | next |
| 14 | e2e CLI demo (`cli/demo.py` P0 chain) | partial — P0 chain done, P1 chain (onion/shard/match/settle) next |
| 15 | Dashboard | not yet built |
