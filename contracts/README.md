## Settlement contracts (Foundry)

Solidity settlement layer for the Planetary Entropy Audit: atomic
proof-verification + payment on delivery of a valid entropy certificate.

### Layout

```
contracts/
  foundry.toml
  src/
    EntropySettlement.sol   # proof-gated settlement (payments per nullifier)
    IVerifier.sol           # Groth16 verifier interface (snarkjs-compatible)
    Verifier.sol            # reference verifier using the toy circuit's
                            # public-signal layout (compile + wire real one)
  test/
    Settlement.t.sol        # Foundry test suite
```

### Run

```powershell
# Requires Foundry (https://book.getfoundry.sh)
forge install            # pulls forge-std (network needed once)
forge test               # full suite
```

### Verification contract

`EntropySettlement` never verifies proofs itself — it delegates to an
`IVerifier`. The shipped `Verifier.sol` implements the exact public-signal
layout of the toy circuit (`window_id`, `nullifier`) so the P0 artifact is
immediately usable: it recomputes the two public signals from an honest
proof structure and asserts the window gate (`window_id == 42`).

Swap in the real Groth16 artifact any time with:

```powershell
snarkjs zkey export solidityverifier toy.zkey Verifier.sol
```

### Anti-double-mint

Settlement is gated on `nullifier`: each nullifier settles at most once (a
mapping keeps the spent set). This is the on-chain counterpart of the
identity-layer nullifier — the same signal proves "this entropy window was
already claimed".

### Payment

`settle(...)` requires `msg.value >= price`; the surplus is refunded
immediately (atomic, reentrancy-guarded by checks-effects-interactions and
the spent-nullifier guard executing before any transfer).