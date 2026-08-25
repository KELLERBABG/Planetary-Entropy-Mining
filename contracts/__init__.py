"""Settlement layer: Solidity source (contracts/src) + laptop-run simulator.

The Solidity contracts are the authoritative settlement logic (run with
Foundry: `forge test`); `settlement_sim.py` mirrors the same rules in pure
Python so the deterministic e2e demo can run without the Solidity
toolchain.
"""