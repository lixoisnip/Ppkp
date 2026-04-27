# DKS module handler attribution (v1)

Generated: 2026-04-27 09:45:55Z

## Main interpretation
- `0x497A` is treated as **shared dispatcher/runtime bridge**, not an exclusive MDS/MUP/PVK handler.
- `0x613C` is treated as **state updater/latch bridge**, not a module-private entrypoint.
- Stronger module-specific candidates remain around `0x673C`, `0x758B`, `0x53E6`, `0xAB62` depending on branch/slot context.

## Why not exclusive assignment for `0x497A`
`0x497A` appears in shared chain adjacency, multiple slot contexts, and high fan-out call graph patterns; current evidence supports common dispatch behavior.

## Why `0x613C` is updater/bridge
Manual downstream and module decompile artifacts place `0x613C` in state-latch progression between shared runtime and downstream gating, with no slot-exclusive signature.

## Remaining unresolved areas
See `docs/dks_module_unresolved_handlers.csv` for slot-level unknowns and next static/bench actions.
