# Cross-family static deepening v1

Generated: 2026-04-27 11:08:18Z

## What improved after this milestone.
- A03/A04 packet-bridge adjacency is deeper with candidates/context/callsite traces.
- shifted_DKS + v2_1 XDATA clusters are now partitioned into conserved/offset/divergent/unknown.
- RTOS_service chain has a focused family-specific manual-static decompile baseline.

## What remains unknown.
- Packet field semantics across non-DKS families.
- Whether v2_1 is primarily analog-preserving or evolved schema branch in key clusters.
- RTOS_service module-side physical semantics and exact MDS/MASH interactions.

## Which family should be analyzed next.
- Priority recommendation: RTOS_service + A03/A04 callsite micro-decompile pass.

## Which function targets are most valuable next.
- See `cross_family_deep_targets_next.csv`.

## Updated understanding percent by family.
- See `cross_family_static_deepening_dashboard.csv`.
