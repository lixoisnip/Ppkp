# A03/A04 packet bridge deepening (v2 static)

Generated: 2026-04-27 11:08:18Z

## Scope and guardrails.
- Scope: A03_26.PZU and A04_28.PZU static-only evidence.
- DKS 0x5A7F used as structural reference only.
- No transfer of DKS physical semantics to A03/A04.
- Evidence levels used: exact_fingerprint, near_fingerprint, callgraph_match, xdata_pattern_match, string_marker_match, manual_static, hypothesis, unknown.

## A03 vs A04 identity/config differences.
- A04 string markers contain explicit A.04 identity markers where available.
- Candidate density differs: A03=105, A04=107.

## Packet bridge candidates.
- Consolidated into `a03_a04_packet_bridge_candidates_v2.csv`.
- Roles remain candidate-level unless strengthened by fingerprint evidence.

## Packet context XDATA.
- Packet-window neighborhood mapped in `a03_a04_packet_context_matrix.csv`.
- XDATA entries represent adjacency/context only.

## Callsite patterns.
- Callsite traces in `a03_a04_packet_callsite_trace_v2.csv` focus on calls into candidate bridge/builder functions.
- Pre-call context tracks likely DPTR setup neighborhoods.

## Difference from DKS packet bridge.
- Current A03/A04 candidates show partial callgraph and XDATA-window alignment, but no exact_fingerprint parity to DKS 0x5A7F was established.

## Best current hypothesis.
- A03/A04 include branch-specific packet bridge/builder adjacency chain(s) with overlapping structural motifs and family-specific implementation details.

## What remains unknown.
- Packet framing and field-level semantics.
- Whether top A03/A04 candidates split builder/bridge responsibilities differently from DKS.
