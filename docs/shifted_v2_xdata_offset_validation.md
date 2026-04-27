# Shifted_DKS + v2_1 XDATA offset validation

Generated: 2026-04-27 11:08:18Z

## Scope and guardrails
- Families analyzed: 90CYE_shifted_DKS and 90CYE_v2_1 against DKS structural references.
- DKS semantics are **not** transferred; only address/callgraph/XDATA patterns are compared.
- Evidence levels: exact_fingerprint, near_fingerprint, callgraph_match, xdata_pattern_match, string_marker_match, manual_static, hypothesis, unknown.

## Key answers
- Conserved/offset cluster rows: 12
- Divergent/unknown rows: 16
- 90CYE02 @0x3104: retained as shifted object-status pattern candidate, not confirmed semantic parity.
- v2_1 branch appears as analog-capable structural family in selected anchors, with divergence in part of the XDATA schema.

## Which clusters are conserved / offset / divergent?
See `shifted_v2_xdata_offset_matrix.csv` and `shifted_v2_schema_divergence.csv`.

## Function anchor mapping
See `shifted_v2_function_anchor_map.csv` for function-level structural analog candidates.
