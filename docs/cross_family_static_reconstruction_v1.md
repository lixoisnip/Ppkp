# Cross-family static reconstruction v1

Generated: 2026-04-27 11:08:18Z

## 1. Scope and evidence rules
Evidence levels used: exact_fingerprint, near_fingerprint, callgraph_match, xdata_pattern_match, string_marker_match, screen_configuration, chain_adjacency, hypothesis, unknown.

## 2. Firmware families and files
Families included: 90CYE_DKS, 90CYE_shifted_DKS, 90CYE_v2_1, A03_A04, RTOS_service.

## 3. DKS as reference, not universal truth
DKS chain is used as structural reference only.

## 4. Function analog map
Rows: 33 (exact=0, near=0).

## 5. XDATA schema comparison
Rows: 89 with confirmed/probable=35.

## 6. Packet/export comparison
Bridge candidate rows: 8.

## 7. Output/action comparison
Output/action candidate rows: 14.

## 8. Enum/state comparison
Enum matrix rows: 9.

## 9. Module semantics comparison
Module matrix rows: 120; present rows=90.

## 10. Family-specific summaries
- 90CYE_DKS: reference-only anchor.
- 90CYE_shifted_DKS: strongest address-shift analog family.
- 90CYE_v2_1: strong structural overlap, semantics still family-scoped.
- A03_A04: partial overlap; packet/output model may diverge.
- RTOS_service: separate family with partial chain analogs.

## 11. What is confirmed across families
- Dispatcher-level structural analogs exist.
- Some XDATA clusters are conserved or shifted.

## 12. What is probable
- Packet/export bridge analogs in non-DKS families.
- Shared enum vocabulary at byte-level.

## 13. What is hypothesis
- Output/action semantic equivalence.
- Module-level physical behavior mapping.

## 14. What remains unknown
See `cross_family_remaining_unknowns.csv`.

## 15. What external documentation is needed
- Protocol framing docs.
- Module/service family design notes.

## 16. What bench/runtime data would resolve the largest unknowns
- synchronized packet + IO capture with function/XDATA traces.

## 17. Next static iteration plan
See `cross_family_next_static_plan.csv`.

## 18. v1.1 deepening linkage
- Follow-up artifacts:
  - `docs/a03_a04_packet_bridge_deepening.md`
  - `docs/shifted_v2_xdata_offset_validation.md`
  - `docs/rtos_service_chain_decompile_v1.md`
  - `docs/cross_family_static_deepening_v1.md`
- DKS remains structural reference only; family-specific semantics are not transferred without direct evidence.
