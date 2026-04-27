# DKS firmware technical reconstruction v1

Generated: 2026-04-27 11:08:16Z

## 1. Scope and evidence rules
This report keeps strict evidence levels: `confirmed_static`, `probable_static`, `manual_decompile`, `chain_adjacency`, `screen_configuration`, `hypothesis`, `unknown`.
No physical semantics are claimed without direct static + bench evidence.

## 2. Firmware families covered
Primary: `90CYE03_19_DKS.PZU`, cross-check `90CYE04_19_DKS.PZU`; shifted comparison for object-status path: `90CYE02_27 DKS.PZU`; `ppkp2001 90cye01.PZU` only for MDS/MASH comparison context.

## 3. Real DKS configuration evidence
Uses existing `dks_real_configuration_evidence.*` as screen-level ground truth for module slot presence only.

## 4. Reconstructed architecture diagram
Runtime chain anchor remains: `0x497A -> 0x737C -> 0x613C -> 0x84A6 -> 0x728A -> 0x6833 -> 0x5A7F` with `0x7922`, `0x597F`, `0x7DC2` as service/output-side helpers.

## 5. Main 90CYE_DKS execution chain
Current chain understanding: **78%** (probable). Side exits remain partially unresolved.

## 6. Module roles: MDS / MUP / MASH / PVK / MVK / input-board
Shared dispatchers are separated from slot-specific candidates. MUP/MVK mapping remains unresolved without bench evidence.

## 7. XDATA memory map
State table candidate: `0x3010..0x301B`; mode/flags cluster: `0x30E7`, `0x30E9`, `0x30EA..0x30F9`; selector/context: `0x31BF`; packet/output context: `0x3640`, `0x364B`, `0x36D3..0x36FD`.

## 8. Enum/state reconstruction
See `dks_enum_state_reconstruction.md` and supporting CSVs. Current enum understanding: **61%**.

## 9. Packet/export reconstruction
See `dks_packet_export_reconstruction.md`. Current packet understanding: **56%**; `0x5A7F` best fit is bridge/helper.

## 10. Output/action reconstruction
See `dks_output_action_reconstruction.md`. Current output-action understanding: **54%**; write `0x04` remains non-physical label candidate.

## 11. Manual/auto mode logic
Manual/auto split around `0x84A6/0x728A` remains probable; manual path can go packet-only while auto path can enter output-start flow.

## 12. What is confirmed
- Screen-level module presence for listed slots.
- Shared runtime chain existence and adjacency.

## 13. What is probable
- Enum/state classes and output-start pipeline sequence.
- Packet-context XDATA clusters and `0x5A7F` bridge role.

## 14. What is hypothesis
- Physical output semantics (valve/siren/GOA/MVK).
- Exclusive handler ownership for some module labels.

## 15. What is unknown
See `dks_remaining_unknowns.csv`.

## 16. Bench validation plan
Consolidated in `dks_output_action_bench_tests.csv` and prior lifecycle/enum probe plans.

## 17. Development implications for future compatible firmware
Use shared runtime-chain abstractions and keep module-specific mappings behind evidence-gated interfaces; avoid hard-coding physical semantics before validation.

## 18. Next iteration plan
See `dks_next_iteration_plan.csv`.

---

## Understanding estimates (v1)
- Global architecture: **72%**
- DKS execution chain: **78%**
- XDATA lifecycle: **74%**
- Packet/export: **56%**
- Output-action: **54%**
- Full physical semantics: **29%**

These values are intentionally conservative and should rise only with bench-confirmed evidence.

## 20. Cross-family deepening note (v1.1)
The v1.1 deepening package is documented in `docs/cross_family_static_deepening_v1.md` and supporting artifacts.
This DKS document stays DKS-scoped: DKS semantics are not auto-applied to A03/A04, shifted_DKS, v2_1, or RTOS_service without direct family-specific evidence.
