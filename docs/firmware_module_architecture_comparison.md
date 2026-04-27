# Firmware module architecture comparison (Issue #52 follow-up)

Date: 2026-04-27 (UTC).

## 1. Scope and compared firmware families

Compared branches: 90CYE_DKS, 90CYE_shifted_DKS, 90CYE_v2_1, A03_A04, RTOS_service.
This report separates shared low-level patterns from application-specific behavior and avoids semantic transfer without code evidence.

## 2. Inputs used by analyzer

- ✅ docs/firmware_manifest.json
- ✅ docs/firmware_inventory.csv
- ✅ docs/firmware_family_matrix.csv
- ✅ docs/function_map.csv
- ✅ docs/basic_block_map.csv
- ✅ docs/disassembly_index.csv
- ✅ docs/call_xref.csv
- ✅ docs/xdata_confirmed_access.csv
- ✅ docs/xdata_xref.csv
- ✅ docs/code_table_candidates.csv
- ✅ docs/string_index.csv
- ✅ docs/module_handler_summary.csv
- ✅ docs/mash_handler_deep_trace.csv
- ✅ docs/mash_handler_deep_trace_summary.csv
- ✅ docs/mash_handler_deep_trace_analysis.md
- ✅ docs/zone_logic_candidates.csv
- ✅ docs/output_control_candidates.csv
- ✅ docs/zone_to_output_chains.csv
- ✅ docs/zone_output_logic_analysis.md
- ✅ docs/runtime_state_machine_nodes.csv
- ✅ docs/runtime_state_machine_edges.csv
- ✅ docs/runtime_state_machine_reconstruction.md
- ✅ docs/xdata_branch_trace_map.csv
- ✅ docs/enum_branch_value_map.csv
- ✅ docs/manual_auto_branch_map.csv
- ✅ docs/output_transition_map.csv
- ✅ docs/xdata_enum_branch_resolution.md
- ⚠️ docs/input_board_core_candidates.csv
- ⚠️ docs/input_board_command_candidates.csv
- ⚠️ docs/paired_input_logic_candidates.csv
- ⚠️ docs/input_board_to_event_chains.csv
- ✅ docs/input_board_core_matrix.csv
- ✅ docs/family_module_architecture_map.csv
- ✅ docs/dks_real_configuration_evidence.csv

## 3. Missing optional inputs/warnings

- ⚠️ optional input missing: docs/input_board_core_candidates.csv
- ⚠️ optional input missing: docs/input_board_command_candidates.csv
- ⚠️ optional input missing: docs/paired_input_logic_candidates.csv
- ⚠️ optional input missing: docs/input_board_to_event_chains.csv

## 4. Shared architecture overview

Shared pattern appears across families: runtime core dispatches module workers, then events/packet export. Module semantics differ per family.

## 5. ASCII architecture diagram

```text
CPU board / runtime core
  -> keyboard + display / menu
  -> module scheduler
      -> MASH address loop
          -> sensor state -> event
      -> input signal board
          -> digital inputs / paired inputs -> object state -> event
      -> MDS discrete signal module
          -> discrete signals -> state table -> event
      -> MVK output module
          -> siren / relay / aerosol line / water valve output
          -> feedback / line supervision / fault
      -> MUP control/start module
          -> command/start/control action
          -> feedback / fault
  -> event queue
  -> packet/export
```

## 6. CPU/runtime core candidates by family

| branch | file | strongest function | confidence | notes |
|---|---|---|---|---|
| 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | 0x497F | confirmed | score=1.000 |
| 90CYE_v2_1 | 90CYE03_19_2 v2_1.PZU | 0x497F | confirmed | score=1.000 |
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x497A | confirmed | score=1.000 |
| 90CYE_v2_1 | 90CYE04_19_2 v2_1.PZU | 0x497F | confirmed | score=1.000 |
| 90CYE_DKS | 90CYE04_19_DKS.PZU | 0x497A | confirmed | score=1.000 |
| A03_A04 | A03_26.PZU | 0x497A | confirmed | score=1.000 |
| A03_A04 | A04_28.PZU | 0x497A | confirmed | score=1.000 |
| RTOS_service | ppkp2001 90cye01.PZU | 0x758B | confirmed | score=1.000 |
| RTOS_service | ppkp2012 a01.PZU | 0x75F7 | confirmed | score=1.000 |
| RTOS_service | ppkp2019 a02.PZU | 0x57DB | confirmed | score=1.000 |

## 7. Keyboard/display/menu/front panel candidates by family

| branch | file | strongest function | confidence | notes |
|---|---|---|---|---|
| 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | 0x497F | unknown | score=0.000 |
| 90CYE_v2_1 | 90CYE03_19_2 v2_1.PZU | 0x497F | unknown | score=0.000 |
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x497A | unknown | score=0.000 |
| 90CYE_v2_1 | 90CYE04_19_2 v2_1.PZU | 0x497F | unknown | score=0.000 |
| 90CYE_DKS | 90CYE04_19_DKS.PZU | 0x497A | unknown | score=0.000 |
| A03_A04 | A03_26.PZU | 0x497A | unknown | score=0.000 |
| A03_A04 | A04_28.PZU | 0x497A | unknown | score=0.000 |
| RTOS_service | ppkp2001 90cye01.PZU | 0x758B | unknown | score=0.000 |
| RTOS_service | ppkp2012 a01.PZU | 0x75F7 | unknown | score=0.000 |
| RTOS_service | ppkp2019 a02.PZU | 0x57DB | unknown | score=0.000 |

## 8. MASH candidates by family

| branch | file | strongest function | confidence | notes |
|---|---|---|---|---|
| 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | 0x497F | confirmed | score=1.000 |
| 90CYE_v2_1 | 90CYE03_19_2 v2_1.PZU | 0x497F | unknown | score=0.000 |
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x497A | confirmed | score=1.000 |
| 90CYE_v2_1 | 90CYE04_19_2 v2_1.PZU | 0x497F | unknown | score=0.000 |
| 90CYE_DKS | 90CYE04_19_DKS.PZU | 0x497A | unknown | score=0.000 |
| A03_A04 | A03_26.PZU | 0x497A | confirmed | score=1.000 |
| A03_A04 | A04_28.PZU | 0x497A | unknown | score=0.000 |
| RTOS_service | ppkp2001 90cye01.PZU | 0x758B | confirmed | score=1.000 |
| RTOS_service | ppkp2001 90cye01.PZU | unknown | confirmed | score=0.700 |
| RTOS_service | ppkp2012 a01.PZU | 0x75F7 | unknown | score=0.000 |
| RTOS_service | ppkp2019 a02.PZU | 0x57DB | unknown | score=0.000 |

## 9. MVK candidates by family

| branch | file | strongest function | confidence | notes |
|---|---|---|---|---|
| 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | 0x497F | confirmed | score=1.000 |
| 90CYE_v2_1 | 90CYE03_19_2 v2_1.PZU | 0x497F | confirmed | score=1.000 |
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x497A | confirmed | score=1.000 |
| 90CYE_v2_1 | 90CYE04_19_2 v2_1.PZU | 0x497F | confirmed | score=1.000 |
| 90CYE_DKS | 90CYE04_19_DKS.PZU | 0x497A | confirmed | score=1.000 |
| A03_A04 | A03_26.PZU | 0x497A | confirmed | score=1.000 |
| A03_A04 | A04_28.PZU | 0x497A | confirmed | score=1.000 |
| RTOS_service | ppkp2001 90cye01.PZU | 0x758B | confirmed | score=1.000 |
| RTOS_service | ppkp2012 a01.PZU | 0x75F7 | confirmed | score=1.000 |
| RTOS_service | ppkp2019 a02.PZU | 0x57DB | confirmed | score=1.000 |

## 10. Input signal board candidates by family

| branch | file | strongest function | confidence | notes |
|---|---|---|---|---|
| 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | 0x497F | unknown | score=0.250 |
| 90CYE_v2_1 | 90CYE03_19_2 v2_1.PZU | 0x497F | unknown | score=0.250 |
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x497A | probable | score=0.650 |
| 90CYE_v2_1 | 90CYE04_19_2 v2_1.PZU | 0x497F | unknown | score=0.250 |
| 90CYE_DKS | 90CYE04_19_DKS.PZU | 0x497A | probable | score=0.650 |
| A03_A04 | A03_26.PZU | 0x497A | unknown | score=0.250 |
| A03_A04 | A04_28.PZU | 0x497A | unknown | score=0.250 |
| RTOS_service | ppkp2001 90cye01.PZU | 0x758B | probable | score=0.650 |
| RTOS_service | ppkp2012 a01.PZU | 0x75F7 | probable | score=0.650 |
| RTOS_service | ppkp2019 a02.PZU | 0x57DB | probable | score=0.650 |

## 11. MDS and MUP modules

- MDS code confidence is based on discrete-signal-like indicators; generic input-board evidence is weak support only.
- MUP code confidence is based on control/start-specific indicators; MUP is not derived from MVK/runtime score.
- Screen evidence and code-level handler candidates are tracked separately.
- Strongest current candidates are listed in `docs/mds_mup_module_candidates.csv`.
- Confidence labels used: confirmed / probable / hypothesis / unknown.
- Next manual decompile targets: top per module from `docs/shared_core_function_map.csv`, `docs/mvk_output_semantics.csv`, `docs/mds_mup_module_candidates.csv`.

## 12. Real DKS configuration evidence

- Screenshots map to repository firmware files and are recorded in `docs/dks_real_configuration_evidence.md` and `docs/dks_real_configuration_evidence.csv`.
- The screenshots confirm module presence at configuration/HMI level, but do not prove exact handler function addresses.
- DKS 90CYE03/90CYE04 confirms MDS, MUP and PVK as separate modules.
- DKS 90CYE01 confirms MDS, PVK and two MASH modules (X05/X06).
- DKS 90CYE02 confirms multiple MDS-like modules and object-status layer (`90SAE...` tags).
- This strengthens module-separation interpretation (MDS/MUP/PVK/MASH, shleif status, object-status layer) without raising function-level confidence by itself.

## 12.1 MDS/MUP confidence audit

- PR #55 added real screen-confirmed module presence.
- Screen evidence confirms slot/module presence, not function addresses.
- Analyzer now separates screen-confirmed module presence, code-level handler candidates, and heuristic-only weak signals.
- MUP is not derived from MVK automatically.
- MDS is not derived from generic input-board evidence automatically.
- Screen-confirmed MUP files: `90CYE03_19_DKS.PZU`, `90CYE04_19_DKS.PZU`.
- Screen-confirmed MDS files: `ppkp2001 90cye01.PZU`, `90CYE02_27 DKS.PZU`, `90CYE03_19_DKS.PZU`, `90CYE04_19_DKS.PZU`.
- Screen-confirmed MASH files: `ppkp2001 90cye01.PZU`.
- Screen-confirmed PVK files: `ppkp2001 90cye01.PZU`, `90CYE03_19_DKS.PZU`, `90CYE04_19_DKS.PZU`.

## 13. APS/aerosol/water-like differences

Heuristic family scores are in `docs/firmware_architecture_matrix.csv`; they do not assert functional identity between branches.

## 14. MVK output semantics

Covered semantics: siren/relay shutdown, aerosol GOA/start line, water valve/actuator, generic output start/reset where evidence exists.

## 15. Aerosol GOA line supervision

Reverse voltage / resistance window / open-short-fault / start permission are listed only as candidates. Weak evidence is marked hypothesis/unknown.

## 16. Water valve/actuator logic

Open command, paired feedback, timeout/fault indications are captured as candidate patterns with conservative confidence.

## 17. Cross-firmware repeated patterns

See `docs/cross_firmware_pattern_summary.csv` for shared packet/core/front-panel/MASH/MVK/input/MDS/MUP patterns.

## 18. Strongest functions to manually decompile next per module

- cpu_board: 90CYE_shifted_DKS:0x497F, 90CYE_v2_1:0x497F, 90CYE_DKS:0x497A, 90CYE_v2_1:0x497F, 90CYE_DKS:0x497A
- mash_address_loop: 90CYE_shifted_DKS:0x497F, 90CYE_DKS:0x497A, A03_A04:0x497A, RTOS_service:0x758B, RTOS_service:unknown
- mvk_output_module: 90CYE_shifted_DKS:0x497F, 90CYE_v2_1:0x497F, 90CYE_DKS:0x497A, 90CYE_v2_1:0x497F, 90CYE_DKS:0x497A
- input_signal_board: 90CYE_DKS:0x497A, 90CYE_DKS:0x497A, RTOS_service:0x758B, RTOS_service:0x75F7, RTOS_service:0x57DB
- mds_discrete_signal_module: 90CYE_shifted_DKS:0x497F, 90CYE_DKS:0x497A, 90CYE_DKS:0x497A, RTOS_service:0x758B, A03_A04:0x497A
- mup_module: 90CYE_DKS:0x497A, 90CYE_DKS:0x497A, 90CYE_DKS:unknown, 90CYE_DKS:unknown, A03_A04:0x497A
- packet_export: 90CYE_DKS:0x497A, 90CYE_DKS:0x497A, 90CYE_shifted_DKS:0x497F, 90CYE_v2_1:0x497F, 90CYE_v2_1:0x497F

## 19. Bench/runtime validation checklist

- [ ] Verify mode-gate behavior around 90CYE_DKS 0x728A (E0/E1/E2 and XDATA 0x30A2/0x30E7).
- [ ] Verify 0x6833 branch side effects (calls 0x7922/0x597F/0x5A7F, XDATA write value 0x04, path to 0x7DC2).
- [ ] Separate manual-like event-only path vs auto-like output-start path.
- [ ] Validate MDS discrete module logic independently from input-board scan logic.
- [ ] Validate MUP control/start independently from MVK output semantics.
- [ ] Validate aerosol line supervision thresholds (reverse/open/short/resistance window) on bench.
- [ ] Validate water valve open/close feedback paired-limit behavior and timeouts.

## 20. Limitations and confidence rules

- Confirmed: repeated static evidence across multiple artifacts and chain consistency.
- Probable: strong but incomplete structural evidence.
- Hypothesis: partial evidence, ambiguous semantics.
- Unknown: insufficient evidence.
- No `.PZU` files were modified.
