# DKS XDATA lifecycle analysis
Date: 2026-04-27 09:45 UTC.

## Scope
- This report is static lifecycle reconstruction only.
- It does **not** prove physical semantics or field wiring meaning.
- It combines direct XDATA access evidence, manual decompile summaries, and chain adjacency.
- Firmware families are not collapsed; 90CYE02 shifted-object layer is kept separate from 90CYE_DKS semantics.

## Input status / missing optional artifacts
- none

## Key XDATA clusters
- `zone_object_state_table`: `0x3010..0x301B` (focus: 0x3010/11/12/13/14/1A/1B).
- `runtime_mode_flags`: `0x315B`, `0x3181`, `0x30E7`, `0x30E9`, `0x30EA..0x30F9`.
- `packet_output_context`: `0x31BF`, `0x3165`, `0x3640`, `0x364B`, `0x36D3..0x36FD` subset.
- `shifted_object_status`: `0x3104` in `90CYE02_27 DKS.PZU`.
- `unknown_or_unresolved`: addresses with only weak adjacency or indirect context.

## XDATA lifecycle table
| address | cluster | known_writers | known_readers | branch_users | downstream_functions | packet_export_adjacency | current_role | confidence | evidence_level | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 0x3010 | zone_object_state_table | 0x737C | 0x737C | - | 0x737C | 0x737C->0x5A7F chain adjacency | zone/object state field candidate | probable | manual_decompile | enum-like values near 0x737C: 0x03, 0x07; reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x3011 | zone_object_state_table | 0x737C | 0x737C | - | 0x737C | 0x737C->0x5A7F chain adjacency | zone/object state field candidate | probable | manual_decompile | enum-like values near 0x737C: 0x03, 0x07; reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x3012 | zone_object_state_table | 0x737C | 0x737C | - | 0x737C | 0x737C->0x5A7F chain adjacency | zone/object state field candidate | probable | manual_decompile | enum-like values near 0x737C: 0x03, 0x07; reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x3013 | zone_object_state_table | 0x737C | 0x737C | - | 0x737C | 0x737C->0x5A7F chain adjacency | zone/object state field candidate | probable | manual_decompile | enum-like values near 0x737C: 0x03, 0x07; reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x3014 | zone_object_state_table | 0x737C | 0x737C | - | 0x737C | 0x737C->0x5A7F chain adjacency | zone/object state field candidate | probable | manual_decompile | enum-like values near 0x737C: 0x03, 0x07; reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x301A | zone_object_state_table | 0x737C | 0x737C | - | 0x737C | 0x737C->0x5A7F chain adjacency | zone/object state field candidate | probable | manual_decompile | enum-like values near 0x737C: 0x03, 0x07; reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x301B | zone_object_state_table | 0x737C | 0x737C | - | 0x737C | 0x737C->0x5A7F chain adjacency | zone/object state field candidate | probable | manual_decompile | enum-like values near 0x737C: 0x03, 0x07; reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x315B | runtime_mode_flags | - | 0x84A6 | 0x5A7F; 0x6833; 0x728A; 0x84A6 | 0x5A7F; 0x6833; 0x84A6 | manual_auto_branch_map | runtime/mode gate flag candidate | probable | manual_decompile | reads 0x315B/0x3181/0x3640/0x36D3/0x36D9; calls 0x728A and 0x5A7F; possible manual/auto bridge but physical semantics unknown |
| 0x3181 | runtime_mode_flags | - | 0x84A6 | - | 0x84A6 | - | runtime/mode gate flag candidate | probable | manual_decompile | reads 0x315B/0x3181/0x3640/0x36D3/0x36D9; calls 0x728A and 0x5A7F; possible manual/auto bridge but physical semantics unknown |
| 0x30E7 | runtime_mode_flags | - | - | 0x728A | - | - | runtime/mode gate flag candidate | hypothesis | unknown | 0x728A checks E0/E1/E2 bits and updates this byte in selected paths |
| 0x30E9 | runtime_mode_flags | 0x728A | 0x728A | - | - | - | runtime/mode gate flag candidate | low | direct_static | 0x30E9 appears in 0x728A branch side-path storage |
| 0x30EA..0x30F9 | runtime_mode_flags | - | - | - | - | - | runtime/mode gate flag candidate | hypothesis | unknown | - |
| 0x31BF | packet_output_context | - | 0x497A; 0x737C | 0x497A | 0x497A; 0x737C | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | Generic runtime state dispatcher with packet-export adjacency; not exclusively MDS or MUP.; reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x3165 | packet_output_context | - | - | - | - | - | packet/output context candidate | hypothesis | unknown | - |
| 0x3640 | packet_output_context | - | 0x84A6 | - | 0x84A6 | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads 0x315B/0x3181/0x3640/0x36D3/0x36D9; calls 0x728A and 0x5A7F; possible manual/auto bridge but physical semantics unknown |
| 0x364B | packet_output_context | - | - | - | 0x5A7F; 0x6833; 0x728A | packet/export context neighbor | packet/output context candidate | low | chain_adjacency | manual decompile places 0x364B near 0x728A/0x6833/0x5A7F transition |
| 0x36D3 | packet_output_context | - | 0x84A6 | - | 0x737C; 0x84A6 | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads 0x315B/0x3181/0x3640/0x36D3/0x36D9; calls 0x728A and 0x5A7F; possible manual/auto bridge but physical semantics unknown; reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x36D9 | packet_output_context | - | 0x84A6 | - | 0x84A6 | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads 0x315B/0x3181/0x3640/0x36D3/0x36D9; calls 0x728A and 0x5A7F; possible manual/auto bridge but physical semantics unknown |
| 0x36EC | packet_output_context | - | - | - | 0x737C | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x36EE | packet_output_context | - | - | - | 0x737C | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x36EF | packet_output_context | - | - | - | 0x737C | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x36F2 | packet_output_context | - | - | - | 0x737C | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x36F3 | packet_output_context | - | - | - | 0x737C | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x36F4 | packet_output_context | - | - | - | 0x737C | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x36FC | packet_output_context | - | - | - | 0x737C | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x36FD | packet_output_context | - | - | - | 0x737C | packet/export context neighbor | packet/output context candidate | probable | manual_decompile | reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07 |
| 0x3104 | shifted_object_status | 0x673C | 0x673C | - | 0x673C | - | shifted object-status byte candidate | low | chain_adjacency | Small object/status updater; possible relation to 90SAE object-status layer; no direct tag/string binding. |

## Zone/object state table: 0x3010..0x301B
- `0x737C` reads/writes this region in manual downstream reconstruction.
- `0x737C` is treated as probable zone/object state updater.
- `0x737C` calls `0x84A6` and `0x5A7F` in same downstream adjacency chain.
- Current enum-like values observed near this logic: `0x03` and `0x07`.
- Physical meaning remains cautious (attention/service/fault-like classes only as hypothesis).

## Runtime/mode flags
- `0x315B`: read in `0x84A6` and appears in mode-gate maps (possible config/mode flag; potential contributor to `0x30E7` handling remains hypothesis).
- `0x3181`: read by `0x84A6`; current role unresolved side mode/event flag.
- `0x30E7`: read/updated in `0x728A`; bits `E0/E1/E2` gate manual-decompiled branch paths.
- `0x30E9`: updated/used inside `0x728A` paths; probable side mode/state byte.
- `0x30EA..0x30F9`: still a cluster candidate with weak direct writer/reader attribution in this focused lifecycle output.

## Packet/output context
- `0x31BF`: read by `0x497A` and `0x737C`; probable selector/context byte.
- `0x3640`: read by `0x84A6`; possible mode/event-side context.
- `0x364B`: appears around `0x728A` / `0x6833` / `0x5A7F` paths; likely context selector for packet/output transition.
- `0x36D3..0x36FD` subset: used by `0x737C` and `0x84A6`; likely object/zone context cluster with unknown schema.

## 90CYE02 object-status XDATA
- `0x673C` uses `0x3104` in `90CYE02_27 DKS.PZU`.
- Current role: `object_status_updater` candidate.
- Link to visible `90SAE...` tags is indirect only; no direct tag-binding proof in static artifacts.

## Lifecycle graph
```text
0x36xx / 0x31BF context
  -> 0x737C zone/object logic [manual_decompile]
      -> writes 0x3010..0x301B [manual_decompile]
      -> calls 0x84A6 [chain_adjacency]
      -> packet bridge via 0x5A7F [chain_adjacency]

0x315B / 0x3181 / 0x3640
  -> 0x84A6 mode/event bridge [manual_decompile]
      -> 0x728A mode gate [manual_decompile]
          reads 0x30E7, 0x30A2 [manual_decompile]
          updates 0x30E7 / 0x30E9 [manual_decompile]
          manual-like -> 0x5A7F [chain_adjacency]
          auto-like -> 0x6833 [manual_decompile]
              -> 0x7922 [manual_decompile]
              -> 0x597F [manual_decompile]
              -> XDATA[dptr] = 0x04 [manual_decompile]
              -> 0x5A7F [chain_adjacency]
              -> 0x7DC2 [chain_adjacency]

0x3104
  -> 0x673C object/status updater [direct_static + manual_decompile]
      -> 90CYE02 object-status layer candidate [hypothesis]
```

## Confidence updates
| address | previous_role | new_lifecycle_role | confidence_change | reason |
|---|---|---|---|---|
| 0x3010..0x301B | generic state cluster | zone/object state table candidates tied to 0x737C | up (hypothesis -> probable) | manual downstream decompile explicitly ties reads/writes and calls to 0x84A6/0x5A7F |
| 0x30E7 | state byte candidate | runtime mode-gate flag byte used by 0x728A E0/E1/E2 | up (low -> probable) | manual decompile control-point evidence for JNB gates and write-back paths |
| 0x30E9 | unknown side byte | 0x728A side-path state/mode byte | up (hypothesis -> low) | manual 0x728A pseudocode includes repeated writes |
| 0x31BF | generic runtime context | packet/output selector-context byte adjacent to 0x497A/0x737C | stable low | direct reads in trace map + downstream context relation |
| 0x364B | unknown pointer arg | packet/output transition context around 0x728A/0x6833/0x5A7F | up (hypothesis -> low) | manual decompile adjacency around output-start path |
| 0x3104 (90CYE02) | shifted status byte | object-status layer candidate used by 0x673C | up (probable -> probable) | retained from module manual decompile; separate family context |

## Unknowns and bench validation
- Trace writes to `0x3010..0x301B` during fire/fault/service transitions.
- Trace `0x315B/0x3181` before manual/auto mode changes.
- Trace `0x30E7` bits `E0/E1/E2` before/after `0x728A`.
- Trace `0x30E9` around `0x728A` branch paths.
- Trace `0x31BF/0x364B` around packet/export transitions.
- Trace `0x3104` on 90CYE02 object-state changes.

## DKS v1 integration note

Текущая lifecycle-модель является входом для:
- `docs/dks_packet_export_reconstruction.md` (контекст `0x31BF`, `0x364B`, `0x36D3..0x36FD`)
- `docs/dks_output_action_reconstruction.md` (контекст `0x30E7`, `0x30E9`, `0x30EA..0x30F9`)
- `docs/dks_firmware_technical_reconstruction_v1.md` (консолидированный v1 отчёт)

Физическая семантика выходов остаётся в статусе hypothesis до bench-подтверждения.
