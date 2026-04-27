# Project-guided micro-decompile pass

## Scope and evidence rules
- This pass is static micro-decompile only.
- Project evidence is used as search constraint, not as proof of physical semantics.
- No bench-confirmed physical claims are made.
- Function attribution and semantics remain evidence-gated: `project_documentation`, `static_code`, `manual_decompile`, `cross_family_pattern`, `hypothesis`, `unknown`.
- DKS semantics are not blindly transferred into RTOS_service or A03/A04.

- No missing optional inputs detected.

## Target summary

| priority | area | branch | file | function_addr | target_reason | manual_role_before | micro_role_after | confidence | evidence_level | unknowns_reduced |
|---|---|---|---|---|---|---|---|---|---|---|
| P1 | RS-485 | 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x5A7F | RS-485 packet bridge | RS-485 packet bridge | packet_bridge_or_pointer_resolver (not proven frame builder) | medium | manual_decompile+static_code | PU-001|PU-004 |
| P1 | RTOS_service | RTOS_service | ppkp2001 90cye01.PZU | 0x920C | packet/address/baud/parser candidate | packet/address/baud/parser candidate | core_service_worker_candidate; parser/address/baud unresolved | medium | static_code+manual_decompile | PU-002|PU-003 |
| P1 | Delay/Output-start | 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x6833 | 30s delay/output-start | 30s delay/output-start | output_start_stage after gate; writes marker 0x04 | medium | manual_decompile+static_code+project_documentation | PU-006|PU-009 |
| P2 | Valve status | 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | 0x673C | valve object-status | valve object-status | object/status updater candidate with branch split | low_to_medium | manual_decompile+cross_family_pattern | PU-010 |
| P2 | Aerosol outputs | 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x7DC2 | GOA launch vs warning outputs | GOA launch vs warning outputs | downstream output/service transition after start marker | low_to_medium | manual_decompile+static_code | PU-009|PU-011 |

## 0x5A7F micro-decompile: packet bridge vs builder
- Direct callers (call-site addresses): 0x55AD, 0x55C0, 0x55C9, 0x55E6, 0x55F9, 0x5602.
- Immediate constants in local window: 0x82, 0x83.
- Packet/export adjacency rows: 99; output/action adjacency rows: 43.
- XDATA near-window refs: 10; branch-trace refs: 0; enum compare refs: 0.
- Micro-role after pass: packet_bridge_or_pointer_resolver (not proven frame builder) (medium, manual_decompile+static_code).
- Caveat: High fan-in LCALL sink; caller-side MOVX serialization remains stronger than in-function serializer hypothesis.

Pseudocode skeleton:
```c
void fn_5A7F(ctx) {
  // resolve/stage pointer/context from caller registers
  // return quickly; caller continues MOVX/data-path activity
}
```

## 0x920C RTOS_service micro-decompile
- Direct callers (call-site addresses): 0x471D, 0x4374.
- Immediate constants in local window: 0x7638, 0x75A9, 0x7640, 0xCA, 0x49D5, 0x90CD, 0x4A0F, 0x0B.
- Packet/export adjacency rows: 0; output/action adjacency rows: 0.
- XDATA near-window refs: 13; branch-trace refs: 0; enum compare refs: 0.
- Micro-role after pass: core_service_worker_candidate; parser/address/baud unresolved (medium, static_code+manual_decompile).
- Caveat: Compared against 0x758B/0x53E6/0xAB62 anchors; no direct baud divisor proof.

Pseudocode skeleton:
```c
void fn_920C(service_ctx) {
  // service worker step in 0x4358 -> 0x920C -> 0x53E6 chain
  // read/update service flags + context bytes
  // call helpers; return to caller router
}
```

## 0x6833 micro-decompile: 30s delay and output-start
- Direct callers (call-site addresses): 0x7876.
- Immediate constants in local window: 0x5A7F, 0x7108, 0x7922, 0x597F, 0xEA, 0xEF, 0x04, 0x71A8.
- Packet/export adjacency rows: 1; output/action adjacency rows: 28.
- XDATA near-window refs: 16; branch-trace refs: 0; enum compare refs: 0.
- Micro-role after pass: output_start_stage after gate; writes marker 0x04 (medium, manual_decompile+static_code+project_documentation).
- Caveat: 30s semantic remains project-constrained; timer arithmetic not fully isolated in-function.

Pseudocode skeleton:
```c
void fn_6833(start_ctx) {
  // executes after gating path (0x597F)
  // obtains helper result (0x7922 path context)
  // writes XDATA[DPTR] = 0x04 marker candidate
  // continues into 0x7DC2 transition
}
```

## 0x673C micro-decompile: 90CYE02 valve object-status
- Direct callers (call-site addresses): 0x6667.
- Immediate constants in local window: 0x3104, 0x30CE, 0xE2, 0x30B0, 0x321D, 0xF0, 0x20, 0x4575.
- Packet/export adjacency rows: 0; output/action adjacency rows: 0.
- XDATA near-window refs: 28; branch-trace refs: 0; enum compare refs: 0.
- Micro-role after pass: object/status updater candidate with branch split (low_to_medium, manual_decompile+cross_family_pattern).
- Caveat: 0x3104-shifted context suggests status table logic; open/closed/fault bits not fully decoded.

Pseudocode skeleton:
```c
void fn_673C(obj_ctx) {
  // read shifted status context (including 0x3104-neighborhood)
  // branch by masks/comparisons into status-update paths
  // update object/status table candidates
}
```

## 0x7DC2 micro-decompile: GOA launch pulse vs warning outputs
- Direct callers (call-site addresses): no direct call-window constants found.
- Immediate constants in local window: 0x7121, 0xF0.
- Packet/export adjacency rows: 0; output/action adjacency rows: 3.
- XDATA near-window refs: 18; branch-trace refs: 0; enum compare refs: 0.
- Micro-role after pass: downstream output/service transition after start marker (low_to_medium, manual_decompile+static_code).
- Caveat: GOA pulse vs AN/AU/AO split unresolved; no direct pulse-width immediate found in local window.

Pseudocode skeleton:
```c
void fn_7DC2(out_ctx) {
  // downstream transition after output-start marker path
  // service/output dispatch tail
  // may bridge to packet/export path (0x5A7F adjacency)
}
```

## Cross-target relationship

- 90CYE01 fire -> RS-485 export -> 90CYE03/04 fire receive (`project_documentation`)
- -> 0x84A6 / 0x728A mode gate (`manual_decompile`)
- -> prestart / delay candidate (`hypothesis`)
- -> 0x6833 output-start candidate (`manual_decompile`)
- -> 0x597F guard (`manual_decompile`)
- -> 0x7922 state/table helper (`manual_decompile`)
- -> XDATA[dptr] = 0x04 (`static_code+manual_decompile`)
- -> 0x5A7F packet/export bridge (`manual_decompile+static_code`)
- -> 0x7DC2 output/service transition (`manual_decompile`)

- 90CYE02 fire receive (`project_documentation`)
- -> 0x673C object/status updater candidate (`cross_family_pattern+manual_decompile`)
- -> valve close / limit-switch feedback hypothesis (`hypothesis`)

- RTOS_service (`project_documentation`)
- -> 0x920C candidate (`static_code+manual_decompile`)
- -> 0x758B / 0x53E6 / 0xAB62 neighborhood (`static_code`)

## Unknowns reduced

| unknown_id | old_status | new_status | reason | remaining_gap | next_step |
|---|---|---|---|---|---|
| PU-001 | partial_static_narrowing | micro_narrowed_bridge_vs_builder | 0x5A7F appears bridge/resolver with caller-side MOVX evidence | exact frame byte layout | expand 0x497A/0x737C byte loops |
| PU-002 | unresolved | partial_static_narrowing | 0x920C chain context refined; no explicit 90CYE01/02/03/04 map constant | address table unresolved | scan code/data tables near 0x920C/0x53E6 |
| PU-003 | unresolved | partial_static_narrowing | 0x920C classified as service worker; divisor-like constants not proven | baud divisor constant unresolved | trace UART init windows |
| PU-004 | unresolved | partial_static_narrowing | no strong checksum arithmetic loop in 0x5A7F micro window | CRC/checksum algorithm unknown | target arithmetic loops adjacent to packet writers |
| PU-006 | partial_static_narrowing | micro_narrowed | 0x6833/0x597F/0x7922 ordering strengthened; 0x04 marker observed | numeric enum codes still ambiguous | extract more compare immediates |
| PU-009 | unresolved | partial_static_narrowing | 0x6833->0x7DC2 path refined | pulse width constant unresolved | search timer blocks post-0x7DC2 |
| PU-010 | partial_static_narrowing | micro_narrowed | 0x673C status updater branch separation strengthened | terminal/object exact mapping unknown | trace 0x3104-shifted paths |
| PU-011 | partial_static_narrowing | micro_narrowed | warning-vs-launch split at 0x7DC2 remains candidate only | AN/AU/AO/GOA terminal mapping unresolved | separate output classes by write targets |

## Next micro targets
- P2 Delay/Output-start: 0x597F
- P2 Delay/Output-start: 0x7922
- P2 RS-485: 0x497A
- P2 RS-485: 0x737C
- P2 RTOS_service: 0x4374
- P2 RTOS_service: 0x9255
- P2 Valve status: 0x613C
- P3 Aerosol outputs: 0x84A6
- P3 Valve status: 0x758B
