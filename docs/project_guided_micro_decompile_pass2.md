# Project-guided micro-decompile pass #2

## Scope
- Static micro-decompile pass #2.
- Project evidence used as constraint only.
- No bench confirmation.
- Families kept separate (DKS / shifted_DKS / RTOS_service).
- DKS semantics were not blindly transferred to RTOS_service.

- No optional input warnings.

## Target summary

| priority | area | branch | file | function_addr | target_reason | micro_role_after | confidence | evidence_level | unknowns_reduced | next_step |
|---|---|---|---|---|---|---|---|---|---|---|
| P2 | Delay/Output-start | 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x597F | compact helper around 0x6833 start path | bitmask_guard_helper (returns A & 0x07) | probable | manual_decompile+static_code | PU-006|PU-009 | deepen callsite windows / helper context extraction |
| P2 | Delay/Output-start | 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x7922 | two-byte helper in 0x6833/0x728A path | two_byte_xdata_pair_reader (R0/R1) | probable | manual_decompile+static_code | PU-006|PU-009 | deepen callsite windows / helper context extraction |
| P2 | RS-485 / runtime bridge | 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x497A | byte-loop expansion around 0x5A7F caller windows | shared_runtime_dispatcher_with_packet_bridge_adjacency | medium | manual_decompile+static_code+project_documentation | PU-001|PU-004 | deepen callsite windows / helper context extraction |
| P2 | Zone/object | 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x737C | zone/object event/state path feeding 0x84A6 and 0x5A7F | zone_object_state_update_plus_event_bridge_adjacency | medium | manual_decompile+static_code | PU-010|PU-011 | deepen callsite windows / helper context extraction |
| P3 | Mode/event bridge | 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x84A6 | mode/context bridge to 0x728A and packet bridge | mode_context_bridge_to_0x728A_and_0x5A7F | low_to_medium | manual_decompile+static_code+hypothesis | PU-009|PU-011 | deepen callsite windows / helper context extraction |
| P2 | RTOS_service | RTOS_service | ppkp2001 90cye01.PZU | 0x4374 | caller/router around 0x920C | service_router_init_window_calling_0x920C | medium | static_code+manual_decompile | PU-002|PU-003|PU-004 | deepen callsite windows / helper context extraction |
| P2 | RTOS_service | RTOS_service | ppkp2001 90cye01.PZU | 0x9255 | post-0x920C helper continuation | rtos_service_helper_continuation (snapshot/copy from 0x763A.. into regs) | medium | static_code+manual_decompile | PU-002|PU-003|PU-004 | deepen callsite windows / helper context extraction |
| P2 | RTOS_service | RTOS_service | ppkp2001 90cye01.PZU | 0x758B | high-fanout RTOS dispatcher XDATA timeline | rtos_service_dispatcher_with_state_xdata_timeline | medium | static_code+manual_decompile | PU-002|PU-003|PU-006 | deepen callsite windows / helper context extraction |
| P2 | Shifted status bridge | 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | 0x613C | shifted_DKS follow-up for status/valve path | shifted_status_bridge_candidate (not assumed equal to DKS 0x613C) | low_to_medium | static_code+cross_family_pattern | PU-010 | deepen callsite windows / helper context extraction |

## 0x597F guard/helper analysis
- Direct callers: 0x5935, 0x7194, 0x7711, 0x6077, 0x6FA7, 0x70CC, 0x740F, 0x7439, 0x7462, 0x683A.
- Callee targets in local function window: none in bounded window.
- Local constants: 0x07.
- XDATA refs (near-window/branch-map): 23/0.
- Enum compare values in map: none mapped for this function.
- Output-transition adjacency rows: 0; packet-callsite adjacency rows: 0.
- Micro role after pass2: bitmask_guard_helper (returns A & 0x07) (probable; manual_decompile+static_code).
- Conservative caveat: No XDATA access in helper body; caller-side meaning (permission/mode/fault) remains unresolved.
- Is it really `A & 0x07`? **Yes, in the direct body window (ANL A,#0x07), with conservative `probable` confidence.**
- What consumes return value? **Caller paths near 0x6833/0x737C via callsites (e.g., 0x5935, 0x7194, 0x73BA) consume masked accumulator context.**
- Output-start/project launch gate relation: **hypothesis only; no direct physical gate claim.**

## 0x7922 state/table reader analysis
- Direct callers: 0x54C1, 0x7187, 0x72C8, 0x72FF, 0x7349, 0x6836.
- Callee targets in local function window: none in bounded window.
- Local constants: none extracted.
- XDATA refs (near-window/branch-map): 49/0.
- Enum compare values in map: none mapped for this function.
- Output-transition adjacency rows: 0; packet-callsite adjacency rows: 0.
- Micro role after pass2: two_byte_xdata_pair_reader (R0/R1) (probable; manual_decompile+static_code).
- Conservative caveat: Confirmed MOVX->R0, INC DPTR, MOVX->R1 pattern; table semantic remains context-dependent.
- Confirmed pseudocode: `MOVX A,@DPTR -> R0; INC DPTR; MOVX A,@DPTR -> R1; RET`.
- DPTR source remains caller-provided; static evidence supports generic pair/table reads in 0x6833/0x728A-adjacent paths.

## 0x497A byte-loop / packet-prep analysis
- Direct callers: none listed.
- Callee targets in local function window: none in bounded window.
- Local constants: 0x0F, 0x0035, 0xF0, 0x04.
- XDATA refs (near-window/branch-map): 3/1.
- Enum compare values in map: 0x01, 0x02, 0x04, 0x05, 0x08, 0x7E, 0xFF.
- Output-transition adjacency rows: 29; packet-callsite adjacency rows: 1.
- Micro role after pass2: shared_runtime_dispatcher_with_packet_bridge_adjacency (medium; manual_decompile+static_code+project_documentation).
- Conservative caveat: Many callsites into 0x5A7F exist; caller-side loops/state fanout dominate over in-body serializer proof.
- Caller-side repeated calls into 0x5A7F are visible in transition map/callsite matrices.
- MOVX writes are present in broader function windows, but strict in-body byte-serialization proof remains incomplete.
- Classified as mixed dispatcher + packet bridge adjacency, not hard-labeled packet builder.

## 0x737C zone/object event-record analysis
- Direct callers: 0x8625.
- Callee targets in local function window: 0x5AA3, 0x5A7F, 0x73BA, 0x848E, 0x84A6, 0x74C0, 0x597F.
- Local constants: 0x5A7F, 0x31BF, 0x00, 0x01, 0x03, 0x0F, 0xF0, 0x597F, 0x07, 0x848E, 0x08, 0x36EC.
- XDATA refs (near-window/branch-map): 38/1.
- Enum compare values in map: 0x03, 0x07.
- Output-transition adjacency rows: 10; packet-callsite adjacency rows: 2.
- Micro role after pass2: zone_object_state_update_plus_event_bridge_adjacency (medium; manual_decompile+static_code).
- Conservative caveat: Touches 0x3010..0x301B and reads 0x31BF/0x36xx cluster before calling 0x84A6 and 0x5A7F.
- Evidence supports both state-table updates (`0x3010..0x301B`) and bridge adjacency to packet path (0x5A7F).
- Enum-like compares/masks include `0x03`, `0x07`, and CJNE branches (still hypothesis-level semantics).

## 0x84A6 mode/event bridge analysis
- Direct callers: 0x7105, 0x73FD.
- Callee targets in local function window: 0x862D, 0x7D42, 0x6025, 0x77BF, 0x7184, 0x7889, 0x728A, 0x770C, 0x6EF2, 0x7017, 0x6E32, 0x7A9A.
- Local constants: 0x36D3, 0x862D, 0x3181, 0x315B, 0xAF, 0x30D4, 0x5A7F, 0xE3, 0xE5, 0x7D42, 0x3640, 0x3C.
- XDATA refs (near-window/branch-map): 37/0.
- Enum compare values in map: none mapped for this function.
- Output-transition adjacency rows: 0; packet-callsite adjacency rows: 0.
- Micro role after pass2: mode_context_bridge_to_0x728A_and_0x5A7F (low_to_medium; manual_decompile+static_code+hypothesis).
- Conservative caveat: Mode/event bridge plausible from XDATA cluster 0x315B/0x3181/0x3640/0x36D3/0x36D9 but physical mapping stays hypothesis.
- Exact mode/context XDATA references include `0x315B`, `0x3181`, `0x3640`, `0x36D3`, `0x36D9` (plus broader adjacent context).
- Can feed 0x728A gate inputs and selected packet-bridge context, but door-open/auto-disabled physical semantics remain hypothesis.

## 0x4374 RTOS_service caller/router analysis
- Direct callers: none listed.
- Callee targets in local function window: 0x920C, 0x916D, 0x9275, 0x8F8C, 0x43FC, 0x498F, 0x9143, 0x9134, 0x6BA4.
- Local constants: 0x8F8C, 0x80, 0x10, 0x05, 0x0C, 0x04, 0x66EB, 0x6408, 0x07, 0x920C, 0x916D, 0xFF.
- XDATA refs (near-window/branch-map): 48/0.
- Enum compare values in map: none mapped for this function.
- Output-transition adjacency rows: 0; packet-callsite adjacency rows: 0.
- Micro role after pass2: service_router_init_window_calling_0x920C (medium; static_code+manual_decompile).
- Conservative caveat: Contains looped MOVX writes and immediate table initialization after 0x920C/0x916D.
- Calls 0x920C then executes service-init style loops (MOVX writes around 0x646E/0x67EA/0x785F/0x6FE8 windows).
- Treated as RTOS_service-local router/init path; no DKS semantic transfer.

## 0x9255 RTOS_service helper analysis
- Direct callers: none listed.
- Callee targets in local function window: 0x53E6, 0x8F8C, 0x90D1, 0x93BC, 0x92C5.
- Local constants: 0x8F8C, 0x66FF, 0x03, 0x90D1, 0x0F, 0x01, 0x53E6, 0x7640, 0x75A9, 0x763A, 0x06, 0x67D7.
- XDATA refs (near-window/branch-map): 27/0.
- Enum compare values in map: none mapped for this function.
- Output-transition adjacency rows: 0; packet-callsite adjacency rows: 0.
- Micro role after pass2: rtos_service_helper_continuation (snapshot/copy from 0x763A.. into regs) (medium; static_code+manual_decompile).
- Conservative caveat: Calls 0x53E6 then copies multi-byte XDATA sequence into R6..R1; checksum/baud role not proven.
- Classified as parser/service continuation helper candidate (calls 0x53E6, copies data block from 0x763A..).
- Address/baud/checksum signatures are not proven from this window alone.

## 0x758B RTOS_service XDATA timeline
- Direct callers: 0xABF5.
- Callee targets in local function window: 0x75B6, 0x75EA, 0x8F8C, 0x762C, 0x763E, 0x764C, 0x7659, 0x766A, 0x7677, 0x7690, 0x769E, 0x76AC.
- Local constants: 0x06, 0x00, 0x01, 0x03, 0x8F8C, 0x6406, 0x02, 0x08, 0x04, 0x14, 0x8FAF, 0x7F.
- XDATA refs (near-window/branch-map): 45/0.
- Enum compare values in map: none mapped for this function.
- Output-transition adjacency rows: 0; packet-callsite adjacency rows: 0.
- Micro role after pass2: rtos_service_dispatcher_with_state_xdata_timeline (medium; static_code+manual_decompile).
- Conservative caveat: Writes 0x3011/0x3014 markers, checks 0x66EA mask, updates 0x3010, mirrors 0x6406(+1).
- Timeline shows writes to 0x3011/0x3014, masked check on 0x66EA, conditionally updates 0x3010 and mirrors around 0x6406.
- Fits mixed shared dispatcher/service-role in RTOS_service context.

## 0x613C shifted_DKS status bridge analysis
- Direct callers: none listed.
- Callee targets in local function window: 0x61F6, 0x791E, 0x61D0, 0x6215, 0x61CC.
- Local constants: 0xF0, 0x10, 0x82, 0x83, 0x4575, 0x00, 0x30AF, 0xE6, 0xE5, 0x31DD, 0x791E, 0x32B2.
- XDATA refs (near-window/branch-map): 17/0.
- Enum compare values in map: none mapped for this function.
- Output-transition adjacency rows: 0; packet-callsite adjacency rows: 0.
- Micro role after pass2: shifted_status_bridge_candidate (not assumed equal to DKS 0x613C) (low_to_medium; static_code+cross_family_pattern).
- Conservative caveat: Reads 0x32B2 and writes around 0x3108/0x31DD windows; suggests status-bridge logic with shifted mapping.
- In 90CYE02 shifted_DKS, 0x613C appears relevant to object/status bridge behavior but is not assumed identical to DKS 0x613C semantics.
- Branch/mask and old/new-state style behavior is plausible; open/closed/fault mapping still unresolved.

## Unknowns update
- Updated: PU-001, PU-002, PU-003, PU-004, PU-006, PU-009, PU-010, PU-011 in `docs/project_guided_micro_pass2_unknowns_update.csv`.

## Next targets
- P1: `0x728A` (DKS gate context deepening), `0x920C` (RTOS parser/init boundary confirmation).
- P2: `0x9275` (RTOS_service helper after 0x4374 loop), `0x7773` (shifted_DKS analog table/context).
- P3: `0x73FD` (0x737C caller window refinement).
- blocked_until_docs: project-level protocol/commissioning pages for address/baud framing semantics.
- blocked_until_bench: physical terminal mapping and pulse timing confirmation.
