# Project-guided micro-decompile pass #3

## Scope
- Static pass #3 only.
- Project evidence used as constraints.
- No bench claims.
- Family separation preserved (90CYE_DKS / 90CYE_shifted_DKS / RTOS_service).
- No optional input warnings.

## Pending target summary
| priority | area | branch | file | function_addr | micro_role_after | confidence | evidence_level |
|---|---|---|---|---|---|---|---|
| P2 | RTOS_service | RTOS_service | ppkp2001 90cye01.PZU | 0x9275 | rtos_service_generic_helper_with_table_copy_adjacency | medium | static_code+manual_decompile |
| P2 | Shifted status bridge | 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | 0x7773 | shifted_status_branch_helper_candidate | low_to_medium | static_code+cross_family_pattern |
| P3 | Zone/object | 90CYE_DKS | 90CYE03_19_DKS.PZU | 0x73FD | caller_envelope_prep_for_0x737C_0x84A6 | medium | static_code+manual_decompile+hypothesis |

## 0x9275 RTOS_service table/helper analysis
- What calls 0x9275? callers=0x4382; callees=0x8F8C,0x90D1,0x93BC,0x92C5; xdata_refs=35/0; enum_values=-
- Classification: generic service/helper with table-copy adjacency; not enough proof for baud/checksum helper.
- Relation to 0x920C/0x9255/0x4374/0x758B: same RTOS_service envelope; 0x4374 appears as caller-router window and 0x9255 as nearby helper continuation.

## 0x7773 shifted_DKS status branch analysis
- Function-window summary: callers=-; callees=0x6331,0x7866,0x604B,0x7851,0x6200; xdata_refs=53/0; enum_values=-
- XDATA around 0x3104/0x3108/0x31DD/0x32B2/0x32B3 was searched via xdata proximity and branch map context.
- Relation to 0x613C/0x673C: strengthened as shifted status branch helper candidate only; open/closed/fault bit mapping remains unproven.

## 0x73FD DKS caller-envelope analysis
- Function-window summary: callers=-; callees=0x84A6,0x5A7F,0x74C0,0x597F; xdata_refs=55/0; enum_values=-
- 0x73FD is retained as caller-envelope prep around 0x737C/0x84A6 context staging and bridge adjacency.
- Enum compare extraction remains incomplete; immediate values extracted conservatively in constants CSV.

## UART/baud candidate search
- Candidate rows: 25 (token-hits only, generally low confidence).
- PU-003 status: unchanged unresolved/no_baud_proof unless stronger register-divisor linkage appears.

## CRC/checksum candidate search
- Candidate rows: 208 (xor/add/rotate op proximity hits).
- PU-004 status: still unresolved; no bounded packet-buffer checksum loop/table proved.

## 0x5A7F caller block expansion
- Caller rows added for: 0x55AD, 0x55C0, 0x55C9, 0x55E6, 0x55F9, 0x5602.
- Each row records pre-call setup, post-call write behavior (if present), and conservative field-role hypothesis.

## Timer/output downstream search
- Candidate rows: 5 from 0x728A/0x6833/0x7DC2/0x84A6 downstream trace neighborhoods.
- Pulse-width constants remain unresolved; outputs classified as candidate classes only.

## Unknowns update
- Updated PU-001, PU-002, PU-003, PU-004, PU-006, PU-009, PU-010, PU-011 in pass3 unknowns CSV.

## Next targets
- next_static: 0x920C table-origin root, 0x5A7F post-call write-class separators, 0x613C/0x673C exit-to-status handlers.
- blocked_until_docs: protocol baud/framing/checksum details; terminal/object tables.
- blocked_until_bench: physical terminal mapping and pulse-duration confirmation.
- low_priority: broad cross-family cosmetic enum labels without new static anchors.
