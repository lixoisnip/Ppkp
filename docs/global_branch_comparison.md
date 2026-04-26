# Global branch comparison after smoke-test

## Smoke-test verification
- Проверено команд smoke-test: **18** (pass=18, fail=0).
- Firmware count по manifest: **10**.
- Глобальные скрипты считаются универсальными, A03/A04-скрипты считаются специализированными.

## Branches in scope
- A03_A04
- 90CYE_DKS
- 90CYE_v2_1
- 90CYE_shifted_DKS
- RTOS_service

## Branch `A03_A04`
- Files (2): A03_26.PZU, A04_28.PZU
- Valid/checksum: valid_hex=2/2, checksum_errors=0
- Entry vectors: 0x4100/0x4176/0x41D0/0x492E/0x4954/0x497A (x2)
- XDATA clusters: ui_object_state:0x3292-0x329C(confirmed); packet_path_window:0x4EAB-0x5003(likely); upper_xdata_flags:0x7FF2-0x7FF6(likely)
- Function count: 212
- Basic block count: 863
- Packet-like functions (global roles only): 36
- Writer-like functions (xdata_write_count>0): 36
- Confidence: **high**
- Notes: Contains specialized packet-window hypotheses; keep scoped to A03/A04.

## Branch `90CYE_DKS`
- Files (2): 90CYE03_19_DKS.PZU, 90CYE04_19_DKS.PZU
- Valid/checksum: valid_hex=2/2, checksum_errors=0
- Entry vectors: 0x4100/0x4176/0x41D0/0x492E/0x4954/0x497A (x2)
- XDATA clusters: dks_runtime_block:0x30EA-0x30F9(confirmed); dks_snapshot_pair:0x3122-0x3125(likely); dks_service_window:0x360C-0x36D3(likely)
- Function count: 196
- Basic block count: 1236
- Packet-like functions (global roles only): 56
- Writer-like functions (xdata_write_count>0): 60
- Confidence: **high**

## Branch `90CYE_v2_1`
- Files (2): 90CYE03_19_2 v2_1.PZU, 90CYE04_19_2 v2_1.PZU
- Valid/checksum: valid_hex=2/2, checksum_errors=0
- Entry vectors: 0x4100/0x4176/0x41D0/0x4933/0x4959/0x497F (x2)
- XDATA clusters: v2_state_block:0x315D-0x3195(confirmed); v2_object_window:0x3270-0x32D7(confirmed); v2_payload_window:0x449D-0x462D(likely); v2_upper_markers:0x740C-0x740F(likely)
- Function count: 266
- Basic block count: 1352
- Packet-like functions (global roles only): 54
- Writer-like functions (xdata_write_count>0): 42
- Confidence: **high**

## Branch `90CYE_shifted_DKS`
- Files (1): 90CYE02_27 DKS.PZU
- Valid/checksum: valid_hex=1/1, checksum_errors=0
- Entry vectors: 0x4100/0x4176/0x41D0/0x4933/0x4959/0x497F (x1)
- XDATA clusters: n/a
- Function count: 96
- Basic block count: 411
- Packet-like functions (global roles only): 15
- Writer-like functions (xdata_write_count>0): 17
- Confidence: **medium**
- Notes: Within-branch similarity unavailable for single-file branch.

## Branch `RTOS_service`
- Files (3): ppkp2001 90cye01.PZU, ppkp2012 a01.PZU, ppkp2019 a02.PZU
- Valid/checksum: valid_hex=1/3, checksum_errors=2
- Entry vectors: 0x4100/0x4176/0x41D0/0xB395/0xB3BB/0xB3E1 (x1)
- XDATA clusters: rtos_dispatch_core:0x6406-0x6422(confirmed); rtos_service_flags:0x759C-0x75AE(confirmed); rtos_secondary_flags:0x769C-0x76AA(likely)
- Function count: 305
- Basic block count: 3722
- Packet-like functions (global roles only): 101
- Writer-like functions (xdata_write_count>0): 64
- Confidence: **high**

## Evidence separation
### Global evidence
- Firmware inventory/manifest, branch matrix, vector entrypoints, function/basic-block/call/string aggregates.
- Packet-like and writer-like counts derived only from global `function_map.csv` attributes.

### A03/A04-only evidence
- Addresses 0x329C, 0x329D, 0x5003..0x5010 treated as branch-specific and excluded from global proof claims.
- A03/A04 specialized scripts (packet candidates, local traces, packet-window writers) are scoped hypotheses.

### Experimental evidence
- Any role annotations with confidence `hypothesis`/`unknown` remain experimental until branch-independent confirmation.

## Recommendation: next branch after A03/A04
- Recommended branch: **RTOS_service**.
- Why: Ветка RTOS_service имеет наибольшее покрытие по образцам (files=3) и достаточно глобальных структурных кандидатов (packet_like=101, writer_like=64).
- Continue analysis is feasible without scope mixing if global-vs-specialized evidence boundary above is preserved.
