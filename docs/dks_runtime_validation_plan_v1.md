# DKS runtime validation plan v1

Generated: 2026-04-27 10:12:33Z

## Scope and safety
- This document is a **validation plan** and does not contain bench-confirmed runtime evidence.
- Static reconstruction evidence and future runtime evidence must be kept separate in stored artifacts.
- No physical semantics hypothesis (valve/siren/GOA/MVK/etc.) is promoted to confirmed status before direct IO capture.
- External outputs must be tested with safe dummy loads/indicators, never with real extinguishing actuators.
- All procedures must explicitly avoid unintended fire-extinguishing activation.

## Validation objectives
- U-001 packet_export: exact frame boundary and byte order around `0x5A7F`.
- U-002 output_action: physical meaning/correlation of `XDATA[DPTR] = 0x04`.
- U-003 enum_state_values: per-value operational meaning under controlled scenarios.
- U-004 MUP_handler: exclusive MUP handler attribution under slot isolation.
- U-005 PVK_handler: PVK-specific handler attribution under slot isolation.
- U-006 physical_output_semantics: whether output paths map to specific physical classes.

## Required instrumentation
- Serial/packet capture (if available).
- Logic analyzer and/or IO capture for output lines.
- XDATA watch/log mechanism (if available).
- Synchronized timestamping across all capture channels.
- Scenario trigger log with exact operator action timestamps.
- Screen/HMI status photo/video log.
- Power/reset state notes for each run.
- Module configuration notes (slot mapping before each scenario).

## XDATA watch list
- `0x3010..0x301B`
- `0x30E7`
- `0x30E9`
- `0x30EA..0x30F9`
- `0x315B`
- `0x3181`
- `0x31BF`
- `0x3640`
- `0x364B`
- `0x36D3..0x36FD`
- `0x3104` (for `90CYE02_27 DKS` object-status tests only)

## Function/path watch list
- `0x497A`, `0x737C`, `0x613C`, `0x84A6`, `0x728A`, `0x6833`, `0x5A7F`, `0x7922`, `0x597F`, `0x7DC2`
- `0x673C` (for `90CYE02_27 DKS` object-status tests)

## Packet/export validation tests
See `docs/dks_runtime_validation_matrix.csv` rows `PKT-01..PKT-07`.
For each test the matrix captures:
- trigger scenario
- expected function path
- XDATA watch list
- expected packet observation
- what would confirm `0x5A7F` role
- what would falsify the current packet hypothesis

## Output-action validation tests
See `docs/dks_runtime_validation_matrix.csv` rows `OA-01..OA-08`.
For each test the matrix captures:
- trigger scenario
- expected function path
- expected XDATA change
- external IO observation
- packet observation
- pass/fail criteria

## Enum/state validation tests
See `docs/dks_runtime_validation_matrix.csv` rows `ENUM-01..ENUM-10`.
For each test the matrix captures:
- required stimulus
- expected XDATA state byte
- expected downstream path
- expected screen/HMI status
- expected packet/export behavior
- confidence if confirmed

## MUP/PVK handler attribution tests
See `docs/dks_runtime_validation_matrix.csv` rows `MOD-01..MOD-06`.
For each test the matrix captures:
- screen slot
- module label
- expected candidate functions
- XDATA watch list
- expected external IO or status effect
- pass/fail criteria

## 90CYE02 object-status tests
See `docs/dks_runtime_validation_matrix.csv` rows `OBJ-01..OBJ-04`.

## Data collection procedure
1. Record firmware file and device screen before test.
2. Record module slots and enabled/disabled state.
3. Reset device to known normal state.
4. Start packet capture.
5. Start IO capture.
6. Start XDATA/function trace (if available).
7. Trigger one scenario.
8. Save captured data artifacts.
9. Annotate exact trigger time.
10. Return device to normal.
11. Repeat each test three times.

## Data import workflow
- Raw captures should be normalized into:
  - `docs/dks_packet_capture_schema.csv`
  - `docs/dks_io_capture_schema.csv`
- Summarized test outcomes should be appended using:
  - `docs/dks_bench_result_import_template.csv`
- Import commits must keep static evidence and bench evidence in separate sections/commits when practical.

## Confidence uplift model
If required tests succeed with synchronized evidence, projected uplift targets are:
- `packet_export`: `56% -> 75–85%`
- `output_action`: `54% -> 75–85%`
- `enum_state_values`: `61% -> 80–90%`
- `MUP_handler`: `49% -> 65–80%`
- `PVK_handler`: `47% -> 60–75%`
- `physical_output_semantics`: `29% -> 55–75%`
