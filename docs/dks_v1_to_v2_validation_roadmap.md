# DKS v1 -> v2 validation roadmap

Generated: 2026-04-27 10:12:33Z

## What v1 knows
- Global architecture and runtime chain are reconstructed at conservative confidence levels.
- Current estimates: global architecture 72%, execution chain 78%, XDATA lifecycle 74%.
- Packet/export, output-action, enum/state values and module-attribution edges remain validation-limited.

## Why bench/runtime validation is needed
Static analysis established plausible paths and candidate semantics, but unresolved unknowns U-001..U-006 require synchronized packet/IO/XDATA/function evidence to move from hypothesis/probable to validated.

## What to test first
Prioritize tests that collapse multiple unknowns at once and produce reusable data schemas:
1. packet framing (`PKT-01`, `PKT-02`)
2. output-start split and 0x04 correlation (`OA-02`, `OA-03`, `OA-06`)
3. enum anchors (`ENUM-02`, `ENUM-05`)
4. module slot isolation (`MOD-01`, `MOD-03`)

## Expected impact
Successful completion of the minimal set should significantly reduce ambiguity in packet framing, output-action meaning, enum values and MUP/PVK attribution.

## Minimal test set for fastest confidence uplift
- PKT-01
- PKT-02
- OA-02
- OA-03
- OA-06
- ENUM-02
- ENUM-05
- MOD-01
- MOD-03

## Full test set for v2.0 report
- Packet/export: `PKT-01..PKT-07`
- Output-action: `OA-01..OA-08`
- Enum/state: `ENUM-01..ENUM-10`
- Module attribution: `MOD-01..MOD-06`
- Object-status layer: `OBJ-01..OBJ-04`

## v2.0 readiness gate
v2.0 validated reconstruction should be published only after import-ready bench evidence exists in standardized packet/IO/result schema files and unknowns U-001..U-006 have explicit pass/fail outcomes linked to test IDs.
