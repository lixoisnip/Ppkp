# Project-guided MDS/MVK/valve/aerosol output static analysis

## CP/CF/CH linkage status
Project evidence strongly constrains expected inputs, but code-level channel/bit mapping is still low-confidence. CP/CF anchors are narrowed to upstream RTOS_service candidates, while CH-group mapping remains hypothesis.

## MVK-2.1 any-zone-fire output
A plausible static path candidate exists (`0x4358->0x920C->0x53E6`) for common fire output flow, but this is cross-family/static only and not bench-confirmed.

## 90CYE02 valve feedback narrowing
`0x673C` is currently the strongest static candidate for damper voltage-removal + limit switch feedback state handling. `0x758B` remains a secondary router hypothesis.

## Aerosol outputs separation
Candidate groups for AN/AU/AO/GOA can be separated statically into distinct path classes, but terminal-level mapping and pulse electrical parameters remain unresolved.

## MUP/PVK split status
MUP/PVK remain explicitly split: visible in screen configuration evidence but not confirmed in current project page subset; handler ownership remains unresolved.
