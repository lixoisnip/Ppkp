# Cross-family input-board core and command set (Issue #50)

Date: 2026-04-26 (UTC).

## Goal

Identify a **shared input-board command vocabulary** and a **probable shared input-core role** across firmware families, while keeping confidence scoped to static evidence.

## Evidence sources used

- `docs/string_index.csv` (operator-command strings and addresses)
- `docs/output_control_candidates.csv` (functions with command-string adjacency and xdata/call evidence)
- `docs/zone_logic_candidates.csv` (RTOS-side high-score candidates with same command markers)
- `docs/runtime_branch_comparison.csv` (cross-branch role alignment for sensor/zone entry nodes)
- `docs/firmware_family_map.md` (branch grouping context)

## 1) Shared command vocabulary (confirmed where present)

The following panel command strings are present as a stable cluster:

- `<FUNC>`
- `<ENTER>`
- `<ACTIV>`
- `<SILENCE>`
- `<RESET>`

Observed in:

- `90CYE_DKS`: `90CYE03_19_DKS.PZU`, `90CYE04_19_DKS.PZU`
- `RTOS_service`: `ppkp2001 90cye01.PZU`, `ppkp2019 a02.PZU`

See machine-readable summary: `docs/input_board_core_matrix.csv`.

## 2) Probable shared input-core role across families

A role-level pattern is stable across branch families:

`input/sensor entry -> zone logic -> state/event bridge -> output/packet path`

Anchor functions for the entry/input side (from `runtime_branch_comparison.csv`):

- `90CYE_DKS`: `0x497A` (`sensor_zone`, same-address match)
- `90CYE_v2_1`: `0x497F` (`sensor_zone`, similar-role match)
- `90CYE_shifted_DKS`: `0x497F` (`sensor_zone`, similar-role match)
- `A03_A04`: `0x497A` (`sensor_zone`, same-address/similar-role)
- `RTOS_service`: `0xAB62` (`sensor_zone`, similar-role match)

Interpretation: addresses differ by branch family, but a **shared architectural role** for an input-core dispatcher/entry is preserved.

## 3) Command-adjacent core candidates (strongest static candidates)

Command markers co-locate with high-score output/state workers:

- `90CYE_DKS`: `0x6833` (both files), string refs include `<FUNC>/<ENTER>/<ACTIV>/<RESET>`
- `RTOS_service`: `0x9407` (`ppkp2001`) and `0x9826` (`ppkp2019`), plus numeric-key marker (`"  1 2 3 4 5 6 7 8"`)

This supports that these nodes are part of shared **operator-input to runtime-action** processing, even if branch-local implementations diverge.

## 4) What is shared vs what is still branch-specific

Shared (high confidence):

1. Command vocabulary cluster (`FUNC/ENTER/ACTIV/SILENCE/RESET`) in DKS + RTOS_service families.
2. Repeating role topology with an input/sensor-side entry node that feeds zone/state/output/packet stages.

Branch-specific / not fully proven:

1. Exact command decode table and key-scanning routine boundaries in A03/A04 and 90CYE_v2_1 (no stable command-string cluster extracted yet).
2. One-to-one equivalence of concrete function addresses across all families.
3. Full semantic mapping of numeric keys and long-press combinations without bench traces.

## 5) Milestone outcome for Issue #50

Issue #50 target is reached at **cross-cutting identification level**:

- Shared input-board command set identified where extractable.
- Shared input-core role identified across all branch families at role-topology level.
- Candidate per-family anchor addresses consolidated in `docs/input_board_core_matrix.csv`.

## 6) Recommended next deep step

1. Add a branch-scoped key-decoder trace around:
   - DKS: `0x6833`
   - RTOS: `0x9407/0x9826`
2. Correlate numeric-key markers (`"1..8"`) with xdata flag mutations and packet-export side effects.
3. For A03/A04 + v2_1, prioritize code-table (`MOVC`) extraction near `0x497A/0x497F` analogs to recover missing command-table evidence.
