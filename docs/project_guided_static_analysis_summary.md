# Project-guided static analysis summary

## 1. Scope and evidence separation
Project documentation was used as search constraints. Code claims remain separated into `static_code`, `manual_decompile`, `cross_family_pattern`, `hypothesis`, and `unknown` levels.

## 2. What project docs confirmed
- Device roles: 90CYE01 fire source, 90CYE02 damper controller, 90CYE03/04 aerosol start controllers.
- Project-level confirmation for RS-485 fire transfer, 30-second delay, door interlock, MDS CP/CF/CH, MVK output and warning/launch stages.

## 3. What static code search now supports
- RS-485 chain narrowed to high-fan-in bridge neighborhoods.
- Mode/timer/interlock chain narrowed around 0x84A6/0x728A/0x6833/0x7DC2.
- MDS/MVK/valve/output candidates grouped by device role with confidence caps.

## 4. RS-485 findings
- Strongest bridge remains 0x5A7F; no decisive frame-builder replacement identified.
- CRC/address/baud details remain unresolved.

## 5. Enum/delay/interlock findings
- Static support for 30-second delay path is present but timer-base details unresolved.
- Door-open to auto-disabled behavior is most strongly represented in 0x728A/0x84A6 candidate gates.

## 6. MDS/MVK/valve/aerosol output findings
- CP/CF/CH lines constrained by project docs; channel-bit mapping still unresolved.
- 90CYE02 valve feedback narrowed to 0x673C-centered candidates.
- AN/AU/AO/GOA separated into candidate output classes without terminal certainty.

## 7. MUP/PVK evidence split
MUP/PVK split is preserved explicitly: present in screen evidence, absent in current project-page subset, unresolved handler ownership.

## 8. What confidence improved
See `docs/project_guided_confidence_updates.csv`.

## 9. What remains unknown
See `docs/project_guided_remaining_unknowns_v2.csv`; PU-001..PU-013 remain open with narrowed static targets.

## 10. Next static targets
See `docs/project_guided_next_static_targets.csv`.

## 11. What additional project sheets would help most
- Protocol appendix (RS-485 frame/address/CRC/baud/timeout).
- Full terminal/object cross-reference for 90CYE02/03/04 outputs.
- MUP/PVK-specific project pages to reduce split-evidence ambiguity.


## Micro-decompile follow-up

Generated focused micro-decompile outputs (static-only, evidence-gated):
- docs/project_guided_micro_decompile.md
- docs/project_guided_micro_decompile_summary.csv
- docs/project_guided_micro_pseudocode.csv
- docs/project_guided_micro_constants.csv
- docs/project_guided_micro_xdata_flow.csv
- docs/project_guided_micro_unknowns_update.csv

## Micro-decompile pass #2

Generated artifacts:
- docs/project_guided_micro_decompile_pass2.md
- docs/project_guided_micro_pass2_summary.csv
- docs/project_guided_micro_pass2_pseudocode.csv
- docs/project_guided_micro_pass2_constants.csv
- docs/project_guided_micro_pass2_xdata_flow.csv
- docs/project_guided_micro_pass2_callsite_matrix.csv
- docs/project_guided_micro_pass2_unknowns_update.csv
