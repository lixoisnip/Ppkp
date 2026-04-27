# 90CYE01 / ППКП-01Ф-20.01 logic (project documentation)

Evidence level: `project_documentation`

## Confirmed role
- Address fire alarm controller and fire-state source.

## Confirmed detection/state logic
- One automatic detector in zone -> `Внимание`.
- Two automatic detectors in zone -> `Пожар`.
- One manual detector -> `Пожар`.

## Confirmed downstream actions on fire
- СОУЭ activation.
- Ventilation shutdown via address relay modules.
- MVK-2.1 output activation on any zone fire.
- RS-485 transfer of `Пожар` state from 90CYE01 to 90CYE02/03/04.

## Confirmed MDS water-extinguishing discrete signals context
- 90CYE01 includes MDS еФ5.104.156 with CP/CF/CH discrete input set (see dedicated MDS note).

## Firmware search implications
- zone table and zone status update logic.
- automatic detector count thresholds (1->attention, 2->fire).
- manual detector branch forcing fire.
- any_zone_fire aggregation and broadcast condition.
- packet/export path for propagated fire event.
- MVK output path for common fire output.
- MDS discrete input scan integration in 90CYE01 runtime.

## Guardrails
- Project docs confirm physical meaning, not handler ownership.
- Function addresses and numeric enums remain unresolved without static/bench evidence.
