# 90CYE02 / ППКП-01Ф-27 fire damper logic

Evidence level: `project_documentation`

## Confirmed function
- 90CYE02 controls огнезадерживающие клапаны (fire dampers).
- Receives `Пожар` from 90CYE01 over RS-485.
- On fire: removes voltage from damper control circuits.
- Valves close after voltage removal.
- Valve state is monitored by open/closed limit switches.
- Block assembly status is monitored.

## Firmware search implications
- RS-485 fire input decode/dispatch path.
- remove_voltage action branch.
- valve_close state transition path.
- open/closed limit switch readback.
- wrong position / fault handling hypothesis.
- object status table updater (shifted_DKS candidate family).

## Unknowns
- exact terminal tables in extracted scope.
- timeout/retry logic.
- line supervision details.
- numeric enum values and command IDs.
