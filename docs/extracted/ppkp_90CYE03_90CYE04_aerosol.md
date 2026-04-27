# 90CYE03/90CYE04 / ППКП-01Ф-19 aerosol start logic

Evidence levels: `project_documentation` + linkage hints to `manual_decompile`

## Confirmed project-level behavior
- 90CYE03 and 90CYE04 receive `Пожар` from 90CYE01 via RS-485.
- Auto/manual modes are present.
- `ПУСК` command path exists.
- Warning boards АН/АУ are activated before start.
- Start delay is 30 seconds.
- Launch pulse is sent to aerosol generators after delay.
- Door limit switch blocks auto mode.
- Open door -> auto disabled/manual mode.
- AO `Автоматика отключена`:
  - ON in manual mode.
  - OFF in automatic mode.

## Firmware linkage targets (not direct confirmation)
- 0x84A6 / 0x728A: mode/event/mode-gate candidates.
- 0x6833: output-start candidate.
- 0x597F: guard/helper candidate.
- 0x7DC2: downstream transition candidate.
- timer/delay search for 30 sec / 30000 ms equivalents.
- door_open / auto_disable branch conditions.
- warning output table candidates.

## Unknowns
- launch-line supervision (resistance/open/short) not confirmed.
- launch pulse parameters (duration/form) not found.
- numeric command code for launch/start remains unknown.
