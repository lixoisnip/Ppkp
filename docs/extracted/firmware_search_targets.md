# Firmware search targets from project extraction

Evidence level: `project_documentation` (search guidance only)

## Russian strings
- Внимание
- Пожар
- Пуск
- Автоматика отключена
- Аэрозоль
- Газ! Не входи
- Ручной
- Автоматический
- Открыто
- Закрыто
- Неисправность
- Нет связи
- ИО 102-26
- БОП
- ФИЛИН

## Latin transliteration / English terms
- FIRE
- ATTENTION
- START
- AUTO
- MANUAL
- DOOR
- VALVE
- DAMPER
- RS485
- PACKET
- EXPORT

## Module names and aliases
- MDS
- МДС
- eF5.104.156
- EF5_104_156
- MVK
- МВК
- МВК-2.1

## Tag names / equipment identifiers
- CP051
- CF051
- CF052
- CF053
- CH001
- CH002
- CH003
- CH004
- CH001..CH004
- GH003
- BC-12-A
- VSR
- VSR-6
- PS10
- MCP5A
- WR4001I

## Numeric constants / delay targets
- 30
- 30000

## Algorithm-centric search patterns
- one_automatic_detector_attention
- two_automatic_detectors_fire
- one_manual_detector_fire
- any_zone_fire
- rs485_fire_export
- remove_voltage
- valve_close
- door_open_auto_disable
- mode_gate
- start_delay_30s
- warning_board_prestart


## Project-guided analyzer targets
- RS-485 bridge/builder/parser/CRC/timeout paths (PU-001..PU-005).
- Enum and delay/interlock paths around `0x84A6/0x728A/0x6833` (PU-006).
- MDS CP/CF/CH input grouping, MVK output, valve feedback, aerosol AN/AU/AO/GOA split (PU-007..PU-013).
