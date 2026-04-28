# Front-panel display/keypad observation

- evidence_level: `hardware_observed`
- source: user-provided front-panel photos (2 photos)
- scope: physical front-panel UI evidence only; no firmware protocol claims.

## Observed display text

### Photo 1
- Line 1 (high confidence): `УСТАНОВКА`
- Line 2 (medium/low confidence due to glare/pixel readability): `Автоопред-е` or visually similar abbreviation.

### Photo 2
- Line 1 (high confidence): `АДР.МОДУЛЬ1.М2 300`
- Line 2 (high confidence): `ТИП2 НОРМА`

## Observed keypad buttons
- Numeric: `1,2,3`, `4,5,6`, `7,8,9`, `*,0,#`
- Navigation/actions: `Up arrow`, `Down arrow`, `РЕЖИМ`, `ВВОД`, `ПУСК`, `ОТБОЙ`, `ОТКЛ. ЗВУКА`, `СБРОС`

## Observed LED labels
- `ПУСК`
- `ПОЖАР`
- `ВНИМАНИЕ`
- `НЕИСПР.`
- `ПРОГРАММА`
- `КОНТРОЛЬ`
- `СВЯЗЬ`
- `ТЕСТ`
- `РУЧНОЙ`
- `АВТ.`
- `ОСНОВНОЕ`
- `РЕЗЕРВНОЕ`

## Interpretation (conservative)
- Device has a front-panel LCD/text display.
- Firmware and/or a connected display/keypad controller produces Russian UI text.
- Displayed UI appears relevant to runtime state, module address, type, and status.
- High-value firmware search anchors from observed text: `АДР.`, `МОДУЛЬ`, `ТИП`, `НОРМА`.

## Unknowns
- Display controller type.
- Display bus/protocol.
- Character encoding.
- Whether display is driven by direct MCU port writes, `MOVX` external I/O, or another controller.
- Exact firmware function(s) that format display strings.
- Keypad scan implementation details.
- LED output mapping.

## Boundaries
- Do **not** claim display protocol from photos.
- Do **not** claim exact encoded bytes unless found in firmware evidence.
- Do **not** map LEDs to bitfields without code/bench proof.
- Do **not** infer RS-485 commands from UI text.
