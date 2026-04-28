# RS-485 hardware observation: MAX1480ACPI modules

## Evidence level
- `hardware_observed`

## Observed hardware
- PCB silkscreen near interface area: `RS485`.
- Interface module marking observed in board photo: `MAX1480ACPI`.
- User-reported board population: two such RS-485 modules on the device board.

## Conservative interpretation
- Physical RS-485-capable hardware is confirmed on the board.
- With two observed/reported MAX1480-class transceiver modules, emulator reporting should consider two physical RS-485 channel candidates instead of assuming one channel.
- This increases confidence that UART/SFR/SBUF tracing is relevant as a data-source strategy.

## Unknown / unresolved
- Exact MCU pin mapping to each MAX1480 module.
- Exact UART0/UART1/SBUF mapping for this firmware+board combination.
- Direction-enable control pins and their SFR/GPIO mapping.
- Channel ownership/roles (inter-device bus vs internal module bus vs service/config channel).
- Baudrate and frame format.
- Addressing, command bytes, and payload layout.
- CRC/checksum rules.

## Boundaries
- Do **not** claim RS-485 command bytes from board-photo evidence alone.
- Do **not** assign physical channel roles without schematic/code/bench evidence.
- Do **not** treat SBUF-candidate writes as confirmed RS-485 traffic until MCU-UART-to-transceiver mapping is validated.

## Reporting impact
- Keep `SBUF0` / `SBUF1` as candidate mappings.
- When reporting UART/SBUF candidates, maintain explicit two-channel uncertainty (for example: channel candidate 0/1 or physical channel unknown).
- Keep protocol status conservative: unresolved until direct, repeatable UART/SBUF byte evidence (and ideally bench correlation) exists.
