# Project scan technical extraction report v0.1

source_type: project_scan_extraction  
status: preliminary  
evidence_level: project_documentation  
generated_from: user supplied extraction  
limitations: OCR/readability limits; no RS-485 frame format; no numeric enum codes; no full terminal tables.

## General summary
This extraction consolidates project-level evidence for PPKP / DKS / extinguishing logic and ties it to firmware reconstruction targets. It confirms physical/system meaning for 90CYE01/02/03/04 roles and MDS/MVK integrations, while keeping code-level attribution evidence-gated.

## Sources
- User supplied project scan extraction report.
- Related project sheets/spec references in extraction package (69-1ES-AFP-SA-001 / 69-1ES-AFP-SA-002).

## Devices
- 90CYE01 / ППКП-01Ф-20.01: address fire alarm role, fire-state source, water extinguishing discrete input collector.
- 90CYE02 / ППКП-01Ф-27: fire damper control via voltage removal logic and limit-switch monitoring.
- 90CYE03 / ППКП-01Ф-19: aerosol start controller.
- 90CYE04 / ППКП-01Ф-19: aerosol start controller.

## Module/equipment table
- MDS еФ5.104.156 in 90CYE01 with CP/CF/CH discrete signals.
- MVK-2.1 as common any-zone-fire output path.
- GH003 / BC-12-A terminal box for CH001..CH004 routing.
- Sensors and controls include PS10, VSR, VSR-6, MCP5A, WR4001I.S, ИО 102-26.

## Terminals/connections
- MDS X03 CP/CF inputs on odd terminals (X03:1/3/5/7) tied through XG01 and L+.
- CH001..CH004 on X03:9..16 with GH003 / BC-12-A termination path.
- Cable family noted: КВВГЭнг(A)-FRLS 4х1,5.

## Algorithms
- 90CYE01 zone logic: one automatic detector -> Внимание, two automatic detectors -> Пожар, one manual detector -> Пожар.
- On fire in any zone: СОУЭ activation, ventilation shutdown via address relay modules, MVK-2.1 common output activation.
- 90CYE01 exports Пожар to 90CYE02/03/04 over RS-485.
- 90CYE02 on received fire: remove voltage from damper circuits, valves close, monitor limit-switch and block status.
- 90CYE03/04 on received fire: warning boards, auto/manual gating, ПУСК handling, 30 s delay, launch pulse to aerosol generators.
- Door limit switch disables auto mode for aerosol start; manual mode forces AO indicator semantics.

## States/enum candidates
Project-level terms: Внимание, Пожар, Автоматический режим, Ручной режим, Автоматика отключена, ПУСК, Дверь открыта/закрыта, Открыто/Закрыто, Неисправность, Нет связи, Обрыв, КЗ, Адресный конфликт, Не обнаружен, Сервис.
Numeric enum codes are not provided by project documentation.

## MDS/MUP/MVK/PVK section
- MDS presence in 90CYE01 is confirmed by project documentation.
- MVK-2.1 any-zone-fire role is confirmed by project documentation.
- MUP/PVK are not confirmed by project sheets in this extraction and remain split evidence: screen_configuration confirms labels, code handlers unresolved.

## Launch lines/control lines
- Aerosol launch action path is physically described at project level for 90CYE03/04.
- Launch-line resistance/open/short supervision is not confirmed in this extraction.

## RS-485/protocols
- Functional transfer Пожар from 90CYE01 -> 90CYE02/03/04 is confirmed.
- Frame format, numeric command codes, addressing map, baudrate, timeout/retry, CRC/checksum remain unknown.

## Firmware linkage
The extraction supports physical semantics and prioritizes firmware search targets for:
- zone state/threshold logic,
- any_zone_fire aggregation,
- packet/export fire transfer,
- MDS discrete input scan,
- damper voltage removal + limit status,
- aerosol mode gate + 30-second delay + start pulse chain.

## Confirmed / probable / hypothesis / unknown
### Confirmed (project_documentation)
- Device physical roles for 90CYE01/02/03/04.
- MDS еФ5.104.156 role and listed CP/CF/CH input set in 90CYE01.
- RS-485 fire-state transfer intent from 90CYE01 to 90CYE02/03/04.
- Aerosol 30-second delay and door interlock behavior.

### Probable (project_documentation + manual_decompile linkage)
- DKS aerosol chain candidates around 0x84A6/0x728A/0x6833/0x597F/0x7DC2/0x5A7F map to mode/start/export path.

### Hypothesis
- Exact handler ownership and full physical output mapping at function-address granularity.

### Unknown
- RS-485 packet format and numeric enums.
- Launch-line supervision details.
- Full terminal maps for all cabinets/modules beyond extracted sheets.

## What to add to repo
- Extracted markdown evidence pages under docs/extracted.
- Machine-readable device map (YAML).
- Project-to-firmware linkage bridge CSV.
- Project unknowns CSV.
- Search-target list for static/decompile follow-up.

## Search targets
See `docs/extracted/firmware_search_targets.md`.

## Conclusions
Project scans materially strengthen physical/system-level meaning but do not directly prove code-level handler addresses or numeric protocol/enum values. Evidence levels must stay separated and conservative until static/bench confirmation is added.

## Project-guided static analysis linkage

This extraction now feeds dedicated static analyzers:
- `scripts/project_guided_rs485_analyzer.py`
- `scripts/project_guided_enum_delay_interlock_analyzer.py`
- `scripts/project_guided_mds_mvk_valve_output_analyzer.py`
- `scripts/project_guided_static_summary_builder.py`

Outputs remain evidence-separated and do not imply bench confirmation.
