#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTRACTED = ROOT / "docs" / "extracted"


def write_file(relative_path: str, content: str) -> None:
    path = ROOT / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def main() -> int:
    EXTRACTED.mkdir(parents=True, exist_ok=True)

    write_file(
        "docs/extracted/project_scan_report_v0_1.md",
        """# Project scan technical extraction report v0.1

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
""",
    )

    write_file(
        "docs/extracted/ppkp_90CYE01_logic.md",
        """# 90CYE01 / ППКП-01Ф-20.01 logic (project documentation)

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
""",
    )

    write_file(
        "docs/extracted/ppkp_90CYE01_mds_water_extinguishing.md",
        """# 90CYE01 MDS water extinguishing discrete inputs

Evidence level: `project_documentation`

## Confirmed module
- MDS A1 еФ5.104.156 is present in 90CYE01 project documentation.

## Confirmed inputs
- 03SGC01CP051
- 03SGC01CF051
- 03SGC01CF052
- 03SGC01CF053
- 90CYE01CH001
- 90CYE01CH002
- 90CYE01CH003
- 90CYE01CH004

## Physical interpretation from project extraction
- CP051 = pressure switch PS10.
- CF051 = flow switch VSR.
- CF052/CF053 = VSR-6 sprinkler flow switches.
- CH001..CH004 = remote fire pump start devices.

## Terminal evidence
- X03:1 / XG01 + L+
- X03:3 / XG01 + L+
- X03:5 / XG01 + L+
- X03:7 / XG01 + L+
- X03:9..16 = CH001..CH004
- GH003 / BC-12-A terminal box used for CH lines.

## Firmware search implications
- discrete input scan routines for MDS-origin signals.
- bit masks / bitfield unpack paths for CP/CF/CH signals.
- edge vs level event generation around water signals.
- event terms tied to water pressure, flow, and remote pump start.

## Unknowns
- internal MDS address in runtime structures.
- protocol details between CPU and MDS.
- input word/byte layout.
- line break/short supervision behavior.
""",
    )

    write_file(
        "docs/extracted/ppkp_90CYE02_valves.md",
        """# 90CYE02 / ППКП-01Ф-27 fire damper logic

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
""",
    )

    write_file(
        "docs/extracted/ppkp_90CYE03_90CYE04_aerosol.md",
        """# 90CYE03/90CYE04 / ППКП-01Ф-19 aerosol start logic

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
""",
    )

    write_file(
        "docs/extracted/terminals_90CYE01_mds.md",
        """# 90CYE01 MDS terminals and connections

Evidence level: `project_documentation`

## MDS X03 input terminals
| Terminal | Tag / purpose | Notes |
|---|---|---|
| X03:1 | 03SGC01CP051 | via XG01 + L+ |
| X03:3 | 03SGC01CF051 | via XG01 + L+ |
| X03:5 | 03SGC01CF052 | via XG01 + L+ |
| X03:7 | 03SGC01CF053 | via XG01 + L+ |
| X03:9 | 90CYE01CH001 | CH group |
| X03:10 | unknown/reserve (CH group context) | extraction incomplete |
| X03:11 | unknown/reserve (CH group context) | extraction incomplete |
| X03:12 | unknown/reserve (CH group context) | extraction incomplete |
| X03:13 | 90CYE01CH002 | CH group |
| X03:14 | 90CYE01CH003 | CH group |
| X03:15 | 90CYE01CH004 | CH group |
| X03:16 | CH group return/context | extraction partial |

## GH003 / BC-12-A terminals
- GH003 identified as BC-12-A terminal box used for CH001..CH004 connectivity.
- Full pin-level GH003 table remains incomplete in current extraction.

## Cables and common lines
- Cable: `КВВГЭнг(A)-FRLS 4х1,5`.
- `L+` used as common line in listed CP/CF paths.
""",
    )

    write_file(
        "docs/extracted/states_enum_candidates.md",
        """# Project-level state/enum candidates

Evidence level: `project_documentation`

> Numeric codes remain unknown from project docs. Existing firmware enum candidates stay `hypothesis` unless direct static evidence upgrades them.

| term | project meaning | device scope | possible firmware enum/code sign | current numeric enum mapping if known | confidence | unknowns |
|---|---|---|---|---|---|---|
| Внимание | attention/pre-fire condition | 90CYE01 | zone state byte candidate | unknown | medium | exact enum value |
| Пожар | fire condition | 90CYE01/02/03/04 | fire_state / event code candidate | unknown | high | numeric code |
| Автоматический режим | automatic mode enabled | 90CYE03/04 | mode flag candidate | unknown | medium | bit/byte position |
| Ручной режим | manual mode enabled | 90CYE03/04 | mode flag inverse/state | unknown | medium | value mapping |
| Автоматика отключена | automation disabled indication | 90CYE03/04 | AO indicator output/state bit | unknown | medium | output index |
| ПУСК | start command | 90CYE03/04 | command/event branch | unknown | medium | command code |
| Дверь открыта | door-open interlock active | 90CYE03/04 | door_open input bit | unknown | medium | polarity and bit |
| Дверь закрыта | door closed normal state | 90CYE03/04 | door flag normal state | unknown | medium | value mapping |
| Открыто | valve/damper open position | 90CYE02 | limit-switch/open state | unknown | medium | enum/sign code |
| Закрыто | valve/damper closed position | 90CYE02 | limit-switch/closed state | unknown | medium | enum/sign code |
| МДС | module identity for discrete water inputs | 90CYE01 | module slot/id token | unknown | high | internal module id |
| Давление воды | water pressure status (PS10) | 90CYE01 | CP051-derived state/event | unknown | high | event code |
| Поток воды | flow status (VSR/VSR-6) | 90CYE01 | CF051/52/53-derived state/event | unknown | high | event code |
| Дистанционный пуск насосов | remote pump start input state | 90CYE01 | CH001..CH004 input state/event | unknown | high | bit mapping |
| Нерабочее положение | wrong/non-working position | 90CYE02 | fault state candidate | unknown | low | trigger logic |
| Неисправность клапана | valve fault | 90CYE02 | fault enum candidate | unknown | low | numeric code |
| Нет связи | no communication | all RS-485 linked devices | comm loss state | unknown | medium | timeout threshold |
| Обрыв | line break | lines/modules | line supervision fault | unknown | low | confirmed scope |
| КЗ | short circuit | lines/modules | short supervision fault | unknown | low | confirmed scope |
| Адресный конфликт | address conflict | addressed modules/bus | address conflict event | unknown | low | location in protocol |
| Не обнаружен | module/sensor not detected | modules/sensors | presence/missing enum | unknown | medium | code value |
| Сервис | service mode/state | maintenance context | service flag/state | unknown | low | where stored |
""",
    )

    write_file(
        "docs/extracted/firmware_search_targets.md",
        """# Firmware search targets from project extraction

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
""",
    )

    write_file(
        "docs/extracted/spec_69_1ES_AFP_SA_001.md",
        """# Spec 69-1ES-AFP-SA-001 extraction summary

Source: project specification extraction (user supplied project scan extraction report)
Evidence level: `project_documentation`

## Listed indications / labels
- `Газ! Не входи!`
- `Автоматика отключена`
- `Аэрозоль - не входи!`

## Listed devices/sensors/components
- ИО 102-26
- MCP5A
- WR4001I.S

## Notes
This file is a textual extraction summary only. Numeric enum/protocol/code mappings are not provided by this source.
""",
    )

    write_file(
        "docs/extracted/spec_69_1ES_AFP_SA_002.md",
        """# Spec 69-1ES-AFP-SA-002 extraction summary

Source: project specification extraction (user supplied project scan extraction report)
Evidence level: `project_documentation`

## Current extraction status
The source specification is referenced in the extraction package, but detailed row-level equipment breakdown for this sheet is incomplete in the current OCR/readability slice.

## Placeholder
- Keep this file as a placeholder marker for follow-up extraction pass.
- Do not infer additional equipment rows without direct source visibility.
""",
    )

    write_file(
        "docs/extracted/ppkp_devices.yaml",
        """devices:
  90CYE01:
    type: ППКП-01Ф-20.01
    role:
      - address_fire_alarm
      - zone_control
      - fire_state_source
      - water_extinguishing_discrete_input_collector
    confirmed_functions:
      - one_automatic_detector_attention
      - two_automatic_detectors_fire
      - one_manual_detector_fire
      - soue_activation
      - ventilation_shutdown
      - mvk_2_1_any_zone_fire
      - rs485_fire_export_to_90CYE02_03_04
    modules:
      MDS:
        type: еФ5.104.156
        evidence: project_documentation
        inputs:
          - tag: 03SGC01CP051
            physical: pressure_switch_PS10
            meaning: water_pressure_after_stop_chamber
          - tag: 03SGC01CF051
            physical: flow_switch_VSR
            meaning: flow_after_water_alarm_valve
          - tag: 03SGC01CF052
            physical: flow_switch_VSR_6
            meaning: sprinkler_pipe_flow
          - tag: 03SGC01CF053
            physical: flow_switch_VSR_6
            meaning: sprinkler_pipe_flow
          - tag: 90CYE01CH001
            physical: remote_pump_start
          - tag: 90CYE01CH002
            physical: remote_pump_start
          - tag: 90CYE01CH003
            physical: remote_pump_start
          - tag: 90CYE01CH004
            physical: remote_pump_start
      MVK_2_1:
        evidence: project_documentation
        role: any_zone_fire_output
    communications:
      rs485_fire_export_to:
        - 90CYE02
        - 90CYE03
        - 90CYE04

  90CYE02:
    type: ППКП-01Ф-27
    role:
      - fire_damper_control
    confirmed_functions:
      - receives_fire_from_90CYE01_rs485
      - removes_voltage_from_damper_control_circuits
      - monitors_limit_switches
    unknowns:
      - full_terminal_table
      - timeout
      - rs485_protocol

  90CYE03:
    type: ППКП-01Ф-19
    role:
      - aerosol_extinguishing_start
    confirmed_functions:
      - receives_fire_from_90CYE01_rs485
      - auto_manual_modes
      - warning_boards
      - start_delay_30s
      - launch_pulse
      - door_open_auto_disable

  90CYE04:
    type: ППКП-01Ф-19
    role:
      - aerosol_extinguishing_start
    confirmed_functions:
      - same_as_90CYE03_unless_project_specific_difference_found

equipment:
  GH003:
    type: BC-12-A
    role: terminal_box_for_CH001_CH004
  tabs:
    - Газ! Не входи
    - Автоматика отключена
    - Аэрозоль - не входи
  sensors:
    - ИО 102-26
    - PS10
    - VSR
    - VSR-6
    - MCP5A
    - WR4001I.S
""",
    )

    write_file(
        "docs/extracted/project_to_firmware_linkage.csv",
        """project_evidence_id,device,project_function,physical_signal,module_or_equipment,firmware_family,firmware_file,possible_function_addr,possible_xdata,possible_code_pattern,confidence,evidence_level,notes
P-90CYE01-ZONE-001,90CYE01,one_auto_attention_two_auto_fire_manual_fire,zone_detector_events,zone_logic,90CYE_DKS_reference,90CYE03_19_DKS.PZU,0x497A|0x737C,"0x3010..0x301B",threshold_branch_attention_fire,hypothesis,project_documentation+static_code,Project semantics confirmed for 90CYE01; function family candidate only.
P-90CYE01-MVK-001,90CYE01,any_zone_fire_to_MVK_2_1,mvk_common_fire_output,MVK-2.1,90CYE_DKS_reference,90CYE03_19_DKS.PZU,0x6833|0x7DC2,"0x3640|0x364B",any_zone_fire_output_branch,probable,project_documentation+manual_decompile,Physical role confirmed by project docs; output address mapping unresolved.
P-90CYE01-RS485-001,90CYE01,rs485_fire_export,fire_state_event,RS-485,90CYE_DKS_reference,90CYE03_19_DKS.PZU,0x5A7F|0x7922,"0x36D3..0x36FD",packet_export_on_fire,probable,project_documentation+manual_decompile,Transfer intent confirmed; packet format unknown.
P-90CYE01-MDS-001,90CYE01,mds_discrete_input_scan,CP051_CF051_CF052_CF053_CH001_CH004,MDS_еФ5.104.156,90CYE_shifted_DKS,90CYE02_27 DKS.PZU,0x673C|unknown,"0x3104|unknown",discrete_input_scan_and_status_update,probable,project_documentation+hypothesis,Project confirms physical MDS inputs; handler remains candidate.
P-90CYE02-DAMPER-001,90CYE02,fire_damper_voltage_removal,valve_control_voltage,damper_blocks,90CYE_shifted_DKS,90CYE02_27 DKS.PZU,0x673C,"0x3104",object_status_updater_shifted_DKS,probable,project_documentation+hypothesis,0x673C candidate linkage only; no direct proof of exclusive damper handler.
P-90CYE03-AERO-001,90CYE03,aerosol_start_chain_with_delay,warning_boards_start_pulse,aerosol_generators,90CYE_DKS,90CYE03_19_DKS.PZU,0x84A6|0x728A|0x6833|0x597F|0x7DC2|0x5A7F,"0x30E7|0x30E9|0x30EA..0x30F9",mode_gate_delay_start_export_chain,probable,project_documentation+manual_decompile,Physical action semantics strengthened; bench evidence still needed.
P-90CYE04-AERO-001,90CYE04,aerosol_start_chain_with_delay,warning_boards_start_pulse,aerosol_generators,90CYE_DKS,90CYE04_19_DKS.PZU,0x84A6|0x728A|0x6833|0x597F|0x7DC2|0x5A7F,"0x30E7|0x30E9|0x30EA..0x30F9",mode_gate_delay_start_export_chain,probable,project_documentation+manual_decompile,Treated same as 90CYE03 unless branch-specific divergence appears.
P-DOOR-INTERLOCK-001,90CYE03_90CYE04,door_open_auto_disable_manual_mode,door_limit_switch,door_interlock,90CYE_DKS,90CYE03_19_DKS.PZU,0x84A6|0x728A,"0x30E9|0x30EA",door_open_blocks_auto_mode,probable,project_documentation+manual_decompile,Door interlock semantics confirmed at project level; signal polarity unknown.
P-AO-INDICATOR-001,90CYE03_90CYE04,ao_automation_disabled_indicator,AO_indicator,warning_board_AO,90CYE_DKS,90CYE03_19_DKS.PZU,unknown,unknown,output_mapping_required,hypothesis,project_documentation+unknown,AO mode indication semantics known but output mapping unresolved.
""",
    )

    write_file(
        "docs/extracted/project_unknowns.csv",
        """unknown_id,area,description,device,needed_evidence,priority,next_static_step,next_doc_step,next_bench_step
PU-001,RS-485_format,Frame format and field layout,90CYE01_02_03_04,packet captures + code parse path,high,trace packet builder/parser around 0x5A7F,request protocol sheets,collect synchronized serial captures
PU-002,RS-485_addresses,Address map for 90CYE01/02/03/04,90CYE01_02_03_04,protocol docs or decoded captures,high,search constants and compare branch tables,extract addressing pages from project set,capture bus traffic with per-device isolation
PU-003,RS-485_baudrate,Configured baudrate and framing,90CYE01_02_03_04,device settings or captures,medium,scan init UART constants,locate commissioning pages,measure serial timing on bench
PU-004,CRC_checksum,CRC/checksum algorithm details,90CYE01_02_03_04,frame bytes + code confirmation,high,search checksum loops/xor/crc tables,find protocol appendix,capture valid/invalid frame behavior
PU-005,timeout_retry,Retry and timeout policy,90CYE01_02_03_04,code path + runtime capture,medium,find timers in comm state machine,find operational timing notes,bus fault injection tests
PU-006,numeric_enum_codes,Numeric enum values for state terms,all,static constants + runtime correlation,high,search compare-immediate branches around state bytes,locate enum tables in docs,map HMI states to memory bytes
PU-007,launch_line_supervision,Launch-line resistance/open/short supervision,90CYE03_90CYE04,bench + code + electrical docs,high,search supervision-related checks near launch path,request electrical supervision section,inject open/short simulations safely
PU-008,line_break_short_supervision,Line break/short supervision for CP/CF/CH and control lines,90CYE01_02_03_04,bench + wiring tables,medium,search fault state transitions,extract full line monitoring sheets,simulate line faults with dummy loads
PU-009,launch_pulse_parameters,Exact launch pulse duration/form,90CYE03_90CYE04,timing captures and code constants,high,search timer constants near 0x6833 chain,extract launch timing requirements,scope launch output with safe simulator
PU-010,damper_terminal_table,Full damper terminal map,90CYE02,complete project terminal sheets,medium,map known tags to object table slots,extract full terminal scans,validate with wiring continuity test
PU-011,goa_terminal_table,Full GOA terminal map,90CYE03_90CYE04,complete project terminal sheets,medium,search output index candidates for GOA/AN/AU,extract GOA cabinet sheets,bench trace output to terminal mapping
PU-012,MUP_conflict_split,MUP visible in screen evidence but absent in current project pages,DKS,combined evidence governance,medium,keep MUP handler as unresolved and separate evidence tags,expand project scan coverage for MUP sheets,run slot-isolated MUP bench tests
PU-013,PVK_conflict_split,PVK visible in screen evidence but absent in current project pages,DKS,combined evidence governance,medium,keep PVK handler as unresolved and separate evidence tags,expand project scan coverage for PVK sheets,run slot-isolated PVK bench tests
""",
    )

    write_file(
        "docs/extracted/project_evidence_confidence_impact.csv",
        """area,previous_confidence,new_project_evidence_confidence,code_confidence_changed,reason,notes
90CYE03_90CYE04_aerosol_physical_role,medium,high,no,Project docs explicitly describe aerosol start role with 30s delay and door interlock,Function-address ownership still requires static+bench confirmation
90CYE01_MDS_physical_role,medium,high,no,Project docs explicitly identify MDS еФ5.104.156 and CP/CF/CH signals,Runtime word/bit mapping remains unknown
90CYE02_damper_voltage_removal_role,medium,high,no,Project docs explicitly describe voltage removal and limit-switch monitoring,Exact terminals and timeout logic still unknown
RS485_packet_format,low,low,no,Project docs confirm transfer intent but no frame specification,Format/address/CRC/retry remain unknown
numeric_enum_codes,low,low,no,Project docs contain labels but no numeric codes,Enum numeric mapping remains evidence-gated
launch_line_supervision,low,low,no,No direct project confirmation of resistance/open/short supervision,Keep unknown until direct evidence
""",
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
