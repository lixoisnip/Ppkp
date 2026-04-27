# Runtime state-machine reconstruction for 90CYE_DKS / 90CYE03_19_DKS.PZU
Дата: 2026-04-26 (UTC).

## 1. Зачем нужен этот milestone
Этот milestone объединяет разрозненные candidate-артефакты в связанную runtime state-machine модель (датчик -> зона -> режим -> событие -> выход -> пакет) для ветки 90CYE_DKS. Цель — получить рабочую инженерную картину для стендовой валидации, а не очередной список изолированных функций.

## 2. Общая прикладная схема
```text
датчик -> зона -> режим -> событие -> выход -> пакет
```

## 3. Major nodes
| function | proposed role | score | confidence | key flags |
|---|---|---:|---|---|
| 0x497A | sensor/zone state candidate | 1.500 | high | - |
| 0x737C | zone table / zone logic candidate | 1.500 | high | - |
| 0x613C | zone state / feedback candidate | 1.500 | high | - |
| 0x84A6 | mode/event bridge candidate | 1.500 | high | - |
| 0x728A | auto/manual mode-check candidate | 1.500 | medium | - |
| 0x6833 | output / relay / extinguishing start candidate | 1.500 | medium | - |
| 0x5A7F | packet/export candidate | 1.500 | hypothesis | - |

## 4. Функции и признаки
### 0x497A
- Роль (candidate): sensor/zone state candidate.
- XDATA read/write: 0/0 (reads: -; writes: -).
- Calls out/in: - / -.
- Ветвления/битовые операции: 0/0.
- Признаки state/mode/output/packet: score=1.500, confidence=high.
- Evidence: docs/auto_manual_gating_deep_trace_analysis.md, docs/auto_manual_gating_deep_trace_summary.csv, docs/basic_block_map.csv, docs/extinguishing_output_gating_chains.csv, docs/function_map.csv, docs/mash_handler_deep_trace_analysis.md, docs/module_logic_overview.md, docs/output_control_candidates.csv, docs/sensor_state_candidates.csv, docs/state_mode_logic_analysis.md, docs/zone_logic_candidates.csv, docs/zone_output_deep_trace_analysis.md, docs/zone_output_deep_trace_summary.csv, docs/zone_output_logic_analysis.md, docs/zone_state_mode_candidates.csv
### 0x737C
- Роль (candidate): zone table / zone logic candidate.
- XDATA read/write: 0/0 (reads: -; writes: -).
- Calls out/in: - / , flow.
- Ветвления/битовые операции: 0/0.
- Признаки state/mode/output/packet: score=1.500, confidence=high.
- Evidence: docs/auto_manual_gating_deep_trace_analysis.md, docs/auto_manual_gating_deep_trace_summary.csv, docs/basic_block_map.csv, docs/call_xref.csv, docs/disassembly_index.csv, docs/extinguishing_output_gating_chains.csv, docs/function_map.csv, docs/mash_handler_deep_trace_analysis.md, docs/module_logic_overview.md, docs/output_control_candidates.csv, docs/sensor_state_candidates.csv, docs/state_mode_logic_analysis.md, docs/zone_logic_candidates.csv, docs/zone_output_deep_trace_analysis.md, docs/zone_output_deep_trace_summary.csv, docs/zone_output_logic_analysis.md, docs/zone_state_mode_candidates.csv
### 0x613C
- Роль (candidate): zone state / feedback candidate.
- XDATA read/write: 0/0 (reads: -; writes: -).
- Calls out/in: - / , flow.
- Ветвления/битовые операции: 0/0.
- Признаки state/mode/output/packet: score=1.500, confidence=high.
- Evidence: docs/auto_manual_gating_deep_trace_analysis.md, docs/auto_manual_gating_deep_trace_summary.csv, docs/basic_block_map.csv, docs/call_xref.csv, docs/disassembly_index.csv, docs/extinguishing_output_gating_chains.csv, docs/function_map.csv, docs/module_logic_overview.md, docs/output_control_candidates.csv, docs/sensor_state_candidates.csv, docs/state_mode_logic_analysis.md, docs/zone_logic_candidates.csv, docs/zone_output_deep_trace_analysis.md, docs/zone_output_deep_trace_summary.csv, docs/zone_output_logic_analysis.md, docs/zone_state_mode_candidates.csv
### 0x84A6
- Роль (candidate): mode/event bridge candidate.
- XDATA read/write: 0/0 (reads: -; writes: -).
- Calls out/in: - / , flow.
- Ветвления/битовые операции: 0/0.
- Признаки state/mode/output/packet: score=1.500, confidence=high.
- Evidence: docs/auto_manual_gating_deep_trace_analysis.md, docs/auto_manual_gating_deep_trace_summary.csv, docs/basic_block_map.csv, docs/call_xref.csv, docs/disassembly_index.csv, docs/extinguishing_output_gating_chains.csv, docs/function_map.csv, docs/mash_handler_deep_trace_analysis.md, docs/module_logic_overview.md, docs/output_control_candidates.csv, docs/state_mode_logic_analysis.md, docs/zone_logic_candidates.csv, docs/zone_output_deep_trace_analysis.md, docs/zone_output_logic_analysis.md
### 0x728A
- Роль (candidate): auto/manual mode-check candidate.
- XDATA read/write: 0/0 (reads: -; writes: -).
- Calls out/in: - / , flow.
- Ветвления/битовые операции: 0/0.
- Признаки state/mode/output/packet: score=1.500, confidence=medium.
- Evidence: docs/auto_manual_gating_deep_trace_analysis.md, docs/auto_manual_gating_deep_trace_summary.csv, docs/basic_block_map.csv, docs/call_xref.csv, docs/disassembly_index.csv, docs/function_map.csv, docs/mash_handler_deep_trace_analysis.md, docs/module_logic_overview.md, docs/output_control_candidates.csv, docs/state_mode_logic_analysis.md, docs/zone_logic_candidates.csv, docs/zone_output_deep_trace_analysis.md, docs/zone_output_logic_analysis.md
### 0x6833
- Роль (candidate): output / relay / extinguishing start candidate.
- XDATA read/write: 0/0 (reads: -; writes: -).
- Calls out/in: - / , flow.
- Ветвления/битовые операции: 0/0.
- Признаки state/mode/output/packet: score=1.500, confidence=medium.
- Evidence: docs/auto_manual_gating_deep_trace_analysis.md, docs/auto_manual_gating_deep_trace_summary.csv, docs/basic_block_map.csv, docs/call_xref.csv, docs/disassembly_index.csv, docs/function_map.csv, docs/module_logic_overview.md, docs/output_control_candidates.csv, docs/sensor_state_candidates.csv, docs/state_mode_logic_analysis.md, docs/zone_output_deep_trace_analysis.md, docs/zone_output_deep_trace_summary.csv, docs/zone_output_logic_analysis.md, docs/zone_state_mode_candidates.csv
### 0x5A7F
- Роль (candidate): packet/export candidate.
- XDATA read/write: 0/0 (reads: -; writes: -).
- Calls out/in: - / , flow.
- Ветвления/битовые операции: 0/0.
- Признаки state/mode/output/packet: score=1.500, confidence=hypothesis.
- Evidence: docs/auto_manual_gating_deep_trace_analysis.md, docs/auto_manual_gating_deep_trace_summary.csv, docs/basic_block_map.csv, docs/call_xref.csv, docs/disassembly_index.csv, docs/function_map.csv, docs/module_logic_overview.md, docs/state_mode_logic_analysis.md, docs/zone_output_deep_trace_analysis.md

## 5. Sensor state
Вероятные state-узлы датчиков расположены вокруг `0x497A` и таблиц/флагов `0x30EA..0x30F9`; наблюдаются признаки обновления state-флагов и условных развилок.
Известные классы состояний: normal/blocked/not_detected/conflict/fire/fault exact numeric encodings remain partially unresolved.

## 6. Zone state
Наиболее вероятная зона-таблица/логика: `0x737C`; зона/feedback state-кандидат: `0x613C`. Признаки attention/fire/fault присутствуют как условные ветки и XDATA-gating, но точная декодировка кодов зон частично неизвестна.

## 7. Auto/manual
`0x315B` остаётся главным кандидатом manual/auto flag (confidence: medium/high по совокупности трасс). `0x728A` выглядит как mode-check/branch gate, `0x84A6` — mode/event bridge. Наблюдается развилка manual-like и auto-like пути.

## 8. Extinguishing/output
`0x6833` — strongest candidate для output/relay/extinguishing start. Видны признаки output-start path, но без стенда нельзя окончательно заявлять полное восстановление алгоритма пожаротушения.

## 9. Packet/export
`0x5A7F` — packet/export узел; связан как с manual-event веткой, так и с auto-output веткой в реконструированном графе.

## 10. Runtime graph
```text
0x497A sensor/zone
  -> 0x737C zone logic
  -> 0x613C state/feedback
  -> 0x84A6 mode/event bridge
  -> 0x728A mode check
      -> manual-like: event/packet only -> 0x5A7F
      -> auto-like: 0x6833 output start -> 0x5A7F
```

## 11. Branch comparison
Сравнение с 90CYE04_19_DKS / 90CYE02_27 / A03_26 / A04_28 / ppkp2001 90cye01 вынесено в `docs/runtime_branch_comparison.csv`. Одинаковый адрес в разных ветках интерпретируется только как candidate-match с confidence, не как доказательство тождественности функции.

## 12. Confirmed / probable / hypothesis / unknown
- Confirmed: наличие связанного runtime-контура state->mode->output/packet как статической модели переходов.
- Probable: `0x315B` manual/auto flag, `0x6833` output-start, `0x5A7F` packet-export bridge.
- Hypothesis: точные условия всех ветвлений fire/attention/fault/manual/auto и все side effects на физические исполнительные механизмы.
- Unknown: полная семантика части XDATA-флагов и таймерных/межпрерывательных взаимодействий без стенда.

## 13. Bench validation plan
- [ ] датчик в норме.
- [ ] датчик заблокирован.
- [ ] датчик не определяется.
- [ ] конфликт адресов.
- [ ] пожар одного датчика.
- [ ] пожар двух датчиков.
- [ ] зона внимание.
- [ ] зона пожар.
- [ ] зона неисправность.
- [ ] зона manual.
- [ ] зона auto.
- [ ] пожар в manual: проверить, что output не стартует.
- [ ] пожар в auto: проверить, что output стартует.
- [ ] проверить реле/задвижку/исполнительный выход.
- [ ] сравнить исходящие пакеты.
- [ ] снять изменения XDATA/логов, если возможно.
