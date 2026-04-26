# State/mode logic analysis (sensor/zone + auto/manual gating)

Дата: 2026-04-26 (UTC).

## 1. Зачем нужен анализ состояний датчиков/зон/режимов
Цель — перейти от общего zone/output mining к прикладной state-machine модели: состояние датчика → состояние зоны → режим auto/manual → событие/передача → запуск выхода/тушения (или отсутствие запуска). Все выводы ниже помечены confidence.

## 2. Прикладная модель
- Датчик: норма / блок / отключен / нет связи / конфликт адресов / пожар / неисправность.
- Зона: норма / внимание / пожар / авария(alarm) / неисправность / отключена/заблокирована.
- Режим: manual / auto.
- Логика действия: manual => fire event+packet only; auto => fire event+packet + output/extinguishing start (если разрешения соблюдены).

## 3. Декодированные enum-кандидаты (milestone #41)
- Сформирован файл `docs/state_mode_enum_candidates.csv`, строк: **34**.
- Метод: извлечение immediate-констант (`#0xNN`) в ключевых инструкциях + доменные словари (sensor/zone/mode).
- Важно: это **candidate decode**, а не финальный протокол; для ряда значений сохраняется unknown/hypothesis.

## 4. Что найдено по состояниям датчиков
- Candidate rows: **84** (фокус по 90CYE_DKS/90CYE03_19_DKS.PZU и функциям 0x497A, 0x5A7F, 0x613C, 0x6833, 0x728A, 0x737C, 0x84A6).
- Распределение top state-candidates: unknown_sensor_state:84.
- Confidence: в основном `hypothesis/low`, точечные `probable` на участках с bit+cond+XDATA совпадением.

## 5. Что найдено по конфликту адресов
- Маркеры address/conflict обнаруживаются в candidate-паттернах (operands/notes/string-index), но без полного recovery enum/state-id.
- Статус: **probable/hypothesis**; требуется ручной deep-dive сравнений и XDATA map на стенде.

## 6. Что найдено по состояниям зон
- Candidate rows: **84**. Top zone-states: unknown:84.
- Наиболее информативные узлы остаются вокруг 0x737C/0x613C/0x497A (90CYE_DKS focus).

## 7. Что найдено по автоматическому/ручному режиму
- Top mode-candidates: unknown:84.
- Ищутся ветки `XDATA flag read -> conditional -> output call` и `XDATA flag read -> event/packet only`.

## 8. Есть ли в коде gating logic между fire и output
- Chain rows: **80**. Есть признаки partial/full gating chains в 90CYE_DKS и cross-branch pipeline chains.
- Для части цепочек output отсутствует и остается только event/packet (manual-like гипотеза).

## 9. Признаки веток manual vs auto
- manual-like: цепочки типа `fire_to_event_only` с evidence event/packet без output.
- auto-like: цепочки `fire_to_output_auto`/`mode_check_to_output` где присутствует output_control_function.

## 10. Наиболее вероятные XDATA флаги state/mode
- Наиболее вероятны адреса XDATA из trace около 0x30EA..0x30F9 / 0x315B / 0x3165 / 0x31BF / 0x364B (90CYE_DKS контур, confidence=probable/hypothesis).

## 11. Strongest functions сейчас
- sensor state: 0x497A, 0x737C (probable).
- zone state: 0x737C, 0x613C (probable).
- mode check: 0x84A6, 0x728A (hypothesis->low).
- output gating: 0x6833 + chain bridges (low/probable mix).
- packet/export: 0x5A7F (probable packet bridge).

## 12. Техническая логика (псевдокод)
```text
sensor_state = decode_sensor_enum(sensor_raw)
zone_state   = fold_sensor_to_zone(sensor_state, zone_flags)
mode         = read_mode_flag(0x315B?)  # candidate
emit_event_packet(zone_state, sensor_state)
if mode == auto and zone_state in {fire, alarm} and output_permit_flags_ok():
    start_output_or_extinguishing()
else:
    keep_event_only_path()
```

## 13. Confirmed / probable / hypothesis / unknown
- confirmed: есть event/packet path и output-подобные узлы в анализируемых ветках.
- probable: sensor/zone state update и partial gating цепочки.
- hypothesis: строгий auto/manual flag-id и полный trigger-условный набор для тушения.
- unknown: полный enum всех state-кодов и 100% привязка к физическим исполнительным устройствам.

## 14. Следующий ручной deep-dive
- Приоритет: 0x84A6 -> 0x728A -> 0x5A7F, а также детализация ветвей от 0x737C/0x613C/0x6833.

## 15. Нужные стендовые проверки
- датчик: норма / заблокирован / не определяется / конфликт адресов (2 датчика на одном адресе).
- зона: manual vs auto; пожар в manual (event/packet only) vs пожар в auto (output start).
- подтверждение, что выход включается только при auto + разрешающих условиях.

## Warnings по входным данным
- none

## Appendix: target branch strongest summary rows
- 0x497A: score=2453.500, role=sensor_to_zone_mapping_candidate
- 0x737C: score=755.000, role=zone_table_candidate
- 0x613C: score=61.900, role=zone_table_candidate
- 0x6833: score=40.700, role=relay_output_candidate
