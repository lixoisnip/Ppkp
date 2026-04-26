# Zone/output-control logic analysis
Дата: 2026-04-26 (UTC).

## 1) Зачем нужен анализ зон и выходов
Чтобы восстановить прикладную логику прибора: от датчика/адреса и логики зоны до события, включения внешних устройств и экспорта состояния.

## 2) Предполагаемая прикладная схема
`датчик -> номер датчика -> зона -> логика зоны -> событие -> выходной модуль -> реле/задвижка/оповещение -> packet/export`.

## 3) Признаки зон
Top zone candidates (code evidence):
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x497A (sensor_to_zone_mapping_candidate), score=30.960, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x737C (zone_table_candidate), score=24.460, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x613C (zone_table_candidate), score=14.400, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x7BC2 (sensor_to_zone_mapping_candidate), score=14.060, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x84A6 (sensor_to_zone_mapping_candidate), score=11.620, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x7017 (sensor_to_zone_mapping_candidate), score=11.280, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x59A0 (zone_table_candidate), score=11.160, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x5EDC (sensor_to_zone_mapping_candidate), score=10.320, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x7184 (sensor_to_zone_mapping_candidate), score=9.580, confidence=low.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x7D85 (zone_table_candidate), score=8.620, confidence=low.

## 4) Кандидаты таблицы датчик -> зона
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x497A (sensor_to_zone_mapping_candidate), table_hits=12, movc=0, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x737C (zone_table_candidate), table_hits=10, movc=1, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x613C (zone_table_candidate), table_hits=6, movc=3, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x7BC2 (sensor_to_zone_mapping_candidate), table_hits=6, movc=0, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x84A6 (sensor_to_zone_mapping_candidate), table_hits=1, movc=0, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x7017 (sensor_to_zone_mapping_candidate), table_hits=1, movc=0, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x59A0 (zone_table_candidate), table_hits=6, movc=2, confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x5EDC (sensor_to_zone_mapping_candidate), table_hits=2, movc=0, confidence=medium.

## 5) Кандидаты логики зоны из меню
- Прямых menu-zone маркеров недостаточно; только косвенные state/dispatcher признаки (hypothesis).

## 6) Функции, похожие на обработчики зон

## 7) Функции, похожие на модули выходных сигналов
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x497A (output_module_dispatcher_candidate) score=27.670 confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x737C (output_module_dispatcher_candidate) score=19.400 confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x7017 (output_module_dispatcher_candidate) score=17.760 confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x728A (output_module_dispatcher_candidate) score=17.280 confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x84A6 (output_module_dispatcher_candidate) score=16.620 confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x6833 (relay_output_candidate) score=14.680 confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x613C (actuator_feedback_candidate) score=7.170 confidence=low.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x5EDC (output_module_dispatcher_candidate) score=4.660 confidence=hypothesis.
- 90CYE_DKS 90CYE04_19_DKS.PZU 0x497A (output_module_dispatcher_candidate) score=27.670 confidence=medium.
- 90CYE_DKS 90CYE04_19_DKS.PZU 0x6833 (relay_output_candidate) score=14.680 confidence=medium.

## 8) Цепочки от зоны к выходу
- 90CYE_DKS 90CYE03_19_DKS.PZU: 0x497A -> 0x497A -> ? -> 0x613C -> 0x497A; partial_chain missing: event; confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU: 0x84A6 -> 0x7017 -> ? -> 0x84A6 -> 0x7017; partial_chain missing: event; confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU: 0x84A6 -> 0x737C -> ? -> 0x84A6 -> 0x737C; partial_chain missing: event; confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU: 0x497A -> 0x6ACB -> ? -> ? -> 0x497A; partial_chain missing: event, output_control; confidence=low.
- 90CYE_DKS 90CYE03_19_DKS.PZU: 0x497A -> 0x673C -> ? -> ? -> 0x497A; partial_chain missing: event, output_control; confidence=low.
- 90CYE_DKS 90CYE03_19_DKS.PZU: 0x497A -> 0x673C -> ? -> ? -> 0x497A; partial_chain missing: event, output_control; confidence=low.
- 90CYE_DKS 90CYE04_19_DKS.PZU: 0x497A -> 0x497A -> ? -> 0x613C -> 0x497A; partial_chain missing: event; confidence=medium.
- 90CYE_DKS 90CYE04_19_DKS.PZU: 0x84A6 -> 0x737C -> ? -> 0x737C -> 0x737C; partial_chain missing: event; confidence=medium.
- 90CYE_DKS 90CYE04_19_DKS.PZU: 0x84A6 -> 0x7017 -> ? -> ? -> 0x7017; partial_chain missing: event, output_control; confidence=low.
- 90CYE_DKS 90CYE04_19_DKS.PZU: 0x497A -> 0x6ACB -> ? -> ? -> 0x497A; partial_chain missing: event, output_control; confidence=low.

## 9) Статусы confirmed / probable / hypothesis / unknown
- confirmed (code evidence): есть устойчивые branch-specific кандидаты zone/output и partial chain к packet/export.
- probable: часть функций совмещает признаки zone-state/event/output write path.
- hypothesis: точное восстановление zone menu-logic правил (AND/OR/1-of-2/2-of-2/delay) и точные map-таблицы sensor->zone.
- unknown: окончательная привязка конкретных реле/задвижек/исполнителей к конкретным XDATA-флагам без стенда.

## 10) Следующий ручной deep-dive
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x497A (sensor_to_zone_mapping_candidate), confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x737C (zone_table_candidate), confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x613C (zone_table_candidate), confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x7BC2 (sensor_to_zone_mapping_candidate), confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x84A6 (sensor_to_zone_mapping_candidate), confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x497A (output_module_dispatcher_candidate), confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x737C (output_module_dispatcher_candidate), confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x7017 (output_module_dispatcher_candidate), confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x728A (output_module_dispatcher_candidate), confidence=medium.
- 90CYE_DKS 90CYE03_19_DKS.PZU 0x84A6 (output_module_dispatcher_candidate), confidence=medium.

## 11) Нужные стендовые проверки
- назначить датчик в зону 1;
- назначить датчик в зону 2;
- изменить логику зоны в меню;
- вызвать пожар одного датчика;
- вызвать пожар двух датчиков;
- проверить включение реле;
- проверить управление задвижкой;
- проверить отключение/включение зоны;
- сравнить исходящие пакеты.

## Warnings
- none

## Прямые строковые маркеры
