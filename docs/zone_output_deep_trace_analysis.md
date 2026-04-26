# Zone-output deep trace analysis

Файл анализа: `90CYE03_19_DKS.PZU` (ветка `90CYE_DKS`).

## Почему выбраны функции 0x497A / 0x737C / 0x613C / 0x6833
- `0x497A`: ранее помечалась как сильный `sensor_to_zone_mapping_candidate` и `output_module_dispatcher_candidate`.
- `0x737C`: ранее помечалась как `zone_table_candidate` и `output_module_dispatcher_candidate`.
- `0x613C`: ранее помечалась как `zone_table_candidate` и `actuator_feedback_candidate`.
- `0x6833`: ранее помечалась как `relay_output_candidate`.

## Ordered static trace по функциям
### 0x497A
- proposed_role: `sensor_to_zone_mapping_candidate`; confidence=medium; score=2453.500; blocks=91; calls=76; xdata(r/w)=23/24.
- markers: zone=588, output=228, event=588, packet_export=29; cond=42, bit_ops=8, movc=0.
- confidence note: `strong_zone_candidate`.

### 0x737C
- proposed_role: `zone_table_candidate`; confidence=medium; score=755.000; blocks=33; calls=20; xdata(r/w)=11/6.
- markers: zone=176, output=79, event=176, packet_export=10; cond=15, bit_ops=10, movc=1.
- confidence note: `strong_zone_candidate`.

### 0x613C
- proposed_role: `zone_table_candidate`; confidence=medium; score=61.900; blocks=3; calls=0; xdata(r/w)=39/16.
- markers: zone=12, output=12, event=12, packet_export=0; cond=1, bit_ops=1, movc=3.
- confidence note: `none`.

### 0x6833
- proposed_role: `relay_output_candidate`; confidence=medium; score=40.700; blocks=2; calls=6; xdata(r/w)=16/2.
- markers: zone=0, output=24, event=0, packet_export=3; cond=1, bit_ops=0, movc=0.
- confidence note: `missing_event_link;strong_relay_output_candidate`.

## Интерпретация цепочки
- Наиболее вероятный `sensor -> zone mapping`: **0x497A** (по числу zone_marker hits) — confidence: medium.
- Наиболее вероятная `zone table / zone logic`: **0x737C** (устойчивые zone/event/branch маркеры).
- Наиболее вероятное `output / relay control`: **0x6833** (relay_output marker + packet bridge hits) — confidence: medium.
- Event-звено частично найдено: лучшая функция **0x497A** с 588 event_marker hits.
- Вероятный разрыв цепочки event наблюдается в: 0x6833.
- Путь `zone -> output`: observed (probable).
- Путь `output -> packet/export`: observed (probable).

## Статус утверждений
- confirmed: присутствуют ordered static trace rows, XDATA read/write и call/jump/branch структуры для всех 4 функций.
- probable: роли `zone logic` и `relay output` распределяются на основе marker-hit профиля.
- hypothesis: точные semantic-правила (конкретные реле/зоны/алгоритмы меню/AND-OR) без стендовой проверки не утверждаются.
- unknown: полный event queue bridge и окончательный packet-format mapping в этом PR.

## Следующие 2–3 функции для ручной декомпозиции
- `0x84A6` — вероятный event/state bridge рядом с zone dispatcher узлами.
- `0x728A` — вероятный packet/export bridge в цепочках 90CYE_DKS.
- `0x5A7F` — подтвержденный packet builder/service exporter для проверки output->packet перехода.
