# Общая модель логики модулей ППКП (МАШ / МАС / другие)

Дата: 2026-04-26 (UTC).

Основание: статические артефакты `function_map/basic_block_map/call_xref/xdata_confirmed_access/global_packet_pipeline_candidates/mash_code_evidence_candidates/rtos_service_function_candidates`, плюс документальные данные по извещателям ИП212-200 22051E и ИП212-200/1 22051EI (System Sensor 200AP/200+, адреса 01..159, LED, изолятор).

> Важно: в прошивках не найдено надёжных строковых маркеров `МАШ`/`МАС`; привязка обработчиков выполнена по структуре кода, петлям, XDATA-кластерам, call-chain и косвенным признакам.

## 1) Единый рабочий цикл (сводная блок-схема)

```text
[Init/Boot]
  -> [Branch runtime dispatcher]
  -> [Module handler select (table/switch/MOVC-like)]
  -> [Poll module inputs: address loop / analog / service]
  -> [State update in XDATA object tables]
  -> [Event select + change queue push]
  -> [Packet build buffer fill]
  -> [Transmit/service export]
  -> [Loop]
```

Уровни уверенности:
- **подтверждено**: наличие init->dispatcher->packet-export цикла во всех ветках (по chain/candidate данным).
- **вероятно**: модульный выбор через table/switch (MOVC-кандидаты и повторяемые dispatcher-hubs).
- **гипотеза**: точные коды типов модулей (numeric module type IDs) без ручной декомпозиции таблиц.

## 2) Ядро XDATA по веткам (очередь/селектор/таблица/буфер)

## A03_A04
- Очередь изменений: `0x3281/0x3282/0x3293/0x3298` — **вероятно**.
- Селектор события/передачи: `0x7FF2/0x7FF6` — **гипотеза**.
- Таблица объектов: `0x3292..0x329C` + индекс `0x0001` — **вероятно**.
- Буфер/окно пакета: `0x4EAB..0x5003` (+смежно `0x3298..0x329C`) — **вероятно**.

## 90CYE_DKS
- Очередь изменений: `0x30EB`, `0x3612..0x3617` — **вероятно**.
- Селектор события/передачи: `0x315B`, `0x3122..0x3125` — **гипотеза**.
- Таблица объектов: `0x30EA..0x30F9` + индекс `0x0001` — **вероятно**.
- Буфер пакета: `0x31BF`, `0x364B`, `0x3165` (pointer-arg path к `0x5A7F`) — **вероятно/подтверждено**.

## 90CYE_v2_1
- Очередь изменений: `0x3173/0x3177/0x317B` — **вероятно**.
- Селектор события/передачи: `0x740C/0x740F` — **гипотеза**.
- Таблица объектов: `0x3178/0x3179/0x3195` + `0x3270..0x32D7` — **вероятно/подтверждено**.
- Буфер пакета: `0x44A3/0x44E3/0x44C3`, `0x3353`, `0x317D` — **вероятно**.

## 90CYE_shifted_DKS
- Очередь изменений: `0x30B1/0x30B2/0x30A4/0x30A5` — **вероятно**.
- Селектор события/передачи: `0x4575/0x4577/0x4578` — **вероятно**.
- Таблица объектов: `0x30A4..0x30B2` + индекс `0x0001` — **вероятно**.
- Буфер пакета: `0x31DD`, `0x7248/0x724A`, `0x52F8` — **вероятно**.

## RTOS_service
- Очередь изменений: `0x759C/0x759D/0x759F/0x75A0` — **вероятно**.
- Селектор события/передачи: `0x75AA/0x75AB/0x75AD` — **вероятно**.
- Таблица объектов: `0x6406/0x6422` (глобальный low-index не стабилен) — **вероятно/неизвестно**.
- Буфер пакета: `0x68AA/0x6700/0x6703/0x444A/0x443D` — **вероятно**.

## 3) Обработчики модулей

## МАШ (адресный шлейф)
Выбор обработчика:
- Наиболее вероятная схема: `dispatcher (0x497A/0x497F/0x758B) -> поддиспетчер (0x800B/0x737C/0x8BE5/0x7574)`.
- Признаки: `polling_loop_candidate`, `address_range_candidate`, `led_control_candidate`, `isolator_status_candidate`.

Опрос/измерение:
- Есть устойчивые loop-паттерны и event queue integration во всех ветках — **вероятно**.
- Диапазон адресов 1..159 для ИП212-200 семейства подтверждён документально (PDF), а кодовая привязка к конкретному циклу — **вероятно/гипотеза**.

Хранение состояния:
- Идёт через branch-specific object/flag XDATA-кластеры (см. раздел 2).

Формирование события:
- После обновления флагов вызываются event/packet кандидаты (`event_queue_candidate`, `packet_export_candidate`) — **вероятно**.

## МАС (аналоговый сигнал)
Выбор обработчика:
- Прямого текстового признака `МАС` не обнаружено — **подтверждено** (отсутствие маркеров).
- Кандидаты выделены по сочетанию `arithmetic-heavy + xdata read/write + event path` (напр. `0x722E`, `0x613C`, `0x93F9`, `0x774F`, `0x95B0`) — **гипотеза/вероятно**.

Опрос/измерение:
- Вероятна схема: чтение значения -> сравнение с порогами -> установка состояний `норма/тревога/неисправность` -> событие.

Хранение состояния:
- Через те же объектные кластеры, но с отдельными flag-байтами в change queue/event code зонах.

Формирование события:
- Через общую очередь изменений и packet-builder контур, аналогично МАШ.

## Другие модули (service/UI/системные)
- Есть стабильные packet/service builders в каждой ветке (`0x6C07`, `0x5A7F`, `0x72AB`, `0x655F`, `0x92EF`) — **подтверждено** как транспортные обработчики.
- Как минимум часть из них выполняет не опрос датчика, а упаковку/маршрутизацию событий.

## 4) Таблица типов модулей (module type table)

Что найдено:
- Во всех ветках присутствуют `MOVC code_table_or_string_candidate` области и dispatcher-функции.
- В `90CYE_shifted_DKS` функция `0x72E4` даёт характерный табличный профиль и может быть type-decode узлом.

Что не найдено:
- Явных строк/констант вида `MASH`, `MAS`, `200AP` в таблице выбора обработчика.

Вывод:
- Наличие module-type selector — **вероятно**.
- Точные numeric type codes — **неизвестно** (требуется ручная реконструкция MOVC-таблиц и переходов).

## 5) Сравнение веток

Совпадения:
- Семейства `A03/A04`, `90CYE_DKS`, `90CYE_v2_1`, `90CYE_shifted_DKS` имеют общую архитектурную форму `main dispatcher -> worker -> packet builder` — **подтверждено**.
- RTOS_service сохраняет ту же форму, но с другой адресной картой и более выраженным service-слоем — **вероятно**.

Отличия:
- XDATA-адреса между ветками не совпадают один-к-одному, но кластеры по ролям сопоставимы.
- RTOS_service использует отдельные high-density флаговые кластеры (`0x759C..0x75AE`), отсутствующие в таком же виде в A03/A04.

## 6) Связь с реальными датчиками из PDF

Учитываемые факты (документально):
- ИП212-200 22051E и ИП212-200/1 22051EI.
- Протоколное семейство System Sensor 200AP/200+.
- Адреса 01..159.
- Управление LED с панели.
- Наличие изолятора у версии /1.

Связь с кодом:
- `address_range_candidate + led_control_candidate + isolator_status_candidate` подтверждают структурное соответствие МАШ-пути.
- Без прямых строковых маркеров итоговая связка остаётся: **вероятно/гипотеза**.

## 7) Следующий шаг (deep-dive план)

Приоритет ручного анализа функций:
1. Главные диспетчеры: `0x497A/0x497F/0x758B` (по веткам).
2. Поддиспетчеры МАШ: `0x800B`, `0x737C`, `0x8BE5`, `0x7574`, `0xA3FD`.
3. Кандидаты МАС: `0x722E`, `0x613C`, `0x93F9`, `0x774F`, `0x95B0`.
4. Type-table узлы: `0x72E4` (shifted DKS) и ближайшие MOVC-таблицы.
5. Packet bridge: `0x6C07`, `0x5A7F`, `0x72AB`, `0x655F`, `0x92EF`.

XDATA-адреса для подтверждения:
- A03/A04: `0x7FF2/0x7FF6`, `0x3010`.
- DKS: `0x315B`, `0x30A0/0x30A7`.
- v2_1: `0x740C/0x740F`, `0x315C/0x315D`.
- shifted DKS: `0x31D1`, `0x30CE/0x3103`.
- RTOS_service: `0x6408/0x6423`, `0x76AA`.

Сценарии испытаний на приборе:
1. Адресный прогон 1..159 с логированием времени ответа и событий.
2. Тест LED-команд (включение/мигание) с корреляцией event queue.
3. Тест изолятора (короткое замыкание сегмента) и проверка отдельного fault-event.
4. Аналоговый sweep (норма->предтревога->тревога->обрыв) для кандидатов МАС.
5. Сравнение исходящих пакетов между ветками для одинаковых воздействий.


## MASH deep-trace after PR

- Strongest chain candidates after deep trace: `0x737C -> 0x84A6 -> 0x728A` (90CYE_DKS branch family) and `0x497A -> 0xA900 -> 0x800B` (A03_A04 bridge path) — **probable** по loop/XDATA/event/packet marker balance.
- Подтвердилось (code evidence): в top chains есть последовательность dispatcher/core/callee с loop-like контролем, XDATA update, event queue marker и packet/export marker.
- Осталось гипотезой: точная привязка isolator path и полный recovery логики System Sensor 200AP/200+ (не заявляется как завершённый).
- Нужна стендовая проверка: прогон адресов `1..159`, LED-команды, потеря датчика, fault/short-circuit/isolator-like сценарии и сравнение исходящих пакетов.

## Zone and output-control logic after PR

- Strongest zone candidates (probable): `A03_A04:A04_28.PZU:0x497A`, `90CYE_DKS:90CYE03_19_DKS.PZU:0x737C`, `90CYE_v2_1:90CYE03_19_2 v2_1.PZU:0x80EC`, а также branch-specific state-update/dispatcher функции из `docs/zone_logic_candidates.csv`.
- Strongest output-control candidates (probable): dispatcher/state-writer/packet-adjacent функции из `docs/output_control_candidates.csv` (включая MASH-linked call-hub узлы), но без полного доказательства привязки к конкретным реле/задвижкам.
- Найдены partial/full chains в `docs/zone_to_output_chains.csv`: как минимум частичные `sensor/module -> zone/event -> output/service -> packet/export`; для части веток отсутствуют одно или несколько звеньев (отмечены как `partial_chain`).
- Осталось гипотезой: точные правила zone menu logic (AND/OR/задержки/1-из-2/2-из-2), строгая sensor->zone таблица, и окончательная связь конкретного output-флага с физическим устройством без стендовой верификации.


## Zone-output deep trace after PR

- strongest zone function: `0x737C` (zone_table/zone_logic marker balance) — **probable**.
- strongest output function: `0x6833` (relay_output marker concentration) — **probable**.
- event-звено: частично найдено как `event_state_update`/`event_to_output_bridge` маркеры, но явный queue bridge остается **hypothesis**.
- осталось гипотезой: точные правила zone-event->relay и строгая привязка к конкретным физическим реле без стендовой проверки.

## Sensor/zone state and auto/manual mode logic after PR

- Добавлены кандидаты `sensor_state_candidates` и `zone_state_mode_candidates` с confidence-маркировкой для 90CYE_DKS приоритетных функций `0x497A/0x737C/0x613C/0x6833/0x84A6/0x728A/0x5A7F`.
- Есть признаки manual/auto gating в цепочках `fire -> mode check -> event/packet` и `fire -> mode check -> output`, но полный recovery правил запуска тушения остается **hypothesis/probable** и требует стендовой верификации.
- Следующие функции для ручной декомпозиции: `0x84A6`, `0x728A`, `0x5A7F`, затем развилки внутри `0x737C/0x613C/0x6833`.
