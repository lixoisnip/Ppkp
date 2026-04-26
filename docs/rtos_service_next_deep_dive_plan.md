# RTOS_service next deep-dive plan

## Цель
Выбрать 3–5 функций RTOS_service для немедленного глубокого разбора runtime/service pipeline.

## Статус после PR #28
- Первым deep-dive выбран и зафиксирован chain в valid_hex: `ppkp2001 90cye01.PZU: 0x4358 -> 0x920C -> 0x53E6`.
- Артефакты deep-trace: `docs/rtos_service_chain_4358_920c_53e6_trace.csv`, `docs/rtos_service_chain_4358_920c_53e6_summary.csv`, `docs/rtos_service_chain_4358_920c_53e6_analysis.md`.
- Следующий candidate chain после него:
  - `0x464B -> 0x920C -> 0x53E6`
  - или `0xAB62 -> 0x44F1 -> 0x53E6`

## Функция ppkp2001 90cye01.PZU:0x53E6
- Почему выбрана: высокий интегральный score=18, candidate_type=dispatcher_candidate, confidence=probable.
- Какие XDATA-адреса проверить: 0x6406..0x6422, 0x759C..0x75AE.
- Какие вызовы вокруг важны: 0x4358 -> 0x920C -> 0x53E6.
- Что искать: очередь, статус, событие, буфер, таблица, checksum-like арифметика.

## Функция ppkp2012 a01.PZU:0x5436
- Почему выбрана: высокий интегральный score=18, candidate_type=dispatcher_candidate, confidence=hypothesis.
- Какие XDATA-адреса проверить: 0x6406..0x6422, 0x759C..0x75AE.
- Какие вызовы вокруг важны: 0x4358 -> 0x9920 -> 0x5436.
- Что искать: очередь, статус, событие, буфер, таблица, checksum-like арифметика.

## Функция ppkp2001 90cye01.PZU:0x4358
- Почему выбрана: высокий интегральный score=17, candidate_type=dispatcher_candidate, confidence=probable.
- Какие XDATA-адреса проверить: 0x6406..0x6422, 0x759C..0x75AE.
- Какие вызовы вокруг важны: 0x4358 -> 0x920C -> 0x53E6.
- Что искать: очередь, статус, событие, буфер, таблица, checksum-like арифметика.

## Функция ppkp2001 90cye01.PZU:0x464B
- Почему выбрана: высокий интегральный score=17, candidate_type=dispatcher_candidate, confidence=probable.
- Какие XDATA-адреса проверить: 0x6406..0x6422, 0x759C..0x75AE.
- Какие вызовы вокруг важны: 0x464B -> 0x920C -> 0x53E6.
- Что искать: очередь, статус, событие, буфер, таблица, checksum-like арифметика.

## Функция ppkp2012 a01.PZU:0x4358
- Почему выбрана: высокий интегральный score=17, candidate_type=dispatcher_candidate, confidence=hypothesis.
- Какие XDATA-адреса проверить: 0x6406..0x6422, 0x759C..0x75AE.
- Какие вызовы вокруг важны: 0x4358 -> 0x9920 -> 0x5436.
- Что искать: очередь, статус, событие, буфер, таблица, checksum-like арифметика.

## Критерий успеха
- Успех: для каждой выбранной функции получена воспроизводимая роль в caller->core->callee пайплайне и зафиксирована привязка к конкретным XDATA runtime/service state кандидатам без заявлений о полном восстановлении packet format.
