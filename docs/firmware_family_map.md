# Firmware family / branch map (.PZU)

Дата обновления: 2026-04-26 (UTC).

## 1) Краткая таблица веток

| branch | firmware files | notes |
|---|---|---|
| A03_A04 | `A03_26.PZU`, `A04_28.PZU` | близкая пара, общие ранние vectors и близкие XDATA-кластеры |
| 90CYE_DKS | `90CYE03_19_DKS.PZU`, `90CYE04_19_DKS.PZU` | DKS-линейка, сильный service cluster `0x5A7F/0x5D93` |
| 90CYE_v2_1 | `90CYE03_19_2 v2_1.PZU`, `90CYE04_19_2 v2_1.PZU` | v2.1-линейка, выраженные call hubs `0x72AC/0x78EB` |
| 90CYE_shifted_DKS | `90CYE02_27 DKS.PZU` | single-image ветка со сдвинутыми DKS-паттернами |
| RTOS_service | `ppkp2001 90cye01.PZU`, `ppkp2012 a01.PZU`, `ppkp2019 a02.PZU` | отдельный сервисный класс с diverged поздними vectors |

## 2) Характерные entry vectors

Источник: `docs/vector_entrypoints.csv`.

| branch | vector_4000 | vector_4006 | vector_400C | vector_4012 | vector_4018 | vector_401E |
|---|---:|---:|---:|---:|---:|---:|
| A03_A04 | `0x4100` | `0x4176` | `0x41D0` | `0x492E` | `0x4954` | `0x497A` |
| 90CYE_DKS | `0x4100` | `0x4176` | `0x41D0` | `0x492E` | `0x4954` | `0x497A` |
| 90CYE_v2_1 | `0x4100` | `0x4176` | `0x41D0` | `0x4933` | `0x4959` | `0x497F` |
| 90CYE_shifted_DKS | `0x4100` | `0x4176` | `0x41D0` | `0x4933` | `0x4959` | `0x497F` |
| RTOS_service | `0x4100` | `0x4176` | `0x41D0` | varies (`0xB395`/`0xB7C5`/`0xBE71`) | varies | varies |

## 3) Характерные XDATA-кластеры

Источник: `docs/xdata_confirmed_access.csv`.

- **A03_A04:** `0x3292..0x329C`, `0x4EAB..0x5003`, `0x7FF2/0x7FF6`.
- **90CYE_DKS:** `0x30EA..0x30F9`, `0x3122..0x3125`, `0x360C..0x361A`, `0x36D3`.
- **90CYE_v2_1:** `0x315D`, `0x3178..0x3195`, `0x3270`, `0x32A5`, `0x32D7`, `0x449D`, `0x462D`, `0x740C/0x740F`.
- **90CYE_shifted_DKS:** `0x30A4..0x30B2`, `0x30CE`, `0x3103`, `0x43A5/0x43AC`, `0x4575/0x4577/0x4578`.
- **RTOS_service:** `0x6406/0x6422`, `0x759C..0x75AE`, `0x769C/0x76AA`.

## 4) Характерные call-target clusters

Источник: `docs/call_targets_summary.csv`.

- **A03_A04:** `0x6C07`, `0x6D2E`, `0x94CE`, `0x950F`, `0x6F8F`, `0x6FB8`.
- **90CYE_DKS:** `0x5A7F`, `0x5D93`, `0x5D2E`, `0x5D02`, `0x5D60`.
- **90CYE_v2_1:** `0x72AC`, `0x78EB`, `0x7860`, `0x72AB`, `0x8D10`.
- **90CYE_shifted_DKS:** `0x604B`, `0x655F`, `0x6496`, `0x6507`, `0x64D4`.
- **RTOS_service:** `0x92EF`, `0x95B0`, `0x8F8C`, `0x919E`, `0x98B2`, `0x9489`.

## 5) Ограничения анализа

1. Анализ построен по статическим сигнатурам (`MOV DPTR,#imm`, `MOVX`, `MOVC`, `LCALL/LJMP`) без исполнения прошивки.
2. `LCALL/LJMP` выбираются по байтовому паттерну в диапазоне `0x4000..0xBFFF`; возможны отдельные ложные попадания в data-like областях.
3. `probable_pointer_argument` (DPTR→LCALL) показывает передачу указателя, но не доказывает тип структуры без декомпозиции callee.
4. `MOVC`-кандидаты дают указание на CODE-таблицы/строки, но не всегда это UI-строки (часть — lookup tables).
5. В `RTOS_service` поздние entry vectors различаются между тремя файлами, поэтому перенос ролей между ними ограничен.

## CFG-aware notes after PR #10

- `call_xref` теперь строится из reachable disassembly (через entry vectors и достижимые переходы), а не из плоского сканирования всего диапазона.
- Старый byte-scan оставлен только как legacy-слой для сравнения и отладки расхождений.
- `docs/function_map.csv` связывает кандидаты функций с наблюдаемыми XDATA read/write и `MOVC` evidence.
- Границы функций остаются approximate: `size_estimate` и хвосты функций чувствительны к качеству декодирования.
- Следующий шаг: улучшить `scripts/disasm_8051.py` и уточнить таблицу длин opcode, чтобы сократить ложные function tails.

## Function map cleanup after PR #15

- `function_map` теперь использует `basic_block_map` как источник для отсечения внутренних block-level targets и для агрегации метрик на уровне функции.
- Количество `function candidates` уменьшилось примерно с `1860` до `1076` после очистки.
- Внутренние ветви (internal jump/conditional blocks) остаются в `docs/basic_block_map.csv` и не дублируются как отдельные `function_addr` в `docs/function_map.csv`.
- Обновлённый `function_map` лучше подходит для поиска `packet builders` и `runtime service workers`, потому что уменьшается шум от внутренних переходов.
- Границы функций всё ещё `approximate` и требуют дополнительной валидации по CFG/дизассемблеру.

## 6) Что изменилось после PR #6

- Добавлен переход от «плоского» XDATA xref к evidence-based слоям: `confirmed access`, `pointer args`, `code table candidates`.
- Добавлена call cross-reference аналитика (`docs/call_xref.csv`, `docs/call_targets_summary.csv`) для поиска общих сервисных функций по веткам.
- Добавлен индекс строк/таблиц (`docs/string_index.csv`) на базе MOVC + ASCII/CP1251-попытки декодирования.
- Добавлен документ `docs/runtime_role_candidates.md` с кандидатами runtime-ролей и confidence-градацией.
