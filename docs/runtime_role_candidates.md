# Runtime role candidates by firmware branch

Дата обновления: 2026-04-26 (UTC).

Метод: сопоставление `confirmed_xdata_*` + `probable_pointer_argument` + `MOVC` (`code_table_or_string_candidate`) + кластеры `LCALL/LJMP` по веткам. Набор ролей ниже — это рабочие гипотезы для следующего этапа реверса.

## A03_A04

Подтверждающие файлы: `A03_26.PZU`, `A04_28.PZU`.

| role | address/range | чем подтверждается | какие файлы подтверждают | confidence |
|---|---|---|---|---|
| current_object_idx | `0x0001` | стабильные `confirmed_xdata_read` | `A03_26.PZU`, `A04_28.PZU` | probable |
| object_table_base | `0x3292..0x329C` | плотный кластер read/write и offset-access | `A03_26.PZU`, `A04_28.PZU` | probable |
| change_queue_flags | `0x3281/0x3282/0x3293/0x3298` | повторяющиеся `confirmed_xdata_write` | `A03_26.PZU`, `A04_28.PZU` | probable |
| tx_selector | `0x7FF2/0x7FF6` | write/read рядом с сервисными вызовами | `A03_26.PZU`, `A04_28.PZU` | hypothesis |
| snapshot_block_1 | `0x4EAB..0x4EB4` | read+write cluster, встречается в offset-access | `A03_26.PZU`, `A04_28.PZU` | hypothesis |
| snapshot_block_2 | `0x4FCE..0x5003` | самые частые чтения ветки | `A03_26.PZU`, `A04_28.PZU` | probable |
| event_code | `0x3010` | точечные writes в транзакциях | `A03_26.PZU`, `A04_28.PZU` | hypothesis |
| packet_buffer | `0x3298..0x329C` + `0x4FCE..0x5003` | одновременные read/write с указательными аргументами в `0x6C06/0x6D2D` | `A03_26.PZU`, `A04_28.PZU` | probable |
| packet_builders | call-target cluster `0x6C07`, `0x6D2E`, `0x6F8F`, `0x6FB8` | высокий `LCALL`/`LJMP` в `call_targets_summary` | `A03_26.PZU`, `A04_28.PZU` | probable |
| ui_string_table | CODE refs `0x7758..0x8094`; strings `0x5010` и меню-метки | `MOVC` + `string_index` | `A03_26.PZU`, `A04_28.PZU` | probable |
| service_cluster | `0x94CE/0x950F` и `0x9F29` | частые branch-level call hubs | `A03_26.PZU`, `A04_28.PZU` | probable |

### Function-map evidence after PR #10

> Примечание (после PR #15): `function_map.csv` очищен с использованием `basic_block_map.csv`; обычные internal jump/conditional branch targets больше не считаются отдельными `function_addr`; `basic_block_count` и `internal_block_count` теперь используются как индикаторы сложности функции.

| function_addr | role_candidate | basic_block_count | internal_block_count | xdata_read_count | xdata_write_count | movc_count | confidence |
|---|---|---:|---:|---:|---:|---:|---|
| `0x6C7E` | `state_reader_or_packet_builder` | 20 | 19 | 5 | 0 | 1 | `probable` |
| `0x6B57` | `state_reader_or_packet_builder` | 20 | 19 | 5 | 0 | 1 | `probable` |
| `0x8904` | `dispatcher_or_router` | 13 | 12 | 15 | 2 | 0 | `probable` |
| `0x889F` | `dispatcher_or_router` | 13 | 12 | 15 | 2 | 0 | `probable` |
| `0x80C3` | `state_update_worker` | 9 | 8 | 5 | 3 | 0 | `probable` |
| `0x8012` | `state_update_worker` | 9 | 8 | 5 | 3 | 0 | `probable` |

## 90CYE_DKS

Подтверждающие файлы: `90CYE03_19_DKS.PZU`, `90CYE04_19_DKS.PZU`.

| role | address/range | чем подтверждается | какие файлы подтверждают | confidence |
|---|---|---|---|---|
| current_object_idx | `0x0001` | частые чтения | оба DKS-файла | probable |
| object_table_base | `0x30EA..0x30F9` | dense read/write cluster | оба DKS-файла | probable |
| change_queue_flags | `0x30EB`, `0x3612..0x3617` | доминирующие writes | оба DKS-файла | probable |
| tx_selector | `0x315B`, `0x3122..0x3125` | повторяемые reads в управляющих ветках | оба DKS-файла | hypothesis |
| snapshot_block_1 | `0x360C..0x361A` | high-frequency reads + writes | оба DKS-файла | probable |
| snapshot_block_2 | `0x36D3..0x36D5` | самый частый read узел + writes рядом | оба DKS-файла | probable |
| event_code | `0x30A0/0x30A7` | точечные writes при переходах | оба DKS-файла | hypothesis |
| packet_buffer | `0x31BF`, `0x364B`, `0x3165` (как pointer args в `0x5A7F`) | `probable_pointer_argument` | оба DKS-файла | probable |
| packet_builders | `0x5A7F`, `0x5D93`, `0x5D2E` | крупнейший call-target cluster ветки | оба DKS-файла | probable |
| ui_string_table | CODE refs `0x5999..0x6E17`, строки `0x5010`, `0x52EB..0x5C2C` | `MOVC` + `string_index` | оба DKS-файла | probable |
| service_cluster | `0x5D02/0x5D60/0x5D3D` | mixed LCALL/LJMP dispatcher-профиль | оба DKS-файла | probable |

### Function-map evidence after PR #10

> Примечание (после PR #15): `function_map.csv` очищен с использованием `basic_block_map.csv`; обычные internal jump/conditional branch targets больше не считаются отдельными `function_addr`; `basic_block_count` и `internal_block_count` теперь используются как индикаторы сложности функции.

| function_addr | role_candidate | basic_block_count | internal_block_count | xdata_read_count | xdata_write_count | movc_count | confidence |
|---|---|---:|---:|---:|---:|---:|---|
| `0x59A0` | `state_reader_or_packet_builder` | 18 | 17 | 6 | 0 | 2 | `probable` |
| `0x7017` | `dispatcher_or_router` | 17 | 16 | 17 | 4 | 0 | `probable` |
| `0x6EF2` | `dispatcher_or_router` | 15 | 14 | 18 | 4 | 0 | `probable` |
| `0x7BC2` | `dispatcher_or_router` | 13 | 12 | 15 | 2 | 0 | `probable` |
| `0x673C` | `dispatcher_or_router` | 12 | 11 | 8 | 2 | 0 | `probable` |
| `0x737C` | `dispatcher_or_router` | 8 | 7 | 11 | 6 | 1 | `probable` |

## 90CYE_v2_1

Подтверждающие файлы: `90CYE03_19_2 v2_1.PZU`, `90CYE04_19_2 v2_1.PZU`.

| role | address/range | чем подтверждается | какие файлы подтверждают | confidence |
|---|---|---|---|---|
| current_object_idx | `0x0001` | устойчивые reads | оба v2_1-файла | probable |
| object_table_base | `0x3178/0x3179/0x3195` | плотный read/write индексный кластер | оба v2_1-файла | probable |
| change_queue_flags | `0x3173/0x3177/0x317B` | write-heavy группа | оба v2_1-файла | probable |
| tx_selector | `0x740C/0x740F` | частые reads в вызовных цепочках | оба v2_1-файла | hypothesis |
| snapshot_block_1 | `0x3270/0x32A5` | стабильные reads | оба v2_1-файла | probable |
| snapshot_block_2 | `0x32D7` + `0x462D` | два доминирующих read-узла ветки | оба v2_1-файла | confirmed |
| event_code | `0x315C/0x315D` | read/write переключения | оба v2_1-файла | hypothesis |
| packet_buffer | `0x44A3/0x44E3/0x44C3`, `0x3353`, `0x317D` | pointer args для `0x8D10` и `0x72AB` | оба v2_1-файла | probable |
| packet_builders | `0x72AC`, `0x78EB`, `0x72AB`, `0x8D10` | high-volume call hubs | оба v2_1-файла | probable |
| ui_string_table | CODE refs `0x736B..0x8C74`, строки `0x5010`, `0x60EF..0x66E0` | `MOVC` + `string_index` | оба v2_1-файла | probable |
| service_cluster | `0x781A/0x72DC/0x78B8` | смешанные LCALL/LJMP узлы | оба v2_1-файла | probable |

### Function-map evidence after PR #10

> Примечание (после PR #15): `function_map.csv` очищен с использованием `basic_block_map.csv`; обычные internal jump/conditional branch targets больше не считаются отдельными `function_addr`; `basic_block_count` и `internal_block_count` теперь используются как индикаторы сложности функции.

| function_addr | role_candidate | basic_block_count | internal_block_count | xdata_read_count | xdata_write_count | movc_count | confidence |
|---|---|---:|---:|---:|---:|---:|---|
| `0x7375` | `state_reader_or_packet_builder` | 20 | 19 | 8 | 0 | 1 | `probable` |
| `0x8EB8` | `dispatcher_or_router` | 18 | 17 | 16 | 4 | 0 | `probable` |
| `0x8D3B` | `dispatcher_or_router` | 16 | 15 | 3 | 0 | 0 | `probable` |
| `0x93F9` | `dispatcher_or_router` | 14 | 13 | 23 | 6 | 2 | `probable` |
| `0x9D25` | `dispatcher_or_router` | 14 | 13 | 15 | 1 | 0 | `probable` |
| `0x740B` | `state_reader_or_packet_builder` | 14 | 13 | 7 | 0 | 0 | `probable` |

## 90CYE_shifted_DKS

Подтверждающий файл: `90CYE02_27 DKS.PZU`.

| role | address/range | чем подтверждается | какие файлы подтверждают | confidence |
|---|---|---|---|---|
| current_object_idx | `0x0001` | повторяемые reads | `90CYE02_27 DKS.PZU` | probable |
| object_table_base | `0x30A4..0x30B2` | плотный read/write кластер | `90CYE02_27 DKS.PZU` | probable |
| change_queue_flags | `0x30B1/0x30B2/0x30A4/0x30A5` | лидеры writes | `90CYE02_27 DKS.PZU` | probable |
| tx_selector | `0x4575/0x4577/0x4578` | доминирующие reads + синхронизационные writes | `90CYE02_27 DKS.PZU` | probable |
| snapshot_block_1 | `0x43A5/0x43AC` | read/write пара в быстрых циклах | `90CYE02_27 DKS.PZU` | probable |
| snapshot_block_2 | `0x30CE/0x3103` | частые reads в той же подсистеме | `90CYE02_27 DKS.PZU` | hypothesis |
| event_code | `0x31D1` | локальные writes рядом с call-dispatch | `90CYE02_27 DKS.PZU` | hypothesis |
| packet_buffer | `0x31DD`, `0x7248/0x724A`, `0x52F8` | pointer args для `0x6083`, `0x7551`, `0x655F` | `90CYE02_27 DKS.PZU` | probable |
| packet_builders | `0x604B`, `0x655F`, `0x6496`, `0x6507` | крупнейшие call hubs | `90CYE02_27 DKS.PZU` | probable |
| ui_string_table | CODE refs `0x60FC..0x74E9`, строки `0x5010`, `0x5329..0x5C2C` | `MOVC` + `string_index` | `90CYE02_27 DKS.PZU` | probable |
| service_cluster | `0x6067/0x6070/0x6083` | частые сервисные targets для pointer args | `90CYE02_27 DKS.PZU` | probable |

### Function-map evidence after PR #10

> Примечание (после PR #15): `function_map.csv` очищен с использованием `basic_block_map.csv`; обычные internal jump/conditional branch targets больше не считаются отдельными `function_addr`; `basic_block_count` и `internal_block_count` теперь используются как индикаторы сложности функции.

| function_addr | role_candidate | basic_block_count | internal_block_count | xdata_read_count | xdata_write_count | movc_count | confidence |
|---|---|---:|---:|---:|---:|---:|---|
| `0x6106` | `state_reader_or_packet_builder` | 20 | 19 | 6 | 0 | 1 | `probable` |
| `0x774F` | `dispatcher_or_router` | 17 | 16 | 15 | 8 | 0 | `probable` |
| `0x7574` | `dispatcher_or_router` | 16 | 15 | 3 | 0 | 0 | `probable` |
| `0x7E49` | `dispatcher_or_router` | 14 | 13 | 15 | 1 | 0 | `probable` |
| `0x72E4` | `code_table_or_ui_worker` | 9 | 8 | 0 | 0 | 2 | `probable` |
| `0x8442` | `state_reader_or_packet_builder` | 8 | 7 | 6 | 0 | 0 | `probable` |

## RTOS_service

Подтверждающие файлы: `ppkp2001 90cye01.PZU`, `ppkp2012 a01.PZU`, `ppkp2019 a02.PZU`.

| role | address/range | чем подтверждается | какие файлы подтверждают | confidence |
|---|---|---|---|---|
| current_object_idx | unknown | нет единого low-address кандидата во всех 3 образах | все RTOS_service | unknown |
| object_table_base | `0x6406/0x6422` | самые частые reads по ветке | все RTOS_service | probable |
| change_queue_flags | `0x759C/0x759D/0x759F/0x75A0` | write-heavy флаги | все RTOS_service | probable |
| tx_selector | `0x75AA/0x75AB/0x75AD` | комбинированные read/write и вызовные цепочки | все RTOS_service | probable |
| snapshot_block_1 | `0x769C/0x769D` | повторяемые reads+writes | все RTOS_service | probable |
| snapshot_block_2 | `0x76AA` | частые reads в одной подсистеме | все RTOS_service | hypothesis |
| event_code | `0x6408/0x6423` | локальные writes рядом с `0x6406/0x6422` | все RTOS_service | hypothesis |
| packet_buffer | `0x68AA/0x6700/0x6703/0x444A/0x443D` | pointer args к `0x92EF/0x8F8C/0x95B0/0x9848/0x9134` | все RTOS_service | probable |
| packet_builders | `0x92EF`, `0x95B0`, `0x8F8C` | крупнейшие branch-level call hubs | все RTOS_service | probable |
| ui_string_table | CODE refs `0x42D3..0x93B9`, строки `0x5010` и текстовые блоки `0x66CE+` | `MOVC` + `string_index` | все RTOS_service | hypothesis |
| service_cluster | `0x919E`, `0x98B2`, `0x9489`, `0x94D6`, `0x91A5` | устойчивый набор сервисных call-target | все RTOS_service | probable |

### Function-map evidence after PR #10

> Примечание (после PR #15): `function_map.csv` очищен с использованием `basic_block_map.csv`; обычные internal jump/conditional branch targets больше не считаются отдельными `function_addr`; `basic_block_count` и `internal_block_count` теперь используются как индикаторы сложности функции.

| function_addr | role_candidate | basic_block_count | internal_block_count | xdata_read_count | xdata_write_count | movc_count | confidence |
|---|---|---:|---:|---:|---:|---:|---|
| `0x6C9A` | `dispatcher_or_router` | 34 | 33 | 6 | 0 | 0 | `probable` |
| `0x95D3` | `dispatcher_or_router` | 31 | 30 | 4 | 0 | 0 | `probable` |
| `0x4228` | `dispatcher_or_router` | 29 | 28 | 5 | 0 | 1 | `probable` |
| `0x47EF` | `dispatcher_or_router` | 18 | 17 | 0 | 1 | 0 | `probable` |
| `0x4840` | `dispatcher_or_router` | 18 | 17 | 0 | 1 | 0 | `probable` |
| `0x495D` | `dispatcher_or_router` | 18 | 17 | 0 | 1 | 0 | `probable` |

## Ограничения текущей реконструкции ролей

- Анализ статический, без полного CFG и без трассировки исполнения.
- `LCALL/LJMP` выборка строится по байтовым сигнатурам и может включать ложные срабатывания внутри данных.
- `MOVC`-таблицы дают сильную подсказку на CODE-строки/таблицы, но не всегда разделяют `ui_string_table` и другие lookup-table.
- Для `RTOS_service` наблюдается divergence между тремя образами в entry vectors (`0x4012/0x4018/0x401E`), поэтому часть ролей помечена как `hypothesis/unknown`.
