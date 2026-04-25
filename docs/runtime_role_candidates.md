# Runtime role candidates by firmware branch

Дата обновления: 2026-04-25 (UTC).

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

- `0x6D38` — `code_table_or_ui_worker`; xdata r/w=`194/50`; movc=`7`; confidence=`probable`.
- `0x6409` — `state_update_worker`; xdata r/w=`7/5`; movc=`0`; confidence=`probable`.
- `0x9FD8` — `service_or_runtime_worker`; xdata r/w=`4/0`; movc=`0`; confidence=`probable`.
- `0xA2F5` — `dispatcher_or_router`; xdata r/w=`28/3`; movc=`0`; confidence=`probable`.
- `0x6BBB` — `state_reader_or_packet_builder`; xdata r/w=`7/0`; movc=`1`; confidence=`probable`.
- `0x694E` — `unknown`; xdata r/w=`0/0`; movc=`0`; confidence=`hypothesis`.

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

- `0x54BC` — `code_table_or_ui_worker`; xdata r/w=`259/104`; movc=`11`; confidence=`probable`.
- `0x792E` — `state_update_worker`; xdata r/w=`104/14`; movc=`1`; confidence=`probable`.
- `0x859A` — `state_reader_or_packet_builder`; xdata r/w=`5/0`; movc=`0`; confidence=`probable`.
- `0x862D` — `unknown`; xdata r/w=`1/0`; movc=`0`; confidence=`probable`.
- `0x41E8` — `unknown`; xdata r/w=`0/0`; movc=`0`; confidence=`hypothesis`.

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

- `0x72AC` — `code_table_or_ui_worker`; xdata r/w=`157/30`; movc=`8`; confidence=`probable`.
- `0x8FC4` — `code_table_or_ui_worker`; xdata r/w=`61/17`; movc=`3`; confidence=`probable`.
- `0x9B22` — `state_update_worker`; xdata r/w=`88/12`; movc=`0`; confidence=`probable`.
- `0xA5A9` — `code_table_or_ui_worker`; xdata r/w=`39/1`; movc=`6`; confidence=`probable`.
- `0x6E7C` — `state_update_worker`; xdata r/w=`12/9`; movc=`0`; confidence=`probable`.
- `0xAC3A` — `state_reader_or_packet_builder`; xdata r/w=`4/0`; movc=`0`; confidence=`probable`.

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

- `0x5CF4` — `code_table_or_ui_worker`; xdata r/w=`155/66`; movc=`7`; confidence=`probable`.
- `0x7FDB` — `state_update_worker`; xdata r/w=`49/9`; movc=`0`; confidence=`probable`.
- `0x7C46` — `state_update_worker`; xdata r/w=`40/6`; movc=`0`; confidence=`probable`.
- `0x8B6D` — `unknown`; xdata r/w=`2/0`; movc=`0`; confidence=`probable`.
- `0x4176` — `state_reader_or_packet_builder`; xdata r/w=`5/0`; movc=`0`; confidence=`unknown`.

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

- `0x41E8` — `code_table_or_ui_worker`; xdata r/w=`484/98` (до `511/107` в других файлах ветки); movc=`9` (до `21`); confidence=`probable`.
- `0xAFB9` — `state_reader_or_packet_builder`; xdata r/w=`7/0`; movc=`0`; confidence=`probable`.
- `0xAB9B` — `state_reader_or_packet_builder`; xdata r/w=`6/0`; movc=`0`; confidence=`probable`.
- `0xB647` — `state_reader_or_packet_builder`; xdata r/w=`6/0`; movc=`0`; confidence=`probable`.
- `0x4176` — `state_reader_or_packet_builder`; xdata r/w=`5/0`; movc=`0`; confidence=`unknown`.
- `0xAC75` — `dispatcher_or_router`; xdata r/w=`0/0`; movc=`0`; confidence=`hypothesis`.

## Ограничения текущей реконструкции ролей

- Анализ статический, без полного CFG и без трассировки исполнения.
- `LCALL/LJMP` выборка строится по байтовым сигнатурам и может включать ложные срабатывания внутри данных.
- `MOVC`-таблицы дают сильную подсказку на CODE-строки/таблицы, но не всегда разделяют `ui_string_table` и другие lookup-table.
- Для `RTOS_service` наблюдается divergence между тремя образами в entry vectors (`0x4012/0x4018/0x401E`), поэтому часть ролей помечена как `hypothesis/unknown`.
