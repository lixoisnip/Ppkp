# A03/A04 packet builder candidate analysis

Область этого шага ограничена **только веткой A03_A04** и только образами `A03_26.PZU` и `A04_28.PZU`.

## Что считается packet-pipeline candidate XDATA

В ранжировании `docs/a03_a04_packet_builder_candidates.csv` использованы следующие индикаторы:

- `snapshot_hits`: `0x3110`, `0x3128`;
- `queue_hits`: `0x329C`;
- `selector_hits`: `0x329D`;
- `object_table_hits`: `0x343D` и nearby-доступы около `0x343D` (окно ±`0x10`);
- `packet_xdata_hits`: диапазон `0x5003..0x5010`;
- дополнительные pipeline-адреса для заметок: `0x3298`, `0x32A2`.

Scoring-признаки:

- `+3` packet_xdata_hits;
- `+3` queue_hits;
- `+3` selector_hits;
- `+2` snapshot_hits;
- `+2` object_table_hits;
- `+1`, если `xdata_write_count > 0`;
- `+1`, если `xdata_read_count > 0`;
- `+1`, если `incoming_lcalls > 0`;
- `+1`, если `role_candidate` содержит `packet` / `service` / `dispatcher`.

Confidence:

- `probable`: `score >= 6`;
- `hypothesis`: `score = 3..5`;
- `unknown`: `score < 3`.

## Top-10 функций по score

| rank | file | function_addr | score | confidence | ключевые признаки |
|---:|---|---|---:|---|---|
| 1 | A04_28.PZU | 0x889F | 13 | probable | queue + selector + packet window |
| 2 | A03_26.PZU | 0x8904 | 10 | probable | queue + selector + aux(0x3298/0x32A2) |
| 3 | A04_28.PZU | 0x722E | 9 | probable | queue + packet window + aux |
| 4 | A04_28.PZU | 0x714C | 7 | probable | packet window |
| 5 | A03_26.PZU | 0x7259 | 7 | probable | queue |
| 6 | A04_28.PZU | 0xA2E2 | 6 | probable | packet window |
| 7 | A04_28.PZU | 0xB310 | 6 | probable | packet window |
| 8 | A04_28.PZU | 0x6B57 | 6 | probable | packet window |
| 9 | A04_28.PZU | 0x8E4C | 6 | probable | packet window |
| 10 | A04_28.PZU | 0x8F4A | 6 | probable | packet window |

## Почему это кандидаты

- **[confidence: probable]** Верхние кандидаты получают score за комбинацию queue/selector и packet-window (`0x5003..0x5010`) плюс признаки «живости» функции (`incoming_lcalls`, XDATA read/write).
- **[confidence: probable]** `0x889F` (A04) и `0x8904` (A03) выделяются как наиболее плотные по packet-pipeline индикаторам: есть совместные попадания в `0x329C`/`0x329D` и дополнительные вызовные/блочные признаки.
- **[confidence: hypothesis]** Группа функций с score `6..7` может быть как packet-builder path, так и runtime writer/helper path; пока это ранжирование по косвенным признакам, не proof wire-format.

## Что подтверждено vs что остаётся гипотезой

Подтверждено на уровне текущего шага:

- **[confidence: probable]** В A03/A04 есть функции с устойчивыми hit-ами по `0x329C`, `0x329D`, `0x5003..0x5010`.
- **[confidence: probable]** На текущем датасете нет hit-ов по snapshot (`0x3110`, `0x3128`) и object-table (`0x343D ± 0x10`) в отобранных кандидатов (поля `snapshot_hits/object_table_hits` остаются `0`).

Остаётся гипотезой:

- **[confidence: hypothesis]** Разделение на «packet_builder» vs «runtime packet writer» внутри top-кандидатов без трасс исполнения.
- **[confidence: hypothesis]** Семантика полей пакета и точная структура payload только по этим hit-ам.

## Что ещё нужно для восстановления wire-format

- **[confidence: probable]** Трассировка runtime-пути (эмуляция/логирование) для top-5 кандидатов с фиксацией последовательности записей в `0x5003..0x5010`.
- **[confidence: probable]** Корреляция вызовов кандидатов с типами событий/команд, чтобы связать selector/queue с конкретными packet type.
- **[confidence: hypothesis]** Дополнительные подтверждения по object-table/snapshot путям в соседних ветках или через расширенный xref, если эти адреса участвуют опосредованно.

Важно: на этом шаге **не утверждается**, что формат пакета восстановлен; выполнено только ранжирование кандидатов.
