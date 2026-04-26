# A03/A04 packet pipeline chain static trace (ordered)

Источник: `docs/a03_a04_packet_pipeline_chain_trace.csv` (построено скриптом `scripts/extract_pipeline_chain_trace.py`).

## Почему выбраны две цепочки

- A04: `0xB310 -> 0x889F -> 0x89C9` и A03: `0xA900 -> 0x8904 -> 0x8A2E` выбраны как целевые candidate chains из предыдущего этапа (после PR #20), чтобы не расширять call graph и сфокусироваться на внутреннем порядке операций в уже выделенных узлах. **[confidence: high]**
- Трасса остаётся строго static: только reachable disassembly + block/function maps + xdata/call/movc артефакты, без runtime-утверждений. **[confidence: high]**

## Кратко по A04: `0xB310 -> 0x889F -> 0x89C9`

- В `0xB310` есть подготовительные шаги и вызов `0x6C07`; packet-marker адреса в этом узле не доминируют. **[confidence: medium]**
- В `0x889F` появляется основная последовательность маркеров: `0x329C` (queue, read), затем `0x500C/0x500D` (packet-window, read), затем `0x329D` (selector, read), плюс записи в `0x32A0/0x32A1`. **[confidence: high]**
- В `0x89C9` фиксируется запись в окно пакета (`0x500F`) после локального вызова `0x89F9`. **[confidence: high]**

## Кратко по A03: `0xA900 -> 0x8904 -> 0x8A2E`

- `0xA900` выглядит как подготовительный узел с несколькими внешними вызовами (`0x6D38`, `0x6913`, `0x6824`) без явного packet-window marker в пределах текущей разметки. **[confidence: medium]**
- В `0x8904` сначала идут чтения aux-адресов (`0x4DB6`, `0x4FD7`, `0x4FD8`, `0x3298/0x3299`), затем записи в `0x329C` (queue) и `0x329D` (selector). **[confidence: high]**
- В `0x8A2E` в текущем static trace нет новых marker-событий для `0x329C/0x329D/0x5003..0x5010`. **[confidence: medium]**

## Порядок XDATA-событий, видимый в trace

- A04: first marker sequence в пределах chain: `aux(0x4DAC)` -> `queue(0x329C)` -> `packet-window(read @0x500C/0x500D)` -> `selector(0x329D)` -> `aux write(0x32A0/0x32A1)` -> `packet-window(write @0x500F)`. **[confidence: high]**
- A03: `aux(0x4DB6/0x4FD7/0x4FD8)` + `aux(0x3298/0x3299)` -> `queue write(0x329C)` -> `selector write(0x329D)`. Явная запись в `0x5003..0x5010` в данной цепочке не отмечена. **[confidence: high]**

## Где впервые появляется queue `0x329C`

- A04 chain: `0x889F:0x88A5` (read). **[confidence: high]**
- A03 chain: `0x8904:0x8938` (write). **[confidence: high]**

## Где появляется selector `0x329D`

- A04 chain: `0x889F:0x88C4` (read; также повторно `0x8900`). **[confidence: high]**
- A03 chain: `0x8904:0x893C` (write). **[confidence: high]**

## Где появляется packet-window `0x5003..0x5010`

- A04 chain: `0x889F` (read `0x500C`, `0x500D`) и `0x89C9` (write `0x500F`). **[confidence: high]**
- A03 chain: в пределах текущей цепочки не обнаружено marker-событий `0x5003..0x5010`. **[confidence: high]**

## Есть ли арифметика рядом с packet-window write

- В A04 перед write в `0x500F` виден локальный call и чтение `0x329F`; явной плотной серии `ADD/ADDC/SUBB/XRL/ANL/ORL/INC/DEC` непосредственно около `0x500F` не наблюдается (кроме отдельных `INC` в других местах цепочки). **[confidence: medium]**
- В A03, так как packet-window write в этой цепочке не отмечен, сравнимой локальной арифметической подцепочки для window write не видно. **[confidence: medium]**

## Признаки header/type/length/checksum

- По этому static trace нет достаточных оснований утверждать восстановление полей header/type/length/checksum: видно порядок некоторых XDATA-маркеров и вызовов, но не подтверждён wire-format. **[confidence: high]**

## Сравнение A04 и A03

- A04 демонстрирует явный доступ к packet-window (`0x500C/0x500D/0x500F`) внутри выбранной цепочки; A03 в этой же постановке показывает очередь/селектор и aux, но без marker-событий window. **[confidence: high]**
- В A03 queue/selector в trace выглядят как write, а в A04 — как read на этапе `0x889F`; это согласуется с возможным различием роли узлов в pipeline между ветками. **[confidence: medium]**

## Ограничение

- Это **static trace**, а не runtime proof: порядок основан на статическом индексе инструкций и блоков, и не доказывает фактическую динамическую последовательность во всех execution-path. **[confidence: high]**
