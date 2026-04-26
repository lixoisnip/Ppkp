# A03/A04 depth=2 call-neighborhood around weak packet-builder neighbors

## Почему выбраны A04:0x89C9 и A03:0x8A2E

- После предыдущего шага именно эти две функции были ближайшими outgoing-соседями top-candidates (`A04:0x889F` и `A03:0x8904`), но с разной силой сигналов. **[confidence: high]**
- `A04_28.PZU:0x89C9` уже показывал packet-window активность и XDATA read/write, поэтому это приоритетный узел для depth=2. **[confidence: medium]**
- `A03_26.PZU:0x8A2E` имел XDATA read/write без явных packet-window/queue/selector хитов — нужен depth=2 для проверки соседей второго уровня. **[confidence: medium]**

## Что найдено в depth=2

- Для `A04:0x89C9` depth=1 соседи: incoming `0x889F`, outgoing `0x89F9`; depth=2 добавил набор узлов `0x8989/0x8999/0x89B1/0x89DD/0xB310` (incoming_depth2) и `0x8989/0x8999/0x89B1/0x89DD` (outgoing_depth2). **[confidence: high]**
- Для `A03:0x8A2E` depth=1 соседи: incoming `0x8904`, outgoing `0x8A5E`; depth=2 добавил `0x89EE/0x89FE/0x8A16/0x8A42/0xA900` (incoming_depth2) и `0x89EE/0x89FE/0x8A16/0x8A42` (outgoing_depth2). **[confidence: high]**

## Есть ли новые packet-window / selector / queue сигналы

- Новых **depth=2** функций с packet-window hit (`0x5003..0x5010`) не появилось. **[confidence: medium]**
- Новых **depth=2** selector hit (`0x329D`) не появилось. **[confidence: medium]**
- Новых **depth=2** queue hit (`0x329C`) не появилось. **[confidence: medium]**
- Основные сигналы остаются в depth=1 узлах: `A04` через incoming `0x889F` (queue+selector+packet-window), `A03` через incoming `0x8904` (queue+selector). **[confidence: medium]**

## Checksum-like candidates

- Добавлена простая метка `checksum_like`:
  - `true`, если в пределах функции найдено арифметическое ядро (`ADD/ADDC/SUBB/XRL/ANL/ORL`) и есть запись в packet-window/queue/selector;
  - иначе `unknown`. **[confidence: high]**
- В текущем depth=2 срезе новых `checksum_like=true` кандидатов не выявлено; значения остались `unknown`. **[confidence: medium]**

## Сравнение веток A04 и A03

- Ветка `A04:0x89C9` остается сильнее по близости к packet-window цепочке (через depth=1 узел `0x889F` и связь с `0xB310`). **[confidence: medium]**
- Ветка `A03:0x8A2E` подтверждает управляющую/маршрутизирующую близость через `0x8904`, но depth=2 не добавил более явного header/type/length/checksum builder. **[confidence: medium]**

## Ограничения

- Это только статический анализ по `call_xref` + `function_map` + `xdata_confirmed_access` + `disassembly_index`; это не runtime proof и не восстановление packet format. **[confidence: high]**

## Следующий маленький шаг

- Точечно углубить только в `depth=2` узлы с наибольшей связностью (`A04:0x889F`, `A03:0x8904`, `A04:0xB310`, `A03:0xA900`) и проверить, появляются ли явные write-последовательности в `0x5003..0x5010` рядом с арифметическими блоками в более узком trace-окне. **[confidence: medium]**
