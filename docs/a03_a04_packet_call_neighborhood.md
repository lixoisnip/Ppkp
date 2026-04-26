# A03/A04 local call-neighborhood around top packet-builder candidates

## Зачем анализировать соседние функции

Цель — сузить зону поиска формирования недостающих полей пакета (header/type/length/payload/checksum) вокруг двух top candidates (`A04_28.PZU:0x889F`, `A03_26.PZU:0x8904`) через локальный статический call-neighborhood (incoming + outgoing + внутренние переходы по блокам). **[confidence: high]**

Важно: это только статический срез по `LCALL`/`LJMP`/`SJMP` и карте базовых блоков, а не runtime-доказательство порядка формирования байтов пакета. **[confidence: high]**

## Incoming callers

### A04_28.PZU:0x889F

- Incoming caller найден: `0xB310` (вызов `LCALL` из `0xB445`). **[confidence: high]**
- `role_candidate` для `0xB310`: `state_reader_or_packet_builder`; есть XDATA-активность и packet-window хиты, плюс aux-hit `0x32A0`. **[confidence: medium]**

### A03_26.PZU:0x8904

- Incoming caller найден: `0xA900` (вызов `LCALL` из `0xAE4D`). **[confidence: high]**
- `role_candidate` для `0xA900`: `state_reader_or_packet_builder`; есть queue-hit (`0x329C`). **[confidence: medium]**

## Outgoing callees

### A04_28.PZU:0x889F

Outgoing `LCALL` в: `0x8989`, `0x8999`, `0x89B1`, `0x89C9`, `0x89DD`. **[confidence: high]**

- Из них `0x89C9` выделяется: есть XDATA read/write и попадание в packet window (`0x5003..0x5010`). **[confidence: medium]**
- Остальные callee в этом шаге выглядят как вспомогательные leaf-подфункции без выраженных pipeline hit. **[confidence: low]**

### A03_26.PZU:0x8904

Outgoing `LCALL` в: `0x89EE`, `0x89FE`, `0x8A16`, `0x8A2E`, `0x8A42`. **[confidence: high]**

- `0x8A2E` имеет XDATA read/write, но без явных packet-window/queue/selector/snapshot/object hits в текущем срезе. **[confidence: medium]**
- Остальные callee пока без сильных XDATA/MOVC маркеров packet header/type/length/checksum builder. **[confidence: low]**

## Nearby control-flow (внутри target)

- Для обеих целей зафиксированы локальные `LJMP`-блоки и несколько `conditional_branch`-переходов, привязанных к `parent_function_candidate` равному самой целевой функции. **[confidence: high]**
- Это подтверждает наличие внутренней развилки/ветвления в target-функциях, но не доказывает, где именно собирается checksum/length. **[confidence: medium]**

## Кто рядом похож на builder header/type/length/checksum

- По A04 окрестности наиболее перспективен `0x89C9` (из outgoing callee), т.к. он сочетает call-близость к `0x889F` и XDATA packet-window hit. **[confidence: medium]**
- По A03 явного «лучшего» соседа для header/type/length/checksum не выделилось; `0x8A2E` — лишь weak candidate из-за XDATA read/write без pipeline hit. **[confidence: low]**
- В обоих срезах MOVC-сигнатуры у соседей не являются определяющим фактором (в top-neighborhood значимых MOVC не видно). **[confidence: medium]**

## Сравнение A04 vs A03

- A04-ветка вокруг `0x889F` показывает более явный packet-window-сосед (`0x89C9`) и caller с aux-hit (`0xB310`, `0x32A0`). **[confidence: medium]**
- A03-ветка вокруг `0x8904` показывает caller с queue-hit (`0xA900`, `0x329C`), но outgoing-соседи слабее по pipeline-маркерам. **[confidence: medium]**

## Следующий маленький шаг

Сделать depth=2 расширение только для двух слабых мест (`A04:0x89C9`, `A03:0x8A2E`) и проверить их входящие/исходящие соседи на прямые записи в `0x329D` (selector), диапазон `0x5003..0x5010` (packet buffer) и на checksum-подобные паттерны записи/суммирования. **[confidence: medium]**
