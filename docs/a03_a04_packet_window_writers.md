# A03/A04 packet-window writers (0x5003..0x5010)

## Зачем искали packet-window writers
Нужен узкий срез функций ветки `A03_A04`, которые делают **confirmed XDATA write** в окно пакета `0x5003..0x5010`, чтобы локализовать места записи marker/packet-полей и сравнить A03 с A04. Это чисто static analysis по CSV-индексам (`function_map`, `basic_block_map`, `disassembly_index`, `xdata_confirmed_access`, `call_xref`), без runtime-доказательства.

## Что найдено
- `A04_28.PZU`: найдено 2 writer-функции (3 write-события). **[confidence: probable/hypothesis]**
- `A03_26.PZU`: writer-функций с confirmed write в `0x5003..0x5010` не найдено. **[confidence: probable]**

## Top writers для A04
1. `0x497A` (`state_update_worker`): writes в `0x5004` и `0x5005`, при этом внутри функции много арифметики (`nearby_arithmetic_hits=51`). **[confidence: probable]**
2. `0x89C9` (`unknown`): write в `0x500F`, без queue/selector/aux/arith признаков в пределах функции. **[confidence: hypothesis]**

## Top writers для A03
- В текущем confirmed-наборе нет ни одного write в `0x5003..0x5010` для `A03_26.PZU`. **[confidence: probable]**
- Это согласуется с предыдущим наблюдением: в цепочке A03 (`0xA900 -> 0x8904 -> 0x8A2E`) видны queue/selector writes (`0x329C/0x329D`), но не найден явный packet-window write в указанном диапазоне. **[confidence: hypothesis]**

## Аналоги A04:0x89C9 в A03
- Прямого аналога по confirmed write в packet-window пока нет.
- Ближайшие кандидаты для ручной трассировки — уже известная A03-цепочка (`0x8904`, `0x8A2E`) и ее upstream caller'ы, т.к. в статике они ближе к queue/selector pipeline, но не дают confirmed write в `0x5003..0x5010`. **[confidence: hypothesis]**

## Что трассировать следующими
1. В A03: caller-окрестность вокруг `0x8904` и `0x8A2E` (включая переходы между internal blocks), чтобы проверить, не выпадает ли write из confirmed-детектора.
2. В A04: caller/callee-контекст `0x89C9` (write `0x500F`) как эталон короткого packet-window writer-фрагмента.
3. Сверка reachable/disasm coverage в A03 на окнах, где в A04 присутствуют writes (`0x5004/0x5005/0x500F`).

> Важно: это **static analysis**, не runtime proof packet format и не окончательное восстановление packet pipeline.
