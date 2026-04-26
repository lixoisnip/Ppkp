# RTOS_service branch-focused runtime/service pipeline analysis

## Почему выбрана ветка RTOS_service
- По branch-level сравнению ветка RTOS_service остаётся приоритетом для следующего крупного этапа runtime/service reverse.
- summary: files=ppkp2001 90cye01.PZU;ppkp2012 a01.PZU;ppkp2019 a02.PZU, valid_hex=1, checksum_errors=2, packet_like_function_count=101, writer_like_function_count=64.

## Файлы ветки и checksum статус
- ppkp2001 90cye01.PZU: valid_hex=True, checksum_errors=0.
- ppkp2012 a01.PZU: valid_hex=False, checksum_errors=1.
- ppkp2019 a02.PZU: valid_hex=False, checksum_errors=1.

## Почему checksum-error ограничивает confidence
- В этом отчёте метка `confirmed` не используется для кандидатов и цепочек.
- Для checksum_error файлов confidence ограничен уровнем hypothesis, кроме случаев повторяющегося паттерна из valid_hex файла.
- Поэтому результаты для ppkp2012/ppkp2019 трактуются как вероятностные и требуют ручной трассировки в валидном образе.

## XDATA-кластеры ветки RTOS_service
- rtos_core: 0x6406..0x6422
- service_flags: 0x759C..0x75AE
- secondary_flags: 0x769C..0x76AA
- nearby_runtime: 0x6419..0x6423, 0x66EA, 0x6892, 0x6894, 0x75AA, 0x75AB, 0x76AA, 0x76AB

## Top dispatcher candidates
- ppkp2001 90cye01.PZU:0x53E6 score=18 confidence=probable role=dispatcher_or_router hits(core/service/secondary)=17/120/0.
- ppkp2012 a01.PZU:0x5436 score=18 confidence=hypothesis role=dispatcher_or_router hits(core/service/secondary)=17/118/0.
- ppkp2001 90cye01.PZU:0x4358 score=17 confidence=probable role=dispatcher_or_router hits(core/service/secondary)=1/2/0.
- ppkp2001 90cye01.PZU:0x464B score=17 confidence=probable role=dispatcher_or_router hits(core/service/secondary)=1/1/0.
- ppkp2012 a01.PZU:0x4358 score=17 confidence=hypothesis role=dispatcher_or_router hits(core/service/secondary)=1/2/0.
- ppkp2012 a01.PZU:0x4658 score=17 confidence=hypothesis role=dispatcher_or_router hits(core/service/secondary)=1/1/0.
- ppkp2019 a02.PZU:0x57DB score=17 confidence=hypothesis role=dispatcher_or_router hits(core/service/secondary)=15/0/77.
- ppkp2019 a02.PZU:0x439D score=16 confidence=hypothesis role=dispatcher_or_router hits(core/service/secondary)=1/0/2.
- ppkp2019 a02.PZU:0x4744 score=16 confidence=hypothesis role=dispatcher_or_router hits(core/service/secondary)=1/0/1.
- ppkp2001 90cye01.PZU:0x44F1 score=14 confidence=probable role=dispatcher_or_router hits(core/service/secondary)=0/5/0.

## Top service worker candidates
- нет кандидатов

## Top xdata writer candidates
- ppkp2012 a01.PZU:0x84FA score=16 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=44/3/0.
- ppkp2001 90cye01.PZU:0x4F87 score=14 confidence=probable role=state_update_worker hits(core/service/secondary)=4/15/0.
- ppkp2001 90cye01.PZU:0x7EDA score=14 confidence=probable role=unknown hits(core/service/secondary)=44/3/0.
- ppkp2012 a01.PZU:0x4FE9 score=14 confidence=hypothesis role=unknown hits(core/service/secondary)=4/14/0.
- ppkp2019 a02.PZU:0x5388 score=13 confidence=hypothesis role=unknown hits(core/service/secondary)=4/0/14.
- ppkp2019 a02.PZU:0x8247 score=11 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=0/0/3.
- ppkp2019 a02.PZU:0xAF5D score=11 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=3/0/0.
- ppkp2001 90cye01.PZU:0x41E8 score=10 confidence=probable role=unknown hits(core/service/secondary)=0/1/0.
- ppkp2012 a01.PZU:0x41E8 score=10 confidence=hypothesis role=unknown hits(core/service/secondary)=0/1/0.
- ppkp2001 90cye01.PZU:0x4434 score=9 confidence=probable role=unknown hits(core/service/secondary)=10/0/0.

## Top table/string candidates
- ppkp2001 90cye01.PZU:0xA34D score=11 confidence=probable role=state_reader_or_packet_builder hits(core/service/secondary)=1/0/0.
- ppkp2012 a01.PZU:0xAA18 score=11 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=1/0/0.
- ppkp2001 90cye01.PZU:0x6BA4 score=10 confidence=probable role=unknown hits(core/service/secondary)=0/1/0.
- ppkp2012 a01.PZU:0x6C28 score=10 confidence=hypothesis role=unknown hits(core/service/secondary)=0/1/0.
- ppkp2001 90cye01.PZU:0x45FF score=7 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=0/0/0.
- ppkp2012 a01.PZU:0x460C score=7 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=0/0/0.
- ppkp2019 a02.PZU:0x46F8 score=7 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=0/0/0.
- ppkp2001 90cye01.PZU:0x4176 score=6 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=0/0/0.
- ppkp2001 90cye01.PZU:0x6717 score=6 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=0/0/0.
- ppkp2001 90cye01.PZU:0xAB40 score=6 confidence=hypothesis role=state_reader_or_packet_builder hits(core/service/secondary)=0/0/0.

## Top pipeline chains
- ppkp2001 90cye01.PZU rank=1: 0x4358 -> 0x920C -> 0x53E6, chain_score=46, confidence=probable, hits=18/125/0.
- ppkp2001 90cye01.PZU rank=2: 0x464B -> 0x920C -> 0x53E6, chain_score=46, confidence=probable, hits=18/124/0.
- ppkp2012 a01.PZU rank=1: 0x4358 -> 0x9920 -> 0x5436, chain_score=46, confidence=hypothesis, hits=18/123/0.
- ppkp2012 a01.PZU rank=2: 0x4658 -> 0x9920 -> 0x5436, chain_score=46, confidence=hypothesis, hits=18/122/0.
- ppkp2001 90cye01.PZU rank=3: 0xAB62 -> 0x44F1 -> 0x53E6, chain_score=45, confidence=probable, hits=20/125/0.
- ppkp2012 a01.PZU rank=3: 0xB606 -> 0x44FE -> 0x5436, chain_score=45, confidence=hypothesis, hits=20/123/0.
- ppkp2001 90cye01.PZU rank=4: 0x4358 -> 0x6BA4 -> 0x4358, chain_score=44, confidence=probable, hits=2/5/0.
- ppkp2001 90cye01.PZU rank=5: 0x464B -> 0x6BA4 -> 0x4358, chain_score=44, confidence=probable, hits=2/4/0.
- ppkp2012 a01.PZU rank=4: 0x4358 -> 0x6C28 -> 0x4358, chain_score=44, confidence=hypothesis, hits=2/5/0.
- ppkp2012 a01.PZU rank=5: 0x4658 -> 0x6C28 -> 0x4358, chain_score=44, confidence=hypothesis, hits=2/4/0.

## Какие функции стоит трассировать вручную первыми
- ppkp2001 90cye01.PZU:0x53E6 (dispatcher_candidate) — score=18, core/service/secondary=17/120/0, xread/xwrite=144/36.
- ppkp2012 a01.PZU:0x5436 (dispatcher_candidate) — score=18, core/service/secondary=17/118/0, xread/xwrite=144/39.
- ppkp2001 90cye01.PZU:0x4358 (dispatcher_candidate) — score=17, core/service/secondary=1/2/0, xread/xwrite=3/8.
- ppkp2001 90cye01.PZU:0x464B (dispatcher_candidate) — score=17, core/service/secondary=1/1/0, xread/xwrite=4/5.
- ppkp2012 a01.PZU:0x4358 (dispatcher_candidate) — score=17, core/service/secondary=1/2/0, xread/xwrite=3/8.

## confirmed / probable / hypothesis / unknown
- confirmed: не присваивается в рамках этого branch-focused этапа.
- probable: 25
- hypothesis: 129
- unknown: 151

## Что нельзя считать доказанным
- Нельзя считать восстановленным packet format.
- Нельзя считать доказанной семантику runtime/service state только по статическому XDATA-паттерну.
- Нельзя переносить адреса между RTOS_service и A03/A04 как прямые аналоги.

## Сравнение с A03/A04 (только архитектурный уровень)
- A03_A04 packet_like_function_count=36, RTOS_service=101 — обе ветки содержат крупные packet/runtime кластеры, но с разной адресной топологией.
- A03_A04 writer_like_function_count=36, RTOS_service=64 — RTOS_service даёт более плотный service/runtime call hub слой.
- Сопоставление делается по ролям (dispatcher/service/writer), а не по адресному переносу.

## Следующий практический milestone
- Выполнить deep-dive 3–5 функций из top score в valid_hex файле ppkp2001, затем проверить устойчивость выводов в checksum_error образах как secondary evidence.
- Smoke-test baseline на момент анализа: 20/20 pass.
