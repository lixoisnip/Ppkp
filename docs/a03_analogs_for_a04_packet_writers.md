# A03 analogs for A04 packet-window writer functions

Этот документ нужен, чтобы выбрать функции A03 для следующей трассировки, когда в A03 нет confirmed write в 0x5003..0x5010.

Прямого совпадения по write в packet-window недостаточно: часть логики может быть вынесена в соседние worker/dispatcher функции, поэтому мы используем structural similarity по function-map, xdata-паттернам и call-neighborhood.

### Top A03 candidates for A04:0x497A
- A03:0x497A score=10.25 confidence=probable pipeline_hits=0 near_chain=yes role=state_update_worker
- A03:0x86C5 score=8.25 confidence=probable pipeline_hits=0 near_chain=yes role=state_update_worker
- A03:0x810E score=7.50 confidence=hypothesis pipeline_hits=0 near_chain=yes role=state_update_worker
- A03:0x8B0B score=7.25 confidence=hypothesis pipeline_hits=1 near_chain=yes role=state_update_worker
- A03:0x7953 score=7.00 confidence=hypothesis pipeline_hits=3 near_chain=yes role=state_update_worker

### Top A03 candidates for A04:0x89C9
- A03:0x89EE score=9.25 confidence=probable pipeline_hits=0 near_chain=yes role=unknown
- A03:0xA248 score=9.25 confidence=probable pipeline_hits=0 near_chain=yes role=unknown
- A03:0x680C score=9.00 confidence=probable pipeline_hits=0 near_chain=yes role=unknown
- A03:0x8A42 score=9.00 confidence=probable pipeline_hits=0 near_chain=yes role=unknown
- A03:0x6834 score=8.75 confidence=probable pipeline_hits=0 near_chain=yes role=unknown

## Связь с цепочкой A03 0xA900 -> 0x8904 -> 0x8A2E

- Метка `near_known_a03_chain=yes` означает расстояние в call-neighborhood <=2 от этой цепочки.
- Это индикатор приоритета трассировки, но не доказательство packet format.

## Следующие кандидаты для трассировки

- В первую очередь: кандидаты `confidence=probable` и `near_known_a03_chain=yes`.
- Затем: `confidence=hypothesis` с ненулевым `a03_pipeline_hits`.

**Важно:** это structural similarity analysis, не финальное доказательство соответствия packet формату.
