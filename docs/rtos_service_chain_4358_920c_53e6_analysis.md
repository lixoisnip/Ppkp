# RTOS_service deep chain trace: 0x4358 -> 0x920C -> 0x53E6

## Почему выбрана эта цепочка

- В `rtos_service_pipeline_chains.csv` цепочка имеет высокий chain_score=46 и confidence=probable (valid_hex=true).
- Цепочка полностью в `ppkp2001 90cye01.PZU` (основной валидный файл) и не требует опоры на checksum-error как primary evidence.
- Фокус: порядок XDATA-событий и роли caller/core/callee без заявлений о полном восстановлении packet format.

## Разбор функций цепочки

### 0x4358
- candidate role: **caller_router_candidate** (confidence=probable).
- XDATA read/write: 3/8; marker hits: rtos_core=3, service_flags=6, secondary=0, nearby=3.
- XDATA clusters/адреса (статически): 0x0001, 0x6408, 0x646E, 0x66E8, 0x66E9, 0x66EA, 0x66EB, 0x67EA, 0x759D, 0x75A9, 0x78E4.
- Calls/jumps: call_count=13; call targets sample: 0x43FC, 0x498F, 0x6BA4, 0x8F8C, 0x9134, 0x9143, 0x916D, 0x920C, 0x9275.
- table/string признаки: movc=0, string_refs=0; arithmetic_hits=12.

### 0x920C
- candidate role: **core_service_worker_candidate** (confidence=probable).
- XDATA read/write: 5/3; marker hits: rtos_core=0, service_flags=9, secondary=0, nearby=0.
- XDATA clusters/адреса (статически): 0x75A9, 0x7638, 0x7639, 0x763A, 0x7640.
- Calls/jumps: call_count=4; call targets sample: 0x49D5, 0x4A0F, 0x53E6, 0x90CD.
- table/string признаки: movc=0, string_refs=0; arithmetic_hits=14.

### 0x53E6
- candidate role: **dispatcher_candidate** (confidence=probable).
- XDATA read/write: 4/2; marker hits: rtos_core=0, service_flags=0, secondary=0, nearby=3.
- XDATA clusters/адреса (статически): 0x6423, 0x6433, 0x78E5, 0x78E9, 0x78EB.
- Calls/jumps: call_count=13; call targets sample: 0x4365, 0x4755, 0x4781, 0x49DF, 0x4A3B, 0x543D, 0x90C5, 0x90E0, 0x9134, 0x9143.
- table/string признаки: movc=0, string_refs=0; arithmetic_hits=10.

## Общий порядок событий в цепочке

1. 0x4358: instruction-flow + xdata(R/W=3/8), calls=13, conditional=10 (confidence=probable).
2. 0x920C: instruction-flow + xdata(R/W=5/3), calls=4, conditional=0 (confidence=probable).
3. 0x53E6: instruction-flow + xdata(R/W=4/2), calls=13, conditional=6 (confidence=probable).

## Где впервые появляются ключевые кластеры

- rtos_core 0x6406..0x6422: 0x4358 @ 0x436A.
- service_flags 0x759C..0x75AE: 0x4358 @ 0x4366.
- secondary_flags 0x769C..0x76AA: в этой цепочке не зафиксировано.

## Интерпретация ролей (confidence-capped)

- 0x53E6 как dispatcher: dispatcher_score=6, service_flag_hits=0 -> **strong candidate**, confidence=probable.
- 0x920C как core/service worker: service_worker_score=17 -> **worker-like**, confidence=probable.
- 0x4358 как caller/router: call_count=13 + branch activity -> **router-like**, confidence=probable.

## Признаки подготовки service/packet сообщения

- Есть признаки service-state обработки: множественные service_flags/rtos_core XDATA hits и арифметика в цепочке.
- Есть control-flow, похожий на dispatch/update pipeline (caller->core->callee).
- **Ограничение:** это статический трейс; формат packet/service сообщения не восстановлен и не заявляется как доказанный.

## Чего не хватает для доказательства

- Runtime подтверждения порядка событий (динамика/эмуляция/трассировка).
- Валидации семантики полей буфера и границ сообщений.
- Корреляции с внешним протоколом/реальными телеметрическими кадрами.

## Secondary comparison (checksum-error, только паттерн)

- ppkp2012 a01.PZU: 0x4358 -> 0x9920 -> 0x5436 присутствует в `rtos_service_pipeline_chains.csv` (confidence=hypothesis).
- ppkp2012 a01.PZU: 0x4658 -> 0x9920 -> 0x5436 также присутствует и структурно похожа на valid-цепочку.
- Использование строго secondary: checksum-error файлы не применяются как primary доказательство.

## Следующие функции (без нового широкого анализа)

- 0x464B -> 0x920C -> 0x53E6 (ближайшая альтернативная caller ветка в valid файле).
- 0xAB62 -> 0x44F1 -> 0x53E6 (вторая сильная ветка с общим callee 0x53E6).
- Дополнительно: углубить 0x44F1 как potential mid-layer service router/worker.
