# MASH/address-loop code evidence analysis

## Что искали по PDF
- address_range_1_159: Verify address-loop scan cardinality (expected pattern: for addr in 1..159 or compare/counter bounds around 0x01 and 0x9F, confidence=medium).
- system_sensor_200ap_200plus_protocol: Find explicit protocol linkage (expected pattern: constants/tables/state machine matching 200AP or 200+ framing assumptions, confidence=low).
- led_control_from_panel: Map panel-driven LED behavior (expected pattern: bits/commands that toggle detector LEDs or remote LED outputs, confidence=medium).
- smoke_alarm_status: Locate smoke/alarm threshold path (expected pattern: analog value read plus threshold compare leading to alarm state/event, confidence=medium).
- fault_status: Track fault/normal/alarm tri-state logic (expected pattern: status flags for fault/open/short/device error with event mapping, confidence=medium).
- short_circuit_isolator_status: Support 22051EI isolator behavior (expected pattern: flags/branching for isolator trip or loop segment isolation, confidence=low).
- address_loop_polling: Find recurring query/response cycle (expected pattern: periodic scheduler task calling poll routine over address set, confidence=high).
- event_queue_integration: Connect detector state to event pipeline (expected pattern: enqueue/write into event buffer after status evaluation, confidence=high).
- packet_export_integration: Connect local events to outbound transport (expected pattern: packet builder/transmit calls after event enqueue, confidence=medium).

## Document evidence vs code evidence vs hypothesis
- **Document evidence:** IP212-200 22051E/22051EI, System Sensor 200AP/200+, адреса 01-159, LED from panel, short-circuit isolator (from PDF seed data).
- **Code evidence (this pass):** ranked candidates by branch/file/function for address-range constants, polling loops, bit+XDATA LED/status patterns, event queue and packet-export integration.
- **Hypothesis only:** isolator-specific behavior and full System Sensor protocol reconstruction remain hypothesis until direct textual/protocol markers are found.

## Top candidates по веткам
### 90CYE_DKS
- 90CYE03_19_DKS.PZU:0x497A — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=76; loops=100).
- 90CYE03_19_DKS.PZU:0x737C — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=20; loops=34).
- 90CYE03_19_DKS.PZU:0x84A6 — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=24; loops=14).
- 90CYE03_19_DKS.PZU:0x7184 — polling_loop_candidate score=6.880 confidence=medium (role=dispatcher_or_router; calls=16; loops=17).
- 90CYE03_19_DKS.PZU:0x497A — packet_export_candidate score=6.800 confidence=medium (role=dispatcher_or_router; calls=76; loops=100).
- 90CYE03_19_DKS.PZU:0x77BF — polling_loop_candidate score=6.720 confidence=medium (role=dispatcher_or_router; calls=14; loops=26).
- 90CYE03_19_DKS.PZU:0x7BC2 — polling_loop_candidate score=6.720 confidence=medium (role=dispatcher_or_router; calls=14; loops=23).
### 90CYE_shifted_DKS
- 90CYE02_27 DKS.PZU:0x497F — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=85; loops=63).
- 90CYE02_27 DKS.PZU:0x745A — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=22; loops=14).
- 90CYE02_27 DKS.PZU:0x7574 — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=22; loops=17).
- 90CYE02_27 DKS.PZU:0x497F — packet_export_candidate score=6.800 confidence=medium (role=dispatcher_or_router; calls=85; loops=63).
- 90CYE02_27 DKS.PZU:0x7E49 — polling_loop_candidate score=6.720 confidence=medium (role=dispatcher_or_router; calls=14; loops=23).
- 90CYE02_27 DKS.PZU:0x774F — polling_loop_candidate score=6.480 confidence=medium (role=dispatcher_or_router; calls=11; loops=18).
- 90CYE02_27 DKS.PZU:0x7E49 — packet_export_candidate score=6.320 confidence=medium (role=dispatcher_or_router; calls=14; loops=23).
### 90CYE_v2_1
- 90CYE03_19_2 v2_1.PZU:0x497F — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=93; loops=81).
- 90CYE03_19_2 v2_1.PZU:0x8BE5 — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=22; loops=14).
- 90CYE03_19_2 v2_1.PZU:0x90B6 — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=32; loops=45).
- 90CYE03_19_2 v2_1.PZU:0xA5A9 — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=25; loops=20).
- 90CYE03_19_2 v2_1.PZU:0xAA96 — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=30; loops=18).
- 90CYE03_19_2 v2_1.PZU:0x8D3B — polling_loop_candidate score=7.120 confidence=medium (role=dispatcher_or_router; calls=19; loops=18).
- 90CYE03_19_2 v2_1.PZU:0x93F9 — polling_loop_candidate score=7.040 confidence=medium (role=dispatcher_or_router; calls=18; loops=19).
### A03_A04
- A03_26.PZU:0x497A — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=90; loops=78).
- A03_26.PZU:0x800B — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=21; loops=14).
- A03_26.PZU:0xA900 — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=33; loops=15).
- A03_26.PZU:0x497A — packet_export_candidate score=6.800 confidence=medium (role=dispatcher_or_router; calls=90; loops=78).
- A03_26.PZU:0x8904 — polling_loop_candidate score=6.720 confidence=medium (role=dispatcher_or_router; calls=14; loops=23).
- A03_26.PZU:0xA900 — packet_export_candidate score=6.200 confidence=medium (role=dispatcher_or_router; calls=33; loops=15).
- A03_26.PZU:0x4100 — polling_loop_candidate score=6.000 confidence=medium (role=dispatcher_or_router; calls=5; loops=29).
### RTOS_service
- ppkp2001 90cye01.PZU:0x758B — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=127; loops=378).
- ppkp2001 90cye01.PZU:0x9A24 — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=25; loops=16).
- ppkp2001 90cye01.PZU:0xA3FD — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=70; loops=194).
- ppkp2001 90cye01.PZU:0xAB62 — polling_loop_candidate score=7.200 confidence=medium (role=dispatcher_or_router; calls=39; loops=30).
- ppkp2001 90cye01.PZU:0xA833 — polling_loop_candidate score=7.120 confidence=medium (role=dispatcher_or_router; calls=19; loops=40).
- ppkp2001 90cye01.PZU:0xA99A — polling_loop_candidate score=7.120 confidence=medium (role=dispatcher_or_router; calls=19; loops=40).
- ppkp2001 90cye01.PZU:0x485A — polling_loop_candidate score=6.960 confidence=medium (role=dispatcher_or_router; calls=17; loops=76).

## Отдельно A03/A04 candidates
- A03_26.PZU:0x497A polling_loop_candidate score=7.200 confidence=medium.
- A03_26.PZU:0x800B polling_loop_candidate score=7.200 confidence=medium.
- A03_26.PZU:0xA900 polling_loop_candidate score=7.200 confidence=medium.
- A03_26.PZU:0x497A packet_export_candidate score=6.800 confidence=medium.
- A03_26.PZU:0x8904 polling_loop_candidate score=6.720 confidence=medium.
- A03_26.PZU:0xA900 packet_export_candidate score=6.200 confidence=medium.
- A03_26.PZU:0x4100 polling_loop_candidate score=6.000 confidence=medium.
- A03_26.PZU:0x886D polling_loop_candidate score=6.000 confidence=medium.
- A03_26.PZU:0x497A common_mash_dispatcher_candidate score=5.900 confidence=low.
- A03_26.PZU:0x800B common_mash_dispatcher_candidate score=5.900 confidence=low.

## Отдельно RTOS_service candidates
- ppkp2001 90cye01.PZU:0x758B polling_loop_candidate score=7.200 confidence=medium.
- ppkp2001 90cye01.PZU:0x9A24 polling_loop_candidate score=7.200 confidence=medium.
- ppkp2001 90cye01.PZU:0xA3FD polling_loop_candidate score=7.200 confidence=medium.
- ppkp2001 90cye01.PZU:0xAB62 polling_loop_candidate score=7.200 confidence=medium.
- ppkp2001 90cye01.PZU:0xA833 polling_loop_candidate score=7.120 confidence=medium.
- ppkp2001 90cye01.PZU:0xA99A polling_loop_candidate score=7.120 confidence=medium.
- ppkp2001 90cye01.PZU:0x485A polling_loop_candidate score=6.960 confidence=medium.
- ppkp2001 90cye01.PZU:0x9B12 polling_loop_candidate score=6.880 confidence=medium.
- ppkp2001 90cye01.PZU:0x685A polling_loop_candidate score=6.720 confidence=medium.
- ppkp2001 90cye01.PZU:0x4228 polling_loop_candidate score=6.640 confidence=medium.

## Проверка ключевых признаков
- Адресный диапазон 1..159: есть кандидаты (count=21).
- Polling-loop candidates: есть (count=207).
- LED/bit-operation candidates: есть (count=85).
- Event/packet integration candidates: есть (count=170).

## Функции для следующего deep-dive
- 90CYE_DKS 90CYE03_19_DKS.PZU:0x497A (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_DKS 90CYE03_19_DKS.PZU:0x737C (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_DKS 90CYE03_19_DKS.PZU:0x84A6 (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_DKS 90CYE04_19_DKS.PZU:0x497A (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_DKS 90CYE04_19_DKS.PZU:0x737C (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_DKS 90CYE04_19_DKS.PZU:0x84A6 (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_shifted_DKS 90CYE02_27 DKS.PZU:0x497F (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_shifted_DKS 90CYE02_27 DKS.PZU:0x745A (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_shifted_DKS 90CYE02_27 DKS.PZU:0x7574 (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_v2_1 90CYE03_19_2 v2_1.PZU:0x497F (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_v2_1 90CYE03_19_2 v2_1.PZU:0x8BE5 (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.
- 90CYE_v2_1 90CYE03_19_2 v2_1.PZU:0x90B6 (polling_loop_candidate, score=7.200, confidence=medium) — проверить ручным disasm/xref chain.

## Почему это всё ещё не полное восстановление System Sensor 200AP/200+
- Нет прямых строковых/табличных маркеров протокола 200AP/200+.
- Candidate scoring основан на структурных паттернах (loops/xdata/calls), что остаётся косвенным evidence.
- Isolator path и точные packet formats пока отмечены как hypothesis.

