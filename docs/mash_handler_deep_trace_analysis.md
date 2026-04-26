# MASH/address-loop deep trace analysis

Дата: 2026-04-26 (UTC).

## Зачем deep-dive
Переход от общей модели к доказательному ordered static trace по top MASH chains: dispatcher -> handler -> state/event -> packet/export.

## Выбор цепочек
Выбрано цепочек: 8 (top-ranked из docs/mash_candidate_chains.csv c приоритетом dispatcher/core/packet адресов).

| branch | file | rank | chain | score | confidence |
|---|---|---:|---|---:|---|
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 2 | 0x84A6 -> 0x737C -> 0x84A6 | 15.600 | medium |
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 5 | 0x7017 -> 0x84A6 -> 0x737C | 15.600 | medium |
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 6 | 0x737C -> 0x84A6 -> 0x728A | 15.600 | medium |
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 7 | 0x737C -> 0x84A6 -> 0x7017 | 15.600 | medium |
| 90CYE_DKS | 90CYE03_19_DKS.PZU | 8 | 0x737C -> 0x84A6 -> 0x737C | 15.600 | medium |
| 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | 61 | 0x497F -> 0x8A42 -> 0x7574 | 12.000 | medium |
| A03_A04 | A03_26.PZU | 101 | 0x497A -> 0xA900 -> 0x800B | 14.300 | medium |
| RTOS_service | ppkp2001 90cye01.PZU | 117 | 0xAB62 -> 0xAB62 -> 0x758B | 16.300 | confirmed |

## Strongest MASH candidate
Текущий strongest candidate: `0xAB62 -> 0xAB62 -> 0x758B` в `ppkp2001 90cye01.PZU` (rank 117).

## Наблюдения по признакам
- **Признаки цикла адресного шлейфа:** есть в top chains через loop_like + conditional_branch + repeated calls (статически, confidence=probable).
- **Диапазон 1..159:** фиксируются immediate/branch marker с 0x01/0x63/0x9F/0xA0 в части цепочек (confidence=probable, не full recovery).
- **LED/status/fault:** bit_operation + XDATA writes + conditionals присутствуют (smoke_alarm/fault probable; isolator только hypothesis).
- **XDATA update:** подтверждён через xdata_read/xdata_write события в caller/core/callee функциях.
- **Event queue:** event_queue_integration marker встречается в выбранных цепочках (confidence=probable).
- **Packet/export bridge:** packet_export_integration marker встречается в выбранных цепочках (confidence=probable).

## Классификация выводов
- **confirmed:** статически подтверждён путь dispatcher->handler->XDATA->event/packet integration markers (как code evidence).
- **probable:** конкретная реализация опроса 1..159, LED/status/fault state transitions.
- **hypothesis:** isolator status path; полная привязка к конкретной модели извещателя.
- **unknown:** точные wire-level поля пакета для каждого состояния без стендовой валидации.

## Следующие функции для ручной декомпозиции
1. `0x497A` (dispatcher + poll scheduler, переход к state/event).
2. `0x737C` (устойчивый core handler candidate в DKS ветках).
3. `0x800B` (A03/A04 callee bridge к queue/packet зоне).

## Нужные стендовые проверки
- Прогон адресов 1..159 и фиксация реакций event/packet.
- Команда LED (вкл/выкл/мигание) и сравнение XDATA/packet side effects.
- Сценарий потери датчика / обрыв адресного шлейфа.
- Fault/short-circuit/isolator-like сценарий (isolator трактовать как hypothesis до прямых маркеров).
- Сравнение исходящих пакетов до/после событий по тем же адресам.

## Evidence boundaries
PDF по ИП212-200 / 22051E / 22051EI используется только как document evidence; chain-привязка сформирована из disassembly/XDATA/call-chain артефактов.
- global_packet_pipeline_chains.csv прочитан: 60 rows (использован как supporting context).
