# Auto/manual gating deep trace analysis

Файл анализа: `90CYE03_19_DKS.PZU` (ветка `90CYE_DKS`).

## Где вероятный sensor/zone state update
- Основные кандидаты: `0x497A`, `0x737C`, `0x613C` (**probable** по state_marker/XDATA write и цепочке вызовов).

## Где вероятный mode check manual/auto
- Основной mode-check кандидат: `0x728A` (**hypothesis**).
- Внутри mode-кандидатов наибольший вклад дают conditional_branch + обращения к флаговым XDATA (`0x315B`, `0x30EA..0x30F9`).

## Есть ли manual-like ветка: fire -> event/packet only
- Найдены `manual_like_event_packet` trace rows: присутствуют переходы с packet_marker без output_marker (**probable**).
- Это трактуется как fire/event->packet export без явного старта output в том же узле (**hypothesis/probable**).

## Есть ли auto-like ветка: fire -> output/extinguishing start
- Основной output-start кандидат: `0x6833`; packet-export узел: `0x5A7F`.
- Найдены `auto_like_output_start` trace rows (вызов/узел `0x6833`) и downstream переходы к packet/export (**probable**).

## Главные XDATA кандидаты на mode/state flags
- `0x30EA..0x30F9` — state cluster candidate (**probable**).
- `0x315B` — mode/manual-auto candidate (**probable**).
- `0x3165`, `0x31BF`, `0x364B` — output/packet-gating side flags (**hypothesis/probable**).

## Как связаны 0x84A6, 0x728A, 0x6833, 0x5A7F
- `0x84A6`/`0x728A`: mode-branch split/gating candidates.
- `0x6833`: output/extinguishing start candidate.
- `0x5A7F`: packet/export candidate.
- Совокупно формируют вероятную развилку `state -> mode check -> (event/packet only | output start -> packet/export)`.

## Неизвестные enum/state коды
- Точные числовые enum для `fire/attention/fault` и окончательная карта битов manual/auto остаются unknown без стендовой валидации.

## Нужные стендовые тесты
1. Прогон fire в manual режиме: подтвердить отсутствие запуска тушения и наличие event/packet.
2. Прогон fire в auto режиме: подтвердить запуск output/extinguishing и последующий packet/export.
3. Fault/attention сценарии по зоне: сверка XDATA-флагов (`0x30EA..0x30F9`, `0x315B`, `0x3165`).

## Ограничения
- Это branch-specific static trace; полное восстановление логики пожаротушения без стенда **не утверждается**.
