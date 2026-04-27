# Project-level state/enum candidates

Evidence level: `project_documentation`

> Numeric codes remain unknown from project docs. Existing firmware enum candidates stay `hypothesis` unless direct static evidence upgrades them.

| term | project meaning | device scope | possible firmware enum/code sign | current numeric enum mapping if known | confidence | unknowns |
|---|---|---|---|---|---|---|
| Внимание | attention/pre-fire condition | 90CYE01 | zone state byte candidate | unknown | medium | exact enum value |
| Пожар | fire condition | 90CYE01/02/03/04 | fire_state / event code candidate | unknown | high | numeric code |
| Автоматический режим | automatic mode enabled | 90CYE03/04 | mode flag candidate | unknown | medium | bit/byte position |
| Ручной режим | manual mode enabled | 90CYE03/04 | mode flag inverse/state | unknown | medium | value mapping |
| Автоматика отключена | automation disabled indication | 90CYE03/04 | AO indicator output/state bit | unknown | medium | output index |
| ПУСК | start command | 90CYE03/04 | command/event branch | unknown | medium | command code |
| Дверь открыта | door-open interlock active | 90CYE03/04 | door_open input bit | unknown | medium | polarity and bit |
| Дверь закрыта | door closed normal state | 90CYE03/04 | door flag normal state | unknown | medium | value mapping |
| Открыто | valve/damper open position | 90CYE02 | limit-switch/open state | unknown | medium | enum/sign code |
| Закрыто | valve/damper closed position | 90CYE02 | limit-switch/closed state | unknown | medium | enum/sign code |
| МДС | module identity for discrete water inputs | 90CYE01 | module slot/id token | unknown | high | internal module id |
| Давление воды | water pressure status (PS10) | 90CYE01 | CP051-derived state/event | unknown | high | event code |
| Поток воды | flow status (VSR/VSR-6) | 90CYE01 | CF051/52/53-derived state/event | unknown | high | event code |
| Дистанционный пуск насосов | remote pump start input state | 90CYE01 | CH001..CH004 input state/event | unknown | high | bit mapping |
| Нерабочее положение | wrong/non-working position | 90CYE02 | fault state candidate | unknown | low | trigger logic |
| Неисправность клапана | valve fault | 90CYE02 | fault enum candidate | unknown | low | numeric code |
| Нет связи | no communication | all RS-485 linked devices | comm loss state | unknown | medium | timeout threshold |
| Обрыв | line break | lines/modules | line supervision fault | unknown | low | confirmed scope |
| КЗ | short circuit | lines/modules | short supervision fault | unknown | low | confirmed scope |
| Адресный конфликт | address conflict | addressed modules/bus | address conflict event | unknown | low | location in protocol |
| Не обнаружен | module/sensor not detected | modules/sensors | presence/missing enum | unknown | medium | code value |
| Сервис | service mode/state | maintenance context | service flag/state | unknown | low | where stored |
