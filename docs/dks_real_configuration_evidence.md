# Real DKS configuration evidence (repository firmware mapping)

Date: 2026-04-27 (UTC).

## Scope

- Evidence source: manually transcribed field HMI/configuration screenshots from real DKS devices.
- Firmware mapping: screenshots correspond to firmware files present in this repository.
- Scope boundary: configuration/HMI evidence confirms module presence at device/config level.
- Scope boundary: function handler addresses and exact code semantics remain code-evidence dependent.

## Mapping table

| firmware_file | screen_device_name | hmi_version | module_slots | visible_statuses | visible_objects | confirmed_from_screen | probable_interpretation | unknowns | notes |
|---|---|---|---|---|---|---|---|---|---|
| ppkp2001 90cye01.PZU | 90CYE01 / ППКП-01Ф-20.01 | ППКП-01Ф-20.01 | X03=МДС; X04=ПВК; X05=МАШ; X06=МАШ | Соединение 1/2 = НОРМА; КОРПУС = ЗАКРЫТ; ПИТАНИЕ ОСН./РЕЗ. = НОРМА; ШЛЕЙФ 1=НОРМА; ШЛЕЙФ 2..4 visible | none on this screen | MDS/PVK as separate modules; two MASH modules; loop status layer visible | loop and module health are reflected in runtime/config tables | exact handler function addresses remain unknown without code evidence | Config-level confirmation only; function-level conclusions remain code-bound. |
| 90CYE02_27 DKS.PZU | 90CYE02 / ППКП-01Ф-27.00 | ППКП-01Ф-27.00 | X03=МДС; X04=МДС; X05≈МДС; X06≈МДС/МАС; X07≈МЗК/ПЗК; X08≈МЗК/ПЗК | Соединение 1/2 = НОРМА; КОРПУС = ЗАКРЫТ; ПИТАНИЕ ОСН./РЕЗ. = НОРМА | 90SAE01AA005; 90SAE01AA006; 90SAE06AA002; 90SAE06AA003; 90SAE02AA001; 90SAE05AA007; 90SAE05AA008; 90SAE15AA003; 90SAE15AA004 | multiple MDS-like module slots; object-level equipment status layer exists | 90SAE object tags are engineering/fire automation objects | exact meaning of each 90SAE tag and uncertain slot labels | Do not overclaim uncertain labels; config-level evidence only. |
| 90CYE03_19_DKS.PZU | 90CYE03 / ППКП-01Ф-19.02 | ППКП-01Ф-19.02 | X03=МДС; X04≈МШС/МЩС; X05≈МЭК/МЕК; X06=МУП; X07=ПВК | Соединение 1/2 = НОРМА; КОРПУС = ЗАКРЫТ; ПИТАНИЕ ОСН./РЕЗ. = НОРМА; ШЛЕЙФ 1..3=НОРМА; ШЛЕЙФ 4..8 visible | not visible on this frame | MDS/MUP/PVK are separate modules; multiple shleif statuses visible | module health and loop states likely feed runtime state/event tables | X04/X05 exact labels unclear; no automatic function-address proof | MUP remains separate from MVK unless code evidence links them. |
| 90CYE04_19_DKS.PZU | 90CYE04 / ППКП-01Ф-19.02 | ППКП-01Ф-19.02 | X03=МДС; X04≈МШС/МЩС; X05≈МЭК/МЕК; X06=МУП; X07=ПВК | Соединение 1/2 = НОРМА; КОРПУС = ЗАКРЫТ; ПИТАНИЕ ОСН./РЕЗ. = НОРМА; ШЛЕЙФ 1..3=НОРМА; ШЛЕЙФ 4..8 visible | not visible on this frame | MDS/MUP/PVK are separate modules; multiple shleif statuses visible | module health and loop states likely feed runtime state/event tables | X04/X05 exact labels unclear; no automatic function-address proof | MDS remains separate from generic input-board logic unless code evidence links them. |

## Related repository firmware without direct screenshot in this evidence pack

- `90CYE03_19_2 v2_1.PZU` and `90CYE04_19_2 v2_1.PZU` are related files in the repository.
- No direct screenshot is attached here for those v2_1 files, so identical configuration is **not** asserted.

## Machine-readable source

- `docs/dks_real_configuration_evidence.csv`

## Confidence boundary note

- This evidence may raise module-presence confidence.
- It must not raise handler/function confidence by itself.
