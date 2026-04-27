# DKS enum/state reconstruction (v1)

Generated: 2026-04-27 09:45:55Z

## Scope
- Branch: `90CYE_DKS` (`90CYE03_19_DKS.PZU`), with conservative static-only interpretation.
- Core chain context: `0x497A -> 0x737C -> 0x613C -> 0x84A6 -> 0x728A -> 0x6833 -> 0x5A7F`.

## Enum table
| Enum | Probable meaning |
|---|---|
| `0x01` | fire_primary_or_attention_candidate |
| `0x02` | fire_secondary_or_fire_candidate |
| `0x03` | attention_or_alarm_fault_candidate |
| `0x04` | fault_or_output_start_marker_candidate |
| `0x05` | disabled_candidate |
| `0x07` | service_candidate |
| `0x08` | not_detected_candidate |
| `0x7E` | address_conflict_candidate |
| `0xFF` | absent_or_invalid_candidate |

## Per-function evidence summary
- `0x497A`: 7 enum candidates linked.
- `0x737C`: 2 enum candidates linked.

## State transition candidates
- Produced in `docs/dks_enum_state_transition_candidates.csv`.
- Transitions are static candidates only; all physical/runtime meaning remains unconfirmed until bench validation.

## Known / probable / unknown
- **Known (confirmed_static/manual_decompile):** chain functions consume enum-like values and route into output/event paths.
- **Probable (probable_static):** values `0x01/0x02/0x03/0x07` are frequently tied to active/eventful branches.
- **Unknown (hypothesis):** exact physical semantics of `0x04/0x05/0x08/0x7E/0xFF` per module and per family.

## Bench validation plan per enum
- `0x01`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics.
- `0x02`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics.
- `0x03`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics.
- `0x04`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics.
- `0x05`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics.
- `0x07`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics.
- `0x08`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics.
- `0x7E`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics.
- `0xFF`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics.
