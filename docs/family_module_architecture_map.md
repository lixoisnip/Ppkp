# Family-wide shared module architecture map (Issue #52)

Date: 2026-04-26 (UTC).

Goal: compare all firmware families and produce a single map of shared module architecture anchors.

## Shared stages across branches

| stage | role | branches with evidence |
|---|---|---:|
| `sensor_zone` | sensor/input entry | 4/5 |
| `zone_logic` | zone logic dispatcher | 4/5 |
| `zone_state_feedback` | zone state update | 4/5 |
| `mode_event_bridge` | mode/event bridge | 4/5 |
| `manual_auto_check` | manual/auto gate | 4/5 |
| `output_start` | output start | 4/5 |
| `packet_export` | packet/service export | 4/5 |

## Branch comparison summary

| branch | files | stage anchors | module handlers (МАШ / МАС / service) | command cluster |
|---|---|---|---|---|
| A03_A04 | A03_26.PZU<br>A04_28.PZU | sensor_zone:0x497A(same_address/medium)<br>zone_logic:0x497A(similar_role/medium)<br>zone_state_feedback:0x497A(similar_role/medium)<br>mode_event_bridge:0x497A(checksum_limited/hypothesis)<br>manual_auto_check:0x497A(checksum_limited/hypothesis)<br>output_start:0x497A(similar_role/medium)<br>packet_export:0x6C7E(similar_role/hypothesis) | 0x497A|0x800B|0x8904 / 0x722E / 0x6C07 | no |
| 90CYE_DKS | 90CYE03_19_DKS.PZU<br>90CYE04_19_DKS.PZU | sensor_zone:0x497A(same_address/medium)<br>zone_logic:0x737C(same_address/medium)<br>zone_state_feedback:0x613C(same_address/medium)<br>mode_event_bridge:0x84A6(same_address/medium)<br>manual_auto_check:0x728A(same_address/medium)<br>output_start:0x6833(same_address/medium)<br>packet_export:0x5A7F(same_address/medium) | 0x497A|0x737C|0x84A6 / 0x613C / 0x5A7F | yes |
| 90CYE_v2_1 | 90CYE03_19_2 v2_1.PZU<br>90CYE04_19_2 v2_1.PZU | — | 0x497F|0x8BE5 / 0x93F9 / 0x72AB | no |
| 90CYE_shifted_DKS | 90CYE02_27 DKS.PZU | sensor_zone:0x497F(similar_role/medium)<br>zone_logic:0x497F(similar_role/medium)<br>zone_state_feedback:0x497F(similar_role/medium)<br>mode_event_bridge:0x497F(checksum_limited/hypothesis)<br>manual_auto_check:0x497F(checksum_limited/hypothesis)<br>output_start:0x497F(similar_role/medium)<br>packet_export:0x6106(similar_role/hypothesis) | 0x497F|0x7574 / 0x774F / 0x655F | no |
| RTOS_service | ppkp2001 90cye01.PZU<br>ppkp2012 a01.PZU<br>ppkp2019 a02.PZU | sensor_zone:0xAB62(similar_role/medium)<br>zone_logic:0x758B(similar_role/medium)<br>zone_state_feedback:0x758B(similar_role/medium)<br>mode_event_bridge:0x758B(checksum_limited/hypothesis)<br>manual_auto_check:0x758B(checksum_limited/hypothesis)<br>output_start:0x9C99(similar_role/medium)<br>packet_export:0x4176(similar_role/hypothesis) | 0x758B|0xA3FD / 0x95B0 / 0x92EF | yes |

## Machine-readable output

- `docs/family_module_architecture_map.csv`
- `docs/family_module_architecture_map.md`

## Notes and limits

1. Mapping is static-evidence based and does not assert full semantic equivalence of addresses across branches.
2. Stages marked by `checksum_limited`/`hypothesis` remain tentative and require bench validation.
3. Command cluster visibility differs by branch and depends on current string extraction coverage.
