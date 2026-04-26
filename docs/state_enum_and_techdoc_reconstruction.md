# State enum + technical documentation reconstruction (large milestone)
Дата: 2026-04-26 (UTC).

## 1. What is known now
Runtime chain for 90CYE_DKS remains stable: `0x497A -> 0x737C -> 0x613C -> 0x84A6 -> 0x728A -> (manual:event+packet | auto:0x6833 output) -> 0x5A7F`.

## 2. Strongest XDATA flags
- `0x30EA..0x30F9`: sensor/zone state cluster (probable).
- `0x315B`: manual/auto mode gate candidate (probable).
- `0x3165`, `0x31BF`, `0x364B`: output/packet side flags (low..probable).

## 3. State enum hypotheses
Sensor hypotheses: normal/blocked/disabled/not_detected/communication_error/address_conflict/fire_alarm/fault.
Zone hypotheses: normal/attention/fire/alarm/fault/disabled/blocked.
Value-bit mapping remains static hypothesis until bench verification.

## 4. Manual vs auto
Current model: manual path exports event+packet without output start; auto path reaches `0x6833` then exports via `0x5A7F`.

## 5. Output action map
`0x6833` strongest output_start candidate, `0x613C` feedback-adjacent, `0x5A7F` packet export node.

## 6. APS/manual vs extinguishing/auto
APS/manual behaves as signaling/report path; extinguishing/auto adds actuator/output branch before packet export.

## 7. Packet/export role
Packet/export is modeled as common sink for both manual and auto branches; used as observable confirmation channel.

## 8. Cross-branch matching
Use `docs/state_machine_branch_comparison.csv` to separate same-address vs same-role vs similar-chain matches. Do not assume address identity between branches.

## 9. Confidence scale
- confirmed: structural chain presence and repeated call-flow motifs.
- probable: flag/function role fit with multiple sources.
- hypothesis: value-level mapping requiring bench.
- unknown: unresolved enum bits, timer/interrupt side-effects.

## 10. Bench validation required
See `docs/bench_validation_matrix.csv` for mandatory scenarios and watch-list functions.

## 11. Next manual decompile targets
1) `0x84A6` 2) `0x728A` 3) `0x6833` 4) `0x5A7F` 5) branch internals in `0x737C/0x613C`.

## 12. ASCII model
```text
Sensor state
  -> Zone mapping
  -> Zone state enum
  -> Mode flag check
      -> manual: event + packet only
      -> auto: event + output start + packet
  -> Output feedback
  -> Packet/export
```

## 13. Deep follow-up resolver

Для углубления качества после этого оркестратора используется `scripts/xdata_enum_branch_resolver.py`.
Он строит trace-level карты XDATA/enum/branch и обновляет `xdata_lifecycle_map.csv`, `state_enum_hypotheses.csv`,
`auto_manual_mode_hypotheses.csv`, `output_action_map.csv` на основании более узко сфокусированной evidence-базы
для `90CYE_DKS / 90CYE03_19_DKS.PZU`.
