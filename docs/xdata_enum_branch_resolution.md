# XDATA enum/branch resolution (deep milestone)
Date: 2026-04-27 09:45 UTC.

## 1) XDATA lifecycle coverage
- `0x30EA..0x30F9`: reads=-; writes=-; branches=-; exports=- (probable).
- `0x315B`: reads=-; writes=-; branches=-; exports=- (probable).
- `0x3165`: reads=-; writes=-; branches=-; exports=- (hypothesis).
- `0x31BF`: reads=0x497A; 0x737C; writes=-; branches=0x497A; 0x737C; exports=- (low).
- `0x364B`: reads=-; writes=-; branches=-; exports=- (hypothesis).

## 2) 0x315B mode gate
- Main readers/branchers: `0x84A6`, `0x728A`.
- Manual-like path: event/packet-only -> `0x5A7F`.
- Auto-like path: `0x6833` output start -> `0x5A7F`.

## 3) 0x30EA..0x30F9 cluster
- Used as sensor/zone state cluster with compare/update markers in `0x497A/0x737C/0x613C` chain.

## 4) Output-side flags (0x3165/0x31BF/0x364B)
- Present in branch traces near output/packet bridge candidates; exact value semantics remain hypothesis without bench.

## 5) Enum value mapping
- 0x01: sensor_fire_primary_or_zone_attention -> fn 0x497A (hypothesis).
- 0x02: sensor_fire_secondary_or_zone_fire -> fn 0x497A (hypothesis).
- 0x03: sensor_attention_prealarm_or_zone_alarm_fault -> fn 0x737C (hypothesis).
- 0x04: sensor_fault -> fn 0x497A (hypothesis).
- 0x05: sensor_disabled_or_zone_disabled -> fn 0x497A (hypothesis).
- 0x07: sensor_service_or_zone_service -> fn 0x737C (hypothesis).
- 0x08: sensor_not_detected -> fn 0x497A (hypothesis).
- 0x7E: sensor_address_conflict -> fn 0x497A (hypothesis).
- 0xFF: sensor_absent_or_invalid -> fn 0x497A (hypothesis).

## 6) Manual-like vs auto-like
- manual-like event/packet path seen around `0x84A6/0x728A`.
- auto-like output path enters `0x6833` before packet/export.

## 7) Output start and packet/export
- output start candidate: `0x6833`.
- packet/export sink candidate: `0x5A7F`.

## 8) Unknowns
- Full bit-level decode of `0x315B` and all output-side flags.
- Complete enum decode requires bench traces.

## 9) Priority bench tests
- Fire/attention/fault/disabled/not-detected/address-conflict transitions.
- Manual mode should avoid output-start; auto mode should hit `0x6833`.
- Compare exported packets via `0x5A7F` between both paths.

## 10) Next manual decompile targets
1. `0x84A6`  2. `0x728A`  3. `0x6833`  4. `0x5A7F`  5. deep compares in `0x737C/0x613C`.

## 11) ASCII model
```text
0x30EA..0x30F9 state byte/flags
  -> comparisons in 0x497A / 0x737C / 0x613C
  -> zone state path
  -> 0x84A6 / 0x728A mode gate
      -> manual-like: packet/event only -> 0x5A7F
      -> auto-like: output start -> 0x6833 -> packet/export -> 0x5A7F
```

## 12) DKS v1 enum follow-up

Этот документ используется как upstream-база для:
- `docs/dks_enum_state_reconstruction.md`
- `docs/dks_enum_state_matrix.csv`
- `docs/dks_enum_state_transition_candidates.csv`

В v1-слое enum-метки сохранены в evidence-capped режиме с разделением confirmed/probable/hypothesis/unknown.
