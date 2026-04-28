# Config/runtime autonomous model report

## Scope
- Evidence labels used: static_code, emulation_observed, hypothesis, unknown, blocked_until_bench, blocked_until_docs.
- Target chain: 0x4100..0x4165 walker -> 0x5710..0x5733 / XDATA 0x31FF..0x3268 -> 0x36F2..0x36F9.

## Boot exit consistency
- Repeated 0x4100 entry runs ended with stop_reason=ret_from_entry and last RET near 0x4128.
- Seeded config-record scenarios reached 0x415F/0x4165 before returning; the unseeded boot probe stayed in-loop at max_steps.
- Static bytes 0x4128..0x4165: B4 00 03 02 41 5F B4 0A 0B A3 A3 A3 A3 E0 D2 E0 F0 02 41 5F A3 A3 E0 FF A3 E0 F5 82 8F 83 E0 FF A3 E0 FE 8E 82 8F 83 80 D6 74 08 25 82 F5 82 74 00 35 83 F5 83 80 B3 D2 01 D2 00 D2 02 D2

## Runtime handoff
- Forced entries at 0x415F and 0x4165 can continue into runtime-region PCs including 0x5710/0x5717/0x5725.
- This is hypothesis-only because caller state was injected.

## Materialized table and output vector
- 0x5710 scenarios produce writes inside XDATA 0x31FF..0x3268, consistent with materialized object/device table behavior.
- Runtime-hub forced-entry scenarios can co-observe table-region and 0x36F2..0x36F9 writes, but end-to-end linkage from native 0x4100 boot remains unknown.

## Boundary and decision
- Highest-value next step is caller-context reconstruction plus real NVRAM/config dump capture.
- Avoid broad fake peripheral models in this package; they add volume without resolving the blocker.
