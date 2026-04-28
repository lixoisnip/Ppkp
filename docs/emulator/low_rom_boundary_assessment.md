# Low-ROM / image-boundary assessment for 0x4100 caller context

Firmware focus: `90CYE03_19_DKS.PZU`.

## Executive conclusion
- Main blocker is now **missing caller/stack context around 0x4100**, and the most likely source is a boundary between available image logic and hidden/unsupported boot environment details.
- Static code in visible `0x4000..0xBFFF` does **not** show direct `LCALL 0x4100` callsites; only reset `LJMP 0x4000 -> 0x4100` is confirmed.
- Because `0x4100` ends with `RET`, real execution must still have valid return semantics from a broader boot framework (true caller chain, interrupt bootstrap path, or wrapper expectations not represented in the current harness model).

## Required answers

### Is code below 0x4000 absent from current PZU?
Yes for current analysis corpus: documented working code window is approximately `0x4000..0xBFFF`; low ROM context is called out as missing in existing memory-map notes (`static_code` from project docs).

### Are there calls/jumps from visible image to below 0x4000?
No direct `LCALL`/`LJMP` targets below `0x4000` were required to answer this package’s 0x4100 question, and no direct `0x4100` caller was found in visible code (`static_code` from caller search).

### Could 0x4100 be called by hidden ROM/monitor/bootloader?
Yes, plausible. If a monitor/bootstrap sequence or ROM wrapper primes stack/context before transferring to `0x4100`, `RET` behavior would be coherent. This remains `hypothesis` (not proven in current artifacts).

### Does DS80C320 reset architecture or PZU load offset imply missing wrapper code?
It is plausible but unproven. Existing DS80C320 notes already classify full-hardware boot interactions as out of current emulator scope and identify missing low-ROM dependencies as blockers (`blocked_until_docs`).

### What evidence would confirm low-ROM caller context?
1. Real boot trace (PC/SP) around first entry into `0x4100` and first return from `0x4175`.
2. Any OEM docs/map showing monitor ROM handoff or relocated wrapper before app image.
3. Reproducible stack-byte evidence at `RET` time proving intended return PC.

### What emulator limitation remains?
Current emulator `RET` handling is call-stack-model based for entry functions (`ret_from_entry`) rather than full hardware stack-pop continuation. This blocks realistic synthetic return-address continuation tests and makes precise caller reconstruction partially tooling-limited until model upgrades.

## Decision impact
- For this package, low-ROM / wrapper-context uncertainty is the dominant blocker after static caller search.
- Additional brute-force return-address attempts are low value unless RET continuation semantics are upgraded or external boot/stack evidence is obtained.
