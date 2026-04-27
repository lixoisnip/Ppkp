# DS80C320/DS80C323 emulation notes (working hypothesis)

## Context
External project notes mention `_58_3.prw` with `DevType=DS320 processor`. Current repository treats this as **external_analysis** evidence that target MCU is likely Dallas/Maxim DS80C320/DS80C323-compatible.

## Why DS80C320 is current working MCU hypothesis
- DS320 marker aligns with DS80C320 naming.
- Firmware behavior remains broadly 8051-compatible in currently traced windows.
- No silicon ID confirmation is available in-repo; therefore this stays `hypothesis`/`external_analysis`, not `emulation_observed`.

## Standard 8051-compatible baseline used now
- Code fetch and basic control flow (LJMP/LCALL/RET, short branches).
- ACC/DPTR/PSW/SP-centered execution state.
- MOVX-oriented XDATA accesses used by current function-level traces.

## DS80C320-specific features that may matter later
- Dual DPTR (`DPS`-controlled bank switching).
- Two UART channels and SBUF/SCON mapping differences.
- Timer model extensions and timing-dependent behavior.
- Interrupt prioritization/dispatch details.
- Watchdog behavior.
- MOVX stretch / memory-cycle effects.

## Intentionally ignored in current MVP
- Accurate peripheral side effects.
- Real UART TX/RX emulation.
- Interrupt/timer tick scheduling.
- Watchdog/reset behavior.
- Cycle-accurate timing.

## Current blockers for full firmware emulation
- Missing low ROM `<0x4000` in `.PZU` images.
- Unresolved SFR semantics for many addresses.
- No validated interrupt/timer scheduler model.

## Scope statement
Current sandbox remains **function-level tracing**, not full hardware/device emulation.
