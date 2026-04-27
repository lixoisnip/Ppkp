# Full firmware emulation roadmap (conservative)

## Phase 1 — function-level tracing (current)
- Run selected function entrypoints.
- Trace XDATA/direct/SFR/CODE accesses.
- Use explicit stubs for unresolved helpers.

## Phase 2 — application-entry boot trace
- Start at `0x4000` and/or `0x4100`.
- Stop on low-ROM dependency, unsupported opcode, or loop limit.
- Record init writes with evidence labels.

## Phase 3 — UART/SBUF capture
- Detect SCON/SBUF writes.
- Record candidate TX byte streams.
- Correlate with scenario-level events without overclaiming protocol semantics.

## Phase 4 — timers and interrupts
- Introduce timer tick model.
- Introduce interrupt vectors and dispatch.
- Identify scheduler/event-loop interactions.

## Phase 5 — protocol reconstruction
- Merge emulated UART observations with static evidence and future bench captures.
- Keep confidence bounded unless verified by observed bytes and reproducible traces.
