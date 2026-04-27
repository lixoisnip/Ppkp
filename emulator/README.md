# Firmware execution sandbox (experimental MVP)

## Purpose

This sandbox is an **experimental, deterministic function-level trace harness** for firmware reverse engineering. It is focused on running constrained 8051-like function windows to observe:

- register changes (ACC, DPTR, R0..R7);
- call/return flow;
- `MOVX`-driven XDATA reads/writes;
- candidate packet/event record write patterns.

Current focus area: packet/event bridge hypotheses around **0x5A7F** and its high-fan-in caller blocks.

Current experimental scenarios include `packet_bridge_default`, `packet_bridge_seeded_context`, `packet_bridge_stub_5a7f`, and `boot_probe_static`.

## What this is not

This is **not** a full hardware emulator and does not claim full CPU/device accuracy.

Limitations currently include:

- SFR model is skeleton-only and trace-oriented (dictionary-backed, no synthetic peripheral effects);
- UART/SBUF behavior is recorded as SFR access evidence only (no protocol emulation yet);
- no real RS-485 frame decoding yet;
- no timer/interrupt accuracy yet;
- no bench confirmation.

New trace artifacts:
- `docs/emulator/direct_memory_trace.csv` for direct-IDATA reads/writes (separate from XDATA).
- `docs/emulator/sfr_trace.csv` for SFR candidate accesses.
- `docs/emulator/uart_sbuf_trace.csv` for conservative UART/SBUF candidate writes (`hypothesis` evidence only).

All outputs should be interpreted as constrained emulation evidence and labeled conservatively (`emulation_observed`, `static_code`, `hypothesis`, `unsupported`).
