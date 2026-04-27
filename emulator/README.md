# Firmware execution sandbox (experimental MVP)

## Purpose

This sandbox is an **experimental, deterministic function-level trace harness** for firmware reverse engineering. It is focused on running constrained 8051-like function windows to observe:

- register changes (ACC, DPTR, R0..R7);
- call/return flow;
- `MOVX`-driven XDATA reads/writes;
- candidate packet/event record write patterns.

Current focus area: packet/event bridge hypotheses around **0x5A7F** and its high-fan-in caller blocks.

## What this is not

This is **not** a full hardware emulator and does not claim full CPU/device accuracy.

Limitations currently include:

- no verified UART/SFR mapping yet;
- no real RS-485 frame decoding yet;
- no timer/interrupt accuracy yet;
- no bench confirmation.

All outputs should be interpreted as constrained emulation evidence and labeled conservatively (`emulation_observed`, `static_code`, `hypothesis`, `unsupported`).
