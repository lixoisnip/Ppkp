# Emulation limitations (experimental sandbox)

- This is **not** a full CPU/hardware emulator.
- UART/SFR mapping is not confirmed; no confirmed RS-485 decoder exists in this sandbox.
- Interrupt/timer behavior is not modeled with hardware fidelity.
- Some target functions may stop early due to unsupported opcodes or unknown hardware dependencies.
- Results are constrained scenario observations (`emulation_observed`) and do not imply real-device behavior without bench validation.
