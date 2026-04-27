# Emulation limitations (experimental sandbox)

- This is **not** a full CPU/hardware emulator.
- UART/SFR mapping is not confirmed; no confirmed RS-485 decoder exists in this sandbox.
- UART/SBUF candidate tracing is observational only: writes to candidate SBUF addresses are logged with low confidence and do not prove protocol semantics.
- Interrupt/timer behavior is not modeled with hardware fidelity.
- Register-bank support follows PSW.3/PSW.4 for R0..R7 in current subset, but broader PSW flag semantics are incomplete.
- Stack push/pop in IDATA via SP is modeled for LCALL/RET, but not yet validated against full-firmware interrupt paths (`RETI`).
- Some target functions may stop early due to unsupported opcodes or unknown hardware dependencies.
- CJNE carry semantics are approximated in the subset model; broader PSW flag compatibility remains incomplete.
- Results are constrained scenario observations (`emulation_observed`) and do not imply real-device behavior without bench validation.
