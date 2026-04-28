# Boot/runtime boundary report

1. Did reset vector 0x4000 jump to 0x4100? yes (emulation_observed).
2. Did application entry 0x4100 execute beyond initial setup? yes.
3. What was the first unsupported opcode, if any? none_observed.
4. What SFRs were initialized? see docs/emulator/boot_init_write_summary.csv (emulation_observed).
5. Were UART/SCON/SBUF candidates initialized? no (emulation_observed).
6. Were timer/interrupt candidates initialized? no (emulation_observed).
7. Was a main loop or scheduler loop found? yes (emulation_observed).
8. Were display/LCD/output candidates observed? no (emulation_observed).
9. Were display text/message table candidates found? no (static_code).
10. Were keypad/input scan candidates observed? no (emulation_observed).
11. Were SBUF candidate writes observed? no.
12. Were UART TX candidate bytes observed? no.
13. Are RS-485 commands still unresolved? yes.
14. Current blocker: boot_init_loop_or_counter_boundary (early 0x4100..0x4165 loop persists without UART/SBUF/port-output proof).

## Classifier correction and early boot-loop interpretation
- Previous display/keypad counts were contaminated by SP/DPL/DPH/PSW/ACC/B handling: confirmed.
- Corrected display candidates remaining: 0 (all weak unknown_io_candidate unless promoted by stronger path evidence).
- Corrected keypad candidates remaining: 0 (all weak unknown_io_candidate unless promoted by stronger path evidence).
- Display text/message table candidates remaining: 0.
- UART/SCON/SBUF init candidates remaining: 0; SBUF writes observed: 0.
- Timer/interrupt candidates remaining: 0.
- Early 0x4100..0x4165 loop likely represents boot pointer/copy initialization loop (DPTR + DPL/DPH rewrite) rather than peripheral wait loop.
- Next blocker assessment: boot init loop with missing boundary into later runtime services.

## Boot seed matrix addendum (hypothesis-only)
- Seed scenarios tested: zero_pointer, self_pointer, to_0200_ff, to_0200_00, to_0200_02_record, to_0200_0a_record.
- Zero/self pointer remained in stable 0x4100..0x4165 loop window.
- Pointer-to-0x0200 variants exited early loop by returning near 0x4128 (did not reach 0x415F or >0x4165 runtime).
- No UART/SBUF, display, or keypad evidence appeared in seeded runs.
- RS-485 remains unresolved.

