# Boot/runtime boundary report

1. Did reset vector 0x4000 jump to 0x4100? yes (emulation_observed).
2. Did application entry 0x4100 execute beyond initial setup? yes.
3. What was the first unsupported opcode, if any? none_observed.
4. What SFRs were initialized? see docs/emulator/boot_init_write_summary.csv (emulation_observed).
5. Were UART/SCON/SBUF candidates initialized? yes (emulation_observed).
6. Were timer/interrupt candidates initialized? yes (emulation_observed).
7. Was a main loop or scheduler loop found? yes (emulation_observed).
8. Were display/LCD/output candidates observed? yes (emulation_observed).
9. Were display text/message table candidates found? yes (static_code).
10. Were keypad/input scan candidates observed? yes (emulation_observed).
11. Were SBUF candidate writes observed? no.
12. Were UART TX candidate bytes observed? no.
13. Are RS-485 commands still unresolved? yes.
14. Current blocker: blocked_until_peripheral_model (timer/interrupt/UART runtime context incomplete).
