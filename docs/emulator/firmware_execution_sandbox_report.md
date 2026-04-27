# Firmware execution sandbox report

## Scope
Experimental function-level 8051-subset tracing for selected targets. Evidence level: emulation_observed.

## CPU subset status
Implemented subset includes MOV/MOVX/DPTR ops, simple ALU immediates, limited branches, LCALL/LJMP/RET.
Includes initial MOVC table reads and dictionary-backed SFR access tracing (no synthetic UART behavior).
Unsupported opcodes are logged and never silently ignored.

## Loaded firmware/artifact source
90CYE03_19_DKS.PZU via pzu_intel_hex

## Target functions tested
Scenario: boot_probe_static
Functions: 0x4000, 0x4100

## Unsupported opcodes encountered
2

## XDATA writes observed
0

## Candidate packet/event records
See docs/emulator/candidate_packet_records.csv (contiguous observed writes only; no packet format invention).

No real RS-485 command is confirmed unless UART/SBUF writes or decoded packet bytes are observed.
