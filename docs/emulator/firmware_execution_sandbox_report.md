# Firmware execution sandbox report

## Scope
Experimental function-level 8051-subset tracing for selected targets. Evidence level: emulation_observed.

## CPU subset status
Implemented subset includes MOV/MOVX/DPTR ops, simple ALU/immediate ops (including RL A and ADDC A,direct), limited branches, LCALL/LJMP/RET.
Includes initial MOVC table reads and dictionary-backed SFR access tracing (no synthetic UART behavior).
Unsupported opcodes are logged and never silently ignored.
ADDC currently models carry (PSW.7); auxiliary carry/overflow are not yet modeled.

## Loaded firmware/artifact source
90CYE03_19_DKS.PZU via pzu_intel_hex

## Target functions tested
Scenario: packet_bridge_seeded_context
Functions: 0x55AD, 0x5602, 0x5A7F

## Unsupported opcodes encountered
2

## XDATA writes observed
3

## Candidate packet/event records
See docs/emulator/candidate_packet_records.csv (contiguous observed writes only; no packet format invention).

## Issue #78 progress checks
Did 0x55AD pass 0x55AC (0x23 RL A)? yes
Did 0x5602 pass 0x55E5 (0x23 RL A)? yes
Did 0x5A7F pass 0x5A84 (0x35 ADDC A,direct)? yes
Next unsupported opcode for 0x55AD: 0xE5 at 0x597D
Next unsupported opcode for 0x5602: 0xE5 at 0x597D
Next unsupported opcode for 0x5A7F: none observed
Were any SBUF candidate writes observed? no
Were any UART TX candidate bytes observed? no
Were any new candidate packet/event records observed? yes
Are RS-485 commands still unresolved? yes

No real RS-485 command is confirmed unless UART/SBUF writes or decoded packet bytes are observed.
