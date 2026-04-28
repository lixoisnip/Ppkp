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

## Current blocker pass checks (0x75 MOV direct,#imm)
Did 0x55AD pass 0x5972 (0x75 MOV direct,#imm)? yes
Did 0x5602 pass 0x5972 (0x75 MOV direct,#imm)? yes
What is the next unsupported opcode for 0x55AD? 0x84 at 0x5975
What is the next unsupported opcode for 0x5602? 0x84 at 0x5975
Did 0x5A7F still return cleanly? yes (ret_from_entry)
Were any SBUF candidate writes observed? no
Were any UART TX candidate bytes observed? no
Were any new candidate packet/event records observed? yes (unknown_record only; low confidence)
Are RS-485 commands still unresolved? yes

No real RS-485 command is confirmed unless UART/SBUF writes or decoded packet bytes are observed.
