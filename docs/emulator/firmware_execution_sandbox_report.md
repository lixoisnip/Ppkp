# Firmware execution sandbox report

## Scope
Experimental function-level 8051-subset tracing for selected targets. Evidence level: emulation_observed.

## CPU subset status
Implemented subset includes MOV/MOVX/DPTR ops, simple ALU/immediate ops (including RL A, ADDC A,direct, DIV AB, and MUL AB), limited branches, LCALL/LJMP/RET.
Includes initial MOVC table reads and dictionary-backed SFR access tracing (no synthetic UART behavior).
Unsupported opcodes are logged and never silently ignored.
ADDC currently models carry (PSW.7); auxiliary carry/overflow are not yet modeled.
MUL AB reads B from SFR(0xF0) when present and mirrors the high-byte result to state.b + SFR(0xF0); this is conservative if state/sfr become temporarily out-of-sync.

## Loaded firmware/artifact source
90CYE03_19_DKS.PZU via pzu_intel_hex

## Target functions tested
Scenario: packet_bridge_seeded_context
Functions: 0x55AD, 0x5602, 0x5A7F

## Unsupported opcodes encountered
2

## XDATA writes observed
136

## Candidate packet/event records
See docs/emulator/candidate_packet_records.csv (contiguous observed writes only; no packet format invention).

## Issue #84 MUL AB blocker follow-up (2000-step packet_bridge_seeded_context)
Did 0x55AD pass 0x5AA9 (0xA4 MUL AB)? yes (next stop is at 0x6782).
Did 0x5602 pass 0x5AA9 (0xA4 MUL AB)? yes (next stop is at 0x6782).
What is the next unsupported opcode for 0x55AD? 0xD2 at 0x6782.
What is the next unsupported opcode for 0x5602? 0xD2 at 0x6782.
Did 0x5A7F still return from entry? yes (ret_from_entry at step 6).
Were any new SFR writes observed? yes (additional MUL AB updates include B/0xF0 and PSW/0xD0 traces; see docs/emulator/sfr_trace.csv).
Were any SBUF candidate writes observed? no
Were any UART TX candidate bytes observed? no
Are RS-485 commands still unresolved? yes
Did XDATA writes continue changing after 0xA4? yes (XDATA writes continue and total writes remained non-zero after advancing beyond 0x5AA9).
Did hotspot/control-flow summaries change materially? yes (progressed PCs/call paths and hotspot counts now extend to the next blocker at 0x6782).

No real RS-485 command is confirmed unless UART/SBUF writes or decoded packet bytes are observed.
