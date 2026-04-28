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
0

## XDATA writes observed
62

## Candidate packet/event records
See docs/emulator/candidate_packet_records.csv (contiguous observed writes only; no packet format invention).

## Issue #78 progress checks
Did 0x55AD pass 0x55AC (0x23 RL A)? yes
Did 0x5602 pass 0x55E5 (0x23 RL A)? yes
Did 0x5A7F pass 0x5A84 (0x35 ADDC A,direct)? yes
Next unsupported opcode for 0x55AD: none observed
Next unsupported opcode for 0x5602: none observed
Next unsupported opcode for 0x5A7F: none observed
Were any SBUF candidate writes observed? no
Were any UART TX candidate bytes observed? no
Were any new candidate packet/event records observed? yes
Are RS-485 commands still unresolved? yes

No real RS-485 command is confirmed unless UART/SBUF writes or decoded packet bytes are observed.
## Autonomous opcode-unblock loop summary

- Number of iterations performed: 5.
- Opcodes implemented in order: 0xE5, 0x04, 0x45, 0x55, 0x42.

### Opcode details
- 0xE5 — MOV A,direct
  - Standard behavior summary: reads direct byte (IDATA for <0x80, SFR for >=0x80) into ACC, advances PC by 2.
  - Limitations: direct/SFR access follows current sandbox models; no peripheral side effects were synthesized.
  - Observed after implementation: yes (blocker at 0x597D cleared for 0x55AD/0x5602).
- 0x04 — INC A
  - Standard behavior summary: increments ACC modulo 8-bit, advances PC by 1.
  - Limitations: flags left unchanged per current subset assumptions.
  - Observed after implementation: yes.
- 0x45 — ANL A,direct
  - Standard behavior summary: ACC := ACC AND direct byte, advances PC by 2.
  - Limitations: flag side effects not modeled beyond current subset behavior.
  - Observed after implementation: yes.
- 0x55 — XRL A,direct
  - Standard behavior summary: ACC := ACC XOR direct byte, advances PC by 2.
  - Limitations: flag side effects not modeled beyond current subset behavior.
  - Observed after implementation: yes.
- 0x42 — ORL direct,A
  - Standard behavior summary: reads direct byte, writes OR result with ACC back to direct target, advances PC by 2.
  - Limitations: uses existing direct/SFR write model only; no synthetic UART/peripheral behavior.
  - Observed after implementation: yes.

- Final stop reason: stop condition (4) reached — packet_bridge_seeded_context reached max-steps without unsupported opcodes for both 0x55AD and 0x5602.
- Final stop point for 0x55AD: max_steps (500), unsupported_ops=0.
- Final stop point for 0x5602: max_steps (500), unsupported_ops=0.
- Final stop point for 0x5A7F: ret_from_entry.
- Any SBUF candidate writes observed: no.
- Any UART TX candidate bytes observed: no.
- RS-485 commands remain unresolved: yes.
- New XDATA records observed: yes (additional emulation_observed unknown_record/pointer_staging_candidate rows in xdata_write_trace.csv).
- New SFR writes observed: yes (continued writes observed to SP/PSW/B/DPL/DPH via existing SFR tracing).
- New direct-memory records observed: no (direct_memory_trace.csv remained header-only).
- Any CODE reads observed: yes (MOVC A,@A+PC code-table candidate reads captured in code_read_trace.csv).
- Architectural boundary reached: no explicit timer/interrupt/peripheral boundary encountered in this bounded loop.
