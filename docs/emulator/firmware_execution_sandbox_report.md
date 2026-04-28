# Firmware execution sandbox report

## Scope
Experimental function-level 8051-subset tracing for selected targets. Evidence level: emulation_observed.

## CPU subset status
Implemented subset includes MOV/MOVX/DPTR ops, simple ALU/immediate ops (including RL A, ADDC A,direct, DIV AB, MUL AB), limited branches, LCALL/LJMP/RET, and SETB bit (0xD2).
Includes initial MOVC table reads and dictionary-backed SFR access tracing (no synthetic UART behavior).
Unsupported opcodes are logged and never silently ignored.
ADDC currently models carry (PSW.7); auxiliary carry/overflow are not yet modeled.

## Loaded firmware/artifact source
90CYE03_19_DKS.PZU via pzu_intel_hex

## Target functions tested
Scenario: boot_probe_static
Functions: 0x4000, 0x4100

## Unsupported opcodes encountered
0

## XDATA writes observed
0

## Candidate packet/event records
See docs/emulator/candidate_packet_records.csv (contiguous observed writes only; no packet format invention).

## Issue #78 progress checks
Did 0x55AD pass 0x55AC (0x23 RL A)? no
Did 0x5602 pass 0x55E5 (0x23 RL A)? no
Did 0x5A7F pass 0x5A84 (0x35 ADDC A,direct)? no
Next unsupported opcode for 0x55AD: none observed
Next unsupported opcode for 0x5602: none observed
Next unsupported opcode for 0x5A7F: none observed
Were any SBUF candidate writes observed? no
Were any UART TX candidate bytes observed? no
Were any new candidate packet/event records observed? no
Are RS-485 commands still unresolved? yes

No real RS-485 command is confirmed unless UART/SBUF writes or decoded packet bytes are observed.

## Autonomous packet-bridge advance summary
- Number of autonomous iterations performed: 8.
- Opcodes implemented in order:
- 0xD2 SETB bit: implemented because first unsupported blocker at 0x6782 in packet_bridge_seeded_context; standard 8051 behavior: sets addressed bit in idata bit-RAM or bit-addressable SFR byte; PC += 2; limitations: no peripheral side effects beyond conservative memory/SFR bookkeeping; observed after implementation: no.
- 0x43 ORL direct,#imm: implemented because next unsupported blocker at 0x5E7F; standard 8051 behavior: reads direct byte (idata/SFR), ORs immediate mask, writes result back; limitations: no peripheral side effects beyond conservative memory/SFR bookkeeping; observed after implementation: no.
- 0xF4 CPL A: implemented because next unsupported blocker at 0x5E9B; standard 8051 behavior: bitwise inverts accumulator; flags unchanged; limitations: no peripheral side effects beyond conservative memory/SFR bookkeeping; observed after implementation: no.
- 0x53 ANL direct,#imm: implemented because next unsupported blocker at 0x5EA4; standard 8051 behavior: reads direct byte (idata/SFR), ANDs immediate mask, writes result back; limitations: no peripheral side effects beyond conservative memory/SFR bookkeeping; observed after implementation: no.
- 0x20 JB bit,rel: implemented because next unsupported blocker at 0x56DE; standard 8051 behavior: tests addressed bit and branches relative when bit=1; limitations: no peripheral side effects beyond conservative memory/SFR bookkeeping; observed after implementation: no.
- 0x30 JNB bit,rel: implemented because next unsupported blocker at 0x5736; standard 8051 behavior: tests addressed bit and branches relative when bit=0; limitations: no peripheral side effects beyond conservative memory/SFR bookkeeping; observed after implementation: no.
- 0x11 ACALL addr11: implemented because next unsupported blocker at 0x58B8; standard 8051 behavior: pushes return address and branches to 11-bit absolute target; limitations: no peripheral side effects beyond conservative memory/SFR bookkeeping; observed after implementation: no.
- 0x88 MOV direct,Rn: implemented because next unsupported blocker at 0x8363; standard 8051 behavior: writes register bank byte into direct address (idata/SFR); limitations: no peripheral side effects beyond conservative memory/SFR bookkeeping; observed after implementation: yes.
- Final stop reason for 0x55AD: not_run.
- Final stop reason for 0x5602: not_run.
- Final stop reason for 0x5A7F: not_run.
- Current unsupported opcode list: none.
- Whether any SBUF candidate writes were observed: no.
- Whether any UART TX candidate bytes were observed: no.
- Whether RS-485 commands remain unresolved: yes.
- Whether any bit/SFR writes were observed: yes.
- Whether any bit/SFR write is a possible serial-control candidate: no.
- Whether any bit/SFR write is only unknown/hypothesis: no.
- Whether XDATA writes continued after the last implemented blocker: no.
- Whether hotspot/control-flow summaries changed materially: yes, regenerated from this run.
- Whether a hardware/peripheral architectural boundary was reached: no.

### 0x6782 blocker detail (0xD2 SETB bit)
- Did 0x55AD pass 0x6782? no.
- Did 0x5602 pass 0x6782? no.
- opcode at 0x6782 = 0xD2 SETB bit.
- 0x55AD: no bit_access row captured at 0x6782.
- 0x5602: no bit_access row captured at 0x6782.
