# Project-guided final static boundary pass

## Scope
- This pass is the final static boundary pass for the current evidence set.
- It does not close protocol-doc or bench-blocked unknowns.
- Project evidence, static code evidence, and bench/runtime evidence remain separated.

## Remaining pending target analysis

### 0x55AD caller-block analysis
- DPTR/ACC/register setup before `0x5A7F`: 0x55A3 MOVX @DPTR,A; 0x55A4 MOV R0,#0x00; 0x55A6 MOV R2,#0x00; 0x55A8 MOV DPTR,#0x7160; 0x55AB MOV A,R0; 0x55AC UNK 
- MOVX writes before/after call: before=yes, after=yes (post-call is read-first pattern).
- Staging interpretation: pointer_or_index_staging_then_bridge_readback (conservative).
- XDATA context in bounded window: 0x7160|0x30E1.
- Checksum-like arithmetic: none in bounded callsite window.
- PU narrowing: narrows caller-side staging behavior for PU-001/PU-004/PU-011 but does not prove frame/CRC/terminal mapping.

### 0x5602 caller-block analysis
- DPTR/ACC/register setup before `0x5A7F`: 0x55F8 MOV A,R0; 0x55F9 LCALL 0x5A7F; 0x55FC MOV A,R1; 0x55FD MOVX @DPTR,A; 0x55FE MOV DPTR,#0x30BC; 0x5601 MOV A,R0
- MOVX writes before/after call: before=yes, after=yes (post-call shows writeback).
- Staging interpretation: pointer_or_index_staging_then_bridge_writeback (conservative).
- XDATA context in bounded window: 0x30BC.
- Checksum-like arithmetic: none in bounded callsite window.
- PU narrowing: strengthens post-call write-target class hypothesis for PU-011, without terminal-level proof.

## 0x5A7F caller-block synthesis
- Compared callers: 0x55AD, 0x55C0, 0x55C9, 0x55E6, 0x55F9, 0x5602.
- Synthesis: repeated looped caller-envelope staging around `R0/R1/DPTR` is statically visible.
- Likely role: pointer/index staging + bridge invocation + post-call read/write handling class.
- Not supported: full serialized frame format, address map, definitive packet-vs-event schema.

## RS-485 boundary conclusion
- Static evidence supports `0x5A7F` as a high-fan-in packet/event bridge neighborhood with repeated caller staging.
- Static evidence does not support explicit byte-level frame layout or full address map decode.
- PU-001 remains blocked (docs + bench).
- PU-004 remains blocked (docs + bench).
- Needed new evidence: protocol frame/address/checksum appendix and serial capture tied to known events.

## UART/baud boundary conclusion
- Pass3 UART candidates remain low-confidence token hits only; no strong register-level UART init proof.
- PU-003 remains unresolved.
- Commissioning docs or line timing measurement are required.

## CRC/checksum boundary conclusion
- Candidate loops exist, but none is tied to a bounded packet-buffer checksum loop.
- PU-004 remains unresolved.
- Confirmation requires explicit bounded buffer traversal and checksum field linkage (or bench invalid-checksum behavior).

## Timer/output/pulse boundary conclusion
- Static chain support remains: `0x6833` output-start marker `0x04`, `0x7DC2` downstream transition, pass3 timer candidates.
- Exact launch pulse width remains blocked without protocol timing docs or scope capture.

## Valve/status boundary conclusion
- Static support exists around `0x673C`, `0x613C`, `0x7773`, and status neighborhoods (`0x3104/0x3108/0x31DD/0x32B2/0x32B3`).
- Open/closed/fault terminal mapping is still unresolved without terminal docs or bench-labeled probes.

## Evidence boundary dashboard
See `docs/project_guided_final_static_boundary_dashboard.csv`.

## Final static next steps
### 1. worthwhile_next_static
- Ingest new protocol/terminal documents when available and anchor static scans to new concrete constants/tables.
- Tooling-only improvement: parse protocol sheets into searchable field/address dictionaries.

### 2. blocked_until_docs
- RS-485 protocol frame/address/baud/CRC docs.
- 90CYE02/03/04 terminal-object tables and GOA/AN/AU/AO mapping sheets.
- MUP/PVK project pages and launch timing requirements.

### 3. blocked_until_bench
- Serial capture with event labels.
- IO capture for GOA/AN/AU/AO and damper statuses.
- Launch pulse width waveform capture.

### 4. low_value_reanalysis
- Repeating broad scans on `0x5A7F`, `0x6833`, `0x737C`, UART tokens, and checksum token loops without new evidence.
