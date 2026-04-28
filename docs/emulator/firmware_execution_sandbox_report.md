# Firmware execution sandbox report

## Scope
Experimental function-level 8051-subset tracing for selected targets (`emulation_observed`).

## Scenario and comparison basis
- Comparison run A: `packet_bridge_seeded_context --max-steps 500`.
  - Trace IDs used: `..._042928Z`/`..._042929Z` (entry-specific timestamps).
- Comparison run B: `packet_bridge_seeded_context --max-steps 2000`.
  - Trace IDs used: `..._042929Z`/`..._042930Z` (entry-specific timestamps).

## Unsupported opcodes count
- 500-step run: `0` (header-only unsupported report at that limit).
- 2000-step run: `2` total unsupported hits in this scenario summary (`0xA4 at 0x5AA9` for 0x55AD and 0x5602).

## Final stop reasons (latest 2000-step run)
- `0x55AD`: `unsupported_opcode 0xA4 at 0x5AA9`.
- `0x5602`: `unsupported_opcode 0xA4 at 0x5AA9`.
- `0x5A7F`: `ret_from_entry`.

## 500 vs 2000 step diagnostics
- At 500 steps, `0x55AD` and `0x5602` still reached `max_steps` with no unsupported opcodes.
- At 2000 steps, both progressed past the previous bounded-loop window and reached the same new unsupported opcode (`0xA4` at `0x5AA9`) before returning.
- Interpretation: the previous blocker (max-steps loop saturation) was a bounded-window artifact; deeper stepping exposed a later missing opcode.

## Loop / hotspot diagnosis
### Top PC hotspots (latest 2000-step run)
- `0x55AD` path: repeated PCs include `0x567F`, `0x5680`, `0x5682`, `0x5683` (48 hits each), plus recurring `0x5935..0x593D` region.
- `0x5602` path: similar recurring blocks including `0x567F..0x5683` and `0x5935..0x593D`.
- This is consistent with looping control-flow blocks that repeatedly stage/read XDATA and branch back.

### Top control-flow loops (latest 2000-step run)
- Frequent repeated transitions include:
  - `0x567F -> 0x5680 (ORL)`
  - `0x5680 -> 0x5682 (INC)`
  - `0x5682 -> 0x5683 (DJNZ)`
  - `0x5683 -> 0x567F (MOVX)`
- These transitions form a tight recurrent loop; both 0x55AD and 0x5602 pass through this style of repeated subpath.

## CODE table candidates
- `MOVC A,@A+PC` table candidate reads at/around `0x5982` continue to produce the sequence:
  - `0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80`.
- `code_table_candidate_summary.csv` labels this conservatively as `bitmask_table_candidate` (still no physical/protocol mapping claim).

## XDATA behavior
- XDATA writes continue and expand at higher limit (more writes + more unique addresses versus 500-step run).
- No claim is made that these writes are RS-485 command bytes.

## UART/SBUF and RS-485 status
- SBUF candidate writes observed: **no** (`uart_sbuf_trace.csv` remains header-only).
- UART TX candidate bytes observed: **no**.
- RS-485 commands resolved: **no** (still unresolved).

## Hardware evidence integration
- New hardware-observed note documented: MAX1480ACPI module marking + `RS485` silkscreen, with user report of two modules.
- Documentation now explicitly captures two-channel RS-485 uncertainty:
  - do not assume single channel;
  - keep `SBUF0`/`SBUF1` as candidate mappings;
  - do not assign channel roles or protocol bytes from photo-only evidence.

## Current conservative blocker state
- Primary near-term emulator blocker after step-limit increase: unsupported opcode `0xA4` encountered at `0x5AA9` in both 0x55AD and 0x5602 traces.
- RS-485 protocol decoding remains blocked until direct/repeatable UART/SBUF byte evidence (and ideally bench correlation).
