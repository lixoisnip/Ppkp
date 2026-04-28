# Boot XDATA table grammar hypothesis (0x4100..0x4165)

Evidence basis: static decode and compact boot traces only. All roles below are hypothesis.

## Static pattern hypothesis
- Probable pointer seed source: `XDATA[0x0030..0x0031]`.
- `0x4109` / `0x410C` load these bytes and stage into `R7` / `R6`.
- `R7`/`R6` are copied into `DPL`/`DPH`, creating DPTR-backed table traversal.
- Loop body repeatedly reads `MOVX A,@DPTR` and compares via `CJNE`.

## Compared values in-loop
Observed compare constants in 0x4100..0x4165 window:
- `0xFF` (terminator candidate)
- `0x02` (pointer/record candidate)
- `0x00` (terminator/empty candidate)
- `0x0A` (flag-setting candidate)

## Hypothesis-only record grammar sketch
- Record/token byte at `XDATA[DPTR]` controls branch path.
- Possible token classes:
  - `0xFF` → table terminator candidate.
  - `0x02` → pointer/record-form candidate (may consume following bytes).
  - `0x00` → empty/end marker candidate.
  - `0x0A` → flag/action token candidate.
- Back-edge (`0x415D -> 0x4112`) indicates iterative parser/copy-style loop.

## Constraints
- No claim of real project/config format.
- No claim of UART/display/keypad semantics from this region.
- Requires additional runtime context to confirm actual record structure.
