# Boot entry and 0x4100 return-context decode

Firmware analyzed: `90CYE03_19_DKS.PZU`.
Evidence labels used below: `static_code`, `emulation_observed`, `blocked_until_docs`.

## 1) Reset/vector window decode (0x4000..0x4020)

- `0x4000: 02 41 00` -> `LJMP 0x4100` (`static_code`).
- `0x4006: 02 41 76` -> `LJMP 0x4176` (`static_code`).
- `0x400C: 02 41 D0` -> `LJMP 0x41D0` (`static_code`).
- `0x4012: 02 49 2E` -> `LJMP 0x492E` (`static_code`).
- `0x4018: 02 49 54` -> `LJMP 0x4954` (`static_code`).
- `0x401E: 02 49 7A` -> `LJMP 0x497A` (`static_code`).

Interpretation: reset goes directly to `0x4100`; neighboring vectors jump to other handlers and are **not** call-return links into `0x4100`.

## 2) 0x4100..0x4180 compact decode

- `0x4100..0x4118`: pointer setup from XDATA `0x0030/0x0031`, fetch first tag byte.
- `0x4115: B4 FF 03` followed by `0x4118: 02 41 5F` -> type `0xFF` path jumps to `0x415F`.
- `0x411B..0x4138`: type `0x02` / `0x0A` gated decode-style walker logic; additional jumps to `0x415F`.
- `0x413B..0x415D`: linked/pointer iteration (`SJMP` loop back) (`static_code`).
- `0x415F..0x4168`: `SETB` bits and setup writes (`static_code`).
- `0x4169..0x4174`: clears XDATA at `0x2F22..0x2F25` via MOVX writes (`static_code`).
- `0x4175: 22` -> `RET` (`static_code`).

Conclusion: structure still matches a subroutine/config walker ending in `RET`, not a standalone non-returning reset runtime body.

## 3) Post-RET window (0x4170..0x4185)

- `0x4175` is explicitly `RET`.
- `0x4176` begins a new routine: `MOV DPTR,#0x0035`, reads nibbles, compares values (`0x4176..0x4185`) (`static_code`).
- Therefore, code after `0x4175` is meaningful code, but only if control is transferred there by vector/branch/call context.

## 4) Required questions

### Is 0x4100 used like reset entry or subroutine?
Both patterns exist in visible code: reset vector uses `LJMP 0x4100`, but `0x4100` itself is coded as a return-capable routine ending at `RET` (`0x4175`). Best classification: **reset-invoked init walker with subroutine-like termination semantics**.

### What instruction is at 0x4175?
`RET` (`0x22`) (`static_code`).

### What happens if RET at 0x4175 uses an empty/default stack?
On real 8051 silicon, `RET` pops return PC from internal stack; without a valid pushed return this is undefined from firmware intent and typically lands at arbitrary/zeroed stack-derived address (`unknown`).
In the current emulator implementation, `RET` from entry is modeled as immediate stop `ret_from_entry` and does not pop hardware stack bytes (`emulation_observed`, `blocked_until_docs` for true continuation).

### Does code after 0x4175 matter, or is it unreachable without caller?
`0x4176+` is definitely executable code (also interrupt vector target from `0x4006`), so it matters. It is **not** natural fall-through from `0x4100` because `0x4175` returns (`static_code`).

### Is there any visible continuation path from reset without RET?
Within the visible image, reset uses unconditional `LJMP 0x4100`. The only explicit exit from the 0x4100 block is `RET` at `0x4175`; no direct `LJMP`/`SJMP` continuation to runtime hub was found in this window (`static_code`).
