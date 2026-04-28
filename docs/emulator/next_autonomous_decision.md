# Next autonomous decision (boot caller/context boundary reconstruction)

## Passes performed (this package)
1. **Pass 1 (static caller search):** scanned visible code image for direct/indirect references targeting `0x4100`; generated `boot_4100_caller_search.csv`.
2. **Pass 2 (entry/return decode):** compact static decode of `0x4000..0x4020`, `0x4100..0x4180`, and `0x4170..0x4185`; updated return-context interpretation.
3. **Pass 3 (synthetic return hypotheses):** ran bounded synthetic return-address scenarios (hypothesis only) and recorded outcomes.
4. **Pass 4 (boundary assessment):** assessed low-ROM/missing-wrapper risk and emulator model limitations.
5. **Pass 5 (decision synthesis):** consolidated blocker status and next-target ranking.

## Required decisions

### Whether a 0x4100 caller exists in visible PZU
- **No direct visible caller found** (`LCALL/AJMP/ACALL/LJMP` to `0x4100` absent except reset vector). Evidence: `boot_4100_caller_search.csv` (`static_code`).
- **Confirmed reference:** `0x4000: LJMP 0x4100`.

### Whether low-ROM/missing wrapper is now main blocker
- **Yes.** `0x4100` ends at `RET` (`0x4175`), but visible reset path is `LJMP`, not a call that would naturally provide a return address. Reconstructing real return target needs missing caller/stack semantics (likely monitor/wrapper/interrupt context or harness model gap).

### Whether synthetic return-address tests improved runtime reachability
- **No material improvement.** Hypothesis scenarios did not reach `0x5710/0x5717/0x5725`, runtime hubs, or target write ranges under current emulator return handling.

### Whether another autonomous package can proceed without user input
- **Partially yes** for tooling-only tasks (e.g., emulator RET/stack model enhancement, deeper static vector/call-graph refinement).
- **End-to-end proof remains blocked** without low-ROM/wrapper evidence or bench traces (`blocked_until_docs` / `blocked_until_bench`).

## Top 3 next targets
1. **Implement/validate hardware-like RET stack-pop continuation in emulator** for entry functions, then rerun bounded return-context scenarios.
2. **Static decode expansion around vector handlers `0x4176`, `0x41D0`, `0x492E`, `0x4954`, `0x497A`** to map realistic boot/interrupt-context transitions.
3. **Acquire external evidence** (boot SP/PC capture or OEM monitor notes) to confirm whether `0x4100` is entered by hidden wrapper code.

## Single recommended next target
- **Upgrade emulator return semantics (entry RET continuation via internal stack bytes) and rerun this exact caller/return package.**

## Evidence labels summary
- `static_code`: direct caller search + decode windows.
- `emulation_observed`: synthetic hypothesis runs (bounded, non-claiming).
- `hypothesis`: synthetic return-address scenarios.
- `blocked_until_docs` / `blocked_until_bench`: real low-ROM/wrapper confirmation path.
