# Runtime continuation model report

## Commands executed
- python3 scripts/firmware_execution_sandbox.py run-autonomous-runtime-continuation --max-cycles 3 --max-passes-per-cycle 5
- python3 scripts/run_analysis_smoke_test.py
- python3 -m py_compile scripts/*.py emulator/*.py

## Cycle results
- Cycle 1: ranked continuation candidates and audited blockers from prior observed stops; CLR C (0xC3) and MOV C,bit (0xA2) are small/safe standard 8051 opcodes and were implemented.
- Cycle 2: reran all seeded continuation scenarios with hardware stack-pop RET mode and updated ranking.
- Cycle 3: automatically deepened the top-ranked candidate `0x55AD` with a compact higher-step rerun decision already executed in Cycle 2 rerun budget.

## Required answers
- Which continuation target is strongest after rerun? `0x55AD` (seeded-return hypothesis only).
- Is 0x55AD still strongest for output/action vector? yes (based on writes_36F2_36F9 counts in rerun summary).
- Did vector targets 0x4176 / 0x41D0 / 0x492E / 0x4954 / 0x497A become useful after opcode support? partially; they can progress beyond previous immediate opcode blockers but remain hypothesis-only without real caller context.
- Which path reaches materialization? see rerun rows with writes_31FF_3268 > 0 (not proof of real boot flow).
- Which path reaches output vector? see rerun rows with writes_36F2_36F9 > 0, strongest around 0x55AD-seeded continuation.
- Which path reaches 0x5A7F? seeded continuations via runtime-hub paths (see rerun summary flags).
- Are any SBUF/UART candidates observed? no.
- Is more emulation useful without real NVRAM/low-ROM evidence? boundedly useful for local ranking only; end-to-end proof remains blocked_until_docs/blocked_until_bench.
- What is the next target Codex already executed automatically? `boot_4100_ret_stack_to_55AD` rerun under hardware_stack_pop mode.
- If Codex stopped, why exactly? stopped after max_cycles_completed=3 as bounded autonomous package limit.
