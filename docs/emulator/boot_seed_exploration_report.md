# Boot seed exploration report

## Scope
Compact hypothesis-only XDATA seeding for 0x4100 boot-loop boundary exploration.

## Scenarios run
- boot_4100_seed_x0030_zero_pointer: seed {0x0030=0x00, 0x0031=0x00}; stop=stable_runtime_loop_detected, last_pc=0x415B, exited_loop=no.
- boot_4100_seed_x0030_self_pointer: seed {0x0030=0x30, 0x0031=0x00}; stop=stable_runtime_loop_detected, last_pc=0x415B, exited_loop=no.
- boot_4100_seed_x0030_to_0200_ff: seed {0x0030=0x00, 0x0031=0x02, 0x0200=0xFF}; stop=ret_from_entry, last_pc=0x4128, exited_loop=yes.
- boot_4100_seed_x0030_to_0200_00: seed {0x0030=0x00, 0x0031=0x02, 0x0200=0x00}; stop=ret_from_entry, last_pc=0x4128, exited_loop=yes.
- boot_4100_seed_x0030_to_0200_02_record: seed {0x0030=0x00, 0x0031=0x02, 0x0200=0x02, 0x0203=0x00, 0x0204=0x03, 0x0300=0x00}; stop=ret_from_entry, last_pc=0x4128, exited_loop=yes.
- boot_4100_seed_x0030_to_0200_0a_record: seed {0x0030=0x00, 0x0031=0x02, 0x0200=0x0A, 0x0204=0x00}; stop=ret_from_entry, last_pc=0x4128, exited_loop=yes.
- boot_4100_seed_x0030_project_like_minimal: seed {not run (insufficient project-config evidence in repo for safe minimal real seed)}; not_run.

## Findings
- Early loop exit achieved by pointer-to-0x0200 scenarios (FF/00/02/0A variants), but exits via early return at 0x4128 rather than progression into post-0x4165 runtime.
- Zero-pointer and self-pointer scenarios remained in stable loop near 0x415B within 2000-step window.
- No scenario reached 0x415F or beyond 0x4165.
- No scenario produced UART init evidence, SBUF writes, or UART TX candidate bytes.
- No scenario produced display or keypad candidates after classifier correction.
- RS-485 command decoding remains unresolved.

## Confidence and limitations
- Confidence: medium for loop-boundary behavior (deterministic under emulated seeds).
- Limitation: this is subset emulation; early-return behavior may reflect missing external context or memory preconditions.
- Limitation: project-like real config seed intentionally not invented without direct evidence.
