# RET stack continuation model report

## Does hardware-like RET continuation work technically?
- yes: mode `hardware_stack_pop` was executed and RET stack-pop events were recorded in trace rows (`trace_type=ret_stack_pop`).

## What happens with unseeded stack?
- Unseeded scenario stop_reason: `ret_target_unknown`; continued_pc: `0x0000`.
- This remains hypothesis about caller context; no low-ROM caller bytes were invented.

## Which seeded return targets reach runtime/materialization/output candidates?
- Runtime/materialization-reaching scenarios: boot_4100_ret_stack_to_5710, boot_4100_ret_stack_to_55AD.
- See `ret_stack_continuation_audit.csv` for per-target reachability flags.

## Are any return targets plausible from static evidence?
- Vector-table targets 0x4176/0x41D0/0x492E/0x4954/0x497A are static_code candidates only.
- 0x5710 and 0x55AD were included as hypothesis runtime handoff targets; no claim they are real hardware return addresses.

## Does this reduce low-ROM/wrapper uncertainty?
- Partially: it proves the emulator can continue after RET by stack pop.
- It does not identify true pre-0x4100 caller provenance, so low-ROM/wrapper uncertainty remains.

## What remains hypothesis?
- All seeded return-address scenarios are hypothesis.
- Any continued path after synthetic stack seeding is emulation_observed only, not confirmed firmware boot reality.

## Commands
- python3 scripts/firmware_execution_sandbox.py run-autonomous-boot-caller-context --ret-mode hardware_stack_pop --max-passes 5
