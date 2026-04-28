# Next autonomous decision (config/runtime reconstruction)

## Internal passes performed
1. Priority A boot exit consistency audit across required 0x4100 seed scenarios.
2. Priority B forced post-0x415F/post-0x4165 runtime handoff probes.
3. Priority C materialization-loop write audit for XDATA 0x31FF..0x3268.
4. Priority D linkage attempt from materialization contexts into 0x36F2..0x36F9.
5. Priority E decision synthesis and stop boundary classification.

## What changed
- Added explicit audits for boot exit consistency, post-415F handoff, and materialization-to-output linkage.
- Added hypothesis-only scenarios for forced entries at 0x415F, 0x4165, and 0x5710 contexts.

## Strongest new evidence
- Seeded 0x4100 entries reach 0x415F/0x4165 and then stop with ret_from_entry near 0x4128; unseeded probe remains looped.
- Forced entries at 0x415F/0x4165 can reach 0x5710/0x5717/0x5725 under injected context.
- Materialization writes in 0x31FF..0x3268 are reproducible; direct 0x36F2..0x36F9 linkage is still not proven.

## Confirmed / probable / hypothesis / unknown
### Confirmed
- static_code: 0x4100 walker includes conditional branches to LJMP 0x415F sites.
- emulation_observed: direct 0x4100 entry behaves as subroutine return path in this harness.
### Probable
- 0x5710..0x5733 materializes runtime table-like records at XDATA 0x31FF..0x3268.
### Hypothesis
- 0x415F flag-setting block is reached in full boot only when caller/stack context is supplied by pre-4100 code.
- runtime hubs (0x55AD/0x5602/0x5A7F) consume materialized records before output vector writes.
### Unknown
- Exact config record grammar and exact mapping into output/action vector slots.

## Current best model
- Boot reset enters 0x4100 walker logic, but isolated 0x4100 harness entry misses upstream caller semantics.
- Post-walker runtime likely transitions toward 0x5710 materialization and then runtime hubs.
- Output vector 0x36F2..0x36F9 remains downstream and not yet causally linked in bounded emulation.

## Top 3 next targets
1. Reconstruct boot caller/stack context immediately before 0x4100 (highest impact).
2. Capture/compare real battery-backed NVRAM/config dumps for known UI settings.
3. Trace caller-context around 0x5710 and runtime hubs with minimal additional emulator instrumentation.

## Single recommended next Codex target
- Prioritize **boot caller/stack context reconstruction around pre-0x4100 low-ROM path**, then re-run the same audits.

## Low-value paths to avoid
- Blindly expanding UART/interrupt/timer peripheral emulation without caller-context evidence.
- Claiming exact record-field semantics (0xFF/0x02/0x00/0x0A) without external data.
- Large raw trace dumps that do not improve causal linkage.

## Requires user/bench/docs input
- Known-setting NVRAM/config snapshots (before/after battery removal and menu edits).
- Any board docs indicating bootstrap caller flow into 0x4100.

## Can another autonomous package proceed without user input?
- Yes, but only for a narrow package focused on static caller-context reconstruction around pre-0x4100 and callsite mapping into 0x5710.
- Full end-to-end proof (config -> materialized table -> output vector) is blocked_until_bench/blocked_until_docs.
