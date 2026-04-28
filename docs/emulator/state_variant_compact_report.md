# State variant compact report

- Variants run: packet_bridge_loop_force_djnz_exit_candidate, packet_bridge_loop_force_jb_not_taken_candidate, packet_bridge_loop_force_r3_01, packet_bridge_seeded_context_base, packet_bridge_seeded_context_bitmask_walk, packet_bridge_seeded_context_ff, packet_bridge_seeded_context_mode_e0, packet_bridge_seeded_context_mode_e1, packet_bridge_seeded_context_mode_e2, packet_bridge_seeded_context_output_flags, packet_bridge_seeded_context_zeroed.
- Variants rerun at 5000 steps and why: packet_bridge_seeded_context_bitmask_walk, packet_bridge_seeded_context_mode_e1; selected by compact-interest criteria.
- Any variant exit instead of max_steps: no (none).
- Any new unsupported opcodes: no.
- Any SBUF candidate writes: no.
- Any UART TX candidate bytes: no.
- Material XDATA write changes vs base: no (none).
- Material bit/SFR access changes: no confirmed material change in compact pass.
- Most seed-sensitive XDATA addresses (compact): 0x31FF(23); 0x30D4(20); 0x30CC(20); 0x3202(20); 0x3205(20); 0x3208(20); 0x320B(20); 0x320E(20).
- Branch decisions keeping 0x55AD/0x5602 in loops: see docs/emulator/branch_decision_summary.csv (JB/JNB/CJNE/JZ/JNZ/DJNZ compact aggregates).
- RS-485 commands still unresolved: yes (no confirmed UART/SBUF payload evidence).

## Seed-effect audit summary
- Which seed addresses are actually read? 0x30AC, 0x30EE, 0x31BF, 0x36D3, 0x36ED, 0x36FA, 0x36FB.
- Which seed addresses are overwritten before first read? 0x30AC, 0x31BF, 0x36ED, 0x36FB.
- Which seed addresses influence branch decisions? none confirmed.
- Which branches keep 0x55AD/0x5602 in 0x5715..0x5733? 0x5729:JB, 0x5733:DJNZ.
- Does loop state change over time or stay constant? changes across sampled snapshots, but still does not exit hotspot loops.
- Is the current blocker likely wrong seed selection or missing runtime/peripheral context? likely missing runtime/peripheral context (seed variants do not materially alter loop-exit behavior).
- Did any SBUF candidate write appear? no.
- Did any UART TX candidate byte appear? no.
- Are RS-485 commands still unresolved? yes.

## Forced loop-exit path summary

- Scope: hypothesis-only forced-entry scenarios (`packet_bridge_loop_force_r3_01`, `packet_bridge_loop_force_djnz_exit_candidate`, `packet_bridge_loop_force_jb_not_taken_candidate`) at `max_steps=500`.
- Is `0x573C` valid executable code, padding, or unknown? **Valid executable code** (`0x00` executes as NOP and falls through into coherent instruction stream).
- Did implementing NOP allow progress beyond `0x573C`? **Yes**; forced paths advance through `0x573D..0x574E` after reaching `0x573C`.
- What is the next stop after `0x573C`? No immediate unsupported opcode in that window; compact forced runs stop by `max_steps`.
- Does forced loop exit reach `0x5A7F` again? **No within these 500-step forced runs** (a static `LCALL 0x5A7F` exists at `0x574E`, but it was not observed before the step budget stop in this compact pass).
- Does forced loop exit reach any SFR/SBUF write? No SBUF-candidate writes observed.
- Does forced loop exit produce UART TX candidate bytes? No UART TX candidate bytes observed.
- Is RS-485 still unresolved? **Yes** (no direct UART/SBUF payload evidence).
- Interpretation: evidence favors a valid post-loop path rather than padding at `0x573C`, while remaining uncertainty is dominated by missing caller/stack/runtime context in forced-entry hypothesis scenarios.
