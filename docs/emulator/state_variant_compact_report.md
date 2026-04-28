# State variant compact report

- Variants run: packet_bridge_loop_force_acc0_clear, packet_bridge_loop_force_acc0_set, packet_bridge_loop_force_djnz_exit_candidate, packet_bridge_loop_force_jb_not_taken_candidate, packet_bridge_loop_force_r3_00, packet_bridge_loop_force_r3_01, packet_bridge_seeded_context, packet_bridge_seeded_context_base, packet_bridge_seeded_context_bitmask_walk, packet_bridge_seeded_context_ff, packet_bridge_seeded_context_mode_e0, packet_bridge_seeded_context_mode_e1, packet_bridge_seeded_context_mode_e2, packet_bridge_seeded_context_output_flags, packet_bridge_seeded_context_zeroed.
- Variants rerun at 5000 steps and why: packet_bridge_seeded_context_bitmask_walk, packet_bridge_seeded_context_mode_e1; selected by compact-interest criteria.
- Any variant exit instead of max_steps: yes (packet_bridge_loop_force_r3_01:0x5715; packet_bridge_loop_force_jb_not_taken_candidate:0x5715; packet_bridge_loop_force_djnz_exit_candidate:0x5715; packet_bridge_seeded_context:0x5A7F).
- Any new unsupported opcodes: yes.
- Any SBUF candidate writes: no.
- Any UART TX candidate bytes: no.
- Material XDATA write changes vs base: yes (packet_bridge_seeded_context:0x55AD; packet_bridge_seeded_context:0x5602).
- Material bit/SFR access changes: no confirmed material change in compact pass.
- Most seed-sensitive XDATA addresses (compact): 0x30D4(22); 0x30CC(22); 0x31FF(22); 0x3202(22); 0x3205(22); 0x3208(22); 0x320B(20); 0x320E(20).
- Branch decisions keeping 0x55AD/0x5602 in loops: see docs/emulator/branch_decision_summary.csv (JB/JNB/CJNE/JZ/JNZ/DJNZ compact aggregates).
- RS-485 commands still unresolved: yes (no confirmed UART/SBUF payload evidence).

## Seed-effect audit summary
- Which seed addresses are actually read? 0x30AC, 0x30EE, 0x31BF, 0x36D3, 0x36ED, 0x36FA, 0x36FB, 0x7160.
- Which seed addresses are overwritten before first read? 0x30AC, 0x31BF, 0x36ED, 0x36FB.
- Which seed addresses influence branch decisions? none confirmed.
- Which branches keep 0x55AD/0x5602 in 0x5715..0x5733? 0x5729:JB, 0x5733:DJNZ.
- Does loop state change over time or stay constant? changes across sampled snapshots, but still does not exit hotspot loops.
- Is the current blocker likely wrong seed selection or missing runtime/peripheral context? likely missing runtime/peripheral context (seed variants do not materially alter loop-exit behavior).
- Did any SBUF candidate write appear? no.
- Did any UART TX candidate byte appear? no.
- Are RS-485 commands still unresolved? yes.

## Loop runtime-context audit summary

- What controls the `0x5715..0x5733` loop? Mixed control: `JB bit 0xE0` (ACC.0) at `0x5729` plus `DJNZ R3,-32` at `0x5733` after `MOV R3,#0x14` at `0x571B`.
- What is the role of R3 at `0x5733`? `R3` is the loop counter used by `DJNZ`.
- What is the exact bit tested at `0x5729`? Bit address `0xE0` -> SFR-byte `0xE0`, bit 0 -> ACC.0.
- Which instruction sets/clears that bit before branch? `MOV A,#0x80` (`0x5715`) initializes; repeated `RLC A` (`0x571E`) updates ACC.0.
- Does forcing R3 change loop exit? Yes in hypothesis-only entry overrides: `R3=1` exits loop hotspot and reaches `0x573C` blocker; `R3=0` does not.
- Does forcing ACC.0 / bit 0xE0 change loop exit? No exit by ACC-only forcing in these experiments.
- Does any forced loop-exit scenario reach new code? Yes, reaches `0x5735..0x573C` before unsupported-op stop.
- Does any scenario reach SBUF candidate writes? No.
- Does any scenario produce UART TX candidate bytes? No.
- Are RS-485 commands still unresolved? Yes.
- Next blocker assessment: missing runtime/register context and additional opcode support after `0x573C`; missing timer/peripheral effects remain plausible but unproven.
