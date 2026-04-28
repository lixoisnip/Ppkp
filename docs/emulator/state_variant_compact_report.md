# State variant compact report

- Variants run: packet_bridge_seeded_context_base, packet_bridge_seeded_context_bitmask_walk, packet_bridge_seeded_context_ff, packet_bridge_seeded_context_mode_e0, packet_bridge_seeded_context_mode_e1, packet_bridge_seeded_context_mode_e2, packet_bridge_seeded_context_output_flags, packet_bridge_seeded_context_zeroed.
- Variants rerun at 5000 steps and why: packet_bridge_seeded_context_bitmask_walk, packet_bridge_seeded_context_mode_e1; selected by compact-interest criteria.
- Any variant exit instead of max_steps: no (none).
- Any new unsupported opcodes: no.
- Any SBUF candidate writes: no.
- Any UART TX candidate bytes: no.
- Material XDATA write changes vs base: no (none).
- Material bit/SFR access changes: no confirmed material change in compact pass.
- Most seed-sensitive XDATA addresses (compact): 0x30D4(20); 0x30CC(20); 0x31FF(20); 0x3202(20); 0x3205(20); 0x3208(20); 0x320B(20); 0x320E(20).
- Branch decisions keeping 0x55AD/0x5602 in loops: see docs/emulator/branch_decision_summary.csv (JB/JNB/CJNE/JZ/JNZ/DJNZ compact aggregates).
- RS-485 commands still unresolved: yes (no confirmed UART/SBUF payload evidence).
