# Serial absence check

- Is there any direct static write to SBUF0 0x99? no.
- Is there any direct static write to SCON0 0x98? no.
- Is there any bit operation on SCON0? yes.
- Is there any DS80C320 UART1 candidate SFR access? unknown in this compact pass; no direct UART1 write confirmed in emulation_observed traces.
- Are there suspicious external UART/bit-banged serial patterns? only weak/generic bit and SFR activity; no direct TX byte evidence.
- Could RS-485 be driven through external memory-mapped hardware instead of standard SBUF? yes, still plausible (hypothesis) while standard SBUF/SCON writes remain unobserved.
- What evidence would be needed to prove this?
  - repeated MOVX writes to a stable external range in packet/event context (emulation_observed);
  - caller-linked path from high-fan-in hub (e.g., 0x5A7F/0x5935 region) into those writes;
  - bench capture correlating bus activity to wire-level RS-485 timing/bytes.

Conclusion: standard 8051 UART path is not currently observed; protocol absence is not concluded.
