# Field vs firmware output hypothesis

## Question-oriented assessment

### Does current firmware evidence support the field observation that firmware/config changes output fanout?
Yes, **partially**. The field report states unchanged interchangeable modules with different fanout (1 relay vs 8 outputs), and compared DKS firmware images show role-aligned divergence in candidate configuration/action regions (`0x5984..0x598B`, `0x55AD..0x56DF`, `0x5935..0x59AF`). This is consistent with firmware/config-driven fanout differences, but not yet a proof of exact physical channels.

### Which code/data regions best support this?
- `0x5984..0x598B`: 8-bit mask ramp in 90CYE03/90CYE04 DKS and divergent values in 90CYE02 DKS.
- `0x36F2..0x36F9`: observed sequential 8-slot writes in compact emulation traces from `0x55AD/0x5602`.
- `0x36ED..0x36F1` and `0x36FB..0x36FF`: adjacent header/trailer-like candidate fields around the same staging sequence.
- `0x55AD..0x56DF` and `0x5935..0x59AF`: runtime blocks that differ between 90CYE02 and 90CYE03 DKS, while matching between 90CYE03 and 90CYE04 DKS.
- `0x6833 -> 0x7DC2` plus `0x84A6/0x728A`: static chain consistent with start/mode/interlock gating.

### Which project documents support output-module presence?
- `docs/extracted/ppkp_devices.yaml` confirms device roles and output-related functions (MVK any-zone fire on 90CYE01; damper control on 90CYE02; aerosol start + warning outputs on 90CYE03/90CYE04).
- `docs/extracted/project_to_firmware_linkage.csv` links project functions to candidate firmware neighborhoods with confidence/evidence labels.
- `docs/project_guided_static_analysis_summary.md` and `docs/project_guided_final_static_boundary.md` preserve project-first interpretation and explicit unresolved boundaries.

### Which firmware lacks or differs in the 8-bit selector table?
- `90CYE03_19_DKS.PZU` and `90CYE04_19_DKS.PZU` share `01 02 04 08 10 20 40 80` at `0x5984..0x598B`.
- `90CYE02_27 DKS.PZU` differs at `0x5984..0x598B` (non-ramp bytes), consistent with a different control profile.
- `_2 v2_1` images are currently non-comparable at these absolute offsets.

### Is `0x36F2..0x36F9` likely tied to 8 outputs?
**Probable**, because an 8-element sequential write burst is directly observed and it is adjacent to candidate control/header fields. However, this is still an internal action/output vector hypothesis; exact relay/terminal identity is unproven.

### What evidence is still missing to confirm exact relay mapping?
- Terminal/object mapping sheets for 90CYE02/03/04.
- Bench traces that tie specific terminal toggles to candidate XDATA bytes in synchronized time.
- Controlled event capture across auto/manual and interlock conditions.

### What would external HVO PZU comparison prove?
If an external HVO image that shows 1-relay behavior is compared and demonstrates narrowed or altered structures in the same candidate regions (especially `0x5984..0x598B`, `0x55AD..0x56DF`, `0x36F2..0x36F9` consumers), it would materially strengthen firmware-side fanout configuration causality.

## Required conclusion

- confirmed:
  - Field observation states modules are interchangeable and not reprogrammed.
  - Project docs confirm output-related roles exist for 90CYE01/02/03/04 in different functional classes.
  - DKS diff evidence confirms role-aligned differences between 90CYE02 vs 90CYE03 in key candidate regions.
- probable:
  - `0x36F2..0x36F9` is an internal 8-slot output/action vector.
  - `0x5984..0x598B` participates in 8-bit output selection logic for DKS aerosol-role firmware.
- hypothesis:
  - 1-relay vs 8-output field difference is driven by firmware configuration/action tables and/or runtime dispatch differences.
  - `0x6833/0x7DC2` and `0x84A6/0x728A` chains gate output start and mode/interlock behavior that affect fanout.
- unknown:
  - Exact relay number, terminal number, and physical channel mapping for candidate bytes.
  - RS-485 byte-level frame semantics tied to those output actions.
- blocked_until_docs:
  - Full terminal-object sheets, GOA/AN/AU/AO mapping pages, and protocol appendix details.
- blocked_until_bench:
  - Terminal-labeled captures proving physical mapping of candidate bytes to real outputs.
