# Manual DKS module decompile: upstream candidates

Date: 2026-04-27 (UTC).

## Scope

- This report is a semi-manual static reconstruction from existing CSV artifacts only (no live `.PZU` disassembly during this run).
- Screen/config evidence confirms module presence at slots but does not directly prove exact handler addresses.
- Function targets come from `docs/dks_module_deep_trace_analysis.md` and are refined here into pseudocode-style roles with explicit confidence labels.
- Physical semantics remain unknown unless directly supported by static code evidence.

## Target summary table

| firmware_file | branch | function_addr | screen_module_context | deep_trace_role | manual_role | confidence | key_evidence | next_step |
|---|---|---|---|---|---|---|---|---|
| 90CYE03_19_DKS.PZU | 90CYE_DKS | 0x497A | X03/X04/X05/X06/X07 in DKS screens | top upstream candidate; deep-trace mds_event_generation + mup_feedback_check | generic runtime state dispatcher with packet-export adjacency | confirmed | calls=76, xdata=47, out=24 | runtime trace around listed XDATA and downstream calls |
| 90CYE03_19_DKS.PZU | 90CYE_DKS | 0x613C | X03/X04/X05/X06/X07 in DKS screens | upstream state bridge candidate near 0x497A chain | small state latch/bridge updater | confirmed | calls=0, xdata=55, out=0 | runtime trace around listed XDATA and downstream calls |
| 90CYE04_19_DKS.PZU | 90CYE_DKS | 0x497A | X03/X04/X05/X06/X07 in DKS screens | cross-variant compare against 90CYE03 | same as 90CYE03: generic runtime dispatcher | confirmed | calls=76, xdata=47, out=24 | runtime trace around listed XDATA and downstream calls |
| 90CYE04_19_DKS.PZU | 90CYE_DKS | 0x613C | X03/X04/X05/X06/X07 in DKS screens | cross-variant compare against 90CYE03 | same as 90CYE03: small state latch/bridge updater | confirmed | calls=0, xdata=55, out=0 | runtime trace around listed XDATA and downstream calls |
| 90CYE02_27 DKS.PZU | 90CYE_shifted_DKS | 0x673C | X03/X04(+X06/X07/X08 unknown modules) | top shifted-DKS object/status candidate | small object/status updater | confirmed | calls=0, xdata=77, out=0 | runtime trace around listed XDATA and downstream calls |
| ppkp2001 90cye01.PZU | RTOS_service | 0x758B | X03(MDS), X05/X06(MASH), X04(PVK unknown) | shared high-score dispatcher candidate | shared high-fanout dispatcher (MDS+MASH candidate overlap) | confirmed | calls=127, xdata=68, out=57 | runtime trace around listed XDATA and downstream calls |
| ppkp2001 90cye01.PZU | RTOS_service | 0x53E6 | X03(MDS), X04(PVK unknown) | strong MDS upstream candidate | state preparation + update routine feeding service path | confirmed | calls=13, xdata=180, out=13 | runtime trace around listed XDATA and downstream calls |
| ppkp2001 90cye01.PZU | RTOS_service | 0xAB62 | X05/X06(MASH), X04(PVK unknown) | strong MASH upstream candidate | MASH-side decoder/dispatcher with calls into 0x758B | probable | calls=39, xdata=13, out=28 | runtime trace around listed XDATA and downstream calls |

## 90CYE03/04 DKS: 0x497A

### Static code evidence
- Function-map profile: call_count=76, xdata_reads=23, xdata_writes=24, movc_count=0.
- XDATA addresses observed (confirmed + branch-trace): 0x0035, 0x31BF.
- Main call targets (unique): 0x58B1, 0x5935, 0x594B, 0x59A0, 0x5A7F, 0x5AA3, 0x5D13, 0x5D22, 0x60E4, 0x673C, 0x6ACB, 0x6CFB, 0x78D8, 0x7922, 0x7928, 0x826B, 0x8291, 0x8320.
- Branch features: branch_ops=47, loop_like_back_edges=21, bitmask_ops=2.
- Relation to requested chain functions:
  - 0x737C: no direct call/jump in function body (static artifacts).
  - 0x613C: no direct call/jump in function body (static artifacts).
  - 0x84A6: no direct call/jump in function body (static artifacts).
  - 0x728A: no direct call/jump in function body (static artifacts).
  - 0x6833: no direct call/jump in function body (static artifacts).
  - 0x5A7F: direct call/jump seen.
- Deep-trace still links this function into the broader `0x497A->0x737C->0x613C->0x84A6->0x728A` neighborhood; this is adjacency evidence, not a direct-call proof for each hop.
### Manual interpretation
- Most defensible role: **generic runtime state dispatcher** with strong packet/export adjacency (many calls to `0x5A7F`) and branch-heavy gating.
- It is **not safely classifiable as only MDS or only MUP** from this evidence; it appears shared/central.
- Bit-mask and loop behavior are present; this supports state-flag handling, but not physical semantics.
- Unknowns: exact module ownership of each branch path, and exact event payload semantics.
### 90CYE03 vs 90CYE04 comparison
- 0x497A fingerprint (90CYE03): `8f4550f1e9e2754fe69e33ccf60add985fca8dbb7c83a7211548fc4028a8a208`
- 0x497A fingerprint (90CYE04): `8f4550f1e9e2754fe69e33ccf60add985fca8dbb7c83a7211548fc4028a8a208`
- Result: **identical instruction fingerprint** across 90CYE03 and 90CYE04 for this function.

## 90CYE03/04 DKS: 0x613C

### Static code evidence
- Very small routine (instruction_count from blocks: 12) with low fan-out (outgoing targets: none).
- XDATA addresses observed: 0x315D.
- Instruction pattern is read-compare/branch-then-write (`MOVX A,@DPTR`, `JNZ`, followed by `MOVX @DPTR,A` writes).
- No direct calls to `0x84A6`, `0x728A`, or `0x5A7F` from this function body in current static artifacts.
### Manual interpretation
- Best fit: **state/feedback bridge updater** (likely old/new or zero/non-zero gate, then latch update).
- Evidence linking to MDS/MUP is **heuristic and chain-based**, not direct module-signature proof.
- Confidence: probable for a state updater role; unknown for physical module ownership.
### 90CYE03 vs 90CYE04 comparison
- 0x613C fingerprint (90CYE03): `5ba445b91b417816083daaf9d310fd2a7a21199710de0d1cc7958c9504a165c9`
- 0x613C fingerprint (90CYE04): `5ba445b91b417816083daaf9d310fd2a7a21199710de0d1cc7958c9504a165c9`
- Result: **identical instruction fingerprint** across 90CYE03 and 90CYE04 for this function.

## 90CYE02 DKS: 0x673C

### Why deep-trace ranked it highly
- Deep-trace top score reaches 0.862 (confirmed bucket) for MDS/event candidate rows.
- It is repeatedly selected across multiple DKS slots in candidate artifacts, which boosts chain consistency.
### Static code evidence
- Incoming callsites: 0x6667; outgoing direct targets: none.
- XDATA addresses observed: 0x3104.
- Routine is short and write-oriented after a branch gate, matching an object/status updater profile more than a root dispatcher.
- No direct string/object-tag binding to visible `90SAE...` names is present in current string-index links; keep tag mapping indirect.

## ppkp2001 90cye01: 0x758B

### Static code evidence
- Large branch-heavy body: call_count=127, xdata_reads=66, xdata_writes=2, branch_ops=164.
- XDATA observed at entry-level evidence: none; outgoing targets include 0x7408, 0x75B6, 0x75EA, 0x762C, 0x763E, 0x764C, 0x7659, 0x766A, 0x7677, 0x7690, 0x769E, 0x76AC, 0x76BA, 0x76D9, 0x76EF, 0x770C, 0x7729, 0x7746, 0x775F, 0x7775.
- Deep-trace ranks it for both MDS and MASH contexts (X03 and X05/X06), indicating overlap/shared control path.
### Resolution
- Most probable interpretation: **shared dispatcher** rather than exclusive MDS-only or MASH-only handler.
- MASH linkage evidence: appears in MASH deep-trace chain summary and is called from 0xAB62.
- MDS linkage evidence: highest MDS deep-trace score for X03 in this firmware.
- Ambiguous: exact partition of MDS vs MASH sub-branches without runtime branch labeling.

## ppkp2001 90cye01: 0x53E6

### Static code evidence
- Candidate strength: deep-trace high score bucket (max=0.870) for MDS rows.
- XDATA addresses observed: 0x78E5; incoming callsites: 0x4513, 0x9255.
- Outgoing calls include 0x4365, 0x4755, 0x4781, 0x49DF, 0x4A3B, 0x543D, 0x90C5, 0x90E0, 0x9134, 0x9143, 0x916D, 0x919E, 0x91EB, suggesting state prep + service handoff pattern.
### Manual interpretation
- Looks more like **discrete/state update preparation with downstream service calls** than a pure packet exporter.
- Packet/export feeding may exist indirectly downstream, but this function itself is primarily state-moving/conditioning by current evidence.

## ppkp2001 90cye01: 0xAB62

### Static code evidence
- MASH-side candidate score bucket: 0.572 with branch+compare-heavy structure.
- XDATA addresses observed: 0x75B1; outgoing includes recursive/self and `0x758B` call linkage.
- Address-loop style compare/update patterns and chained helper calls align with sensor/event decoding style handlers.
### Manual interpretation
- Probable role: **sensor-state decoder / event dispatcher** feeding shared dispatcher `0x758B`.
- Relation: `0xAB62` appears more MASH-local; `0x758B` appears shared; `0x53E6` appears more MDS-side state prep.

## Relationship to existing 0x728A / 0x6833 manual decompile

- `0x728A` remains a **probable mode gate** (unchanged).
- `0x6833` remains a **probable output-start entry** (unchanged).
- New upstream candidates here are treated as potential state-preparation/feed paths toward that chain, not as replacements.
- This report does **not** relabel `0x6833` as MUP-only handler; evidence remains chain-adjacent and mixed.

## Downstream decompile follow-up

- `docs/manual_dks_downstream_decompile.md`
- `docs/manual_dks_downstream_decompile_summary.csv`
- `docs/manual_dks_downstream_pseudocode.csv`

## Manual pseudocode

```c
void fn_497A(...) {
    // read runtime flags/context from XDATA
    // branch on bit masks and loop through state buckets
    // call packet/export bridge (notably 0x5A7F) and helper handlers
    // update runtime state flags
}

void fn_613C(...) {
    // read state latch value
    // branch on zero/non-zero (old/new-like gate)
    // write back latch/state bytes
    // return to upstream dispatcher
}

void fn_673C(...) {
    // read object/status byte
    // branch on state flag
    // write updated status and side-state bytes
    // return
}

void fn_758B(...) {
    // read broad context and multiple state bits
    // dispatch across many branch paths
    // call shared helper/service routines
    // write state/event outputs
}

void fn_53E6(...) {
    // copy/normalize state values
    // run checksum/aggregation-like loop
    // call downstream service/update helpers
    // commit updated state
}

void fn_AB62(...) {
    // decode/compare sensor-like state bytes
    // branch per code/state value
    // call helper routines and shared dispatcher (0x758B)
    // update event/state outputs
}
```
