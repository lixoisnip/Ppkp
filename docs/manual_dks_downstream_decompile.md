# Manual downstream DKS decompile: 0x5A7F / 0x737C / 0x84A6 / 0x7922 / 0x597F / 0x7DC2

Date: 2026-04-27 (UTC).

## Machine-readable outputs
- `docs/manual_dks_downstream_decompile_summary.csv`
- `docs/manual_dks_downstream_pseudocode.csv`

## Scope
- Static semi-manual reconstruction only.
- Targets selected because they sit downstream of 0x497A / 0x613C / 0x728A / 0x6833 chain.
- 0x728A and 0x6833 already have a separate manual decompile and are not duplicated.
- Cross-check is limited to identical-address/fingerprint matches in 90CYE04_19_DKS.PZU.
- Physical semantics remain conservative: static code role != proven field action.

## Target summary table
| firmware_file | branch | function_addr | known_context | manual_role | confidence | key_evidence | next_step |
|---|---|---|---|---|---|---|---|
| 90CYE03_19_DKS.PZU | 90CYE_DKS | 0x5A7F | called from 0x497A/0x728A/0x6833 in packet-adjacent paths | packet_export_bridge | unknown | callers=95; callees=none; 90CYE04_fingerprint_match | refine with targeted dynamic trace on this node |
| 90CYE03_19_DKS.PZU | 90CYE_DKS | 0x737C | between 0x497A and 0x84A6 in prior deep-trace chain | zone_object_logic | probable | callers=1; callees=0x597F,0x5A7F,0x5AA3,0x73BA; xdata=0x3010(write),0x3011(write),0x3012(read); 90CYE04_fingerprint_match | refine with targeted dynamic trace on this node |
| 90CYE03_19_DKS.PZU | 90CYE_DKS | 0x84A6 | between 0x737C and 0x728A in prior deep-trace chain | mode_event_bridge | hypothesis | callers=2; callees=0x59A0,0x5A7F,0x6025,0x6CB5; xdata=0x315B(read),0x3181(read),0x3640(read); 90CYE04_fingerprint_match | refine with targeted dynamic trace on this node |
| 90CYE03_19_DKS.PZU | 90CYE_DKS | 0x7922 | frequent helper call in 0x728A and 0x6833 branches | state_table_reader | unknown | callers=6; callees=none; 90CYE04_fingerprint_match | refine with targeted dynamic trace on this node |
| 90CYE03_19_DKS.PZU | 90CYE_DKS | 0x597F | pre-check helper before 0x6833 output write | condition_check_helper | unknown | callers=10; callees=none; 90CYE04_fingerprint_match | refine with targeted dynamic trace on this node |
| 90CYE03_19_DKS.PZU | 90CYE_DKS | 0x7DC2 | downstream jump target from 0x6833 tail | output_downstream_transition | unknown | callers=1; callees=0x7121,0x7D9B; xdata=0x0001(read); 90CYE04_fingerprint_match | refine with targeted dynamic trace on this node |

## 0x5A7F packet/export bridge analysis
- Repeated packet/export treatment is supported by high fan-in from dispatch/gate paths (0x497A, 0x728A, 0x6833 contexts) and frequent call sites that set `DPTR` + selector in `A` immediately before call.
- Callers (sample): 0x55AD, 0x55C0, 0x55C9, 0x55E6, 0x55F9, 0x5602, 0x5628, 0x5663, 0x569D, 0x571A, 0x5730, 0x574E, 0x575A, 0x577A, 0x5786, 0x57A4, 0x57B0, 0x57CE, 0x57DA, 0x57F8.
- Direct XDATA reads/writes inside 0x5A7F are not confirmed in `xdata_confirmed_access.csv`; function body is a tiny DPTR staging return helper.
- Static shape suggests pointer/address resolver or packet-field bridge (not a full packet payload builder on its own).
- Return behavior: moves into DPTR registers and returns, consistent with pointer-like handoff.
- Interaction with 0x31BF/0x364B/0x30E7/0x30E9/0x30EA..0x30F9 appears indirect via caller-set DPTR contexts (e.g., 0x728A/0x6833 set these addresses then call 0x5A7F).
- In 0x497A/0x728A/0x6833 neighborhoods it repeatedly appears as a bridge between state/mode branch and later `MOVX` reads/writes.
- Cautious role: **packet_export_bridge** (probable), with unresolved split between packet sink vs pointer resolver contribution.

```c
void fn_5A7F(uint8_t selector_or_index) {
    // very small helper
    // update DPTR bytes from current selector/context
    // return with pointer-like DPTR state for caller MOVX activity
}
```

## 0x737C zone/object logic analysis
- Treated as zone/object candidate due to high branch density, state-table reads/writes, and links to 0x84A6 and 0x5A7F.
- Confirmed XDATA in function: 0x3010(write), 0x3011(write), 0x3012(read), 0x3013(write), 0x3014(write), 0x301A(write), 0x301B(write), 0x31BF(read), 0x36D3(read), 0x36EC(read), 0x36EE(read), 0x36EF(read), 0x36F2(read), 0x36F3(read), 0x36F4(read), 0x36FC(read), 0x36FD(read).
- Enum-like value evidence from `enum_branch_value_map.csv`: 0x03, 0x07 (requested values 0x01/0x02/0x04/0x05/0x08/0x7E/0xFF are not confirmed in this node from provided enum map).
- Calls observed: includes 0x84A6 and 0x5A7F; no direct call to 0x613C or 0x728A seen in this function body.
- Writes to 0x3010/0x3011/0x3013/0x3014/0x301A/0x301B support state/object-table update behavior.
- Cautious role: **zone_object_logic** (probable), but still compatible with branch-dispatcher interpretation.

```c
void fn_737C(...) {
    // read object/zone context (e.g., 0x31BF + 0x36E* cluster)
    // branch on masked enum/state values
    // call sub-helpers and 0x84A6 bridge
    // update 0x301* state table fields
    // invoke 0x5A7F when packet/export-adjacent path is needed
}
```

## 0x84A6 mode/event bridge analysis
- Treated as mode/event bridge because it calls 0x728A and also calls 0x5A7F from a control-heavy dispatcher with multiple downstream service handlers.
- Callers: 0x7105, 0x73FD.
- Key XDATA reads: 0x315B(read), 0x3181(read), 0x3640(read), 0x36D3(read), 0x36D9(read).
- Manual/auto map hints: manual_downstream=0x5A7F, auto_downstream=0x6833;0x5A7F (confidence=hypothesis).
- It appears to both bridge event generation and perform gating-like checks (bit tests + conditional dispatch), so role is mixed.
- Manual-like vs auto-like physical semantics are still hypothesis-level; static evidence only proves branch/dispatch structure.

```c
void fn_84A6(...) {
    // read mode/state cluster (0x315B/0x3181/0x36D3/0x36D9/0x3640)
    // evaluate branch flags / thresholds
    // call 0x728A for downstream gate path
    // call 0x5A7F for packet/pointer bridge on selected paths
    // dispatch to service/output helpers
}
```

## 0x7922 service/event helper analysis
- Frequent calls from 0x728A/0x6833 are explained by tiny fixed behavior: read two bytes from `@DPTR` and place into R0/R1.
- Callers (sample): 0x54C1, 0x6836, 0x7187, 0x72C8, 0x72FF, 0x7349.
- Pre-call pattern repeatedly sets DPTR to table-like addresses (e.g., 0x7108/0x7128/0x7138/0x0001), so arguments are pointer-by-DPTR.
- No direct XDATA writes by 0x7922 itself; no calls to packet/export functions from inside 0x7922.
- Cautious role: table/service read helper used to load event/output context, not a standalone queue or packet routine.

```c
void fn_7922(void) {
    // A = XDATA[DPTR]; R0 = A
    // DPTR++
    // A = XDATA[DPTR]; R1 = A
    // return
}
```

## 0x597F condition-check helper analysis
- 0x6833 calls 0x597F after loading A from R7 and before output-start write; this is consistent with a compact condition normalization/check helper.
- Body-level static behavior is tiny (`ANL A,#0x07` + return paths), so result is likely returned in ACC-derived state used by caller branches.
- No direct XDATA access in this helper from confirmed access map.
- In 0x6833 specifically, result is moved to R2 and later branch-tested before writing 0x04 to target XDATA entry.
- Cautious role: **condition_check_helper** (probable), exact semantic (permission/fault/mode) unknown.

```c
uint8_t fn_597F(uint8_t in_a) {
    // reduce/normalize condition bits
    // return (in_a & 0x07)
}
```

## 0x7DC2 downstream output/service transition analysis
- 0x6833 ends with `LJMP 0x7DC2` after packet/context setup calls; this supports downstream transition/finalization role.
- Callers: 0x6862.
- Direct callees from 0x7DC2 block: 0x7121, 0x7D9B.
- Basic-block map places 0x7DC2 inside parent 0x7D85, so this address is likely a sub-entry/tail block rather than an independent large function.
- Output transition map references into this target: 1 rows.
- Cautious role: output/service transition tail that writes final bytes to XDATA and returns; not enough evidence to call it packet finalizer exclusively.

```c
void fn_7DC2(...) {
    // downstream sub-block in parent routine (0x7D85)
    // call helper(s) (e.g., 0x7121), then emit several bytes via MOVX @DPTR
    // return to caller chain tail
}
```

## Relationship to existing chain
```text
0x497A shared runtime/state dispatcher
  -> 0x737C zone/object logic candidate                [prior trace hypothesis + static adjacency]
  -> 0x613C state latch/update                         [direct call (existing upstream report)]
  -> 0x84A6 mode/event bridge candidate                [prior trace hypothesis + static adjacency]
  -> 0x728A probable mode gate                         [direct call from 0x84A6]
      manual-like -> 0x5A7F packet/export bridge      [direct call]
      auto-like   -> 0x6833 probable output-start      [direct call (existing downstream context)]
          -> 0x7922 service/event helper               [direct call]
          -> 0x597F condition check                    [direct call]
          -> XDATA[dptr] = 0x04                        [direct write in 0x6833]
          -> 0x5A7F packet/export bridge               [direct call]
          -> 0x7DC2 downstream transition              [direct LJMP to sub-block in 0x7D85]
```

## Evidence separation
- **Static code evidence:** call graph edges, immediate constants, DPTR/XDATA accesses, and basic-block adjacency from CSV artifacts.
- **Manual pseudocode interpretation:** helper roles inferred from compact instruction patterns (pointer bridge, table read helper, masked condition helper).
- **Chain adjacency evidence:** prior reports (`manual_decompile_0x728A_0x6833.md`, `auto_manual_gating_deep_trace_analysis.md`) used only as contextual adjacency, not as proof of physical action.
- **Unknown physical meaning:** no direct claim is made that these addresses correspond to specific field actuators or named physical devices.

## Pseudocode section (specific, non-generic)

### 0x5A7F
```c
void fn_5A7F(uint8_t selector_or_index) {
    // update DPTR bytes from current selector/context
    // return pointer-like DPTR state for caller MOVX activity
}
```

### 0x737C
```c
void fn_737C(...) {
    // read object/zone context (0x31BF + 0x36xx cluster)
    // branch on masked enum/state values
    // call 0x84A6 and 0x5A7F on selected paths
    // update 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B state-table fields
}
```

### 0x84A6
```c
void fn_84A6(...) {
    // read mode/state cluster (0x315B/0x3181/0x3640/0x36D3/0x36D9)
    // evaluate branch flags / thresholds
    // call 0x728A for downstream gate path
    // call 0x5A7F for packet/pointer bridge on selected paths
}
```

### 0x7922
```c
void fn_7922(void) {
    // A = XDATA[DPTR]; R0 = A
    // DPTR++
    // A = XDATA[DPTR]; R1 = A
    // return
}
```

### 0x597F
```c
uint8_t fn_597F(uint8_t in_a) {
    // return in_a & 0x07
}
```

### 0x7DC2
```c
void fn_7DC2(...) {
    // downstream sub-block in parent routine (0x7D85)
    // call helper(s) (0x7121 and 0x7D9B), then continue output/service transition tail
}
```
