# RTOS_service chain decompile v1 (manual-static)

Generated: 2026-04-27 11:08:18Z

## Scope and family separation.
- Scope: RTOS_service family only (ppkp2001 90cye01.PZU, ppkp2012 a01.PZU, ppkp2019 a02.PZU).
- DKS is used only as structural comparator.
- Evidence levels: exact_fingerprint, near_fingerprint, callgraph_match, xdata_pattern_match, string_marker_match, manual_static, hypothesis, unknown.

## ppkp2001 90cye01 chain.
- Candidate rows: 5.
- Includes anchor neighborhoods around 0x758B/0x53E6/0xAB62 where present.

## ppk2012 a01 comparison.
- Candidate rows: 4.
- Shared dispatcher patterns are tracked as analog candidates.

## ppkp2019 a02 comparison.
- Candidate rows: 3.
- Divergences are preserved as family-local behavior.

## 0x758B shared dispatcher analysis.
- Presence in summary: True.
- Treated as high-fanout dispatcher candidate under callgraph evidence.

## 0x53E6 MDS/state preparation analysis.
- Included as RTOS_service anchor candidate with manual-static pseudocode skeleton.

## 0xAB62 MASH-side decoder analysis.
- Included as decoder/dispatcher analog candidate with branch-local confidence.

## RTOS_service-specific string markers.
- Marker hits (if indexed): 0x4FF1:PECTAPT; 0xA026:PECTAPT; 0xA31B:6500-1; 0xA322:6500-2; 0x5053:PECTAPT; 0xA6F1:PECTAPT; 0xA9E6:6500-1; 0xA9ED:6500-2.

## How RTOS_service differs from 90CYE_DKS.
- No direct semantic transfer from DKS chain.
- Function matches are labeled analog candidates unless fingerprint-level proof exists.

## Next manual/static targets.
- Expand function-local pseudocode for top fanout functions near 0x758B and 0xAB62.
- Add deeper XDATA lineage traces for MDS/MASH candidate interactions.
