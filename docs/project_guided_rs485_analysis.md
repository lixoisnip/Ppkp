# Project-guided RS-485 static analysis

Evidence policy: project documentation constrains search, but all findings below are static-code/cross-family hypotheses unless explicitly marked unknown.

## Inputs used
- Project linkage rows: 9
- function/call/xdata matrices from docs baseline
- DKS packet callsite matrices and A03/A04 bridge candidates

## Strongest TX/RX/parser/builder candidates
- `0x5A7F` (90CYE_DKS): strongest **packet_export_bridge** by fan-in call topology (static_code).
- `0x737C` / `0x497A` (90CYE_DKS): strongest **event/context-to-export path** neighbors for transmit-side staging.
- `0x84A6` and `0x613C` remain dispatcher/gate candidates that can participate in sender/receiver split but do not prove frame format.

## 0x5A7F role question
Static evidence still supports `0x5A7F` primarily as bridge/helper. A stronger dedicated packet builder has not been isolated with current artifacts.

## Checksum / CRC candidates
No high-confidence CRC table or explicit polynomial loop was isolated in currently linked function windows. PU-004 stays unresolved.

## Address constants / timeout counters
- Candidate selector bytes around `0x31BF/0x364B` remain plausible dispatcher context only.
- RTOS_service chain includes retry/timeout-like topology candidate (`0x53E6`) but with cross-family confidence cap.
- Numeric address map and baud constants remain unresolved.

## Unknown closure status
- PU-001 frame format: **partial static narrowing**, unresolved.
- PU-002 address map: **unresolved**.
- PU-003 baudrate: **unresolved**.
- PU-004 CRC/checksum: **unresolved**.
- PU-005 timeout/retry: **low-confidence candidate only**, unresolved.
