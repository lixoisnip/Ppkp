# Configuration record grammar hypothesis (8-byte model)

## Scope and evidence posture
- This document is **hypothesis-only reconstruction** from static decode and emulator traces.
- No claim is made that exact field semantics are confirmed.
- This model is tied to battery-backed configuration field evidence (front-panel menu programming, loss after battery depletion/power removal).

## Current best grammar candidate

### 1) Record stride candidate: 8 bytes (probable)
- Boot walker branch at `0x4151..0x415D` computes `DPTR = DPTR + 0x0008` then loops to `0x4112`.
- This is the strongest current static evidence of fixed record cadence.
- Confidence: **probable**, not confirmed.

### 2) Root pointer candidate at XDATA `0x0030..0x0031` (probable)
- `0x4106` seeds `DPTR=0x0030`, then bytes from `0x0030/0x0031` are moved into DPL/DPH and become active walker pointer.
- Interpreted as root/head pointer to configuration record area.
- Confidence: **probable**, not confirmed.

### 3) Observed tag/value checks in walker
- `0xFF` check at `0x4113`.
- `0x02` check at `0x4119`.
- `0x00` check at `0x4128` (after nested pointer redirection path).
- `0x0A` check at `0x412E`.

## Meaning hypotheses (explicitly unconfirmed)
- `0xFF` = terminator/invalid/end-marker candidate.
- `0x02` = structured record type candidate that triggers nested pointer handling.
- `0x00` = null/empty record candidate.
- `0x0A` = special record/version/processed-flag candidate (path sets ACC.0 into a byte then exits).

## Relation to battery-backed configuration evidence
- If installer-configured settings live in battery-backed memory, the `0x4100..0x4165` walker can be interpreted as early validation of those persisted records.
- The downstream materialization loop near `0x5710..0x5733` then looks compatible with building runtime object/device-like tables from already-validated state.
- This chain is still incomplete end-to-end in current emulator-only traces; keep confidence conservative.

## Open gaps
- Exact per-byte record layout inside each 8-byte unit.
- Exact ownership of fields written by `0x5717/0x5725` (address/type/zone/etc. unresolved).
- Hardware-backed confirmation via real-device captures/NVRAM comparison is still required.
