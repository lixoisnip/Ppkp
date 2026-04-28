# How to compare an external HVO PZU image later

This guide explains how to test whether a user-provided ХВО image encodes a different module/output behavior profile (e.g., 1 relay vs 8 outputs during fire).

## 1) Where to place the external file

1. Copy the file into repository root (`/workspace/Ppkp`) or a subfolder under the repo.
2. Keep original filename if possible (for evidence traceability), e.g.:
   - `HVO_YYYYMMDD.PZU`
3. Do **not** modify any `.PZU` contents.

## 2) Minimal comparison workflow

Run static diff windows against a DKS reference (example uses `90CYE03_19_DKS.PZU`):

```bash
python3 scripts/compare_pzu_variants.py '90CYE03_19_DKS.PZU' 'HVO_YYYYMMDD.PZU' --start 0x4000 --end 0xC000
```

Then check high-value candidate ranges directly (bitmask/helper + runtime hubs):
- `0x55AD..0x56DF`
- `0x5935..0x59AF`
- `0x5984..0x598B`
- `0x36ED..0x36FF` (if represented/aligned in the image map)
- `0x0000..0x03FF` (boot/config candidate)

## 3) What to run for runtime evidence (compact)

For each target function, run compact traces on both images and compare XDATA write summaries:

```bash
python3 scripts/firmware_execution_sandbox.py run-function --firmware '90CYE03_19_DKS.PZU' --addr 0x55AD --max-steps 1200
python3 scripts/firmware_execution_sandbox.py run-function --firmware 'HVO_YYYYMMDD.PZU' --addr 0x55AD --max-steps 1200
```

Repeat for:
- `0x5602`
- `0x5935`
- `0x5A7F`

## 4) Evidence patterns that would support 1-relay vs 8-output config split

### Stronger supporting evidence
- HVO run shows reduced or absent 8-slot write pattern at `0x36F2..0x36F9` while DKS shows full 8-slot staging.
- Candidate bitmask table differs from `01 02 04 08 10 20 40 80` to a narrower mask model (or callsites no longer consume 8-bit helper).
- Hub code blocks (`0x55AD/0x5602/0x5935`) diverge with aligned behavior differences in XDATA writes.

### Not sufficient alone
- Single-byte random differences without runtime corroboration.
- Differences in non-aligned or FF-heavy ranges when image layout compatibility is unknown.

## 5) Reporting discipline

When documenting results:
- label findings as `static_code`, `emulation_observed`, or `hypothesis`.
- do **not** claim RS-485 byte format from this comparison.
- do **not** claim exact relay physical mapping without bench correlation.
