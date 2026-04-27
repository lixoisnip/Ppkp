# Project-guided enum/delay/interlock static analysis

## Scope
Project-constrained static search for enum/state terms and aerosol timing/interlock logic.

## 30-second delay support
Static support is **present at medium confidence** around `0x6833` in 90CYE_DKS (manual_decompile + prior chain traces). Exact timer base (ticks/divider) remains unresolved.

## Door-open -> auto-disabled / manual behavior
Strongest candidates: `0x728A` (mode split gate) and `0x84A6` (upstream interlock gate). Evidence remains static/manual-decompile and not runtime-confirmed.

## Strongest auto/manual XDATA flags
`0x30E7`, `0x30E9`, `0x315B`, `0x3181` remain the strongest clustered mode/status bytes; exact bit semantics remain partially unresolved.

## АН/АУ/АО output visibility
Static evidence supports separated output candidate classes, but exact terminal/object mapping remains hypothesis. AO is most directly tied to mode-path gating, while AN/AU are prestart warning candidates.

## Enum value linkage quality
Project terms can now be linked to specific compare-value candidates with improved traceability, but numeric semantics remain confidence-capped unless reinforced by deeper static branch-byte extraction or bench traces.
