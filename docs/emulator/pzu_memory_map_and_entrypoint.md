# PZU memory map and entrypoint notes

- `.PZU` files are treated as Intel HEX-like code sources.
- Current hypothesis range is approximately `0x4000..0xBFFF`.
- Reset/vector hypothesis: entry logic starts at `0x4000`, often with jump towards `0x4100`.

## Missing low-ROM risk
Code below `0x4000` is absent in available PZU artifacts; helpers/drivers there may be required for real boot/runtime behavior.

## Policy for low-ROM calls
- If execution needs `<0x4000`, mark as **unsupported** explicitly.
- Stubs may be used only as explicit stubs with visible trace labeling.
- Never report silent success for unresolved low-ROM functionality.

## Implication
- Function-level traces are still useful for local dataflow evidence.
- Full-firmware emulation must account for entrypoint assumptions and missing low ROM dependencies.
