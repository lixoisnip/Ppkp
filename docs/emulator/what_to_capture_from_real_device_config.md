# What to capture from a real device to reconstruct configuration model

## Goal
Collect real-world evidence that can be correlated with firmware traces to identify where and how configuration records are stored and consumed.

## Highest-value captures
1. **Menu screenshots/photos** for pages that configure:
   - шлейф type;
   - шлейф logic;
   - zoning/зонирование;
   - loop count;
   - detector count;
   - zones;
   - external modules;
   - module type (including M201E if present);
   - module address.
2. **List of configured loops** and detector count per loop.
3. **Zone mapping table** (which loop/device belongs to which zone).
4. **External module inventory with addresses** (e.g., M201E instances and their configured addresses).
5. **Output/action mapping table** (event/zone -> relay/output action), if menu exposes it.

## Battery-retention behavior evidence
1. Record exact procedure and timestamps:
   - configure settings;
   - remove AC/power;
   - keep/remove battery;
   - reapply power.
2. Note which settings survive and which reset.
3. Capture menu pages both **before** and **after** battery-loss test.

## Memory-forensics-friendly artifacts (if possible)
1. Before/after binary dumps of configuration storage (same device, controlled one-field edit).
2. Two dumps that differ by exactly one menu change (e.g., module address +1).
3. Photos of PCB area containing:
   - battery-backed SRAM/NVRAM/RTC-related ICs;
   - backup battery/supercap path;
   - markings and part numbers.

## Minimal metadata to include with every capture
- Device model and board revision.
- Firmware label/file if known.
- Date/time of capture.
- Exact menu path used.
- Which single field was changed (for diff-based inference).

## Important cautions
- Do not infer numeric type codes from labels alone.
- Do not assume address field size without dump/trace evidence.
- Keep one-variable-at-a-time edits to avoid ambiguous diffs.
