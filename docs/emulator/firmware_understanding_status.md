# Firmware understanding status

## Confirmed
- Reset vector `0x4000` jumps to `0x4100`.
- Boot execution repeatedly stays in `0x4100..0x4165` pointer/init loop under default and zero/self seeds.
- Pointer-to-`0x0200` seeds exit early via `ret_from_entry` near `0x4128`, without reaching later runtime.
- No emulation-observed UART SBUF writes, display outputs, or keypad scan events.

## Probable
- `0x410A..0x4165` is boot config pointer/XDATA table walk, not final runtime scheduler.
- Packet/event logic around `0x55AD/0x5602/0x5A7F` is likely downstream runtime work (function harness evidence).

## Hypothesis
- Runtime scheduler/main loop is likely outside early boot window (candidate ranges include `0x5715..0x5733`, `0x5935..0x593D`).
- UART/RS-485 and display/keypad paths likely require reaching deeper runtime contexts not currently boot-reachable.

## Unknown
- True boot config source for XDATA pointer table (preexisting RAM vs code-copy vs external loader).
- Definitive UART init/TX path and RS-485 direction handling.
- Definitive display/keypad concrete routines and payload encoding.

## Blocked
- Current boot path never crosses the `0x4100..0x4165` boundary in default loop traces.
- CPU subset + scenario context may be insufficient to trigger late init branches from cold boot only.

## Estimated understanding by subsystem
- boot/init: 70%
- runtime scheduler: 25%
- packet/event bridge: 45%
- UART/RS-485: 10%
- display: 10%
- keypad: 10%
- XDATA/config: 35%
- project-level physical architecture: 15%

## Recommended next work (ranked)
1. Pivot from seed brute-force to static+targeted function-context tracing around packet/runtime hubs (`0x55AD`, `0x5602`, `0x5935`) with conservative scenario assumptions.
2. Build targeted reachability attempts from boot toward first call beyond `0x4165` using only evidenced config-source candidates.
3. Expand static SFR/bit-usage correlation around timer/interrupt and serial candidates, then test with minimal context harness runs.
4. Only run at most one new seed-to-`0x415F` and one config-source-follow scenario when justified by static evidence.

> Warning: do **not** overfocus on additional `0x4100` seed variants unless global feature/call maps show no higher-value reachable targets.

## Post-wide-map targeted audit results

- Promising boot/config candidates: none high-confidence yet; 0x6F5C and 0x76E6 showed the most low-XDATA-touch potential in forced-entry traces, but still hypothesis-level without caller-context proof.
- Promising runtime hubs: 0x5A7F (fan-in 142), 0x5935 (fan-in 20), 0x597F (fan-in 17), then 0x55AD/0x5602 as packet-bridge-adjacent probes.
- Prioritized next path: runtime hub emulation with caller-context reconstruction first, then config-source reconstruction from upstream callers; static serial path search continues; bench capture after memory-mapped serial candidate isolation.
- Continue 0x4100 seed brute force? No, not recommended now (except one evidence-driven follow-up if a boot candidate yields direct low-XDATA config-write evidence).
- Updated understanding estimate: boot/config init path 35%, runtime/event hub map 60%, serial transport attribution 20%.

## Module/output configuration evidence

### Field observation summary
- Field reports indicate interchangeable hardware modules across приборs without module reflashing.
- Reported behavior differs by firmware context: one observed setup drives only one relay on fire, another drives 8 outputs on fire.
- This pattern supports firmware/config-side behavior selection rather than module-internal fixed behavior.

### Why interchangeability points to прибор firmware/config
- If module hardware is transferable and remains functional after moving between приборs, persistent module-local programming is less likely to explain major fanout differences.
- A firmware-level object/module/output table (or action dispatch logic) in PZU is a conservative explanation for 1-relay vs 8-output behavior differences.
- Evidence remains correlation-level; exact table format and runtime gating are still unresolved.

### Candidate tables found
- Code table candidate at `0x5984..0x598B`: exact `01 02 04 08 10 20 40 80` bitmask helper sequence in DKS images (`90CYE03_19_DKS.PZU`, `90CYE04_19_DKS.PZU`).
- Runtime XDATA candidate cluster at `0x36ED..0x36FF`, especially `0x36F2..0x36F9` written as an 8-slot sequence by `0x55AD/0x5602` compact traces.
- Global/control candidate bytes around `0x31BF`, plus object/event state candidate range `0x30EA..0x30F9`.
- Broader object/status candidate range `0x36D3..0x36D9` referenced by multiple runtime hubs and downstream handlers.

### What remains unknown
- Exact semantic mapping of fields to loop/module/address/type/status/output numbers.
- Direct physical relay-to-bit mapping and definitive fire-event mapping without bench confirmation.
- Whether low-XDATA boot range `0x0000..0x03FF` is materially involved in this specific behavior split (no diff found among compared DKS images).
- Whether non-DKS `_2 v2_1` images are address-aligned/comparable to DKS at these offsets.

### Next best step
1. Compare against an external ХВО PZU (if available) using the same candidate ranges and function neighborhoods.
2. Run bench capture to correlate real fire events with candidate XDATA transitions (`0x36F2..0x36F9`, `0x36ED..0x36FF`, `0x31BF`).
3. Perform targeted emulation with richer caller context around `0x55AD/0x5602/0x5935/0x5A7F` to stabilize record-field interpretation.

## Project-guided output module configuration status

- Project evidence is now used to separate where output modules are present from where they are not (e.g., 90CYE02 damper outputs vs 90CYE03/04 aerosol-start outputs; MDS retained as discrete-input module under current evidence).
- Code evidence around `0x36F2..0x36F9` and `0x5984..0x598B` is consistent with an 8-output/action structure in the DKS aerosol-role images.
- Exact physical relay/channel mapping remains unconfirmed and is explicitly blocked until terminal documents and bench traces are available.
- RS-485 frame bytes remain unresolved; however, byte-level protocol decoding is not required to show that internal output configuration/action structures exist in firmware.
