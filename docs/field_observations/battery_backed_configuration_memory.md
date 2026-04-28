# Battery-backed configuration/settings memory (field observations)

## Evidence classification
- **field_observed**: The user reports the прибор has settings memory that depends on battery support.
- **field_observed**: With depleted battery and full power removal, settings may be lost.
- **field_observed**: Settings are configured from front-panel keyboard/menu.
- **field_observed**: Menu includes configuration of шлейф type/logic, zoning, loop count, detector count, zones, external modules, module type (example: System Sensor M201E), and module address.
- **field_observed**: External modules are interchangeable and are not reprogrammed per installation.

## Conservative interpretation for firmware work
- **hypothesis**: PZU firmware likely contains logic that reads, validates, and consumes installation-specific configuration.
- **hypothesis**: Installation/object configuration may be stored outside executable code space (battery-backed RAM/NVRAM/external memory).
- **hypothesis**: Early boot loop `0x4100..0x4165` is a strong candidate for initial configuration walk/validation.
- **unknown**: Exact storage technology (internal RAM retention, dedicated NVRAM, external SRAM+battery, etc.).
- **unknown**: Exact record/table format for loops/devices/zones/modules.
- **unknown**: Exact coding used for module types (including M201E) and module addresses.

## Boundaries explicitly preserved
- No claim of exact memory type without hardware proof.
- No claim of exact config table layout without decode/trace proof.
- No claim of exact M201E numeric handling code without direct evidence.

## Implication for ongoing reverse engineering
- Lack of direct display strings in scanned images should **not** be treated as proof that menu-config logic is absent.
- Priority should be reconstruction of config-memory model and config-to-runtime consumption path, starting from boot/config candidates and runtime consumers (`0x55AD/0x5602/0x5935/0x5A7F`).
