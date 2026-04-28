# Module/output behavior field observation

## Evidence statements

- **field_observed**: modules themselves were not reprogrammed during the observed swaps.
- **field_observed**: a module moved from one прибор to another still operated with the other прибор.
- **field_observed**: one firmware used in ХВО drove only one relay during fire.
- **field_observed**: another firmware used in the main прибор drove 8 outputs during fire.
- **hardware_observed**: modules are physically interchangeable between tested приборs (same hardware module accepted by multiple приборs).

## Conservative interpretation

- **hypothesis**: output-control behavior is likely parameterized by прибор firmware/configuration tables, not only by module-internal logic.
- **hypothesis**: PZU likely contains object/module/output configuration and/or output action mapping that changes fire-response fanout.
- **hypothesis**: table location/format is still unresolved and needs code+trace correlation.

## Explicit non-claims (scope guard)

- This observation does **not** prove RS-485 frame byte layout.
- This observation does **not** prove exact module protocol semantics.
- This observation does **not** prove where display/keypad firmware/text resides.

## Why this matters for current reverse task

Field behavior difference (1 relay vs 8 outputs during fire) with unchanged interchangeable modules is consistent with firmware-side configuration or control-logic divergence in the прибор image(s). Therefore table hunting should prioritize runtime hubs and nearby XDATA/object/output structures in PZU.
