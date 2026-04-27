# DKS packet/export reconstruction (v1)

Generated: 2026-04-27 09:45:55Z

## Core answer: what is `0x5A7F`?
Current best fit: **packet/export bridge helper** with high fan-in callsites; not yet proven as full packet builder and not proven as final sink in isolation.

## Functions preparing data before `0x5A7F`
- `0x497A`, `0x737C`, `0x84A6`, `0x728A`, `0x6833` appear in pre-export adjacency and call matrices.
- DPTR/ACC exact staging is still partially unresolved from currently indexed windows and remains a follow-up item.

## Likely packet-context XDATA
- Selector/context: `0x31BF`.
- Packet-adjacent cluster: `0x364B`, `0x36D3..0x36FD`, plus neighbor `0x3640`.

## Best current packet format hypothesis
See `docs/dks_packet_format_hypothesis.csv`; model currently uses selector + state cluster + mode flags + output-start marker candidates.

## Unknowns
- Exact packet byte layout and ordering.
- Whether `0x5A7F` directly emits transport frame or only resolves pointers/field bridge context.
- Required bench capture points for proving framing boundaries.
