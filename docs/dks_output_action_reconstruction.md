# DKS output/action reconstruction (v1)

Generated: 2026-04-27 09:45:55Z

## Core answers
- `XDATA[DPTR] = 0x04` is currently best modeled as **output-start marker / command-code candidate**, not physically named output type.
- `0x597F` most likely guards branch admission (mask-like, `A & 0x07` hypothesis).
- `0x7922` behaves as state-table/service reader feeding start-path context.
- `0x7DC2` looks like downstream transition finalizer before packet/export bridge `0x5A7F`.

## Physical semantics status
Static evidence is **insufficient** to claim direct mapping to MUP/MVK/GOA/valve/siren classes.
All physical output naming remains hypothesis pending bench capture.

## Artifacts
- `docs/dks_output_action_matrix.csv`
- `docs/dks_output_start_path_trace.csv`
- `docs/dks_output_action_bench_tests.csv`
