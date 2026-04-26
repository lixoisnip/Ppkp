# Next reverse milestone plan (major step)

## Chosen branch

**RTOS_service** (scoped as the next large milestone).

Why this branch:
- Highest global pipeline density in `global_packet_pipeline_mining.md` (dispatcher/service + reader/writer + hub signals).
- Multi-file runtime/service surface gives more chain options for broad progress, not only local A03/A04 hypotheses.

Main risk:
- `RTOS_service` contains files with checksum errors, so confidence for cross-file conclusions is reduced and must stay scoped/experimental until validated.

## Priority functions for manual/static reverse (3–5)

1. `ppkp2001 90cye01.PZU:0x758B` — top dispatcher/service + writer/read aggregate candidate.
2. `ppkp2001 90cye01.PZU:0x53E6` — very strong runtime reader/service center.
3. `ppkp2012 a01.PZU:0x5436` — stable cross-file analog of service/dispatcher core.
4. `ppkp2012 a01.PZU:0x75F7` — high packet/service + table/runtime evidence.
5. `ppkp2019 a02.PZU:0x57DB` — third-image corroboration point for chain stability.

## CSV and artifacts to use in this milestone

Primary:
- `docs/global_packet_pipeline_candidates.csv`
- `docs/global_packet_pipeline_chains.csv`
- `docs/function_map.csv`
- `docs/call_xref.csv`
- `docs/xdata_confirmed_access.csv`
- `docs/xdata_map_by_branch.csv`
- `docs/disassembly_index.csv`
- `docs/code_table_candidates.csv`
- `docs/string_index.csv`

Support/scoping:
- `docs/branch_comparison_summary.csv`
- `docs/global_packet_pipeline_mining.md`

## Hypotheses to verify

1. The RTOS-service pipeline has one/two dispatch cores that feed shared xdata state workers, not isolated handlers.
2. `0x758B/0x53E6/0x5436` are chain anchors that repeatedly appear as caller or core nodes in top-ranked chains.
3. Callee-level functions connected to these cores split into at least two roles: writer-like state updates and table/string runtime helpers.
4. The same functional chain motif exists across 2001/2012/2019 images (with shifted addresses but preserved role topology).

## Runtime probes needed after static stage

1. Branch-scoped call-sequence probe around top chains: `caller -> core -> callee` for RTOS_service only.
2. XDATA mutation probe around RTOS cluster windows from `xdata_map_by_branch.csv`:
   - `0x6406-0x6422`
   - `0x759C-0x75AE`
   - `0x769C-0x76AA`
3. Side-by-side trace capture for one high-confidence image vs one checksum-error image to measure divergence.

## Success criteria for this milestone

1. At least **3 validated chain families** in RTOS_service with concrete `caller -> core -> callee` evidence (static + runtime-consistent).
2. At least **3 functions upgraded** from medium/experimental to stable scoped confidence for RTOS_service.
3. A clear split between:
   - **global evidence** (branch-wide reproducible), and
   - **RTOS_service-scoped evidence** (not generalized outside scope).
4. A finalized shortlist of concrete next reverse targets (minimum 5 addresses) for deeper semantic decomp/reconstruction.

## Scope guardrails

- This milestone is **not** packet format reconstruction proof.
- A03/A04 packet-window findings remain scoped and are not used as universal criteria.
- Any conclusions derived mainly from checksum-error files are explicitly marked as lowered-confidence/experimental.
