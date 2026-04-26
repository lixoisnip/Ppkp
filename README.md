# Ppkp — reverse engineering база по ППКП-01Ф

Репозиторий для поэтапного реверс-инжиниринга прошивок ППКП-01Ф и подготовки архитектуры совместимой новой прошивки.

## Быстрый старт

1. Начать с основной техбазы: `docs/ppkp_firmware_reverse_rev2.md`.
2. Затем перейти к специализированным артефактам ниже.
3. Для воспроизводимого сравнения образов использовать `scripts/compare_pzu_variants.py`.

## Карта документации

- Основной документ (ред.2): `docs/ppkp_firmware_reverse_rev2.md`
- Схема object record: `docs/object_record_schema.md`
- Типы пакетов и builders: `docs/packet_types.md`
- Карта вариантных окон A03/A04: `docs/variant_windows_map.md`
- Сценарии стендового replay: `docs/replay_scenarios.md`
- Карта XDATA (CSV): `docs/xdata_map.csv`
- `docs/disassembly_index.csv` — минимальный reachable 8051 disassembly index.
- `docs/call_xref_legacy.csv` — legacy byte-scan call reference for comparison.
- `docs/function_map.csv` — preliminary reachable function map with XDATA/MOVC evidence.
- `docs/basic_block_map.csv` — preliminary basic block map separating function entries from internal branch targets.
- `docs/a03_a04_packet_builder_candidates.csv` — A03/A04 packet builder candidate ranking.
- `docs/a03_a04_top_packet_function_trace.csv` — static trace of top A03/A04 packet-builder candidates.
- `docs/a03_a04_packet_call_neighborhood.csv` — local call-neighborhood around A03/A04 top packet-builder candidates.
- docs/a03_a04_packet_call_neighborhood_depth2.csv — depth=2 call-neighborhood around A04:0x89C9 and A03:0x8A2E.
- docs/a03_a04_packet_pipeline_chain_trace.csv — ordered static trace for A03/A04 packet pipeline candidate chains.
- docs/a03_a04_packet_window_writers.csv — A03/A04 functions with confirmed writes into packet-window 0x5003..0x5010.
- docs/a03_analogs_for_a04_packet_writers.csv — structural A03 analog candidates for A04 packet-window writer functions.
- docs/global_branch_comparison.md — global comparison of firmware branches after smoke-test verification.
- docs/global_packet_pipeline_mining.md — global packet/runtime pipeline candidate mining across all firmware branches.
- docs/rtos_service_pipeline_analysis.md — RTOS_service branch-focused runtime/service pipeline candidate analysis.
- docs/rtos_service_chain_4358_920c_53e6_analysis.md — deep static trace of top RTOS_service candidate chain.
- docs/mash_address_loop_sensor_model.md — preliminary MASH/address-loop sensor model based on IP212-200 / 22051E documentation.
- docs/mash_code_evidence_analysis.md — code-evidence search for MASH/address-loop behaviour based on IP212 sensor documentation.
- docs/mash_handler_deep_trace_analysis.md — deep trace of top MASH/address-loop handler candidate chains.
- docs/module_logic_overview.md — общий отчёт по логике работы модулей (МАШ/МАС/другие), XDATA-очередям/буферам и межветочному сравнению.
- docs/zone_output_logic_analysis.md — zone logic and output-control module candidate analysis.
- docs/zone_output_deep_trace_analysis.md — deep trace of 90CYE_DKS zone-to-output candidate functions.
- docs/state_mode_logic_analysis.md — sensor/zone state and auto/manual extinguishing-output gating analysis.
- docs/auto_manual_gating_deep_trace_analysis.md — branch-specific deep trace of manual/auto gating chain (0x497A→0x737C→0x613C→0x84A6→0x728A→0x6833→0x5A7F).
- docs/runtime_state_machine_reconstruction.md — reconstructed 90CYE_DKS runtime state-machine model from sensor state to zone, auto/manual gating, output and packet/export.
- docs/state_enum_and_techdoc_reconstruction.md — большой оркестраторный отчёт по гипотезам enum/state/mode, output-action map и bench-validation matrix.
- docs/xdata_enum_branch_resolution.md — trace-level XDATA lifecycle and enum branch resolution for 90CYE_DKS state/mode/output logic.
- docs/manual_decompile_0x728A_0x6833.md — manual decompile milestone #47 for mode gate `0x728A` and output-start entry `0x6833`.
- docs/input_board_core_cross_family.md — issue #50 cross-cutting milestone: shared input-board core role and command vocabulary across firmware families.
- docs/module_handler_summary.csv — сводная таблица кандидатов обработчиков модулей по всем веткам.
- Предыдущий файл анализа/журнал: `PZU_ANALYSIS.md`

## Исходные образы

- `90CYE02_27 DKS.PZU`
- `90CYE03_19_2 v2_1.PZU`
- `90CYE03_19_DKS.PZU`
- `90CYE04_19_2 v2_1.PZU`
- `90CYE04_19_DKS.PZU`
- `A03_26.PZU`
- `A04_28.PZU`
- `ppkp2001 90cye01.PZU`
- `ppkp2012 a01.PZU`
- `ppkp2019 a02.PZU`

> Важно: `.PZU` файлы в репозитории не редактируются, используются только для анализа.

## Analysis verification

Для полной контрольной проверки анализа выполните:

```bash
python3 -m py_compile scripts/*.py
python3 scripts/state_enum_and_techdoc_reconstructor.py
python3 scripts/xdata_enum_branch_resolver.py
python3 scripts/run_analysis_smoke_test.py
```

`scripts/run_analysis_smoke_test.py` выполняет smoke-прогон основных глобальных и специализированных A03/A04-скриптов, проверяет их exit-code и наличие ожидаемых выходных артефактов.

Результаты смотреть в:

- `docs/analysis_smoke_test_results.csv`
- `docs/analysis_health_report.md`
- `docs/script_scope_matrix.csv`
