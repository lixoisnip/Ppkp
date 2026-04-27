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
- docs/family_module_architecture_map.md — issue #52 large milestone: full cross-family comparison and shared module architecture map.
- docs/firmware_module_architecture_comparison.md — cross-firmware architecture comparison of CPU core, keyboard/display, MASH, MVK, input boards, MDS, MUP, aerosol/water/APS-specific logic.
- docs/dks_real_configuration_evidence.md — real DKS HMI/configuration evidence mapping repository firmware files to visible module slots MDS/MUP/PVK/MASH, shleif status and object-status screens.
- docs/dks_real_configuration_evidence.csv — machine-readable module slot evidence from real DKS screenshots.
- docs/dks_module_deep_trace_analysis.md — deep-trace mapping of screen-confirmed DKS module slots MDS/MUP/PVK/MASH to code-level handler candidates.
- docs/dks_module_deep_trace_candidates.csv — function-level candidate evidence for screen-confirmed DKS modules.
- docs/dks_module_slot_summary.csv — per-slot module resolution status.
- docs/manual_dks_module_decompile.md — semi-manual pseudocode reconstruction of DKS module candidates 0x497A, 0x613C, 0x673C, 0x758B, 0x53E6, 0xAB62.
- docs/manual_dks_module_decompile_summary.csv — role/confidence summary for manually reconstructed DKS module candidates.
- docs/manual_dks_module_pseudocode.csv — pseudocode skeletons for selected DKS module candidate functions.
- docs/manual_dks_downstream_decompile.md — semi-manual reconstruction of downstream 90CYE_DKS functions 0x5A7F, 0x737C, 0x84A6, 0x7922, 0x597F, 0x7DC2.
- docs/manual_dks_downstream_decompile_summary.csv — role/confidence summary for downstream DKS functions.
- docs/manual_dks_downstream_pseudocode.csv — pseudocode skeletons for downstream DKS functions.
- docs/dks_xdata_lifecycle_analysis.md — lifecycle reconstruction for key DKS XDATA state/mode/packet context addresses.
- docs/dks_xdata_lifecycle_matrix.csv — address-level XDATA lifecycle matrix.
- docs/dks_xdata_function_roles.csv — function-to-XDATA role mapping for DKS chain functions.
- docs/dks_xdata_bench_probe_plan.csv — runtime probe plan for validating XDATA state/mode/output hypotheses.
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
## DKS reconstruction milestone v1

Новые артефакты большого этапа DKS:
- `docs/dks_enum_state_reconstruction.md`, `docs/dks_enum_state_matrix.csv`, `docs/dks_enum_state_transition_candidates.csv`
- `docs/dks_packet_export_reconstruction.md`, `docs/dks_packet_export_callsite_matrix.csv`, `docs/dks_packet_context_xdata_matrix.csv`, `docs/dks_packet_format_hypothesis.csv`
- `docs/dks_output_action_reconstruction.md`, `docs/dks_output_action_matrix.csv`, `docs/dks_output_start_path_trace.csv`, `docs/dks_output_action_bench_tests.csv`
- `docs/dks_module_handler_attribution.md`, `docs/dks_module_handler_attribution_matrix.csv`, `docs/dks_module_unresolved_handlers.csv`
- `docs/dks_firmware_technical_reconstruction_v1.md`, `docs/dks_reconstruction_confidence_dashboard.csv`, `docs/dks_remaining_unknowns.csv`, `docs/dks_next_iteration_plan.csv`
- `docs/dks_runtime_validation_plan_v1.md`, `docs/dks_runtime_validation_matrix.csv`
- `docs/dks_xdata_watchlist_v2.csv`, `docs/dks_function_watchlist_v2.csv`
- `docs/dks_packet_capture_schema.csv`, `docs/dks_io_capture_schema.csv`
- `docs/dks_bench_result_import_template.csv`, `docs/dks_validation_confidence_uplift.csv`
- `docs/dks_v1_to_v2_validation_roadmap.md`

Для полного прогона v1:
```bash
python3 scripts/dks_enum_state_reconstructor.py
python3 scripts/dks_packet_export_reconstructor.py
python3 scripts/dks_output_action_reconstructor.py
python3 scripts/dks_module_handler_attribution.py
python3 scripts/dks_final_techdoc_builder.py
python3 scripts/dks_runtime_validation_planner.py
python3 scripts/run_analysis_smoke_test.py
```

## Cross-family static reconstruction milestone v1

Добавлен большой статический этап для межсемейного сравнения (без переноса DKS-семантики «по умолчанию»):

- `docs/cross_family_function_analogs.md`, `docs/cross_family_function_analogs.csv`, `docs/cross_family_unmatched_dks_functions.csv`
- `docs/cross_family_xdata_schema_map.md`, `docs/cross_family_xdata_schema_map.csv`, `docs/cross_family_xdata_unresolved.csv`
- `docs/cross_family_packet_output_comparison.md`, `docs/cross_family_packet_bridge_candidates.csv`, `docs/cross_family_output_action_candidates.csv`, `docs/cross_family_packet_format_variants.csv`
- `docs/cross_family_enum_state_comparison.md`, `docs/cross_family_enum_state_matrix.csv`, `docs/cross_family_enum_state_divergences.csv`
- `docs/cross_family_module_semantics.md`, `docs/cross_family_module_semantics_matrix.csv`, `docs/cross_family_module_semantics_unknowns.csv`
- `docs/cross_family_static_reconstruction_v1.md`, `docs/cross_family_confidence_dashboard.csv`, `docs/cross_family_remaining_unknowns.csv`, `docs/cross_family_next_static_plan.csv`

Скрипты:
- `scripts/cross_family_function_analog_mapper.py`
- `scripts/cross_family_xdata_schema_mapper.py`
- `scripts/cross_family_packet_output_comparator.py`
- `scripts/cross_family_enum_state_comparator.py`
- `scripts/cross_family_module_semantics_reporter.py`
- `scripts/cross_family_static_reconstruction_builder.py`

Запуск полного milestone:
```bash
python3 scripts/cross_family_function_analog_mapper.py
python3 scripts/cross_family_xdata_schema_mapper.py
python3 scripts/cross_family_packet_output_comparator.py
python3 scripts/cross_family_enum_state_comparator.py
python3 scripts/cross_family_module_semantics_reporter.py
python3 scripts/cross_family_static_reconstruction_builder.py
python3 scripts/run_analysis_smoke_test.py
```

## Cross-family static deepening milestone v1.1

Добавлен следующий углублённый статический этап (с разделением семейств и без слепого переноса DKS-семантики):

- `docs/a03_a04_packet_bridge_deepening.md`
- `docs/shifted_v2_xdata_offset_validation.md`
- `docs/rtos_service_chain_decompile_v1.md`
- `docs/cross_family_static_deepening_v1.md`

Новые скрипты:
- `scripts/a03_a04_packet_bridge_deepener.py`
- `scripts/shifted_v2_xdata_offset_validator.py`
- `scripts/rtos_service_chain_decompiler.py`
- `scripts/cross_family_static_deepening_builder.py`

Запуск v1.1:
```bash
python3 scripts/a03_a04_packet_bridge_deepener.py
python3 scripts/shifted_v2_xdata_offset_validator.py
python3 scripts/rtos_service_chain_decompiler.py
python3 scripts/cross_family_static_deepening_builder.py
python3 scripts/run_analysis_smoke_test.py
```

## Project scan extraction evidence

Generated extraction layer (project-level evidence, separated from static/decompile code evidence):

- `docs/extracted/project_scan_report_v0_1.md`
- `docs/extracted/ppkp_devices.yaml`
- `docs/extracted/project_to_firmware_linkage.csv`
- `docs/extracted/firmware_search_targets.md`
- `docs/extracted/states_enum_candidates.md`
