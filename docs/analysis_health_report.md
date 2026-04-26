# Analysis health report

Дата проверки: 2026-04-26 (UTC).

## Объём контрольной проверки

- Найдено `.PZU` файлов: **10**.
- Выполнен smoke-прогон через `python3 scripts/run_analysis_smoke_test.py`.
- Проверена компиляция Python-скриптов: `python3 -m py_compile scripts/*.py`.
- Результаты запуска записаны в `docs/analysis_smoke_test_results.csv`.

## Глобальные скрипты (all_firmwares)

- `scripts/validate_pzu.py`
- `scripts/firmware_manifest.py`
- `scripts/family_matrix.py`
- `scripts/xdata_xref.py`
- `scripts/disasm_8051.py`
- `scripts/call_xref.py`
- `scripts/basic_block_map.py`
- `scripts/function_map.py`
- `scripts/string_index.py`

## Специализированные скрипты только для A03/A04

- `scripts/a03_a04_packet_builder_candidates.py`
- `scripts/extract_function_trace.py`
- `scripts/extract_call_neighborhood.py`
- `scripts/extract_pipeline_chain_trace.py`
- `scripts/find_packet_window_writers.py`
- `scripts/find_a03_analogs_for_a04_writers.py`

## Итог запуска

- Всего команд smoke-теста: **16**.
- Успешно: **16**.
- Ошибок: **0**.

### Какие артефакты создаются/обновляются

- Глобальные артефакты: `docs/firmware_manifest.json`, `docs/firmware_inventory.csv`, `docs/vector_entrypoints.csv`, `docs/firmware_family_matrix.csv`, `docs/xdata_xref.csv`, `docs/xdata_xref_detailed.csv`, `docs/xdata_confirmed_access.csv`, `docs/dptr_pointer_args.csv`, `docs/code_table_candidates.csv`, `docs/disassembly_index.csv`, `docs/call_xref.csv`, `docs/call_xref_legacy.csv`, `docs/call_targets_summary.csv`, `docs/basic_block_map.csv`, `docs/function_map.csv`, `docs/string_index.csv`.
- Специализированные артефакты A03/A04: `docs/a03_a04_packet_builder_candidates.csv`, `docs/a03_a04_top_packet_function_trace.csv`, `docs/a03_a04_packet_call_neighborhood.csv`, `docs/a03_a04_packet_pipeline_chain_trace.csv`, `docs/a03_a04_packet_window_writers.csv`, `docs/a03_analogs_for_a04_packet_writers.csv`, `docs/a03_analogs_for_a04_packet_writers.md`.

## Ограничения и честные границы применимости

1. Скрипты A03/A04-ветки **нельзя** считать универсальными для всех прошивок; они жёстко ориентированы на `A03_26.PZU` и `A04_28.PZU` (либо на их feature-ветку `A03_A04`).
2. Часть глобальных скриптов использует цепочку зависимостей от ранее сгенерированных CSV (например call/function/basic-block слои), поэтому воспроизводимость обеспечивается корректным порядком запуска в smoke-тесте.
3. Проверка smoke-теста подтверждает запускоспособность и консистентность артефактов, но не является доказательством полноты реверса или корректности каждой гипотезы роли функций.

## Что нужно сделать перед продолжением реверса

1. Продолжать реверс только после «чистого» smoke-теста (без fail-строк в `docs/analysis_smoke_test_results.csv`).
2. При добавлении нового аналитического скрипта сразу дополнять:
   - `scripts/run_analysis_smoke_test.py`;
   - `docs/script_scope_matrix.csv`;
   - при необходимости раздел `Analysis verification` в `README.md`.
3. Перед глубокими выводами по packet-пайплайну всегда сверяться с актуальными артефактами: `function_map`, `basic_block_map`, `call_xref`, `xdata_confirmed_access`.
