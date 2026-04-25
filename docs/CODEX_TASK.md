# CODEX_TASK: PZU firmware analysis refresh

Цель: обновить артефакты анализа для всех `.PZU` из корня репозитория.

## Шаги

1. Проверить все `.PZU` через `scripts/validate_pzu.py`.
2. Сгенерировать `docs/firmware_manifest.json` и `docs/firmware_inventory.csv` через `scripts/firmware_manifest.py`.
3. Сгенерировать `docs/firmware_family_matrix.csv` через `scripts/family_matrix.py`.
4. Сгенерировать `docs/xdata_xref.csv` через `scripts/xdata_xref.py`.
5. Обновить `README.md`, добавив полный список доступных `.PZU`.
6. Не изменять содержимое `.PZU`.

## Команды

```bash
python3 scripts/validate_pzu.py
python3 scripts/firmware_manifest.py
python3 scripts/family_matrix.py
python3 scripts/xdata_xref.py
```
