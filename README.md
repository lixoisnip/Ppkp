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
- Предыдущий файл анализа/журнал: `PZU_ANALYSIS.md`

## Исходные образы

- `A03_26.PZU`
- `A04_28.PZU`
- `ppkp2012 a01.PZU`
- `ppkp2019 a02.PZU`

> Важно: `.PZU` файлы в репозитории не редактируются, используются только для анализа.
