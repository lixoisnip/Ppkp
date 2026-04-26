#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

CSV_PATH = DOCS / "supported_sensor_evidence.csv"
MD_PATH = DOCS / "mash_address_loop_sensor_model.md"

CSV_HEADERS = [
    "source",
    "device_type",
    "model",
    "protocol",
    "address_range",
    "features",
    "related_module",
    "confidence",
    "notes",
]

CSV_ROWS = [
    {
        "source": "PDF",
        "device_type": "дымовой адресно-аналоговый извещатель",
        "model": "ИП212-200 22051E",
        "protocol": "System Sensor 200AP / 200+",
        "address_range": "01-159",
        "features": "LED control, smoke chamber, optional remote LED",
        "related_module": "MASH/address loop",
        "confidence": "high for document evidence",
        "notes": "Documented sensor profile from PDF; firmware binding remains hypothesis until code evidence is found.",
    },
    {
        "source": "PDF",
        "device_type": "дымовой адресно-аналоговый извещатель с изолятором",
        "model": "ИП212-200/1 22051EI",
        "protocol": "System Sensor 200AP / 200+",
        "address_range": "01-159",
        "features": "short-circuit isolator, LED control, smoke chamber",
        "related_module": "MASH/address loop",
        "confidence": "high for document evidence",
        "notes": "Documented sensor profile from PDF; firmware binding remains hypothesis until code evidence is found.",
    },
]

MD_CONTENT = """# MASH / address-loop sensor model (IP212-200 family)

## Что документально описано в PDF

PDF описывает адресно-аналоговые дымовые извещатели:

- ИП212-200 22051E;
- ИП212-200/1 22051EI;
- протокол семейства System Sensor 200AP / 200+;
- диапазон адресов 01-159;
- индикацию двумя светодиодами, управляемую со стороны ААПКП;
- у версии ИП212-200/1 встроенный изолятор короткого замыкания;
- тестирование магнитом и дымом.

**Confidence:** high (document evidence from PDF).

## Почему это относится к МАШ / адресному шлейфу

Адресный диапазон 01-159, адресно-аналоговая природа устройств и управление индикацией с панели указывают на модель адресного шлейфа (МАШ): панель циклически опрашивает адреса устройств, получает состояние и формирует события.

**Confidence:** medium (engineering mapping from documented sensor behavior to expected panel architecture).

## Какие признаки нужно искать в прошивке

Ниже — признаки, которые нужно подтверждать именно кодовыми артефактами прошивки A03/A04:

1. цикл по адресам 1..159;
2. опрос адресного устройства;
3. чтение аналогового/дымового значения;
4. статус пожар/норма/неисправность;
5. управление LED;
6. статус/обработка изолятора короткого замыкания;
7. потеря связи с адресом/устройством;
8. постановка события в очередь;
9. передача события дальше (в коммуникационный/пакетный контур).

**Confidence:** medium (target code signatures for next reverse stage).

## Предварительная блок-схема

`ППКП -> МАШ -> адресный шлейф -> ИП212-200/22051E -> состояние -> событие -> передача`

**Confidence:** medium (working architecture hypothesis for code search planning).

## Ограничения текущего этапа

- Это документально подтверждённая модель датчика по PDF.
- Прямая связь с конкретными функциями прошивки пока **hypothesis**.
- Если прямые строки/идентификаторы МАШ/МАС в прошивке не найдены, это нужно фиксировать явно в следующем этапе code evidence.

**Warnings:**

- Этот документ не доказывает полное восстановление протокола.
- Для связки с firmware-функциями обязательно нужны дополнительные code-level свидетельства (xref/disasm/string/xdata/call-chain).
"""


def write_csv() -> None:
    DOCS.mkdir(parents=True, exist_ok=True)
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        writer.writerows(CSV_ROWS)


def write_md() -> None:
    DOCS.mkdir(parents=True, exist_ok=True)
    MD_PATH.write_text(MD_CONTENT, encoding="utf-8")


def main() -> int:
    write_csv()
    write_md()
    print(f"[ok] wrote {CSV_PATH.relative_to(ROOT)}")
    print(f"[ok] wrote {MD_PATH.relative_to(ROOT)}")
    print("[warning] firmware linkage remains hypothesis pending code evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
