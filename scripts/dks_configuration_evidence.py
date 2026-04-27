#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

CSV_FIELDS = [
    "firmware_file",
    "branch",
    "screen_name",
    "device_version",
    "slot",
    "module_label",
    "label_confidence",
    "screen_evidence",
    "code_evidence_status",
    "notes",
]

ROWS = [
    ["ppkp2001 90cye01.PZU", "RTOS_service", "90CYE01", "ППКП-01Ф-20.01", "X03", "MDS", "confirmed_from_screen", "visible X03 МДС", "not_function_level_confirmed", "MDS visible as separate module"],
    ["ppkp2001 90cye01.PZU", "RTOS_service", "90CYE01", "ППКП-01Ф-20.01", "X04", "PVK", "confirmed_from_screen", "visible X04 ПВК", "not_function_level_confirmed", "PVK visible as separate module"],
    ["ppkp2001 90cye01.PZU", "RTOS_service", "90CYE01", "ППКП-01Ф-20.01", "X05", "MASH", "confirmed_from_screen", "visible X05 МАШ", "not_function_level_confirmed", "MASH visible"],
    ["ppkp2001 90cye01.PZU", "RTOS_service", "90CYE01", "ППКП-01Ф-20.01", "X06", "MASH", "confirmed_from_screen", "visible X06 МАШ", "not_function_level_confirmed", "second MASH visible"],
    ["90CYE02_27 DKS.PZU", "90CYE_shifted_DKS", "90CYE02", "ППКП-01Ф-27.00", "X03", "MDS", "confirmed_from_screen", "visible X03 МДС", "not_function_level_confirmed", "MDS visible"],
    ["90CYE02_27 DKS.PZU", "90CYE_shifted_DKS", "90CYE02", "ППКП-01Ф-27.00", "X04", "MDS", "confirmed_from_screen", "visible X04 МДС", "not_function_level_confirmed", "MDS visible"],
    ["90CYE02_27 DKS.PZU", "90CYE_shifted_DKS", "90CYE02", "ППКП-01Ф-27.00", "X05", "MDS", "probable_from_screen", "visible label appears МДС", "not_function_level_confirmed", "photo slightly unclear"],
    ["90CYE02_27 DKS.PZU", "90CYE_shifted_DKS", "90CYE02", "ППКП-01Ф-27.00", "X06", "MDS_or_MAS", "uncertain_from_screen", "label unclear", "not_function_level_confirmed", "do not overclaim"],
    ["90CYE02_27 DKS.PZU", "90CYE_shifted_DKS", "90CYE02", "ППКП-01Ф-27.00", "X07", "MZK_or_PZK", "uncertain_from_screen", "label unclear", "not_function_level_confirmed", "do not overclaim"],
    ["90CYE02_27 DKS.PZU", "90CYE_shifted_DKS", "90CYE02", "ППКП-01Ф-27.00", "X08", "MZK_or_PZK", "uncertain_from_screen", "label unclear", "not_function_level_confirmed", "do not overclaim"],
    ["90CYE03_19_DKS.PZU", "90CYE_DKS", "90CYE03", "ППКП-01Ф-19.02", "X03", "MDS", "confirmed_from_screen", "visible X03 МДС", "not_function_level_confirmed", "MDS visible as separate module"],
    ["90CYE03_19_DKS.PZU", "90CYE_DKS", "90CYE03", "ППКП-01Ф-19.02", "X04", "unknown_MSHS_like", "uncertain_from_screen", "label looks like МШС/МЩС", "not_function_level_confirmed", "do not overclaim"],
    ["90CYE03_19_DKS.PZU", "90CYE_DKS", "90CYE03", "ППКП-01Ф-19.02", "X05", "unknown_MEK_like", "uncertain_from_screen", "label looks like МЭК/МЕК", "not_function_level_confirmed", "do not overclaim"],
    ["90CYE03_19_DKS.PZU", "90CYE_DKS", "90CYE03", "ППКП-01Ф-19.02", "X06", "MUP", "confirmed_from_screen", "visible X06 МУП", "not_function_level_confirmed", "MUP visible as separate module"],
    ["90CYE03_19_DKS.PZU", "90CYE_DKS", "90CYE03", "ППКП-01Ф-19.02", "X07", "PVK", "confirmed_from_screen", "visible X07 ПВК", "not_function_level_confirmed", "PVK visible as separate module"],
    ["90CYE04_19_DKS.PZU", "90CYE_DKS", "90CYE04", "ППКП-01Ф-19.02", "X03", "MDS", "confirmed_from_screen", "visible X03 МДС", "not_function_level_confirmed", "MDS visible as separate module"],
    ["90CYE04_19_DKS.PZU", "90CYE_DKS", "90CYE04", "ППКП-01Ф-19.02", "X04", "unknown_MSHS_like", "uncertain_from_screen", "label unclear", "not_function_level_confirmed", "do not overclaim"],
    ["90CYE04_19_DKS.PZU", "90CYE_DKS", "90CYE04", "ППКП-01Ф-19.02", "X05", "unknown_MEK_like", "uncertain_from_screen", "label unclear", "not_function_level_confirmed", "do not overclaim"],
    ["90CYE04_19_DKS.PZU", "90CYE_DKS", "90CYE04", "ППКП-01Ф-19.02", "X06", "MUP", "confirmed_from_screen", "visible X06 МУП", "not_function_level_confirmed", "MUP visible as separate module"],
    ["90CYE04_19_DKS.PZU", "90CYE_DKS", "90CYE04", "ППКП-01Ф-19.02", "X07", "PVK", "confirmed_from_screen", "visible X07 ПВК", "not_function_level_confirmed", "PVK visible as separate module"],
]


def generate_csv() -> None:
    out = DOCS / "dks_real_configuration_evidence.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_FIELDS)
        writer.writerows(ROWS)


def generate_md() -> None:
    out = DOCS / "dks_real_configuration_evidence.md"
    statuses_common = "Соединение 1/2 = НОРМА; КОРПУС = ЗАКРЫТ; ПИТАНИЕ ОСН./РЕЗ. = НОРМА"
    rows = [
        {
            "firmware_file": "ppkp2001 90cye01.PZU",
            "screen_device_name": "90CYE01 / ППКП-01Ф-20.01",
            "hmi_version": "ППКП-01Ф-20.01",
            "module_slots": "X03=МДС; X04=ПВК; X05=МАШ; X06=МАШ",
            "visible_statuses": statuses_common + "; ШЛЕЙФ 1=НОРМА; ШЛЕЙФ 2..4 visible",
            "visible_objects": "none on this screen",
            "confirmed_from_screen": "MDS/PVK as separate modules; two MASH modules; loop status layer visible",
            "probable_interpretation": "loop and module health are reflected in runtime/config tables",
            "unknowns": "exact handler function addresses remain unknown without code evidence",
            "notes": "Config-level confirmation only; function-level conclusions remain code-bound.",
        },
        {
            "firmware_file": "90CYE02_27 DKS.PZU",
            "screen_device_name": "90CYE02 / ППКП-01Ф-27.00",
            "hmi_version": "ППКП-01Ф-27.00",
            "module_slots": "X03=МДС; X04=МДС; X05≈МДС; X06≈МДС/МАС; X07≈МЗК/ПЗК; X08≈МЗК/ПЗК",
            "visible_statuses": statuses_common,
            "visible_objects": "90SAE01AA005; 90SAE01AA006; 90SAE06AA002; 90SAE06AA003; 90SAE02AA001; 90SAE05AA007; 90SAE05AA008; 90SAE15AA003; 90SAE15AA004",
            "confirmed_from_screen": "multiple MDS-like module slots; object-level equipment status layer exists",
            "probable_interpretation": "90SAE object tags are engineering/fire automation objects",
            "unknowns": "exact meaning of each 90SAE tag and uncertain slot labels",
            "notes": "Do not overclaim uncertain labels; config-level evidence only.",
        },
        {
            "firmware_file": "90CYE03_19_DKS.PZU",
            "screen_device_name": "90CYE03 / ППКП-01Ф-19.02",
            "hmi_version": "ППКП-01Ф-19.02",
            "module_slots": "X03=МДС; X04≈МШС/МЩС; X05≈МЭК/МЕК; X06=МУП; X07=ПВК",
            "visible_statuses": statuses_common + "; ШЛЕЙФ 1..3=НОРМА; ШЛЕЙФ 4..8 visible",
            "visible_objects": "not visible on this frame",
            "confirmed_from_screen": "MDS/MUP/PVK are separate modules; multiple shleif statuses visible",
            "probable_interpretation": "module health and loop states likely feed runtime state/event tables",
            "unknowns": "X04/X05 exact labels unclear; no automatic function-address proof",
            "notes": "MUP remains separate from MVK unless code evidence links them.",
        },
        {
            "firmware_file": "90CYE04_19_DKS.PZU",
            "screen_device_name": "90CYE04 / ППКП-01Ф-19.02",
            "hmi_version": "ППКП-01Ф-19.02",
            "module_slots": "X03=МДС; X04≈МШС/МЩС; X05≈МЭК/МЕК; X06=МУП; X07=ПВК",
            "visible_statuses": statuses_common + "; ШЛЕЙФ 1..3=НОРМА; ШЛЕЙФ 4..8 visible",
            "visible_objects": "not visible on this frame",
            "confirmed_from_screen": "MDS/MUP/PVK are separate modules; multiple shleif statuses visible",
            "probable_interpretation": "module health and loop states likely feed runtime state/event tables",
            "unknowns": "X04/X05 exact labels unclear; no automatic function-address proof",
            "notes": "MDS remains separate from generic input-board logic unless code evidence links them.",
        },
    ]

    lines = [
        "# Real DKS configuration evidence (repository firmware mapping)",
        "",
        "Date: 2026-04-27 (UTC).",
        "",
        "## Scope",
        "",
        "- Evidence source: manually transcribed field HMI/configuration screenshots from real DKS devices.",
        "- Firmware mapping: screenshots correspond to firmware files present in this repository.",
        "- Scope boundary: configuration/HMI evidence confirms module presence at device/config level.",
        "- Scope boundary: function handler addresses and exact code semantics remain code-evidence dependent.",
        "",
        "## Mapping table",
        "",
        "| firmware_file | screen_device_name | hmi_version | module_slots | visible_statuses | visible_objects | confirmed_from_screen | probable_interpretation | unknowns | notes |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]

    for row in rows:
        lines.append(
            "| {firmware_file} | {screen_device_name} | {hmi_version} | {module_slots} | {visible_statuses} | {visible_objects} | {confirmed_from_screen} | {probable_interpretation} | {unknowns} | {notes} |".format(**row)
        )

    lines.extend(
        [
            "",
            "## Related repository firmware without direct screenshot in this evidence pack",
            "",
            "- `90CYE03_19_2 v2_1.PZU` and `90CYE04_19_2 v2_1.PZU` are related files in the repository.",
            "- No direct screenshot is attached here for those v2_1 files, so identical configuration is **not** asserted.",
            "",
            "## Machine-readable source",
            "",
            "- `docs/dks_real_configuration_evidence.csv`",
        ]
    )

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    generate_csv()
    generate_md()
    print("Generated: docs/dks_real_configuration_evidence.csv")
    print("Generated: docs/dks_real_configuration_evidence.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
