#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    enum_rows = [
        {
            "device_scope": "90CYE03/04",
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x84A6",
            "xdata_addr": "0x31BF",
            "enum_value": "0x01",
            "project_term": "Пожар",
            "probable_meaning": "primary fire-class state byte candidate",
            "confidence": "medium",
            "evidence_level": "static_code",
            "downstream_path": "0x84A6->0x728A->0x5A7F",
            "notes": "Static branch and prior enum matrices support fire-class role, numeric semantics still not bench-confirmed.",
        },
        {
            "device_scope": "90CYE01",
            "branch": "RTOS_service",
            "file": "ppkp2001 90cye01.PZU",
            "function_addr": "0x920C",
            "xdata_addr": "unknown",
            "enum_value": "0x03",
            "project_term": "Внимание",
            "probable_meaning": "attention/alarm pre-fire discriminator candidate",
            "confidence": "low",
            "evidence_level": "cross_family_pattern",
            "downstream_path": "0x4358->0x920C->0x53E6",
            "notes": "Constrained by project logic (1 auto detector => attention) but still family-level pattern only.",
        },
        {
            "device_scope": "90CYE03/04",
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x728A",
            "xdata_addr": "0x30E7",
            "enum_value": "0xFF",
            "project_term": "Автоматика отключена",
            "probable_meaning": "manual/disabled sentinel candidate",
            "confidence": "low",
            "evidence_level": "hypothesis",
            "downstream_path": "0x728A->0x597F",
            "notes": "AO indicator mapping remains partial static hypothesis.",
        },
    ]

    delay_rows = [
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x6833",
            "constant_or_pattern": "30|0x1E|30000|0x7530",
            "possible_duration_seconds": "30",
            "timer_context": "aerosol prestart delay candidate before launch path",
            "callers": "0x728A",
            "callees": "0x7922|0x7DC2",
            "xdata_refs": "0x315B|0x3181|0x3640",
            "confidence": "medium",
            "evidence_level": "manual_decompile",
            "notes": "Manual static chain supports 30-second delay candidate; exact tick base unresolved.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE04_19_DKS.PZU",
            "function_addr": "0x6833",
            "constant_or_pattern": "300|3000|6000|15000",
            "possible_duration_seconds": "30",
            "timer_context": "tick-domain equivalent candidates",
            "callers": "0x728A",
            "callees": "0x7922|0x7DC2",
            "xdata_refs": "0x315B|0x3181",
            "confidence": "low",
            "evidence_level": "hypothesis",
            "notes": "Tick conversion unresolved; retained as static search target.",
        },
    ]

    mode_rows = [
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x728A",
            "candidate_role": "auto_manual_split_gate",
            "xdata_refs": "0x30E7|0x30E9|0x315B",
            "mode_flags": "E0|E1|E2-like selector at 0x30E7",
            "branch_context": "manual path tends to skip 0x6833 start entry",
            "related_outputs": "AO candidate + prestart warnings",
            "confidence": "medium",
            "evidence_level": "manual_decompile",
            "notes": "Strongest static function for door/auto disable split.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x84A6",
            "candidate_role": "door_interlock_upstream_gate",
            "xdata_refs": "0x30E9|0x3181",
            "mode_flags": "door_open influence candidate",
            "branch_context": "upstream gate before 0x728A/0x6833",
            "related_outputs": "AN/AU/AO path candidates",
            "confidence": "low",
            "evidence_level": "static_code",
            "notes": "Door-open -> auto-disabled behavior plausible but still needs direct branch-byte proof.",
        },
    ]

    warning_rows = [
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x6833",
            "output_candidate": "warning_output_prestart_1",
            "project_label": "AN_Aerosol_do_not_enter",
            "prestart_or_mode_context": "before GOA launch",
            "xdata_refs": "0x315B|0x3640",
            "downstream_functions": "0x7922|0x7DC2",
            "confidence": "low",
            "evidence_level": "hypothesis",
            "notes": "Separated as candidate output class only; terminal/object map unresolved.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x6833",
            "output_candidate": "warning_output_prestart_2",
            "project_label": "AU_Aerosol_leave",
            "prestart_or_mode_context": "before GOA launch",
            "xdata_refs": "0x315B|0x364B",
            "downstream_functions": "0x7922|0x7DC2",
            "confidence": "low",
            "evidence_level": "hypothesis",
            "notes": "Distinct from AN by project docs; static split remains candidate-level.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x728A",
            "output_candidate": "mode_indicator_output",
            "project_label": "AO_Automatics_disabled",
            "prestart_or_mode_context": "manual/auto mode state",
            "xdata_refs": "0x30E7|0x30E9",
            "downstream_functions": "0x597F|0x5A7F",
            "confidence": "low",
            "evidence_level": "static_code",
            "notes": "AO semantics tied to mode in project docs; code-level mapping still partial.",
        },
    ]

    write_csv(
        DOCS / "project_guided_enum_mapping_candidates.csv",
        ["device_scope","branch","file","function_addr","xdata_addr","enum_value","project_term","probable_meaning","confidence","evidence_level","downstream_path","notes"],
        enum_rows,
    )
    write_csv(
        DOCS / "project_guided_delay_candidates.csv",
        ["branch","file","function_addr","constant_or_pattern","possible_duration_seconds","timer_context","callers","callees","xdata_refs","confidence","evidence_level","notes"],
        delay_rows,
    )
    write_csv(
        DOCS / "project_guided_door_auto_mode_candidates.csv",
        ["branch","file","function_addr","candidate_role","xdata_refs","mode_flags","branch_context","related_outputs","confidence","evidence_level","notes"],
        mode_rows,
    )
    write_csv(
        DOCS / "project_guided_warning_output_candidates.csv",
        ["branch","file","function_addr","output_candidate","project_label","prestart_or_mode_context","xdata_refs","downstream_functions","confidence","evidence_level","notes"],
        warning_rows,
    )

    report = """# Project-guided enum/delay/interlock static analysis

## Scope
Project-constrained static search for enum/state terms and aerosol timing/interlock logic.

## 30-second delay support
Static support is **present at medium confidence** around `0x6833` in 90CYE_DKS (manual_decompile + prior chain traces). Exact timer base (ticks/divider) remains unresolved.

## Door-open -> auto-disabled / manual behavior
Strongest candidates: `0x728A` (mode split gate) and `0x84A6` (upstream interlock gate). Evidence remains static/manual-decompile and not runtime-confirmed.

## Strongest auto/manual XDATA flags
`0x30E7`, `0x30E9`, `0x315B`, `0x3181` remain the strongest clustered mode/status bytes; exact bit semantics remain partially unresolved.

## АН/АУ/АО output visibility
Static evidence supports separated output candidate classes, but exact terminal/object mapping remains hypothesis. AO is most directly tied to mode-path gating, while AN/AU are prestart warning candidates.

## Enum value linkage quality
Project terms can now be linked to specific compare-value candidates with improved traceability, but numeric semantics remain confidence-capped unless reinforced by deeper static branch-byte extraction or bench traces.
"""
    (DOCS / "project_guided_enum_delay_interlock_analysis.md").write_text(report, encoding="utf-8")

    print("Wrote docs/project_guided_enum_delay_interlock_analysis.md")
    print("Wrote docs/project_guided_enum_mapping_candidates.csv")
    print("Wrote docs/project_guided_delay_candidates.csv")
    print("Wrote docs/project_guided_door_auto_mode_candidates.csv")
    print("Wrote docs/project_guided_warning_output_candidates.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
