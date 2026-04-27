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
    mds_rows = [
        {"branch":"RTOS_service","file":"ppkp2001 90cye01.PZU","function_addr":"0x4358","input_signal_candidate":"CP051","project_tag":"MDS_input","terminal_hint":"X03:1","xdata_refs":"unknown","bitmask_or_channel_hint":"channel_group_0","confidence":"low","evidence_level":"project_documentation","notes":"Project-doc confirmed signal; static channel-bit mapping unresolved."},
        {"branch":"RTOS_service","file":"ppkp2001 90cye01.PZU","function_addr":"0x4358","input_signal_candidate":"CF051","project_tag":"MDS_input","terminal_hint":"X03:3","xdata_refs":"unknown","bitmask_or_channel_hint":"channel_group_0","confidence":"low","evidence_level":"project_documentation","notes":"Constrained by extracted terminals; keep static mapping unresolved."},
        {"branch":"RTOS_service","file":"ppkp2001 90cye01.PZU","function_addr":"0x4358","input_signal_candidate":"CF052","project_tag":"MDS_input","terminal_hint":"X03:5","xdata_refs":"unknown","bitmask_or_channel_hint":"channel_group_0","confidence":"low","evidence_level":"project_documentation","notes":"Needs direct code-channel join evidence."},
        {"branch":"RTOS_service","file":"ppkp2001 90cye01.PZU","function_addr":"0x4358","input_signal_candidate":"CF053","project_tag":"MDS_input","terminal_hint":"X03:7","xdata_refs":"unknown","bitmask_or_channel_hint":"channel_group_0","confidence":"low","evidence_level":"project_documentation","notes":"Needs direct code-channel join evidence."},
        {"branch":"RTOS_service","file":"ppkp2001 90cye01.PZU","function_addr":"0x920C","input_signal_candidate":"CH001","project_tag":"MDS_input","terminal_hint":"X03:9/10","xdata_refs":"unknown","bitmask_or_channel_hint":"channel_group_1","confidence":"low","evidence_level":"hypothesis","notes":"CH-lines likely grouped; bit split unresolved."},
        {"branch":"RTOS_service","file":"ppkp2001 90cye01.PZU","function_addr":"0x920C","input_signal_candidate":"CH002","project_tag":"MDS_input","terminal_hint":"X03:11/12","xdata_refs":"unknown","bitmask_or_channel_hint":"channel_group_1","confidence":"low","evidence_level":"hypothesis","notes":"CH-lines likely grouped; bit split unresolved."},
        {"branch":"RTOS_service","file":"ppkp2001 90cye01.PZU","function_addr":"0x920C","input_signal_candidate":"CH003","project_tag":"MDS_input","terminal_hint":"X03:13/14","xdata_refs":"unknown","bitmask_or_channel_hint":"channel_group_1","confidence":"low","evidence_level":"hypothesis","notes":"CH-lines likely grouped; bit split unresolved."},
        {"branch":"RTOS_service","file":"ppkp2001 90cye01.PZU","function_addr":"0x920C","input_signal_candidate":"CH004","project_tag":"MDS_input","terminal_hint":"X03:15/16","xdata_refs":"unknown","bitmask_or_channel_hint":"channel_group_1","confidence":"low","evidence_level":"hypothesis","notes":"CH-lines likely grouped; bit split unresolved."},
    ]

    mvk_rows = [
        {
            "branch": "RTOS_service",
            "file": "ppkp2001 90cye01.PZU",
            "function_addr": "0x53E6",
            "output_candidate": "any_zone_fire_common_output",
            "project_function": "MVK-2.1_any_zone_fire",
            "xdata_refs": "unknown",
            "precondition_path": "fire_threshold_branch",
            "downstream_packet_path": "0x4358->0x920C->0x53E6",
            "confidence": "low",
            "evidence_level": "cross_family_pattern",
            "notes": "Project docs confirm MVK role, but function-level ownership remains static hypothesis.",
        }
    ]

    valve_rows = [
        {
            "branch": "90CYE_shifted_DKS",
            "file": "90CYE02_27 DKS.PZU",
            "function_addr": "0x673C",
            "valve_role_candidate": "damper_remove_voltage_action",
            "open_closed_fault_context": "open/closed limit switch supervision",
            "xdata_refs": "0x3104",
            "limit_switch_pattern": "object_status_update_after_fire",
            "confidence": "medium",
            "evidence_level": "manual_decompile",
            "notes": "Most concrete static candidate for 90CYE02 damper logic narrowing.",
        },
        {
            "branch": "90CYE_shifted_DKS",
            "file": "90CYE02_27 DKS.PZU",
            "function_addr": "0x758B",
            "valve_role_candidate": "limit_feedback_router",
            "open_closed_fault_context": "open/closed/fault split",
            "xdata_refs": "0x3010..0x301B",
            "limit_switch_pattern": "fault_branch_following_state_update",
            "confidence": "low",
            "evidence_level": "hypothesis",
            "notes": "Second-stage status routing candidate; needs deeper branch-byte extraction.",
        },
    ]

    aerosol_rows = [
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x6833",
            "output_candidate": "prestart_warning_1",
            "project_label": "AN_Aerosol_do_not_enter",
            "xdata_refs": "0x315B|0x3640",
            "prestart_delay_context": "before 30s delay completion",
            "start_pulse_context": "before GOA pulse",
            "confidence": "low",
            "evidence_level": "hypothesis",
            "notes": "Separated candidate output group without terminal-level proof.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x6833",
            "output_candidate": "prestart_warning_2",
            "project_label": "AU_Aerosol_leave",
            "xdata_refs": "0x315B|0x364B",
            "prestart_delay_context": "before 30s delay completion",
            "start_pulse_context": "before GOA pulse",
            "confidence": "low",
            "evidence_level": "hypothesis",
            "notes": "Separated candidate output group without terminal-level proof.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x728A",
            "output_candidate": "mode_indicator",
            "project_label": "AO_Automatics_disabled",
            "xdata_refs": "0x30E7|0x30E9",
            "prestart_delay_context": "mode gate stage",
            "start_pulse_context": "not a launch pulse",
            "confidence": "low",
            "evidence_level": "static_code",
            "notes": "AO tied to mode/interlock path candidate.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x7DC2",
            "output_candidate": "launch_line_pulse",
            "project_label": "GOA_launch_pulse",
            "xdata_refs": "0x315B|0x3181",
            "prestart_delay_context": "after delay path",
            "start_pulse_context": "final stage of start chain",
            "confidence": "low",
            "evidence_level": "manual_decompile",
            "notes": "Most plausible launch pulse stage candidate; pulse width parameters unresolved.",
        },
    ]

    split_rows = [
        {
            "source": "project_scan",
            "module_label": "MUP",
            "device_scope": "DKS",
            "evidence_type": "project_documentation",
            "confirmed_by_source": "not_confirmed_in_current_project_pages",
            "handler_status": "unresolved",
            "related_functions": "0x613C|0x728A",
            "notes": "Keep separate from screen config evidence; do not collapse into confirmed mapping.",
        },
        {
            "source": "screen_configuration",
            "module_label": "MUP",
            "device_scope": "DKS",
            "evidence_type": "screen_configuration",
            "confirmed_by_source": "slot_label_present",
            "handler_status": "candidate_only",
            "related_functions": "0x613C|0x758B",
            "notes": "Screen shows module slot but static handler ownership is unresolved.",
        },
        {
            "source": "project_scan",
            "module_label": "PVK",
            "device_scope": "DKS",
            "evidence_type": "project_documentation",
            "confirmed_by_source": "not_confirmed_in_current_project_pages",
            "handler_status": "unresolved",
            "related_functions": "0x613C|0x53E6",
            "notes": "Project extraction lacks PVK-specific sheets in current scope.",
        },
        {
            "source": "screen_configuration",
            "module_label": "PVK",
            "device_scope": "DKS",
            "evidence_type": "screen_configuration",
            "confirmed_by_source": "slot_label_present",
            "handler_status": "candidate_only",
            "related_functions": "0x613C|0x53E6",
            "notes": "Maintain explicit split until static or bench evidence improves.",
        },
    ]

    write_csv(
        DOCS / "project_guided_mds_input_candidates.csv",
        ["branch","file","function_addr","input_signal_candidate","project_tag","terminal_hint","xdata_refs","bitmask_or_channel_hint","confidence","evidence_level","notes"],
        mds_rows,
    )
    write_csv(
        DOCS / "project_guided_mvk_output_candidates.csv",
        ["branch","file","function_addr","output_candidate","project_function","xdata_refs","precondition_path","downstream_packet_path","confidence","evidence_level","notes"],
        mvk_rows,
    )
    write_csv(
        DOCS / "project_guided_valve_feedback_candidates.csv",
        ["branch","file","function_addr","valve_role_candidate","open_closed_fault_context","xdata_refs","limit_switch_pattern","confidence","evidence_level","notes"],
        valve_rows,
    )
    write_csv(
        DOCS / "project_guided_aerosol_output_candidates.csv",
        ["branch","file","function_addr","output_candidate","project_label","xdata_refs","prestart_delay_context","start_pulse_context","confidence","evidence_level","notes"],
        aerosol_rows,
    )
    write_csv(
        DOCS / "project_guided_mup_pvk_evidence_split.csv",
        ["source","module_label","device_scope","evidence_type","confirmed_by_source","handler_status","related_functions","notes"],
        split_rows,
    )

    report = """# Project-guided MDS/MVK/valve/aerosol output static analysis

## CP/CF/CH linkage status
Project evidence strongly constrains expected inputs, but code-level channel/bit mapping is still low-confidence. CP/CF anchors are narrowed to upstream RTOS_service candidates, while CH-group mapping remains hypothesis.

## MVK-2.1 any-zone-fire output
A plausible static path candidate exists (`0x4358->0x920C->0x53E6`) for common fire output flow, but this is cross-family/static only and not bench-confirmed.

## 90CYE02 valve feedback narrowing
`0x673C` is currently the strongest static candidate for damper voltage-removal + limit switch feedback state handling. `0x758B` remains a secondary router hypothesis.

## Aerosol outputs separation
Candidate groups for AN/AU/AO/GOA can be separated statically into distinct path classes, but terminal-level mapping and pulse electrical parameters remain unresolved.

## MUP/PVK split status
MUP/PVK remain explicitly split: visible in screen configuration evidence but not confirmed in current project page subset; handler ownership remains unresolved.
"""
    (DOCS / "project_guided_mds_mvk_valve_output_analysis.md").write_text(report, encoding="utf-8")

    print("Wrote docs/project_guided_mds_mvk_valve_output_analysis.md")
    print("Wrote docs/project_guided_mds_input_candidates.csv")
    print("Wrote docs/project_guided_mvk_output_candidates.csv")
    print("Wrote docs/project_guided_valve_feedback_candidates.csv")
    print("Wrote docs/project_guided_aerosol_output_candidates.csv")
    print("Wrote docs/project_guided_mup_pvk_evidence_split.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
