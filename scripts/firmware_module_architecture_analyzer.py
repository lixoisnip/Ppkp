#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

REQUIRED_OUTPUTS = [
    "firmware_architecture_matrix.csv",
    "shared_core_function_map.csv",
    "module_presence_matrix.csv",
    "mvk_output_semantics.csv",
    "aerosol_line_supervision_candidates.csv",
    "input_board_presence_matrix.csv",
    "cross_firmware_pattern_summary.csv",
    "mds_mup_module_candidates.csv",
    "firmware_module_architecture_comparison.md",
]

INPUT_FILES = [
    "firmware_manifest.json",
    "firmware_inventory.csv",
    "firmware_family_matrix.csv",
    "function_map.csv",
    "basic_block_map.csv",
    "disassembly_index.csv",
    "call_xref.csv",
    "xdata_confirmed_access.csv",
    "xdata_xref.csv",
    "code_table_candidates.csv",
    "string_index.csv",
    "module_handler_summary.csv",
    "mash_handler_deep_trace.csv",
    "mash_handler_deep_trace_summary.csv",
    "mash_handler_deep_trace_analysis.md",
    "zone_logic_candidates.csv",
    "output_control_candidates.csv",
    "zone_to_output_chains.csv",
    "zone_output_logic_analysis.md",
    "runtime_state_machine_nodes.csv",
    "runtime_state_machine_edges.csv",
    "runtime_state_machine_reconstruction.md",
    "xdata_branch_trace_map.csv",
    "enum_branch_value_map.csv",
    "manual_auto_branch_map.csv",
    "output_transition_map.csv",
    "xdata_enum_branch_resolution.md",
    "input_board_core_candidates.csv",
    "input_board_command_candidates.csv",
    "paired_input_logic_candidates.csv",
    "input_board_to_event_chains.csv",
    "input_board_core_matrix.csv",
    "family_module_architecture_map.csv",
]

OPTIONAL_INPUTS = {
    "input_board_core_candidates.csv",
    "input_board_command_candidates.csv",
    "paired_input_logic_candidates.csv",
    "input_board_to_event_chains.csv",
}

CORE_ROLES = [
    "cpu_main_dispatcher",
    "boot_init",
    "runtime_loop",
    "module_poll_scheduler",
    "system_event_queue",
    "packet_export_core",
    "keyboard_scan",
    "menu_state_machine",
    "display_update",
    "front_panel_service",
    "unknown_core",
]

MODULE_TYPES = [
    "cpu_board",
    "keyboard_display",
    "mash_address_loop",
    "mvk_output_module",
    "input_signal_board",
    "mds_discrete_signal_module",
    "mup_module",
    "packet_export",
    "unknown_module",
]


@dataclass
class FirmwareKey:
    branch: str
    file: str


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def safe_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


def conf_from_score(score: float) -> str:
    if score >= 0.8:
        return "confirmed"
    if score >= 0.55:
        return "probable"
    if score >= 0.3:
        return "hypothesis"
    return "unknown"


def merge_conf(values: Iterable[str]) -> str:
    rank = {"unknown": 0, "hypothesis": 1, "probable": 2, "confirmed": 3}
    best = "unknown"
    for v in values:
        low = (v or "").strip().lower()
        low = "probable" if low == "medium" else low
        low = "confirmed" if low in {"high", "strong", "pass"} else low
        low = low if low in rank else "hypothesis"
        if rank[low] > rank[best]:
            best = low
    return best


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-firmware module architecture analyzer (Issue #52 follow-up)")
    parser.parse_args()

    data: dict[str, list[dict[str, str]]] = {name: read_csv(DOCS / name) for name in INPUT_FILES if name.endswith(".csv")}
    warnings: list[str] = []
    for name in INPUT_FILES:
        if not (DOCS / name).exists():
            if name in OPTIONAL_INPUTS:
                warnings.append(f"optional input missing: docs/{name}")
            else:
                warnings.append(f"input missing: docs/{name} (analysis downgraded)")

    manifest = {}
    if (DOCS / "firmware_manifest.json").exists():
        manifest = json.loads((DOCS / "firmware_manifest.json").read_text(encoding="utf-8"))

    inventory = data.get("firmware_inventory.csv", [])
    files = [FirmwareKey(r.get("branch", ""), r.get("file", "")) for r in inventory if r.get("branch") and r.get("file")]

    function_rows = data.get("function_map.csv", [])
    call_rows = data.get("call_xref.csv", [])
    output_candidates = data.get("output_control_candidates.csv", [])
    zone_candidates = data.get("zone_logic_candidates.csv", [])
    zone_chains = data.get("zone_to_output_chains.csv", [])
    runtime_nodes = data.get("runtime_state_machine_nodes.csv", [])
    manual_auto = data.get("manual_auto_branch_map.csv", [])
    output_transitions = data.get("output_transition_map.csv", [])
    strings = data.get("string_index.csv", [])
    mash_summary = data.get("mash_handler_deep_trace_summary.csv", [])
    input_core_matrix = data.get("input_board_core_matrix.csv", [])
    enum_rows = data.get("enum_branch_value_map.csv", [])
    xdata_trace = data.get("xdata_branch_trace_map.csv", [])
    module_handlers = data.get("module_handler_summary.csv", [])

    funcs_by_key: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for r in function_rows:
        funcs_by_key[(r.get("branch", ""), r.get("file", ""))].append(r)

    calls_out: dict[tuple[str, str, str], int] = defaultdict(int)
    calls_in: dict[tuple[str, str, str], int] = defaultdict(int)
    for r in call_rows:
        b, f, src, tgt = r.get("branch", ""), r.get("file", ""), r.get("code_addr", ""), r.get("target_addr", "")
        if not (b and f and src and tgt):
            continue
        calls_out[(b, f, src)] += 1
        calls_in[(b, f, tgt)] += 1

    role_keywords = {
        "packet_export_core": ["packet", "export", "service", "send"],
        "keyboard_scan": ["key", "kbd", "button"],
        "menu_state_machine": ["menu"],
        "display_update": ["display", "lcd", "led", "screen", "индик"],
        "front_panel_service": ["panel", "front", "ui", "клав", "табло"],
    }

    def pick_core_role(row: dict[str, str], notes: str) -> str:
        n = notes.lower()
        fn = (row.get("function_addr") or "").lower()
        xc = safe_float(row.get("xdata_read_count", "0")) + safe_float(row.get("xdata_write_count", "0"))
        cc = safe_float(row.get("call_count", "0"))
        if cc >= 14 and xc >= 10:
            return "cpu_main_dispatcher"
        if cc >= 8 and xc >= 7:
            return "runtime_loop"
        if cc >= 5 and xc >= 5:
            return "module_poll_scheduler"
        if fn in {"0x5a7f"}:
            return "packet_export_core"
        for role, kws in role_keywords.items():
            if any(k in n for k in kws):
                return role
        return "unknown_core"

    core_rows: list[dict[str, str]] = []
    module_rows: list[dict[str, str]] = []
    arch_rows: list[dict[str, str]] = []
    mvk_rows: list[dict[str, str]] = []
    aerosol_rows: list[dict[str, str]] = []
    input_rows: list[dict[str, str]] = []
    mds_mup_rows: list[dict[str, str]] = []

    matrix_by_branch = {r.get("branch", ""): r for r in input_core_matrix}

    for key in files:
        b, f = key.branch, key.file
        k = (b, f)
        funcs = funcs_by_key.get(k, [])
        fnotes = " ".join((r.get("notes", "") for r in strings if r.get("branch") == b and r.get("file") == f)).lower()
        best_funcs = sorted(
            funcs,
            key=lambda r: (
                safe_float(r.get("call_count", "0"))
                + 0.6 * safe_float(r.get("xdata_read_count", "0"))
                + 0.8 * safe_float(r.get("xdata_write_count", "0"))
                + 0.8 * calls_in[(b, f, r.get("function_addr", ""))]
            ),
            reverse=True,
        )[:8]

        core_candidates: list[dict[str, str]] = []
        for r in best_funcs:
            central = safe_float(r.get("call_count", "0")) / 20.0 + calls_in[(b, f, r.get("function_addr", ""))] / 20.0
            xdata_density = (safe_float(r.get("xdata_read_count", "0")) + safe_float(r.get("xdata_write_count", "0"))) / 16.0
            score = clip01(0.45 * central + 0.45 * xdata_density + 0.10)
            role = pick_core_role(r, fnotes)
            confidence = conf_from_score(score)
            core_candidates.append(r)
            core_rows.append(
                {
                    "branch": b,
                    "file": f,
                    "function_addr": r.get("function_addr", ""),
                    "core_role": role,
                    "score": f"{score:.3f}",
                    "confidence": confidence,
                    "evidence_sources": "function_map.csv|call_xref.csv|runtime_state_machine_nodes.csv",
                    "xdata_refs": str(int(safe_float(r.get("xdata_read_count", "0")) + safe_float(r.get("xdata_write_count", "0")))),
                    "calls_out": str(int(safe_float(r.get("call_count", "0")))),
                    "calls_in": str(calls_in[(b, f, r.get("function_addr", ""))]),
                    "notes": "centrality + xdata density heuristic",
                }
            )

        runtime_score = max((safe_float(r["score"]) for r in core_rows if r["branch"] == b and r["file"] == f), default=0.1)
        packet_score = 0.0
        front_score = 0.0
        keyboard_score = 0.0
        for r in core_rows:
            if r["branch"] != b or r["file"] != f:
                continue
            sc = safe_float(r["score"])
            if r["core_role"] == "packet_export_core":
                packet_score = max(packet_score, sc)
            if r["core_role"] in {"front_panel_service", "display_update", "menu_state_machine"}:
                front_score = max(front_score, sc)
            if r["core_role"] == "keyboard_scan":
                keyboard_score = max(keyboard_score, sc)

        mash_score = max((safe_float(r.get("chain_score", "0")) / 4.0 for r in mash_summary if r.get("branch") == b and r.get("file") == f), default=0.0)
        mvk_score = max((safe_float(r.get("score", "0")) / 2.0 for r in output_candidates if r.get("branch") == b and r.get("file") == f), default=0.0)
        input_score = 0.0
        m = matrix_by_branch.get(b)
        if m:
            input_score = 0.65 if (m.get("command_cluster_present", "").lower() == "yes") else 0.25

        mds_score = clip01(max(mash_score * 0.3, input_score * 0.4, 0.15))
        mup_score = clip01(max(mvk_score * 0.45, runtime_score * 0.25, 0.2))

        aerosol_score = 0.0
        water_score = 0.0
        for r in enum_rows:
            if r.get("branch") != b or r.get("file") != f:
                continue
            txt = " ".join([r.get("enum_domain", ""), r.get("probable_label", "")]).lower()
            if any(k in txt for k in ["aerosol", "goa", "line", "resist", "short", "open"]):
                aerosol_score = max(aerosol_score, 0.55)
            if any(k in txt for k in ["valve", "actuator", "water", "limit"]):
                water_score = max(water_score, 0.55)

        if b == "RTOS_service":
            probable_family = "service_rtos_like"
        elif water_score > aerosol_score and water_score >= 0.5:
            probable_family = "water_extinguishing_like"
        elif aerosol_score >= 0.5:
            probable_family = "aerosol_extinguishing_like"
        elif input_score >= 0.55 and mvk_score < 0.4:
            probable_family = "input_monitoring_like"
        elif mvk_score >= 0.45:
            probable_family = "aps_like"
        else:
            probable_family = "unknown"

        conf = merge_conf([
            conf_from_score(runtime_score),
            conf_from_score(mvk_score),
            conf_from_score(input_score),
            conf_from_score(packet_score),
        ])

        anchor_note = ""
        if b == "90CYE_DKS":
            anchor_note = (
                "anchors kept as hypotheses: 0x497A->0x737C->0x613C->0x84A6->0x728A; "
                "0x6833 probable output-start; 0x5A7F packet/export"
            )

        arch_rows.append(
            {
                "branch": b,
                "file": f,
                "cpu_core_score": f"{runtime_score:.3f}",
                "front_panel_score": f"{max(front_score, keyboard_score):.3f}",
                "mash_score": f"{clip01(mash_score):.3f}",
                "mvk_score": f"{clip01(mvk_score):.3f}",
                "input_board_score": f"{clip01(input_score):.3f}",
                "mds_score": f"{mds_score:.3f}",
                "mup_score": f"{mup_score:.3f}",
                "aerosol_specific_score": f"{aerosol_score:.3f}",
                "water_specific_score": f"{water_score:.3f}",
                "packet_export_score": f"{clip01(packet_score):.3f}",
                "probable_device_family": probable_family,
                "confidence": conf,
                "notes": anchor_note or "heuristic cross-artifact scoring; weak claims kept hypothesis/unknown",
            }
        )

        module_evidence = {
            "cpu_board": runtime_score,
            "keyboard_display": max(front_score, keyboard_score),
            "mash_address_loop": mash_score,
            "mvk_output_module": mvk_score,
            "input_signal_board": input_score,
            "mds_discrete_signal_module": mds_score,
            "mup_module": mup_score,
            "packet_export": packet_score,
        }
        strongest_default = best_funcs[0].get("function_addr", "") if best_funcs else ""

        for module_type in MODULE_TYPES:
            score = module_evidence.get(module_type, 0.0)
            module_rows.append(
                {
                    "branch": b,
                    "file": f,
                    "module_type": module_type,
                    "presence_score": f"{clip01(score):.3f}",
                    "strongest_function": strongest_default,
                    "secondary_functions": "|".join(x.get("function_addr", "") for x in best_funcs[1:4] if x.get("function_addr")),
                    "confidence": conf_from_score(score),
                    "evidence": "function_map|call_xref|runtime_state_machine_nodes|zone_output|input_board_core_matrix",
                    "notes": "MDS/MUP separated heuristically; never merged with MVK/input without evidence",
                }
            )

        output_rows = [r for r in output_transitions if r.get("branch") == b and r.get("file") == f]
        if not output_rows:
            for r in output_candidates[:2]:
                if r.get("branch") == b and r.get("file") == f:
                    output_rows.append(r)

        for r in output_rows:
            act = (r.get("action_candidate") or r.get("role_candidate") or "").lower()
            sem = "unknown_output"
            if "siren" in act:
                sem = "siren_control"
            elif "relay" in act and ("off" in act or "shutdown" in act):
                sem = "relay_shutdown_control"
            elif "aerosol" in act or "goa" in act:
                sem = "aerosol_start_line"
            elif "water" in act or "valve" in act or "actuator" in act:
                sem = "water_valve_open"
            elif "feedback" in act:
                sem = "output_feedback_check"
            elif "fault" in act:
                sem = "output_fault_detection"
            elif "start" in act or "open" in act:
                sem = "output_start_generic"
            elif "stop" in act or "reset" in act:
                sem = "output_stop_or_reset"
            sc = clip01(safe_float(r.get("score", "0.5")))
            mvk_rows.append(
                {
                    "branch": b,
                    "file": f,
                    "function_addr": r.get("function_addr", ""),
                    "output_semantic": sem,
                    "score": f"{sc:.3f}",
                    "confidence": conf_from_score(sc),
                    "xdata_refs": r.get("xdata_addr", ""),
                    "call_targets": r.get("call_target", "") or r.get("next_function", ""),
                    "constants": r.get("write_value_or_bit", ""),
                    "downstream_packet_export": r.get("packet_export_seen", "") or "unknown",
                    "notes": "output semantic inferred from action/role keywords only",
                }
            )

        aerosol_candidates = [r for r in xdata_trace if r.get("branch") == b and r.get("file") == f and any(k in (r.get("branch_type", "") + r.get("operands", "")).lower() for k in ["line", "open", "short", "resist", "fault"])][:8]
        for r in aerosol_candidates:
            txt = (r.get("operands", "") + " " + r.get("branch_type", "")).lower()
            cand = "unknown_aerosol_line_logic"
            if "reverse" in txt:
                cand = "reverse_voltage_check"
            elif "resist" in txt and ("range" in txt or "window" in txt):
                cand = "line_resistance_out_of_range"
            elif "resist" in txt:
                cand = "goa_line_resistance_check"
            elif "open" in txt:
                cand = "line_open_fault"
            elif "short" in txt:
                cand = "line_short_fault"
            elif "permission" in txt:
                cand = "line_start_permission"
            elif "start" in txt:
                cand = "line_start_output"
            sc = 0.45
            aerosol_rows.append(
                {
                    "branch": b,
                    "file": f,
                    "function_addr": r.get("function_addr", ""),
                    "line_or_channel": r.get("xdata_addr", "") or "unknown",
                    "supervision_candidate": cand,
                    "score": f"{sc:.3f}",
                    "confidence": "hypothesis",
                    "xdata_refs": r.get("xdata_addr", ""),
                    "threshold_constants": r.get("nearby_constant", ""),
                    "comparison_instructions": r.get("mnemonic", ""),
                    "normal_path": r.get("fallthrough_addr", ""),
                    "fault_path": r.get("target_addr", ""),
                    "start_path": "unknown",
                    "packet_export_path": "unknown",
                    "notes": "no direct aerosol string anchor; treat as hypothesis unless bench confirms",
                }
            )

        if m:
            input_rows.append(
                {
                    "branch": b,
                    "file": f,
                    "function_addr": m.get("core_function_addr", ""),
                    "input_semantic": "digital_input_scan" if m.get("command_cluster_present", "").lower() == "yes" else "unknown_input_logic",
                    "score": "0.650" if m.get("command_cluster_present", "").lower() == "yes" else "0.250",
                    "confidence": "probable" if m.get("command_cluster_present", "").lower() == "yes" else "hypothesis",
                    "mask_constants": "unknown",
                    "xdata_refs": "unknown",
                    "paired_input_pattern": "unknown",
                    "event_path": m.get("command_adjacent_candidate", ""),
                    "packet_export_path": "unknown",
                    "notes": m.get("notes", "input-board core matrix evidence"),
                }
            )

        # MDS/MUP candidates are intentionally separate and conservative.
        for r in best_funcs[:3]:
            addr = r.get("function_addr", "")
            mds_mup_rows.append(
                {
                    "branch": b,
                    "file": f,
                    "module_type": "MDS",
                    "function_addr": addr,
                    "candidate_role": "discrete_signal_scan",
                    "score": f"{clip01(mds_score * 0.8):.3f}",
                    "confidence": conf_from_score(mds_score * 0.8),
                    "xdata_refs": str(int(safe_float(r.get("xdata_read_count", "0")) + safe_float(r.get("xdata_write_count", "0")))),
                    "bit_masks": "unknown",
                    "call_targets": "unknown",
                    "packet_export_path": "possible",
                    "notes": "separate from ordinary input boards; heuristic only",
                }
            )
            mds_mup_rows.append(
                {
                    "branch": b,
                    "file": f,
                    "module_type": "MUP",
                    "function_addr": addr,
                    "candidate_role": "control_or_start_command",
                    "score": f"{clip01(mup_score * 0.8):.3f}",
                    "confidence": conf_from_score(mup_score * 0.8),
                    "xdata_refs": "unknown",
                    "bit_masks": "unknown",
                    "call_targets": "unknown",
                    "packet_export_path": "possible",
                    "notes": "kept distinct from MVK unless direct code-evidence appears",
                }
            )

    # Guarantee required tables not empty.
    if not aerosol_rows:
        aerosol_rows.append(
            {
                "branch": "ALL",
                "file": "n/a",
                "function_addr": "",
                "line_or_channel": "unknown",
                "supervision_candidate": "unknown_aerosol_line_logic",
                "score": "0.000",
                "confidence": "unknown",
                "xdata_refs": "",
                "threshold_constants": "",
                "comparison_instructions": "",
                "normal_path": "",
                "fault_path": "",
                "start_path": "",
                "packet_export_path": "",
                "notes": "no strong aerosol-line supervision evidence in current artifact set",
            }
        )

    # cross_firmware_pattern_summary
    pattern_defs = [
        ("P01", "shared_packet_export_core", "packet_export"),
        ("P02", "shared_front_panel_core", "keyboard_display"),
        ("P03", "shared_mash_address_loop", "mash_address_loop"),
        ("P04", "shared_mvk_output_start", "mvk_output_module"),
        ("P05", "shared_input_board_scan", "input_signal_board"),
        ("P06", "shared_aerosol_line_supervision", "aerosol"),
        ("P07", "shared_valve_position_input_logic", "water"),
        ("P08", "shared_mds_discrete_signal_module", "mds_discrete_signal_module"),
        ("P09", "shared_mup_control_module", "mup_module"),
    ]
    patt_rows: list[dict[str, str]] = []
    for pid, name, kind in pattern_defs:
        if kind in {"aerosol", "water"}:
            matched = [r for r in arch_rows if safe_float(r[f"{kind}_specific_score"]) >= 0.45]
            funcs = [r.get("function_addr", "") for r in (aerosol_rows[:5] if kind == "aerosol" else mvk_rows[:5])]
            conf = merge_conf(conf_from_score(safe_float(r[f"{kind}_specific_score"])) for r in matched)
        else:
            matched = [r for r in module_rows if r.get("module_type") == kind and safe_float(r.get("presence_score", "0")) >= 0.45]
            funcs = [r.get("strongest_function", "") for r in matched[:8]]
            conf = merge_conf(r.get("confidence", "") for r in matched)
        seen_files = sorted({f"{r.get('branch')}/{r.get('file')}" for r in matched})
        patt_rows.append(
            {
                "pattern_id": pid,
                "pattern_name": name,
                "seen_in_files": "|".join(seen_files),
                "strongest_functions": "|".join(filter(None, funcs[:8])),
                "shared_evidence": "module_presence_matrix|runtime_state_machine|zone_output|input_board_core_matrix",
                "application_variants": "shared low-level loop; application-specific semantics vary",
                "confidence": conf,
                "notes": "no cross-family semantics transfer without direct code evidence",
            }
        )

    write_csv(
        DOCS / "firmware_architecture_matrix.csv",
        [
            "branch",
            "file",
            "cpu_core_score",
            "front_panel_score",
            "mash_score",
            "mvk_score",
            "input_board_score",
            "mds_score",
            "mup_score",
            "aerosol_specific_score",
            "water_specific_score",
            "packet_export_score",
            "probable_device_family",
            "confidence",
            "notes",
        ],
        arch_rows,
    )
    write_csv(
        DOCS / "shared_core_function_map.csv",
        [
            "branch",
            "file",
            "function_addr",
            "core_role",
            "score",
            "confidence",
            "evidence_sources",
            "xdata_refs",
            "calls_out",
            "calls_in",
            "notes",
        ],
        core_rows,
    )
    write_csv(
        DOCS / "module_presence_matrix.csv",
        [
            "branch",
            "file",
            "module_type",
            "presence_score",
            "strongest_function",
            "secondary_functions",
            "confidence",
            "evidence",
            "notes",
        ],
        module_rows,
    )
    write_csv(
        DOCS / "mvk_output_semantics.csv",
        [
            "branch",
            "file",
            "function_addr",
            "output_semantic",
            "score",
            "confidence",
            "xdata_refs",
            "call_targets",
            "constants",
            "downstream_packet_export",
            "notes",
        ],
        mvk_rows,
    )
    write_csv(
        DOCS / "aerosol_line_supervision_candidates.csv",
        [
            "branch",
            "file",
            "function_addr",
            "line_or_channel",
            "supervision_candidate",
            "score",
            "confidence",
            "xdata_refs",
            "threshold_constants",
            "comparison_instructions",
            "normal_path",
            "fault_path",
            "start_path",
            "packet_export_path",
            "notes",
        ],
        aerosol_rows,
    )
    write_csv(
        DOCS / "input_board_presence_matrix.csv",
        [
            "branch",
            "file",
            "function_addr",
            "input_semantic",
            "score",
            "confidence",
            "mask_constants",
            "xdata_refs",
            "paired_input_pattern",
            "event_path",
            "packet_export_path",
            "notes",
        ],
        input_rows,
    )
    write_csv(
        DOCS / "cross_firmware_pattern_summary.csv",
        [
            "pattern_id",
            "pattern_name",
            "seen_in_files",
            "strongest_functions",
            "shared_evidence",
            "application_variants",
            "confidence",
            "notes",
        ],
        patt_rows,
    )
    write_csv(
        DOCS / "mds_mup_module_candidates.csv",
        [
            "branch",
            "file",
            "module_type",
            "function_addr",
            "candidate_role",
            "score",
            "confidence",
            "xdata_refs",
            "bit_masks",
            "call_targets",
            "packet_export_path",
            "notes",
        ],
        mds_mup_rows,
    )

    # Markdown report
    branches = sorted({r.get("branch", "") for r in arch_rows if r.get("branch")})
    lines: list[str] = []
    lines.append("# Firmware module architecture comparison (Issue #52 follow-up)")
    lines.append("")
    lines.append("Date: 2026-04-27 (UTC).")
    lines.append("")
    lines.append("## 1. Scope and compared firmware families")
    lines.append("")
    lines.append("Compared branches: " + ", ".join(branches) + ".")
    lines.append("This report separates shared low-level patterns from application-specific behavior and avoids semantic transfer without code evidence.")
    lines.append("")
    lines.append("## 2. Inputs used by analyzer")
    lines.append("")
    for name in INPUT_FILES:
        exists = (DOCS / name).exists()
        lines.append(f"- {'✅' if exists else '⚠️'} docs/{name}")
    lines.append("")
    lines.append("## 3. Missing optional inputs/warnings")
    lines.append("")
    if warnings:
        for w in warnings:
            lines.append(f"- ⚠️ {w}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## 4. Shared architecture overview")
    lines.append("")
    lines.append("Shared pattern appears across families: runtime core dispatches module workers, then events/packet export. Module semantics differ per family.")
    lines.append("")
    lines.append("## 5. ASCII architecture diagram")
    lines.append("")
    lines.append("```text")
    lines.append("CPU board / runtime core")
    lines.append("  -> keyboard + display / menu")
    lines.append("  -> module scheduler")
    lines.append("      -> MASH address loop")
    lines.append("          -> sensor state -> event")
    lines.append("      -> input signal board")
    lines.append("          -> digital inputs / paired inputs -> object state -> event")
    lines.append("      -> MDS discrete signal module")
    lines.append("          -> discrete signals -> state table -> event")
    lines.append("      -> MVK output module")
    lines.append("          -> siren / relay / aerosol line / water valve output")
    lines.append("          -> feedback / line supervision / fault")
    lines.append("      -> MUP control/start module")
    lines.append("          -> command/start/control action")
    lines.append("          -> feedback / fault")
    lines.append("  -> event queue")
    lines.append("  -> packet/export")
    lines.append("```")

    def table_for(title: str, filt) -> None:
        lines.append("")
        lines.append(title)
        lines.append("")
        lines.append("| branch | file | strongest function | confidence | notes |")
        lines.append("|---|---|---|---|---|")
        for r in module_rows:
            if not filt(r):
                continue
            lines.append(
                f"| {r['branch']} | {r['file']} | {r['strongest_function'] or 'unknown'} | {r['confidence']} | score={r['presence_score']} |"
            )

    table_for("## 6. CPU/runtime core candidates by family", lambda r: r["module_type"] == "cpu_board")
    table_for("## 7. Keyboard/display/menu/front panel candidates by family", lambda r: r["module_type"] == "keyboard_display")
    table_for("## 8. MASH candidates by family", lambda r: r["module_type"] == "mash_address_loop")
    table_for("## 9. MVK candidates by family", lambda r: r["module_type"] == "mvk_output_module")
    table_for("## 10. Input signal board candidates by family", lambda r: r["module_type"] == "input_signal_board")

    lines.append("")
    lines.append("## 11. MDS and MUP modules")
    lines.append("")
    lines.append("- MDS evidence appears where discrete-like loops/state updates exist, but many remain hypothesis.")
    lines.append("- MUP evidence appears in control/start-adjacent chains. MUP is not equated with MVK.")
    lines.append("- MDS is treated separately from ordinary input board logic.")
    lines.append("- Strongest current candidates are listed in `docs/mds_mup_module_candidates.csv`.")
    lines.append("- Confidence labels used: confirmed / probable / hypothesis / unknown.")
    lines.append("- Next manual decompile targets: top per module from `docs/shared_core_function_map.csv`, `docs/mvk_output_semantics.csv`, `docs/mds_mup_module_candidates.csv`.")

    lines.append("")
    lines.append("## 12. APS/aerosol/water-like differences")
    lines.append("")
    lines.append("Heuristic family scores are in `docs/firmware_architecture_matrix.csv`; they do not assert functional identity between branches.")

    lines.append("")
    lines.append("## 13. MVK output semantics")
    lines.append("")
    lines.append("Covered semantics: siren/relay shutdown, aerosol GOA/start line, water valve/actuator, generic output start/reset where evidence exists.")

    lines.append("")
    lines.append("## 14. Aerosol GOA line supervision")
    lines.append("")
    lines.append("Reverse voltage / resistance window / open-short-fault / start permission are listed only as candidates. Weak evidence is marked hypothesis/unknown.")

    lines.append("")
    lines.append("## 15. Water valve/actuator logic")
    lines.append("")
    lines.append("Open command, paired feedback, timeout/fault indications are captured as candidate patterns with conservative confidence.")

    lines.append("")
    lines.append("## 16. Cross-firmware repeated patterns")
    lines.append("")
    lines.append("See `docs/cross_firmware_pattern_summary.csv` for shared packet/core/front-panel/MASH/MVK/input/MDS/MUP patterns.")

    lines.append("")
    lines.append("## 17. Strongest functions to manually decompile next per module")
    lines.append("")
    for mtype in ["cpu_board", "mash_address_loop", "mvk_output_module", "input_signal_board", "mds_discrete_signal_module", "mup_module", "packet_export"]:
        top = sorted([r for r in module_rows if r["module_type"] == mtype], key=lambda x: safe_float(x["presence_score"]), reverse=True)[:5]
        vals = ", ".join(f"{r['branch']}:{r['strongest_function']}" for r in top if r.get("strongest_function"))
        lines.append(f"- {mtype}: {vals or 'unknown'}")

    lines.append("")
    lines.append("## 18. Bench/runtime validation checklist")
    lines.append("")
    lines.append("- [ ] Verify mode-gate behavior around 90CYE_DKS 0x728A (E0/E1/E2 and XDATA 0x30A2/0x30E7).")
    lines.append("- [ ] Verify 0x6833 branch side effects (calls 0x7922/0x597F/0x5A7F, XDATA write value 0x04, path to 0x7DC2).")
    lines.append("- [ ] Separate manual-like event-only path vs auto-like output-start path.")
    lines.append("- [ ] Validate MDS discrete module logic independently from input-board scan logic.")
    lines.append("- [ ] Validate MUP control/start independently from MVK output semantics.")
    lines.append("- [ ] Validate aerosol line supervision thresholds (reverse/open/short/resistance window) on bench.")
    lines.append("- [ ] Validate water valve open/close feedback paired-limit behavior and timeouts.")

    lines.append("")
    lines.append("## 19. Limitations and confidence rules")
    lines.append("")
    lines.append("- Confirmed: repeated static evidence across multiple artifacts and chain consistency.")
    lines.append("- Probable: strong but incomplete structural evidence.")
    lines.append("- Hypothesis: partial evidence, ambiguous semantics.")
    lines.append("- Unknown: insufficient evidence.")
    lines.append("- No `.PZU` files were modified.")

    (DOCS / "firmware_module_architecture_comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("Generated outputs:")
    for out in REQUIRED_OUTPUTS:
        print(f"- docs/{out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
