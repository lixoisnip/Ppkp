#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

PRIMARY_BRANCH = "90CYE_DKS"
PRIMARY_FILE = "90CYE03_19_DKS.PZU"
KEY_XDATA = ["0x30EA..0x30F9", "0x315B", "0x3165", "0x31BF", "0x364B"]
ENUM_VALUES = ["0x01", "0x02", "0x03", "0x04", "0x05", "0x07", "0x08", "0x7E", "0xFF"]

INPUT_FILES = [
    "state_enum_and_techdoc_reconstruction.md",
    "xdata_lifecycle_map.csv",
    "state_enum_hypotheses.csv",
    "auto_manual_mode_hypotheses.csv",
    "output_action_map.csv",
    "state_machine_branch_comparison.csv",
    "bench_validation_matrix.csv",
    "state_mode_enum_candidates.csv",
    "runtime_state_machine_reconstruction.md",
    "runtime_state_machine_nodes.csv",
    "runtime_state_machine_edges.csv",
    "xdata_state_mode_flag_map.csv",
    "runtime_branch_comparison.csv",
    "auto_manual_gating_deep_trace.csv",
    "auto_manual_gating_deep_trace_summary.csv",
    "auto_manual_gating_deep_trace_analysis.md",
    "state_mode_logic_analysis.md",
    "sensor_state_candidates.csv",
    "zone_state_mode_candidates.csv",
    "extinguishing_output_gating_chains.csv",
    "zone_output_deep_trace.csv",
    "zone_output_deep_trace_summary.csv",
    "zone_output_deep_trace_analysis.md",
    "function_map.csv",
    "basic_block_map.csv",
    "disassembly_index.csv",
    "call_xref.csv",
    "xdata_confirmed_access.csv",
    "code_table_candidates.csv",
    "string_index.csv",
    "xdata_map_by_branch.csv",
]


def load_csv(path: Path, warnings: list[str]) -> list[dict[str, str]]:
    if not path.exists():
        warnings.append(f"missing file: {path.relative_to(ROOT)}")
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_text(path: Path, warnings: list[str]) -> str:
    if not path.exists():
        warnings.append(f"missing file: {path.relative_to(ROOT)}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def uniq(values: list[str]) -> str:
    out = sorted({v for v in values if v and v != "-"})
    return "; ".join(out) if out else "-"


def xmatch(target: str, addr: str) -> bool:
    if not addr:
        return False
    addr = addr.upper()
    if ".." not in target:
        return addr == target.upper()
    lo, hi = target.split("..", 1)
    try:
        v = int(addr, 16)
        return int(lo, 16) <= v <= int(hi, 16)
    except ValueError:
        return False


def confidence_from_evidence(n: int) -> str:
    if n >= 5:
        return "probable"
    if n >= 2:
        return "low"
    return "hypothesis"


def main() -> int:
    p = argparse.ArgumentParser(description="Resolve XDATA lifecycle and enum branch evidence for 90CYE_DKS")
    p.add_argument("--out-trace", type=Path, default=DOCS / "xdata_branch_trace_map.csv")
    p.add_argument("--out-enum-branch", type=Path, default=DOCS / "enum_branch_value_map.csv")
    p.add_argument("--out-manual-auto", type=Path, default=DOCS / "manual_auto_branch_map.csv")
    p.add_argument("--out-output", type=Path, default=DOCS / "output_transition_map.csv")
    p.add_argument("--out-xdata", type=Path, default=DOCS / "xdata_lifecycle_map.csv")
    p.add_argument("--out-state-enum", type=Path, default=DOCS / "state_enum_hypotheses.csv")
    p.add_argument("--out-mode", type=Path, default=DOCS / "auto_manual_mode_hypotheses.csv")
    p.add_argument("--out-output-action", type=Path, default=DOCS / "output_action_map.csv")
    p.add_argument("--out-md", type=Path, default=DOCS / "xdata_enum_branch_resolution.md")
    args = p.parse_args()

    warnings: list[str] = []
    for fn in INPUT_FILES:
        fp = DOCS / fn
        if fn.endswith(".md"):
            load_text(fp, warnings)
        else:
            load_csv(fp, warnings)

    xacc = [r for r in load_csv(DOCS / "xdata_confirmed_access.csv", warnings) if r.get("branch") == PRIMARY_BRANCH and r.get("file") == PRIMARY_FILE]
    deep = [r for r in load_csv(DOCS / "auto_manual_gating_deep_trace.csv", warnings) if r.get("branch") == PRIMARY_BRANCH and r.get("file") == PRIMARY_FILE]
    zone_deep = [r for r in load_csv(DOCS / "zone_output_deep_trace.csv", warnings) if r.get("branch") == PRIMARY_BRANCH and r.get("file") == PRIMARY_FILE]
    sensor = [r for r in load_csv(DOCS / "sensor_state_candidates.csv", warnings) if r.get("branch") == PRIMARY_BRANCH and r.get("file") == PRIMARY_FILE]
    zone = [r for r in load_csv(DOCS / "zone_state_mode_candidates.csv", warnings) if r.get("branch") == PRIMARY_BRANCH and r.get("file") == PRIMARY_FILE]

    trace_rows: list[dict[str, str]] = []
    for r in deep + zone_deep:
        xa = r.get("xdata_addr", "")
        if not any(xmatch(t, xa) for t in KEY_XDATA):
            continue
        fn = r.get("function_addr", "")
        call_target = r.get("call_target", "")
        path = "unknown_path"
        downstream_role = "unknown"
        if call_target == "0x6833" or fn == "0x6833":
            path = "auto_like_output_start"
            downstream_role = "output_start"
        elif call_target == "0x5A7F" or fn == "0x5A7F":
            path = "packet_export"
            downstream_role = "packet_export"
        elif fn in {"0x84A6", "0x728A"}:
            path = "manual_like_event_packet"
            downstream_role = "mode_gate"
        elif "read" in (r.get("xdata_access_type", "").lower()):
            path = "state_compare"
            downstream_role = "state_check"
        elif "write" in (r.get("xdata_access_type", "").lower()):
            path = "state_update"
            downstream_role = "state_update"

        trace_rows.append(
            {
                "branch": PRIMARY_BRANCH,
                "file": PRIMARY_FILE,
                "xdata_addr": xa,
                "function_addr": fn,
                "code_addr": r.get("code_addr", ""),
                "block_addr": r.get("block_addr", ""),
                "mnemonic": r.get("mnemonic", ""),
                "operands": r.get("operands", ""),
                "access_type": r.get("xdata_access_type", "") or r.get("access_type", ""),
                "nearby_constant": "-",
                "branch_type": r.get("event_type", ""),
                "target_addr": r.get("target_addr", ""),
                "fallthrough_addr": r.get("fallthrough_addr", ""),
                "downstream_function": call_target or fn,
                "downstream_role": downstream_role,
                "path_class": path,
                "confidence": r.get("confidence", "hypothesis"),
                "notes": r.get("notes", ""),
            }
        )

    for r in xacc:
        xa = r.get("dptr_addr", "")
        if not any(xmatch(t, xa) for t in KEY_XDATA):
            continue
        trace_rows.append(
            {
                "branch": PRIMARY_BRANCH,
                "file": PRIMARY_FILE,
                "xdata_addr": xa,
                "function_addr": "-",
                "code_addr": r.get("code_addr", ""),
                "block_addr": "-",
                "mnemonic": "xdata_access",
                "operands": r.get("evidence_type", ""),
                "access_type": r.get("access_type", ""),
                "nearby_constant": "-",
                "branch_type": "-",
                "target_addr": "-",
                "fallthrough_addr": "-",
                "downstream_function": "-",
                "downstream_role": "xdata_reference",
                "path_class": "state_update" if "write" in r.get("access_type", "") else "state_compare",
                "confidence": r.get("confidence", "low"),
                "notes": "from xdata_confirmed_access",
            }
        )

    trace_fields = [
        "branch","file","xdata_addr","function_addr","code_addr","block_addr","mnemonic","operands","access_type",
        "nearby_constant","branch_type","target_addr","fallthrough_addr","downstream_function","downstream_role","path_class","confidence","notes",
    ]
    write_csv(args.out_trace, trace_fields, trace_rows)

    enum_rows: list[dict[str, str]] = []
    value_to_label = {
        "0x01": "sensor_fire_primary_or_zone_attention",
        "0x02": "sensor_fire_secondary_or_zone_fire",
        "0x03": "sensor_attention_prealarm_or_zone_alarm_fault",
        "0x04": "sensor_fault",
        "0x05": "sensor_disabled_or_zone_disabled",
        "0x07": "sensor_service_or_zone_service",
        "0x08": "sensor_not_detected",
        "0x7E": "sensor_address_conflict",
        "0xFF": "sensor_absent_or_invalid",
    }
    candidate_pool = sensor + zone
    for value in ENUM_VALUES:
        related = [r for r in candidate_pool if value in (r.get("constant_hits", "") + ";" + r.get("operands", ""))]
        if not related:
            enum_rows.append(
                {
                    "branch": PRIMARY_BRANCH, "file": PRIMARY_FILE, "function_addr": "-", "enum_domain": "sensor_or_zone",
                    "candidate_value": value, "candidate_bit": "-", "probable_label": value_to_label[value],
                    "comparison_instruction": "-", "comparison_addr": "-", "true_path": "-", "false_path": "-",
                    "downstream_path": "unknown", "confidence": "hypothesis", "notes": "no direct compare evidence in current artifacts",
                }
            )
            continue
        best = related[0]
        fn = best.get("function_addr", "-")
        downstream = "event_packet" if fn in {"0x84A6", "0x728A", "0x5A7F"} else "output_or_state"
        enum_rows.append(
            {
                "branch": PRIMARY_BRANCH,
                "file": PRIMARY_FILE,
                "function_addr": fn,
                "enum_domain": "sensor" if best in sensor else "zone",
                "candidate_value": value,
                "candidate_bit": "-",
                "probable_label": value_to_label[value],
                "comparison_instruction": f"{best.get('mnemonic','')} {best.get('operands','')}".strip() or "-",
                "comparison_addr": best.get("code_addr", "-"),
                "true_path": "manual_like_event_packet" if fn in {"0x84A6", "0x728A"} else "state_or_output_path",
                "false_path": "auto_or_other_path",
                "downstream_path": downstream,
                "confidence": best.get("confidence", "low"),
                "notes": best.get("notes", ""),
            }
        )
    enum_fields = [
        "branch","file","function_addr","enum_domain","candidate_value","candidate_bit","probable_label",
        "comparison_instruction","comparison_addr","true_path","false_path","downstream_path","confidence","notes",
    ]
    write_csv(args.out_enum_branch, enum_fields, enum_rows)

    manual_rows: list[dict[str, str]] = []
    for fn in ["0x84A6", "0x728A", "0x6833", "0x5A7F"]:
        related = [r for r in deep if r.get("function_addr") == fn]
        manual_rows.append(
            {
                "branch": PRIMARY_BRANCH,
                "file": PRIMARY_FILE,
                "xdata_addr": "0x315B",
                "function_addr": fn,
                "code_addr": related[0].get("code_addr", "-") if related else "-",
                "mode_check_instruction": (related[0].get("mnemonic", "") + " " + related[0].get("operands", "")).strip() if related else "-",
                "mode_candidate_value": "0x01",
                "mode_candidate_bit": "bit0",
                "manual_path": "event/packet only -> 0x5A7F",
                "auto_path": "0x6833 output start -> 0x5A7F",
                "manual_downstream": "0x5A7F",
                "auto_downstream": "0x6833;0x5A7F",
                "output_call": "0x6833" if fn in {"0x728A", "0x6833"} else "-",
                "packet_call": "0x5A7F" if fn in {"0x84A6", "0x728A", "0x5A7F"} else "-",
                "confidence": confidence_from_evidence(len(related)),
                "notes": "static path classification; bench validation required",
            }
        )
    manual_fields = [
        "branch","file","xdata_addr","function_addr","code_addr","mode_check_instruction","mode_candidate_value","mode_candidate_bit",
        "manual_path","auto_path","manual_downstream","auto_downstream","output_call","packet_call","confidence","notes",
    ]
    write_csv(args.out_manual_auto, manual_fields, manual_rows)

    output_rows: list[dict[str, str]] = []
    for r in zone_deep + deep:
        fn = r.get("function_addr", "")
        if fn not in {"0x6833", "0x613C", "0x5A7F", "0x728A", "0x84A6"} and r.get("call_target", "") not in {"0x6833", "0x5A7F"}:
            continue
        output_rows.append(
            {
                "branch": PRIMARY_BRANCH,
                "file": PRIMARY_FILE,
                "function_addr": fn,
                "code_addr": r.get("code_addr", ""),
                "action_candidate": "output_start" if (fn == "0x6833" or r.get("call_target") == "0x6833") else "packet_export_or_feedback",
                "trigger_source": r.get("event_type", ""),
                "xdata_addr": r.get("xdata_addr", "") or "-",
                "write_value_or_bit": "-",
                "call_target": r.get("call_target", "") or "-",
                "next_function": r.get("target_addr", "") or "-",
                "packet_export_seen": "yes" if (fn == "0x5A7F" or r.get("call_target") == "0x5A7F") else "no",
                "feedback_seen": "yes" if fn == "0x613C" else "no",
                "confidence": r.get("confidence", "low"),
                "notes": r.get("notes", ""),
            }
        )
    output_fields = [
        "branch","file","function_addr","code_addr","action_candidate","trigger_source","xdata_addr","write_value_or_bit",
        "call_target","next_function","packet_export_seen","feedback_seen","confidence","notes",
    ]
    write_csv(args.out_output, output_fields, output_rows)

    # refresh existing CSVs from synthesized maps
    lifecycle_rows = []
    for xa in KEY_XDATA:
        related = [r for r in trace_rows if xmatch(xa, r.get("xdata_addr", ""))]
        lifecycle_rows.append(
            {
                "branch": PRIMARY_BRANCH,
                "file": PRIMARY_FILE,
                "xdata_addr": xa,
                "range_group": "state_cluster" if xa == "0x30EA..0x30F9" else "mode_or_output_flags",
                "read_functions": uniq([r.get("function_addr", "") for r in related if "read" in (r.get("access_type", "").lower())]),
                "write_functions": uniq([r.get("function_addr", "") for r in related if "write" in (r.get("access_type", "").lower())]),
                "branch_functions": uniq([r.get("function_addr", "") for r in related if r.get("path_class") in {"manual_like_event_packet", "auto_like_output_start", "state_compare"}]),
                "export_functions": uniq([r.get("function_addr", "") for r in related if r.get("path_class") in {"packet_export", "auto_like_output_start"}]),
                "probable_role": "sensor_or_zone_state_cluster" if xa == "0x30EA..0x30F9" else "mode_or_output_side_flag",
                "confidence": confidence_from_evidence(len(related)),
                "evidence_sources": "xdata_branch_trace_map.csv; xdata_confirmed_access.csv; auto_manual_gating_deep_trace.csv",
                "notes": "generated by xdata_enum_branch_resolver",
            }
        )
    write_csv(args.out_xdata, [
        "branch","file","xdata_addr","range_group","read_functions","write_functions","branch_functions","export_functions","probable_role","confidence","evidence_sources","notes"
    ], lifecycle_rows)

    state_rows = []
    for row in enum_rows:
        state_rows.append(
            {
                "branch": row["branch"], "file": row["file"], "state_scope": row["enum_domain"], "state_name": row["probable_label"],
                "candidate_value": row["candidate_value"], "candidate_bit": row["candidate_bit"], "xdata_addr": "0x30EA..0x30F9",
                "function_addr": row["function_addr"], "branch_evidence": row["comparison_instruction"], "downstream_path": row["downstream_path"],
                "confidence": row["confidence"], "notes": row["notes"] or "mapped in enum_branch_value_map.csv",
            }
        )
    write_csv(args.out_state_enum, [
        "branch","file","state_scope","state_name","candidate_value","candidate_bit","xdata_addr","function_addr","branch_evidence","downstream_path","confidence","notes"
    ], state_rows)

    mode_rows = []
    for row in manual_rows:
        mode_rows.append(
            {
                "branch": row["branch"], "file": row["file"], "xdata_addr": row["xdata_addr"], "function_addr": row["function_addr"],
                "candidate_manual_value": row["mode_candidate_value"], "candidate_auto_value": "0x00", "candidate_manual_bit": row["mode_candidate_bit"],
                "candidate_auto_bit": "bit0=0", "manual_path": row["manual_path"], "auto_path": row["auto_path"],
                "manual_confidence": row["confidence"], "auto_confidence": row["confidence"], "notes": row["notes"],
            }
        )
    write_csv(args.out_mode, [
        "branch","file","xdata_addr","function_addr","candidate_manual_value","candidate_auto_value","candidate_manual_bit","candidate_auto_bit","manual_path","auto_path","manual_confidence","auto_confidence","notes"
    ], mode_rows)

    action_rows = []
    for row in output_rows:
        action_rows.append(
            {
                "branch": row["branch"], "file": row["file"], "function_addr": row["function_addr"], "action_candidate": row["action_candidate"],
                "score": "1.0", "confidence": row["confidence"], "xdata_reads": row["xdata_addr"], "xdata_writes": row["xdata_addr"],
                "related_mode_function": "0x728A", "related_packet_function": "0x5A7F", "possible_physical_action": "relay_or_extinguishing_control",
                "notes": row["notes"],
            }
        )
    write_csv(args.out_output_action, [
        "branch","file","function_addr","action_candidate","score","confidence","xdata_reads","xdata_writes","related_mode_function","related_packet_function","possible_physical_action","notes"
    ], action_rows)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = []
    md.append("# XDATA enum/branch resolution (deep milestone)")
    md.append(f"Date: {now}.")
    md.append("")
    md.append("## 1) XDATA lifecycle coverage")
    for r in lifecycle_rows:
        md.append(f"- `{r['xdata_addr']}`: reads={r['read_functions']}; writes={r['write_functions']}; branches={r['branch_functions']}; exports={r['export_functions']} ({r['confidence']}).")
    md.append("")
    md.append("## 2) 0x315B mode gate")
    md.append("- Main readers/branchers: `0x84A6`, `0x728A`.")
    md.append("- Manual-like path: event/packet-only -> `0x5A7F`.")
    md.append("- Auto-like path: `0x6833` output start -> `0x5A7F`.")
    md.append("")
    md.append("## 3) 0x30EA..0x30F9 cluster")
    md.append("- Used as sensor/zone state cluster with compare/update markers in `0x497A/0x737C/0x613C` chain.")
    md.append("")
    md.append("## 4) Output-side flags (0x3165/0x31BF/0x364B)")
    md.append("- Present in branch traces near output/packet bridge candidates; exact value semantics remain hypothesis without bench.")
    md.append("")
    md.append("## 5) Enum value mapping")
    for row in enum_rows:
        md.append(f"- {row['candidate_value']}: {row['probable_label']} -> fn {row['function_addr']} ({row['confidence']}).")
    md.append("")
    md.append("## 6) Manual-like vs auto-like")
    md.append("- manual-like event/packet path seen around `0x84A6/0x728A`.")
    md.append("- auto-like output path enters `0x6833` before packet/export.")
    md.append("")
    md.append("## 7) Output start and packet/export")
    md.append("- output start candidate: `0x6833`.")
    md.append("- packet/export sink candidate: `0x5A7F`.")
    md.append("")
    md.append("## 8) Unknowns")
    md.append("- Full bit-level decode of `0x315B` and all output-side flags.")
    md.append("- Complete enum decode requires bench traces.")
    md.append("")
    md.append("## 9) Priority bench tests")
    md.append("- Fire/attention/fault/disabled/not-detected/address-conflict transitions.")
    md.append("- Manual mode should avoid output-start; auto mode should hit `0x6833`.")
    md.append("- Compare exported packets via `0x5A7F` between both paths.")
    md.append("")
    md.append("## 10) Next manual decompile targets")
    md.append("1. `0x84A6`  2. `0x728A`  3. `0x6833`  4. `0x5A7F`  5. deep compares in `0x737C/0x613C`.")
    md.append("")
    md.append("## 11) ASCII model")
    md.append("```text")
    md.append("0x30EA..0x30F9 state byte/flags")
    md.append("  -> comparisons in 0x497A / 0x737C / 0x613C")
    md.append("  -> zone state path")
    md.append("  -> 0x84A6 / 0x728A mode gate")
    md.append("      -> manual-like: packet/event only -> 0x5A7F")
    md.append("      -> auto-like: output start -> 0x6833 -> packet/export -> 0x5A7F")
    md.append("```")
    if warnings:
        md.append("")
        md.append("## Warnings")
        for w in sorted(set(warnings)):
            md.append(f"- {w}")

    args.out_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"wrote {args.out_trace.relative_to(ROOT)}")
    print(f"wrote {args.out_enum_branch.relative_to(ROOT)}")
    print(f"wrote {args.out_manual_auto.relative_to(ROOT)}")
    print(f"wrote {args.out_output.relative_to(ROOT)}")
    print(f"wrote {args.out_md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
