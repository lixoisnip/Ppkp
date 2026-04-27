#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

PRIMARY_BRANCH = "90CYE_DKS"
PRIMARY_FILE = "90CYE03_19_DKS.PZU"
COMPARE_FILE = "90CYE04_19_DKS.PZU"
SHIFTED_BRANCH = "90CYE_shifted_DKS"
SHIFTED_FILE = "90CYE02_27 DKS.PZU"

REQUIRED_INPUTS = [
    "xdata_confirmed_access.csv",
    "xdata_xref.csv",
    "xdata_branch_trace_map.csv",
    "enum_branch_value_map.csv",
    "function_map.csv",
    "call_xref.csv",
    "basic_block_map.csv",
    "manual_dks_module_decompile_summary.csv",
    "manual_dks_module_pseudocode.csv",
    "manual_dks_downstream_decompile_summary.csv",
    "manual_dks_downstream_pseudocode.csv",
    "manual_decompile_0x728A_0x6833.md",
    "output_transition_map.csv",
    "manual_auto_branch_map.csv",
    "zone_to_output_chains.csv",
    "dks_real_configuration_evidence.csv",
    "dks_module_deep_trace_candidates.csv",
    "dks_module_slot_summary.csv",
]

FUNC_ORDER = ["0x497A", "0x737C", "0x613C", "0x84A6", "0x728A", "0x6833", "0x5A7F", "0x7922", "0x597F", "0x7DC2", "0x673C"]

ADDR_ROWS = [
    "0x3010", "0x3011", "0x3012", "0x3013", "0x3014", "0x301A", "0x301B",
    "0x315B", "0x3181", "0x30E7", "0x30E9", "0x30EA..0x30F9",
    "0x31BF", "0x3165", "0x3640", "0x364B", "0x36D3", "0x36D9", "0x36EC", "0x36EE", "0x36EF", "0x36F2", "0x36F3", "0x36F4", "0x36FC", "0x36FD",
    "0x3104",
]


def normalize_addr(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if ".." in value:
        left, right = value.split("..", 1)
        return f"{normalize_addr(left)}..{normalize_addr(right)}"
    if value.lower().startswith("0x"):
        try:
            return f"0x{int(value, 16):04X}"
        except ValueError:
            return value.upper()
    return value.upper()


def in_range(range_addr: str, probe: str) -> bool:
    if ".." not in range_addr:
        return normalize_addr(range_addr) == normalize_addr(probe)
    lo, hi = normalize_addr(range_addr).split("..", 1)
    try:
        pv = int(normalize_addr(probe), 16)
        return int(lo, 16) <= pv <= int(hi, 16)
    except ValueError:
        return False


def load_csv(path: Path, warnings: list[str]) -> list[dict[str, str]]:
    if not path.exists():
        warnings.append(f"⚠️ missing optional input: {path.relative_to(ROOT)}")
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_text(path: Path, warnings: list[str]) -> str:
    if not path.exists():
        warnings.append(f"⚠️ missing optional input: {path.relative_to(ROOT)}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def split_tokens(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for chunk in text.replace(",", "|").replace(";", "|").split("|"):
        token = chunk.strip()
        if token:
            out.append(token)
    return out


def uniq(items: list[str]) -> str:
    values = sorted({x for x in items if x and x != "-"})
    return "; ".join(values) if values else "-"


def cluster_for_addr(addr: str) -> str:
    n = normalize_addr(addr)
    if n == normalize_addr("0x30EA..0x30F9"):
        return "runtime_mode_flags"
    if n in {normalize_addr(x) for x in ["0x3010", "0x3011", "0x3012", "0x3013", "0x3014", "0x301A", "0x301B"]}:
        return "zone_object_state_table"
    if n in {normalize_addr(x) for x in ["0x315B", "0x3181", "0x30E7", "0x30E9"]} or in_range("0x30EA..0x30F9", n):
        return "runtime_mode_flags"
    if n in {normalize_addr(x) for x in ["0x31BF", "0x3165", "0x3640", "0x364B", "0x36D3", "0x36D9", "0x36EC", "0x36EE", "0x36EF", "0x36F2", "0x36F3", "0x36F4", "0x36FC", "0x36FD"]}:
        return "packet_output_context"
    if n == normalize_addr("0x3104"):
        return "shifted_object_status"
    return "unknown"


def confidence_for(evidence_level: str, count: int) -> str:
    if evidence_level == "manual_decompile":
        return "probable"
    if evidence_level == "direct_static" and count >= 2:
        return "low"
    if evidence_level == "chain_adjacency":
        return "low"
    return "hypothesis"


def main() -> int:
    p = argparse.ArgumentParser(description="Reconstruct DKS XDATA lifecycle from existing artifacts")
    p.add_argument("--out-md", type=Path, default=DOCS / "dks_xdata_lifecycle_analysis.md")
    p.add_argument("--out-matrix", type=Path, default=DOCS / "dks_xdata_lifecycle_matrix.csv")
    p.add_argument("--out-roles", type=Path, default=DOCS / "dks_xdata_function_roles.csv")
    p.add_argument("--out-probes", type=Path, default=DOCS / "dks_xdata_bench_probe_plan.csv")
    args = p.parse_args()

    warnings: list[str] = []
    rows: dict[str, list[dict[str, str]]] = {}
    for name in REQUIRED_INPUTS:
        path = DOCS / name
        if name.endswith(".md"):
            load_text(path, warnings)
            rows[name] = []
        else:
            rows[name] = load_csv(path, warnings)

    mod_sum = [r for r in rows["manual_dks_module_decompile_summary.csv"] if r.get("branch") in {PRIMARY_BRANCH, SHIFTED_BRANCH}]
    down_sum = [r for r in rows["manual_dks_downstream_decompile_summary.csv"] if r.get("branch") == PRIMARY_BRANCH]
    xtrace = [r for r in rows["xdata_branch_trace_map.csv"] if r.get("branch") == PRIMARY_BRANCH]
    xacc = [r for r in rows["xdata_confirmed_access.csv"] if r.get("branch") in {PRIMARY_BRANCH, SHIFTED_BRANCH}]
    enum_map = [r for r in rows["enum_branch_value_map.csv"] if r.get("branch") == PRIMARY_BRANCH]
    mode_map = [r for r in rows["manual_auto_branch_map.csv"] if r.get("branch") == PRIMARY_BRANCH]
    out_map = [r for r in rows["output_transition_map.csv"] if r.get("branch") == PRIMARY_BRANCH]

    fn_info: dict[str, dict[str, str]] = {}
    for r in mod_sum:
        fn_info[r.get("function_addr", "")] = {
            "manual_role": r.get("manual_role", "unknown"),
            "downstream_chain": r.get("downstream_chain", "-"),
            "confidence": r.get("confidence", "unknown"),
            "notes": r.get("notes", ""),
        }
    for r in down_sum:
        fn_info[r.get("function_addr", "")] = {
            "manual_role": r.get("new_manual_role", "unknown"),
            "downstream_chain": r.get("chain_relation", "-"),
            "confidence": r.get("confidence", "unknown"),
            "notes": r.get("notes", ""),
        }

    address_rows: list[dict[str, str]] = []

    for addr in ADDR_ROWS:
        cluster = cluster_for_addr(addr)
        writer_set: list[str] = []
        reader_set: list[str] = []
        branch_users: list[str] = []
        downstream_functions: list[str] = []
        packet_adj: list[str] = []
        notes: list[str] = []

        for r in down_sum:
            fn = r.get("function_addr", "")
            refs = split_tokens(r.get("xdata_refs", ""))
            for ref in refs:
                if (".." in addr and in_range(addr, ref)) or normalize_addr(ref) == normalize_addr(addr):
                    manual_notes = r.get("notes", "")
                    downstream_functions.append(fn)
                    if "writes" in manual_notes and normalize_addr(addr) in manual_notes.upper():
                        writer_set.append(fn)
                    if "reads" in manual_notes and normalize_addr(addr) in manual_notes.upper():
                        reader_set.append(fn)
                    if fn == "0x737C" and cluster == "zone_object_state_table":
                        writer_set.append(fn)
                        reader_set.append(fn)
                    if fn == "0x84A6" and normalize_addr(addr) in {"0x315B", "0x3181", "0x3640", "0x36D3", "0x36D9"}:
                        reader_set.append(fn)
                    notes.append(manual_notes)

        for r in mod_sum:
            fn = r.get("function_addr", "")
            refs = split_tokens(r.get("xdata_refs", ""))
            for ref in refs:
                if normalize_addr(ref) == normalize_addr(addr):
                    downstream_functions.append(fn)
                    if fn == "0x497A" and normalize_addr(addr) == "0x31BF":
                        reader_set.append(fn)
                        branch_users.append(fn)
                    if fn == "0x673C" and normalize_addr(addr) == "0x3104":
                        writer_set.append(fn)
                        reader_set.append(fn)
                    notes.append(r.get("notes", ""))

        for r in xtrace:
            xa = r.get("xdata_addr", "")
            if (".." in addr and in_range(addr, xa)) or normalize_addr(xa) == normalize_addr(addr):
                fn = r.get("function_addr", "")
                at = (r.get("access_type", "") or "").lower()
                if fn and fn != "-":
                    downstream_functions.append(fn)
                if "write" in at and fn and fn != "-":
                    writer_set.append(fn)
                if "read" in at and fn and fn != "-":
                    reader_set.append(fn)
                if r.get("branch_type", "") not in {"", "-", "xdata_read"} and fn and fn != "-":
                    branch_users.append(fn)
                if r.get("downstream_function") not in {"", "-"}:
                    downstream_functions.append(r.get("downstream_function", ""))

        for r in mode_map:
            xa = r.get("xdata_addr", "")
            if normalize_addr(xa) == normalize_addr(addr):
                branch_users.append(r.get("function_addr", ""))
                downstream_functions.extend(split_tokens(r.get("manual_downstream", "")))
                downstream_functions.extend(split_tokens(r.get("auto_downstream", "")))
                packet_adj.append("manual_auto_branch_map")

        for r in out_map:
            xa = r.get("xdata_addr", "")
            if normalize_addr(xa) == normalize_addr(addr):
                fn = r.get("function_addr", "")
                if fn:
                    branch_users.append(fn)
                downstream_functions.extend(split_tokens(r.get("call_target", "")))
                if r.get("packet_export_seen", "").lower() == "yes":
                    packet_adj.append(f"{fn}->packet_export")

        if normalize_addr(addr) in {"0x3010", "0x3011", "0x3012", "0x3013", "0x3014", "0x301A", "0x301B"}:
            packet_adj.append("0x737C->0x5A7F chain adjacency")
        if normalize_addr(addr) in {"0x31BF", "0x364B", "0x36D3", "0x36D9", "0x36EC", "0x36EE", "0x36EF", "0x36F2", "0x36F3", "0x36F4", "0x36FC", "0x36FD", "0x3640"}:
            packet_adj.append("packet/export context neighbor")
        if normalize_addr(addr) == "0x30E7":
            branch_users.append("0x728A")
            notes.append("0x728A checks E0/E1/E2 bits and updates this byte in selected paths")
        if normalize_addr(addr) == "0x30E9":
            writer_set.append("0x728A")
            reader_set.append("0x728A")
            notes.append("0x30E9 appears in 0x728A branch side-path storage")
        if normalize_addr(addr) == "0x364B":
            downstream_functions.extend(["0x728A", "0x6833", "0x5A7F"])
            notes.append("manual decompile places 0x364B near 0x728A/0x6833/0x5A7F transition")

        enum_values = sorted({e.get("candidate_value", "") for e in enum_map if e.get("function_addr") == "0x737C" and e.get("candidate_value") in {"0x03", "0x07"}})
        if cluster == "zone_object_state_table" and enum_values:
            notes.append(f"enum-like values near 0x737C: {', '.join(enum_values)}")

        evidence_level = "unknown"
        if writer_set or reader_set:
            evidence_level = "direct_static"
        if any(normalize_addr(addr) in normalize_addr(x) or (".." in addr and in_range(addr, x)) for r in down_sum for x in split_tokens(r.get("xdata_refs", ""))):
            evidence_level = "manual_decompile"
        elif downstream_functions:
            evidence_level = "chain_adjacency"

        current_role = {
            "zone_object_state_table": "zone/object state field candidate",
            "runtime_mode_flags": "runtime/mode gate flag candidate",
            "packet_output_context": "packet/output context candidate",
            "shifted_object_status": "shifted object-status byte candidate",
            "unknown": "unresolved",
        }[cluster]

        address_rows.append(
            {
                "branch": PRIMARY_BRANCH if cluster != "shifted_object_status" else SHIFTED_BRANCH,
                "file": PRIMARY_FILE if cluster != "shifted_object_status" else SHIFTED_FILE,
                "xdata_addr": normalize_addr(addr),
                "cluster": cluster,
                "access_type": "read_write" if writer_set and reader_set else "write" if writer_set else "read" if reader_set else "indirect_context" if downstream_functions else "unknown",
                "functions": uniq(writer_set + reader_set + branch_users + downstream_functions),
                "known_writers": uniq(writer_set),
                "known_readers": uniq(reader_set),
                "branch_users": uniq(branch_users),
                "downstream_functions": uniq(downstream_functions),
                "packet_export_adjacency": uniq(packet_adj),
                "current_role": current_role,
                "confidence": confidence_for(evidence_level, len(writer_set) + len(reader_set) + len(downstream_functions)),
                "evidence_level": evidence_level,
                "notes": uniq(notes),
            }
        )

    matrix_fields = [
        "branch", "file", "xdata_addr", "cluster", "access_type", "functions", "known_writers", "known_readers", "branch_users",
        "downstream_functions", "packet_export_adjacency", "current_role", "confidence", "evidence_level", "notes",
    ]
    args.out_matrix.parent.mkdir(parents=True, exist_ok=True)
    with args.out_matrix.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=matrix_fields)
        w.writeheader()
        w.writerows(address_rows)

    by_function_reads: dict[str, list[str]] = defaultdict(list)
    by_function_writes: dict[str, list[str]] = defaultdict(list)
    by_function_branches: dict[str, list[str]] = defaultdict(list)
    for row in address_rows:
        addr = row["xdata_addr"]
        for fn in split_tokens(row["known_readers"]):
            by_function_reads[fn].append(addr)
        for fn in split_tokens(row["known_writers"]):
            by_function_writes[fn].append(addr)
        for fn in split_tokens(row["branch_users"]):
            by_function_branches[fn].append(addr)

    role_rows: list[dict[str, str]] = []
    for fn in FUNC_ORDER:
        info = fn_info.get(fn, {"manual_role": "unknown", "downstream_chain": "-", "confidence": "unknown", "notes": ""})
        if fn == "0x6833":
            info = {
                "manual_role": "output_start_entry",
                "downstream_chain": "0x6833->0x7922->0x597F->0x5A7F->0x7DC2",
                "confidence": "probable",
                "notes": "manual_decompile_0x728A_0x6833.md: output-start marker write XDATA[dptr]=0x04 candidate",
            }
        if fn == "0x728A" and info["manual_role"] == "unknown":
            info = {
                "manual_role": "mode_gate",
                "downstream_chain": "0x728A->0x5A7F and 0x728A->0x6833",
                "confidence": "probable",
                "notes": "manual decompile indicates E0/E1/E2 bit-gated branches on 0x30E7",
            }
        clusters = sorted({cluster_for_addr(a) for a in by_function_reads[fn] + by_function_writes[fn] + by_function_branches[fn] if a})
        role_rows.append(
            {
                "branch": PRIMARY_BRANCH if fn != "0x673C" else SHIFTED_BRANCH,
                "file": PRIMARY_FILE if fn != "0x673C" else SHIFTED_FILE,
                "function_addr": fn,
                "manual_role": info.get("manual_role", "unknown"),
                "xdata_reads": uniq(by_function_reads[fn]),
                "xdata_writes": uniq(by_function_writes[fn]),
                "xdata_branches": uniq(by_function_branches[fn]),
                "important_xdata_clusters": "; ".join(clusters) if clusters else "unknown",
                "downstream_chain": info.get("downstream_chain", "-"),
                "confidence": info.get("confidence", "unknown"),
                "notes": info.get("notes", ""),
            }
        )

    with args.out_roles.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "branch", "file", "function_addr", "manual_role", "xdata_reads", "xdata_writes", "xdata_branches",
                "important_xdata_clusters", "downstream_chain", "confidence", "notes",
            ],
        )
        w.writeheader()
        w.writerows(role_rows)

    probe_rows = [
        {
            "probe_id": "P01", "scenario": "manual_fire_event_only", "watch_xdata": "0x315B;0x3181;0x30E7;0x30E9;0x3640",
            "expected_change": "manual path should favor event/packet branch without output-start sequence", "related_function": "0x84A6;0x728A",
            "validation_goal": "validate mode/event bridge split vs output-start bypass", "confidence": "low", "notes": "focus on 0x30E7 E0/E1/E2 bit transitions",
        },
        {
            "probe_id": "P02", "scenario": "auto_fire_output_start", "watch_xdata": "0x30E7;0x30E9;0x364B;0x31BF",
            "expected_change": "auto-like path reaches 0x6833 then downstream write marker path", "related_function": "0x728A;0x6833;0x7DC2",
            "validation_goal": "confirm output-start entry and downstream transition adjacency", "confidence": "low", "notes": "watch for path including 0x7922/0x597F/0x5A7F",
        },
        {
            "probe_id": "P03", "scenario": "zone_fault", "watch_xdata": "0x3010;0x3011;0x3012;0x3013;0x3014;0x301A;0x301B",
            "expected_change": "0x737C updates zone/object state table fields with fault-like class", "related_function": "0x737C",
            "validation_goal": "map writer/reader lifecycle for zone/object table in fault transitions", "confidence": "low", "notes": "enum-like candidates include 0x03/0x07 only",
        },
        {
            "probe_id": "P04", "scenario": "zone_service", "watch_xdata": "0x3010;0x3011;0x3012;0x3013;0x3014;0x301A;0x301B",
            "expected_change": "service-class transitions alter same state table region", "related_function": "0x737C;0x84A6",
            "validation_goal": "confirm service path and mode-event bridge adjacency", "confidence": "low", "notes": "avoid assigning physical tag meaning",
        },
        {
            "probe_id": "P05", "scenario": "disabled_or_absent_sensor", "watch_xdata": "0x30EA..0x30F9;0x31BF;0x36D3..0x36FD",
            "expected_change": "runtime cluster and context selector bytes should shift across disabled/absent state", "related_function": "0x737C;0x497A",
            "validation_goal": "strengthen weak mapping for 0x30EA..0x30F9 and 0x36xx context", "confidence": "hypothesis", "notes": "collect pre/post snapshots",
        },
        {
            "probe_id": "P06", "scenario": "packet_export_after_event", "watch_xdata": "0x31BF;0x364B;0x36D3;0x36EC;0x36FD",
            "expected_change": "context values should align before 0x5A7F calls after event/output transitions", "related_function": "0x737C;0x728A;0x6833;0x5A7F",
            "validation_goal": "verify packet/export adjacency and pointer-like bridge behavior", "confidence": "low", "notes": "0x5A7F treated as bridge, not full packet builder",
        },
        {
            "probe_id": "P07", "scenario": "90CYE02_object_status_change", "watch_xdata": "0x3104",
            "expected_change": "0x673C updates status byte around object-status transitions", "related_function": "0x673C",
            "validation_goal": "confirm shifted object-status layer candidate in 90CYE02", "confidence": "probable", "notes": "90SAE linkage remains indirect",
        },
    ]

    with args.out_probes.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["probe_id", "scenario", "watch_xdata", "expected_change", "related_function", "validation_goal", "confidence", "notes"])
        w.writeheader()
        w.writerows(probe_rows)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    warnings_md = "\n".join(f"- {w}" for w in warnings) if warnings else "- none"

    lines: list[str] = []
    lines.append("# DKS XDATA lifecycle analysis")
    lines.append(f"Date: {now}.")
    lines.append("")
    lines.append("## Scope")
    lines.append("- This report is static lifecycle reconstruction only.")
    lines.append("- It does **not** prove physical semantics or field wiring meaning.")
    lines.append("- It combines direct XDATA access evidence, manual decompile summaries, and chain adjacency.")
    lines.append("- Firmware families are not collapsed; 90CYE02 shifted-object layer is kept separate from 90CYE_DKS semantics.")
    lines.append("")
    lines.append("## Input status / missing optional artifacts")
    lines.append(warnings_md)
    lines.append("")
    lines.append("## Key XDATA clusters")
    lines.append("- `zone_object_state_table`: `0x3010..0x301B` (focus: 0x3010/11/12/13/14/1A/1B).")
    lines.append("- `runtime_mode_flags`: `0x315B`, `0x3181`, `0x30E7`, `0x30E9`, `0x30EA..0x30F9`.")
    lines.append("- `packet_output_context`: `0x31BF`, `0x3165`, `0x3640`, `0x364B`, `0x36D3..0x36FD` subset.")
    lines.append("- `shifted_object_status`: `0x3104` in `90CYE02_27 DKS.PZU`.")
    lines.append("- `unknown_or_unresolved`: addresses with only weak adjacency or indirect context.")
    lines.append("")

    lines.append("## XDATA lifecycle table")
    lines.append("| address | cluster | known_writers | known_readers | branch_users | downstream_functions | packet_export_adjacency | current_role | confidence | evidence_level | notes |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in address_rows:
        lines.append(
            f"| {r['xdata_addr']} | {r['cluster']} | {r['known_writers']} | {r['known_readers']} | {r['branch_users']} | {r['downstream_functions']} | {r['packet_export_adjacency']} | {r['current_role']} | {r['confidence']} | {r['evidence_level']} | {r['notes']} |"
        )
    lines.append("")

    lines.append("## Zone/object state table: 0x3010..0x301B")
    lines.append("- `0x737C` reads/writes this region in manual downstream reconstruction.")
    lines.append("- `0x737C` is treated as probable zone/object state updater.")
    lines.append("- `0x737C` calls `0x84A6` and `0x5A7F` in same downstream adjacency chain.")
    lines.append("- Current enum-like values observed near this logic: `0x03` and `0x07`.")
    lines.append("- Physical meaning remains cautious (attention/service/fault-like classes only as hypothesis).")
    lines.append("")

    lines.append("## Runtime/mode flags")
    lines.append("- `0x315B`: read in `0x84A6` and appears in mode-gate maps (possible config/mode flag; potential contributor to `0x30E7` handling remains hypothesis).")
    lines.append("- `0x3181`: read by `0x84A6`; current role unresolved side mode/event flag.")
    lines.append("- `0x30E7`: read/updated in `0x728A`; bits `E0/E1/E2` gate manual-decompiled branch paths.")
    lines.append("- `0x30E9`: updated/used inside `0x728A` paths; probable side mode/state byte.")
    lines.append("- `0x30EA..0x30F9`: still a cluster candidate with weak direct writer/reader attribution in this focused lifecycle output.")
    lines.append("")

    lines.append("## Packet/output context")
    lines.append("- `0x31BF`: read by `0x497A` and `0x737C`; probable selector/context byte.")
    lines.append("- `0x3640`: read by `0x84A6`; possible mode/event-side context.")
    lines.append("- `0x364B`: appears around `0x728A` / `0x6833` / `0x5A7F` paths; likely context selector for packet/output transition.")
    lines.append("- `0x36D3..0x36FD` subset: used by `0x737C` and `0x84A6`; likely object/zone context cluster with unknown schema.")
    lines.append("")

    lines.append("## 90CYE02 object-status XDATA")
    lines.append("- `0x673C` uses `0x3104` in `90CYE02_27 DKS.PZU`.")
    lines.append("- Current role: `object_status_updater` candidate.")
    lines.append("- Link to visible `90SAE...` tags is indirect only; no direct tag-binding proof in static artifacts.")
    lines.append("")

    lines.append("## Lifecycle graph")
    lines.append("```text")
    lines.append("0x36xx / 0x31BF context")
    lines.append("  -> 0x737C zone/object logic [manual_decompile]")
    lines.append("      -> writes 0x3010..0x301B [manual_decompile]")
    lines.append("      -> calls 0x84A6 [chain_adjacency]")
    lines.append("      -> packet bridge via 0x5A7F [chain_adjacency]")
    lines.append("")
    lines.append("0x315B / 0x3181 / 0x3640")
    lines.append("  -> 0x84A6 mode/event bridge [manual_decompile]")
    lines.append("      -> 0x728A mode gate [manual_decompile]")
    lines.append("          reads 0x30E7, 0x30A2 [manual_decompile]")
    lines.append("          updates 0x30E7 / 0x30E9 [manual_decompile]")
    lines.append("          manual-like -> 0x5A7F [chain_adjacency]")
    lines.append("          auto-like -> 0x6833 [manual_decompile]")
    lines.append("              -> 0x7922 [manual_decompile]")
    lines.append("              -> 0x597F [manual_decompile]")
    lines.append("              -> XDATA[dptr] = 0x04 [manual_decompile]")
    lines.append("              -> 0x5A7F [chain_adjacency]")
    lines.append("              -> 0x7DC2 [chain_adjacency]")
    lines.append("")
    lines.append("0x3104")
    lines.append("  -> 0x673C object/status updater [direct_static + manual_decompile]")
    lines.append("      -> 90CYE02 object-status layer candidate [hypothesis]")
    lines.append("```")
    lines.append("")

    lines.append("## Confidence updates")
    lines.append("| address | previous_role | new_lifecycle_role | confidence_change | reason |")
    lines.append("|---|---|---|---|---|")
    lines.append("| 0x3010..0x301B | generic state cluster | zone/object state table candidates tied to 0x737C | up (hypothesis -> probable) | manual downstream decompile explicitly ties reads/writes and calls to 0x84A6/0x5A7F |")
    lines.append("| 0x30E7 | state byte candidate | runtime mode-gate flag byte used by 0x728A E0/E1/E2 | up (low -> probable) | manual decompile control-point evidence for JNB gates and write-back paths |")
    lines.append("| 0x30E9 | unknown side byte | 0x728A side-path state/mode byte | up (hypothesis -> low) | manual 0x728A pseudocode includes repeated writes |")
    lines.append("| 0x31BF | generic runtime context | packet/output selector-context byte adjacent to 0x497A/0x737C | stable low | direct reads in trace map + downstream context relation |")
    lines.append("| 0x364B | unknown pointer arg | packet/output transition context around 0x728A/0x6833/0x5A7F | up (hypothesis -> low) | manual decompile adjacency around output-start path |")
    lines.append("| 0x3104 (90CYE02) | shifted status byte | object-status layer candidate used by 0x673C | up (probable -> probable) | retained from module manual decompile; separate family context |")
    lines.append("")

    lines.append("## Unknowns and bench validation")
    lines.append("- Trace writes to `0x3010..0x301B` during fire/fault/service transitions.")
    lines.append("- Trace `0x315B/0x3181` before manual/auto mode changes.")
    lines.append("- Trace `0x30E7` bits `E0/E1/E2` before/after `0x728A`.")
    lines.append("- Trace `0x30E9` around `0x728A` branch paths.")
    lines.append("- Trace `0x31BF/0x364B` around packet/export transitions.")
    lines.append("- Trace `0x3104` on 90CYE02 object-state changes.")

    args.out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote: {args.out_md.relative_to(ROOT)}")
    print(f"Wrote: {args.out_matrix.relative_to(ROOT)}")
    print(f"Wrote: {args.out_roles.relative_to(ROOT)}")
    print(f"Wrote: {args.out_probes.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
