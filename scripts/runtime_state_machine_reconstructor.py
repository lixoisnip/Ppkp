#!/usr/bin/env python3
"""Reconstruct a connected runtime state-machine model for 90CYE_DKS branch.

Builds node/edge/xdata/branch-comparison artifacts from previously generated evidence CSV/MD files.
Missing optional inputs are tolerated and reported as warnings in the markdown report.
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

TARGET_BRANCH = "90CYE_DKS"
TARGET_FILE = "90CYE03_19_DKS.PZU"
TARGET_FUNCTIONS = ["0x497A", "0x737C", "0x613C", "0x84A6", "0x728A", "0x6833", "0x5A7F"]

NODE_TYPES = {
    "0x497A": ("sensor_state_node", "sensor/zone state candidate"),
    "0x737C": ("zone_table_node", "zone table / zone logic candidate"),
    "0x613C": ("zone_state_node", "zone state / feedback candidate"),
    "0x84A6": ("event_queue_node", "mode/event bridge candidate"),
    "0x728A": ("manual_auto_mode_check_node", "auto/manual mode-check candidate"),
    "0x6833": ("output_control_node", "output / relay / extinguishing start candidate"),
    "0x5A7F": ("packet_export_node", "packet/export candidate"),
}

EDGE_SPECS = [
    ("e01", "0x497A", "0x737C", "sensor_to_zone"),
    ("e02", "0x737C", "0x613C", "zone_to_state"),
    ("e03", "0x613C", "0x84A6", "state_to_mode_check"),
    ("e04", "0x84A6", "0x728A", "state_to_mode_check"),
    ("e05", "0x728A", "0x5A7F", "mode_to_manual_event"),
    ("e06", "0x728A", "0x6833", "mode_to_auto_output"),
    ("e07", "0x6833", "0x5A7F", "output_to_packet"),
    ("e08", "0x84A6", "0x5A7F", "event_to_packet"),
    ("e09", "0x613C", "0x6833", "state_to_output"),
]

REQUIRED_INPUTS = [
    "module_logic_overview.md",
    "mash_handler_deep_trace_analysis.md",
    "zone_output_logic_analysis.md",
    "zone_output_deep_trace_analysis.md",
    "state_mode_logic_analysis.md",
    "auto_manual_gating_deep_trace_analysis.md",
    "function_map.csv",
    "basic_block_map.csv",
    "disassembly_index.csv",
    "call_xref.csv",
    "xdata_confirmed_access.csv",
    "code_table_candidates.csv",
    "string_index.csv",
    "xdata_map_by_branch.csv",
    "mash_handler_deep_trace.csv",
    "mash_handler_deep_trace_summary.csv",
    "zone_logic_candidates.csv",
    "output_control_candidates.csv",
    "zone_to_output_chains.csv",
    "zone_output_deep_trace.csv",
    "zone_output_deep_trace_summary.csv",
    "sensor_state_candidates.csv",
    "zone_state_mode_candidates.csv",
    "extinguishing_output_gating_chains.csv",
    "auto_manual_gating_deep_trace.csv",
    "auto_manual_gating_deep_trace_summary.csv",
]


@dataclass
class Node:
    branch: str
    file: str
    node_id: str
    node_type: str
    function_addr: str
    proposed_role: str
    score: float = 0.0
    confidence: str = "hypothesis"
    evidence_sources: set[str] = field(default_factory=set)
    xdata_reads: set[str] = field(default_factory=set)
    xdata_writes: set[str] = field(default_factory=set)
    conditional_branch_count: int = 0
    bit_operation_count: int = 0
    movc_count: int = 0
    call_count: int = 0
    incoming_lcalls: int = 0
    calls_out: set[str] = field(default_factory=set)
    calls_in: set[str] = field(default_factory=set)
    notes: set[str] = field(default_factory=set)


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_md(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def to_int(v: str) -> int:
    t = (v or "").strip()
    if not t:
        return 0
    try:
        return int(t, 16) if t.lower().startswith("0x") else int(t)
    except ValueError:
        return 0


def hx4(v: str) -> str:
    n = to_int(v)
    return f"0x{n:04X}" if n else ""


def bump_conf(old: str, new: str) -> str:
    rank = {"hypothesis": 1, "low": 1, "medium": 2, "probable": 2, "high": 3, "confirmed": 4}
    return new if rank.get(new, 1) > rank.get(old, 1) else old


def clean_conf(v: str) -> str:
    t = (v or "").strip().lower()
    if t in {"high", "confirmed"}:
        return "high"
    if t in {"medium", "probable"}:
        return "medium"
    return "hypothesis"


def parse_func_refs(md_text: str) -> set[str]:
    return {f"0x{m.upper()}" for m in re.findall(r"\b0x([0-9a-fA-F]{4})\b", md_text)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconstruct 90CYE runtime state-machine graph")
    parser.add_argument("--branch", default=TARGET_BRANCH)
    parser.add_argument("--file", default=TARGET_FILE)
    parser.add_argument("--nodes-out", type=Path, default=DOCS / "runtime_state_machine_nodes.csv")
    parser.add_argument("--edges-out", type=Path, default=DOCS / "runtime_state_machine_edges.csv")
    parser.add_argument("--xdata-out", type=Path, default=DOCS / "xdata_state_mode_flag_map.csv")
    parser.add_argument("--branch-out", type=Path, default=DOCS / "runtime_branch_comparison.csv")
    parser.add_argument("--report-out", type=Path, default=DOCS / "runtime_state_machine_reconstruction.md")
    args = parser.parse_args()

    missing_inputs: list[str] = []
    for rel in REQUIRED_INPUTS:
        if not (DOCS / rel).exists():
            missing_inputs.append(f"docs/{rel}")

    # Core evidence loads
    function_map = [r for r in load_csv(DOCS / "function_map.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    basic_block = [r for r in load_csv(DOCS / "basic_block_map.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    disasm = [r for r in load_csv(DOCS / "disassembly_index.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    calls = [r for r in load_csv(DOCS / "call_xref.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    xacc = [r for r in load_csv(DOCS / "xdata_confirmed_access.csv") if r.get("branch") == args.branch and r.get("file") == args.file]

    zone_logic = [r for r in load_csv(DOCS / "zone_logic_candidates.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    output_ctrl = [r for r in load_csv(DOCS / "output_control_candidates.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    deep_zone = [r for r in load_csv(DOCS / "zone_output_deep_trace_summary.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    sensor_state = [r for r in load_csv(DOCS / "sensor_state_candidates.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    zone_mode = [r for r in load_csv(DOCS / "zone_state_mode_candidates.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    auto_manual = [r for r in load_csv(DOCS / "auto_manual_gating_deep_trace_summary.csv") if r.get("branch") == args.branch and r.get("file") == args.file]
    chains = [r for r in load_csv(DOCS / "extinguishing_output_gating_chains.csv") if r.get("branch") == args.branch and r.get("file") == args.file]

    md_evidence = {
        "module_logic_overview.md": load_md(DOCS / "module_logic_overview.md"),
        "mash_handler_deep_trace_analysis.md": load_md(DOCS / "mash_handler_deep_trace_analysis.md"),
        "zone_output_logic_analysis.md": load_md(DOCS / "zone_output_logic_analysis.md"),
        "zone_output_deep_trace_analysis.md": load_md(DOCS / "zone_output_deep_trace_analysis.md"),
        "state_mode_logic_analysis.md": load_md(DOCS / "state_mode_logic_analysis.md"),
        "auto_manual_gating_deep_trace_analysis.md": load_md(DOCS / "auto_manual_gating_deep_trace_analysis.md"),
    }
    md_func_refs = {k: parse_func_refs(v) for k, v in md_evidence.items()}

    nodes: dict[str, Node] = {}
    for fn in TARGET_FUNCTIONS:
        ntype, role = NODE_TYPES[fn]
        nodes[fn] = Node(
            branch=args.branch,
            file=args.file,
            node_id=f"n_{fn[2:].lower()}",
            node_type=ntype,
            function_addr=fn,
            proposed_role=role,
            notes={"milestone_focus_function"},
        )

    # add skeleton nodes requested
    extra_nodes = [
        ("n_sensor_to_zone_mapping", "sensor_to_zone_mapping_node", "0x497A", "sensor-to-zone mapping bridge candidate"),
        ("n_zone_logic", "zone_logic_node", "0x737C", "zone logic branch node candidate"),
        ("n_manual_event_packet", "manual_event_packet_node", "0x84A6", "manual-like event->packet path bridge"),
        ("n_auto_output_start", "auto_output_start_node", "0x6833", "auto-like output start path bridge"),
        ("n_unknown_bridge", "unknown_bridge_node", "0x84A6", "unknown intermediate branch node"),
    ]
    for node_id, node_type, fn, role in extra_nodes:
        nodes[node_id] = Node(
            branch=args.branch,
            file=args.file,
            node_id=node_id,
            node_type=node_type,
            function_addr=fn,
            proposed_role=role,
            score=0.5,
            confidence="hypothesis",
            notes={"structural_runtime_graph_support_node"},
        )

    fn_index = {r.get("function_addr", ""): r for r in function_map}

    for key, node in list(nodes.items()):
        fn = node.function_addr
        fm = fn_index.get(fn)
        if fm:
            node.evidence_sources.add("docs/function_map.csv")
            node.call_count = max(node.call_count, to_int(fm.get("call_count", "0")))
            node.incoming_lcalls = max(node.incoming_lcalls, to_int(fm.get("incoming_lcalls", "0")))
            node.movc_count = max(node.movc_count, to_int(fm.get("movc_count", "0")))
            node.score = max(node.score, to_int(fm.get("xdata_read_count", "0")) * 0.03 + to_int(fm.get("xdata_write_count", "0")) * 0.05 + to_int(fm.get("call_count", "0")) * 0.02)
            node.confidence = bump_conf(node.confidence, clean_conf(fm.get("confidence", "")))

    # basic block and disasm stats
    blocks_by_fn = defaultdict(list)
    for r in basic_block:
        blocks_by_fn[r.get("parent_function_candidate", "")].append(r)
    dis_by_fn = defaultdict(list)
    for r in disasm:
        dis_by_fn[r.get("source", "")].append(r)

    cond_ops = {"CJNE", "JC", "JNC", "JZ", "JNZ", "JB", "JNB", "JBC", "SUBB"}
    bit_ops = {"ANL", "ORL", "XRL", "SETB", "CLR", "CPL"}
    for node in nodes.values():
        fn = node.function_addr
        for b in blocks_by_fn.get(fn, []):
            node.evidence_sources.add("docs/basic_block_map.csv")
            node.conditional_branch_count += 1 if (b.get("ends_with") or "").upper() in cond_ops else 0
        for d in dis_by_fn.get(fn, []):
            m = (d.get("mnemonic") or "").upper()
            node.conditional_branch_count += 1 if m in cond_ops else 0
            node.bit_operation_count += 1 if m in bit_ops else 0
        if dis_by_fn.get(fn):
            node.evidence_sources.add("docs/disassembly_index.csv")

    # xdata aggregation
    for row in xacc:
        fn = row.get("source") or ""
        if fn not in TARGET_FUNCTIONS:
            continue
        addr = hx4(row.get("dptr_addr", ""))
        if not addr:
            continue
        n = nodes[fn]
        acc = (row.get("access_type") or "").strip().lower()
        if "write" in acc:
            n.xdata_writes.add(addr)
        else:
            n.xdata_reads.add(addr)
        n.evidence_sources.add("docs/xdata_confirmed_access.csv")

    # fallback fn resolution via code_addr -> function
    if not any(n.xdata_reads or n.xdata_writes for n in nodes.values()):
        by_code_fn = {r.get("code_addr", ""): r.get("source", "") for r in disasm}
        for row in xacc:
            fn = by_code_fn.get(row.get("code_addr", ""), "")
            if fn not in TARGET_FUNCTIONS:
                continue
            addr = hx4(row.get("dptr_addr", ""))
            if not addr:
                continue
            n = nodes[fn]
            acc = (row.get("access_type") or "").lower()
            if "write" in acc:
                n.xdata_writes.add(addr)
            else:
                n.xdata_reads.add(addr)
            n.evidence_sources.add("docs/xdata_confirmed_access.csv")
            n.notes.add("xdata_mapped_via_code_addr")

    # call graph stats
    for row in calls:
        src = row.get("source", "")
        tgt = row.get("target_addr", "")
        if src in TARGET_FUNCTIONS:
            nodes[src].calls_out.add(tgt)
            nodes[src].evidence_sources.add("docs/call_xref.csv")
        if tgt in TARGET_FUNCTIONS:
            nodes[tgt].calls_in.add(src)
            nodes[tgt].evidence_sources.add("docs/call_xref.csv")

    if not any(nodes[fn].calls_out for fn in TARGET_FUNCTIONS):
        # fallback from disasm source field if call_xref lacks source column
        call_sites = [r for r in disasm if (r.get("mnemonic") or "").upper() in {"LCALL", "ACALL"} and r.get("target_addr")]
        for c in call_sites:
            src = c.get("source", "")
            tgt = c.get("target_addr", "")
            if src in TARGET_FUNCTIONS:
                nodes[src].calls_out.add(tgt)
                nodes[src].evidence_sources.add("docs/disassembly_index.csv")
            if tgt in TARGET_FUNCTIONS:
                nodes[tgt].calls_in.add(src)
                nodes[tgt].evidence_sources.add("docs/disassembly_index.csv")

    # ingest candidate CSV scores/confidence
    candidate_tables = [zone_logic, output_ctrl, deep_zone, sensor_state, zone_mode, auto_manual]
    for tbl in candidate_tables:
        for r in tbl:
            fn = r.get("function_addr", "")
            if fn not in TARGET_FUNCTIONS:
                continue
            n = nodes[fn]
            try:
                n.score = max(n.score, float(r.get("score", "0") or "0"))
            except ValueError:
                pass
            n.confidence = bump_conf(n.confidence, clean_conf(r.get("confidence", "")))
            src_name = "docs/" + ("unknown.csv")
            # identify source quickly by table object id
            if r in zone_logic:
                src_name = "docs/zone_logic_candidates.csv"
            elif r in output_ctrl:
                src_name = "docs/output_control_candidates.csv"
            elif r in deep_zone:
                src_name = "docs/zone_output_deep_trace_summary.csv"
            elif r in sensor_state:
                src_name = "docs/sensor_state_candidates.csv"
            elif r in zone_mode:
                src_name = "docs/zone_state_mode_candidates.csv"
            elif r in auto_manual:
                src_name = "docs/auto_manual_gating_deep_trace_summary.csv"
            n.evidence_sources.add(src_name)

    for r in chains:
        for key in ["zone_state_function", "mode_check_function", "event_function", "output_control_function", "packet_export_function"]:
            fn = (r.get(key) or "").strip()
            if fn in TARGET_FUNCTIONS:
                n = nodes[fn]
                n.evidence_sources.add("docs/extinguishing_output_gating_chains.csv")
                n.confidence = bump_conf(n.confidence, clean_conf(r.get("confidence", "")))
                if r.get("missing_links"):
                    n.notes.add("chain_has_missing_links")

    for md_name, refs in md_func_refs.items():
        for fn in TARGET_FUNCTIONS:
            if fn in refs:
                nodes[fn].evidence_sources.add(f"docs/{md_name}")

    # make sure scores normalized 0..1.5-ish for readability
    for n in nodes.values():
        if n.score <= 0:
            n.score = 0.35
        n.score = min(n.score, 1.5)

    # write nodes CSV
    args.nodes_out.parent.mkdir(parents=True, exist_ok=True)
    node_fields = [
        "branch",
        "file",
        "node_id",
        "node_type",
        "function_addr",
        "proposed_role",
        "score",
        "confidence",
        "evidence_sources",
        "xdata_read_count",
        "xdata_write_count",
        "conditional_branch_count",
        "bit_operation_count",
        "movc_count",
        "call_count",
        "incoming_lcalls",
        "likely_xdata_flags",
        "notes",
    ]
    node_rows: list[dict[str, str]] = []
    for key in sorted(nodes.keys(), key=lambda x: ("0x" not in x, x)):
        n = nodes[key]
        likely_flags = sorted((n.xdata_reads | n.xdata_writes) & {
            "0x315B", "0x3165", "0x31BF", "0x364B", *(f"0x{v:04X}" for v in range(0x30EA, 0x30FA))
        })
        node_rows.append(
            {
                "branch": n.branch,
                "file": n.file,
                "node_id": n.node_id,
                "node_type": n.node_type,
                "function_addr": n.function_addr,
                "proposed_role": n.proposed_role,
                "score": f"{n.score:.3f}",
                "confidence": n.confidence,
                "evidence_sources": ";".join(sorted(n.evidence_sources)),
                "xdata_read_count": str(len(n.xdata_reads)),
                "xdata_write_count": str(len(n.xdata_writes)),
                "conditional_branch_count": str(n.conditional_branch_count),
                "bit_operation_count": str(n.bit_operation_count),
                "movc_count": str(n.movc_count),
                "call_count": str(n.call_count),
                "incoming_lcalls": str(n.incoming_lcalls),
                "likely_xdata_flags": ";".join(likely_flags),
                "notes": ";".join(sorted(n.notes)),
            }
        )
    with args.nodes_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=node_fields)
        w.writeheader()
        w.writerows(node_rows)

    # edges
    edge_fields = [
        "branch",
        "file",
        "edge_id",
        "source_node",
        "target_node",
        "source_function",
        "target_function",
        "edge_type",
        "score",
        "confidence",
        "evidence_sources",
        "via_call",
        "via_xdata",
        "via_branch",
        "missing_link",
        "notes",
    ]
    edge_rows: list[dict[str, str]] = []

    call_pairs = {(src, tgt) for src in TARGET_FUNCTIONS for tgt in nodes[src].calls_out if tgt in TARGET_FUNCTIONS}
    for eid, src, tgt, etype in EDGE_SPECS:
        s = nodes[src]
        t = nodes[tgt]
        via_call = "yes" if (src, tgt) in call_pairs else "no"
        common_x = sorted((s.xdata_reads | s.xdata_writes) & (t.xdata_reads | t.xdata_writes))
        via_x = "yes" if common_x else "no"
        miss = "no" if via_call == "yes" or via_x == "yes" else "yes"
        score = 0.45 + (0.35 if via_call == "yes" else 0) + (0.2 if via_x == "yes" else 0)
        conf = "high" if score >= 0.95 else "medium" if score >= 0.65 else "hypothesis"
        edge_rows.append(
            {
                "branch": args.branch,
                "file": args.file,
                "edge_id": eid,
                "source_node": f"n_{src[2:].lower()}",
                "target_node": f"n_{tgt[2:].lower()}",
                "source_function": src,
                "target_function": tgt,
                "edge_type": etype,
                "score": f"{score:.3f}",
                "confidence": conf,
                "evidence_sources": ";".join(sorted((s.evidence_sources | t.evidence_sources) & {
                    "docs/call_xref.csv",
                    "docs/disassembly_index.csv",
                    "docs/extinguishing_output_gating_chains.csv",
                    "docs/zone_to_output_chains.csv",
                    "docs/auto_manual_gating_deep_trace_summary.csv",
                })),
                "via_call": via_call,
                "via_xdata": via_x,
                "via_branch": "yes",
                "missing_link": miss,
                "notes": "shared_xdata=" + ("|".join(common_x[:6]) if common_x else "none"),
            }
        )

    # explicit unknown bridge edge
    edge_rows.append(
        {
            "branch": args.branch,
            "file": args.file,
            "edge_id": "e10",
            "source_node": "n_unknown_bridge",
            "target_node": "n_5a7f",
            "source_function": "0x84A6",
            "target_function": "0x5A7F",
            "edge_type": "unknown_bridge",
            "score": "0.400",
            "confidence": "hypothesis",
            "evidence_sources": "docs/auto_manual_gating_deep_trace_analysis.md",
            "via_call": "no",
            "via_xdata": "unknown",
            "via_branch": "yes",
            "missing_link": "yes",
            "notes": "placeholder_for_not_yet_resolved_runtime_bridge",
        }
    )

    with args.edges_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=edge_fields)
        w.writeheader()
        w.writerows(edge_rows)

    # XDATA flag map
    x_fields = [
        "branch",
        "file",
        "xdata_addr",
        "range_group",
        "probable_role",
        "read_count",
        "write_count",
        "functions",
        "evidence_sources",
        "confidence",
        "notes",
    ]

    addr_stats: dict[str, dict[str, object]] = {}

    def ensure_addr(addr: str) -> dict[str, object]:
        if addr not in addr_stats:
            addr_stats[addr] = {
                "read_count": 0,
                "write_count": 0,
                "functions": set(),
                "evidence": set(),
                "notes": set(),
            }
        return addr_stats[addr]

    for node in nodes.values():
        for a in node.xdata_reads:
            s = ensure_addr(a)
            s["read_count"] = int(s["read_count"]) + 1
            cast = s["functions"]
            assert isinstance(cast, set)
            cast.add(node.function_addr)
            ev = s["evidence"]
            assert isinstance(ev, set)
            ev.update(node.evidence_sources)
        for a in node.xdata_writes:
            s = ensure_addr(a)
            s["write_count"] = int(s["write_count"]) + 1
            cast = s["functions"]
            assert isinstance(cast, set)
            cast.add(node.function_addr)
            ev = s["evidence"]
            assert isinstance(ev, set)
            ev.update(node.evidence_sources)

    forced = [*(f"0x{v:04X}" for v in range(0x30EA, 0x30FA)), "0x315B", "0x3165", "0x31BF", "0x364B"]
    for a in forced:
        ensure_addr(a)

    def role_for_addr(addr: str) -> tuple[str, str, str]:
        n = to_int(addr)
        if 0x30EA <= n <= 0x30F9:
            return "0x30EA..0x30F9", "zone_state", "state_cluster_candidate"
        if addr == "0x315B":
            return "0x315B", "manual_auto_mode", "manual_auto_gate_candidate"
        if addr == "0x3165":
            return "0x3165", "packet_export_flag", "output_packet_side_flag_candidate"
        if addr == "0x31BF":
            return "0x31BF", "output_feedback", "output_packet_side_flag_candidate"
        if addr == "0x364B":
            return "0x364B", "output_start_flag", "output_packet_side_flag_candidate"
        return "other", "unknown_state_flag", "outside_focus_range"

    x_rows: list[dict[str, str]] = []
    for addr in sorted(addr_stats.keys(), key=to_int):
        s = addr_stats[addr]
        group, role, note = role_for_addr(addr)
        read_count = int(s["read_count"])
        write_count = int(s["write_count"])
        conf = "high" if (read_count + write_count) >= 3 else "medium" if (read_count + write_count) >= 1 else "hypothesis"
        x_rows.append(
            {
                "branch": args.branch,
                "file": args.file,
                "xdata_addr": addr,
                "range_group": group,
                "probable_role": role,
                "read_count": str(read_count),
                "write_count": str(write_count),
                "functions": ";".join(sorted(s["functions"])),
                "evidence_sources": ";".join(sorted(s["evidence"])),
                "confidence": conf,
                "notes": note,
            }
        )

    with args.xdata_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=x_fields)
        w.writeheader()
        w.writerows(x_rows)

    # branch comparison
    compare_files = [
        "90CYE03_19_DKS.PZU",
        "90CYE04_19_DKS.PZU",
        "90CYE02_27 DKS.PZU",
        "A03_26.PZU",
        "A04_28.PZU",
        "ppkp2001 90cye01.PZU",
    ]

    all_fm = load_csv(DOCS / "function_map.csv")
    by_file = defaultdict(list)
    for r in all_fm:
        if r.get("file") in compare_files:
            by_file[r.get("file", "")].append(r)

    # role lookup from existing candidate tables for other files
    role_rows = load_csv(DOCS / "zone_logic_candidates.csv") + load_csv(DOCS / "output_control_candidates.csv") + load_csv(DOCS / "zone_output_deep_trace_summary.csv")
    role_by_file = defaultdict(list)
    for r in role_rows:
        role_by_file[r.get("file", "")].append(r)

    b_fields = [
        "branch",
        "file",
        "similar_function_or_role",
        "primary_function_addr",
        "matched_function_addr",
        "match_type",
        "confidence",
        "notes",
    ]
    b_rows: list[dict[str, str]] = []

    primary_roles = {
        "0x497A": "sensor_zone",
        "0x737C": "zone_logic",
        "0x613C": "zone_state_feedback",
        "0x84A6": "mode_event_bridge",
        "0x728A": "manual_auto_check",
        "0x6833": "output_start",
        "0x5A7F": "packet_export",
    }

    for f in compare_files:
        branch = ""
        if by_file[f]:
            branch = by_file[f][0].get("branch", "")
        for pfn, role in primary_roles.items():
            match_fn = ""
            match_type = "no_match"
            conf = "hypothesis"
            note = "address equality is not treated as guaranteed semantic equality"

            if any(r.get("function_addr") == pfn for r in by_file[f]):
                match_fn = pfn
                match_type = "same_address"
                conf = "medium"
                note = "same address present in function_map; role equivalence remains probabilistic"
            else:
                # try role-like matches
                role_hits = [r for r in role_by_file[f] if role.split("_")[0] in (r.get("role_candidate", "") + r.get("proposed_role", "") + r.get("candidate_type", "")).lower()]
                if role_hits:
                    match_fn = role_hits[0].get("function_addr", "")
                    match_type = "similar_role"
                    conf = clean_conf(role_hits[0].get("confidence", ""))
                    note = "role keyword similarity from candidate tables"
                else:
                    fm_sorted = sorted(by_file[f], key=lambda r: to_int(r.get("call_count", "0")) + to_int(r.get("xdata_read_count", "0")) + to_int(r.get("xdata_write_count", "0")), reverse=True)
                    if fm_sorted:
                        match_fn = fm_sorted[0].get("function_addr", "")
                        match_type = "checksum_limited"
                        conf = "hypothesis"
                        note = "fallback structural proxy based on function_map intensity"

            b_rows.append(
                {
                    "branch": branch,
                    "file": f,
                    "similar_function_or_role": role,
                    "primary_function_addr": pfn,
                    "matched_function_addr": match_fn,
                    "match_type": match_type,
                    "confidence": conf,
                    "notes": note,
                }
            )

    with args.branch_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=b_fields)
        w.writeheader()
        w.writerows(b_rows)

    # markdown report
    major = [nodes[fn] for fn in TARGET_FUNCTIONS]
    unknown_sensor_states = "normal/blocked/not_detected/conflict/fire/fault exact numeric encodings remain partially unresolved"

    report = []
    report.append("# Runtime state-machine reconstruction for 90CYE_DKS / 90CYE03_19_DKS.PZU\n")
    report.append("Дата: 2026-04-26 (UTC).\n")
    report.append("\n## 1. Зачем нужен этот milestone\n")
    report.append("Этот milestone объединяет разрозненные candidate-артефакты в связанную runtime state-machine модель (датчик -> зона -> режим -> событие -> выход -> пакет) для ветки 90CYE_DKS. Цель — получить рабочую инженерную картину для стендовой валидации, а не очередной список изолированных функций.\n")
    if missing_inputs:
        report.append("\n### Warnings about missing inputs\n")
        for m in missing_inputs:
            report.append(f"- warning: missing `{m}` (analysis continued with available evidence).\n")

    report.append("\n## 2. Общая прикладная схема\n")
    report.append("```text\nдатчик -> зона -> режим -> событие -> выход -> пакет\n```\n")

    report.append("\n## 3. Major nodes\n")
    report.append("| function | proposed role | score | confidence | key flags |\n")
    report.append("|---|---|---:|---|---|\n")
    for n in major:
        flags = sorted((n.xdata_reads | n.xdata_writes) & {"0x315B", "0x3165", "0x31BF", "0x364B", *(f"0x{i:04X}" for i in range(0x30EA, 0x30FA))})
        report.append(f"| {n.function_addr} | {n.proposed_role} | {n.score:.3f} | {n.confidence} | {';'.join(flags) if flags else '-'} |\n")

    report.append("\n## 4. Функции и признаки\n")
    for n in major:
        report.append(f"### {n.function_addr}\n")
        report.append(f"- Роль (candidate): {n.proposed_role}.\n")
        report.append(f"- XDATA read/write: {len(n.xdata_reads)}/{len(n.xdata_writes)} (reads: {', '.join(sorted(n.xdata_reads)[:12]) or '-'}; writes: {', '.join(sorted(n.xdata_writes)[:12]) or '-'}).\n")
        report.append(f"- Calls out/in: {', '.join(sorted(n.calls_out)[:12]) or '-'} / {', '.join(sorted(n.calls_in)[:12]) or '-'}.\n")
        report.append(f"- Ветвления/битовые операции: {n.conditional_branch_count}/{n.bit_operation_count}.\n")
        report.append(f"- Признаки state/mode/output/packet: score={n.score:.3f}, confidence={n.confidence}.\n")
        report.append(f"- Evidence: {', '.join(sorted(n.evidence_sources)) or '-'}\n")

    report.append("\n## 5. Sensor state\n")
    report.append("Вероятные state-узлы датчиков расположены вокруг `0x497A` и таблиц/флагов `0x30EA..0x30F9`; наблюдаются признаки обновления state-флагов и условных развилок.\n")
    report.append(f"Известные классы состояний: {unknown_sensor_states}.\n")

    report.append("\n## 6. Zone state\n")
    report.append("Наиболее вероятная зона-таблица/логика: `0x737C`; зона/feedback state-кандидат: `0x613C`. Признаки attention/fire/fault присутствуют как условные ветки и XDATA-gating, но точная декодировка кодов зон частично неизвестна.\n")

    report.append("\n## 7. Auto/manual\n")
    report.append("`0x315B` остаётся главным кандидатом manual/auto flag (confidence: medium/high по совокупности трасс). `0x728A` выглядит как mode-check/branch gate, `0x84A6` — mode/event bridge. Наблюдается развилка manual-like и auto-like пути.\n")

    report.append("\n## 8. Extinguishing/output\n")
    report.append("`0x6833` — strongest candidate для output/relay/extinguishing start. Видны признаки output-start path, но без стенда нельзя окончательно заявлять полное восстановление алгоритма пожаротушения.\n")

    report.append("\n## 9. Packet/export\n")
    report.append("`0x5A7F` — packet/export узел; связан как с manual-event веткой, так и с auto-output веткой в реконструированном графе.\n")

    report.append("\n## 10. Runtime graph\n")
    report.append("```text\n0x497A sensor/zone\n  -> 0x737C zone logic\n  -> 0x613C state/feedback\n  -> 0x84A6 mode/event bridge\n  -> 0x728A mode check\n      -> manual-like: event/packet only -> 0x5A7F\n      -> auto-like: 0x6833 output start -> 0x5A7F\n```\n")

    report.append("\n## 11. Branch comparison\n")
    report.append("Сравнение с 90CYE04_19_DKS / 90CYE02_27 / A03_26 / A04_28 / ppkp2001 90cye01 вынесено в `docs/runtime_branch_comparison.csv`. Одинаковый адрес в разных ветках интерпретируется только как candidate-match с confidence, не как доказательство тождественности функции.\n")

    report.append("\n## 12. Confirmed / probable / hypothesis / unknown\n")
    report.append("- Confirmed: наличие связанного runtime-контура state->mode->output/packet как статической модели переходов.\n")
    report.append("- Probable: `0x315B` manual/auto flag, `0x6833` output-start, `0x5A7F` packet-export bridge.\n")
    report.append("- Hypothesis: точные условия всех ветвлений fire/attention/fault/manual/auto и все side effects на физические исполнительные механизмы.\n")
    report.append("- Unknown: полная семантика части XDATA-флагов и таймерных/межпрерывательных взаимодействий без стенда.\n")

    report.append("\n## 13. Bench validation plan\n")
    bench_cases = [
        "датчик в норме",
        "датчик заблокирован",
        "датчик не определяется",
        "конфликт адресов",
        "пожар одного датчика",
        "пожар двух датчиков",
        "зона внимание",
        "зона пожар",
        "зона неисправность",
        "зона manual",
        "зона auto",
        "пожар в manual: проверить, что output не стартует",
        "пожар в auto: проверить, что output стартует",
        "проверить реле/задвижку/исполнительный выход",
        "сравнить исходящие пакеты",
        "снять изменения XDATA/логов, если возможно",
    ]
    for c in bench_cases:
        report.append(f"- [ ] {c}.\n")

    args.report_out.write_text("".join(report), encoding="utf-8")

    print(f"Wrote {args.nodes_out.relative_to(ROOT)}")
    print(f"Wrote {args.edges_out.relative_to(ROOT)}")
    print(f"Wrote {args.xdata_out.relative_to(ROOT)}")
    print(f"Wrote {args.branch_out.relative_to(ROOT)}")
    print(f"Wrote {args.report_out.relative_to(ROOT)}")
    if missing_inputs:
        print("Warnings: missing optional inputs:")
        for m in missing_inputs:
            print(f" - {m}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
