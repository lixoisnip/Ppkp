#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import quantiles

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

TARGET_BRANCHES = ["A03_A04", "90CYE_DKS", "90CYE_v2_1", "90CYE_shifted_DKS", "RTOS_service"]

INPUT_FILES = [
    "docs/firmware_manifest.json",
    "docs/firmware_inventory.csv",
    "docs/branch_comparison_summary.csv",
    "docs/function_map.csv",
    "docs/basic_block_map.csv",
    "docs/call_xref.csv",
    "docs/xdata_confirmed_access.csv",
    "docs/xdata_map_by_branch.csv",
    "docs/disassembly_index.csv",
    "docs/code_table_candidates.csv",
    "docs/string_index.csv",
    "docs/script_scope_matrix.csv",
    "docs/analysis_smoke_test_results.csv",
]

CANDIDATE_FIELDS = [
    "branch",
    "file",
    "function_addr",
    "candidate_type",
    "score",
    "confidence",
    "role_candidate",
    "basic_block_count",
    "internal_block_count",
    "incoming_lcalls",
    "call_count",
    "xdata_read_count",
    "xdata_write_count",
    "movc_count",
    "string_refs",
    "cluster_hits",
    "call_hub_score",
    "writer_score",
    "reader_score",
    "table_score",
    "notes",
]

CHAIN_FIELDS = [
    "branch",
    "file",
    "chain_rank",
    "caller_function",
    "core_function",
    "callee_function",
    "caller_role",
    "core_role",
    "callee_role",
    "caller_score",
    "core_score",
    "callee_score",
    "chain_score",
    "confidence",
    "notes",
]

ROLE_WEIGHT = {
    "state_reader_or_packet_builder": 1.1,
    "service_or_runtime_worker": 1.2,
    "dispatcher_or_router": 1.25,
    "state_update_worker": 1.05,
    "unknown": 0.95,
}


@dataclass
class FunctionStat:
    branch: str
    file: str
    addr: str
    addr_int: int
    role: str
    confidence: str
    incoming_lcalls: int
    call_count: int
    xdata_read_count: int
    xdata_write_count: int
    basic_block_count: int
    internal_block_count: int
    movc_count: int = 0
    string_refs: int = 0
    cluster_hits: int = 0
    dense_neighborhood: bool = False
    call_hub_score: float = 0.0
    writer_score: float = 0.0
    reader_score: float = 0.0
    table_score: float = 0.0
    dispatcher_score: float = 0.0
    packet_service_score: float = 0.0


def load_csv(path: Path, warnings: list[str]) -> list[dict[str, str]]:
    if not path.exists():
        warnings.append(f"WARNING: missing input file: {path.relative_to(ROOT)}")
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_json(path: Path, warnings: list[str]) -> dict:
    if not path.exists():
        warnings.append(f"WARNING: missing input file: {path.relative_to(ROOT)}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        warnings.append(f"WARNING: failed to parse json: {path.relative_to(ROOT)}")
        return {}


def to_int(value: str) -> int:
    text = (value or "").strip()
    if not text:
        return 0
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return 0


def to_float(value: str) -> float:
    try:
        return float((value or "").strip())
    except ValueError:
        return 0.0


def fmt_score(value: float) -> str:
    return f"{value:.3f}"


def confidence_label(score: float, checksum_errors: int = 0) -> str:
    if checksum_errors > 0:
        if score >= 2.8:
            return "medium"
        if score >= 1.6:
            return "low"
        return "experimental"
    if score >= 3.2:
        return "high"
    if score >= 2.0:
        return "medium"
    if score >= 1.2:
        return "low"
    return "experimental"


def map_addr_to_function(addr: int, starts: list[tuple[int, str]]) -> str | None:
    if not starts:
        return None
    lo = 0
    hi = len(starts) - 1
    best: str | None = None
    while lo <= hi:
        mid = (lo + hi) // 2
        start, fn = starts[mid]
        if addr < start:
            hi = mid - 1
        else:
            best = fn
            lo = mid + 1
    return best


def main() -> int:
    parser = argparse.ArgumentParser(description="Global branch-wide packet/runtime pipeline candidate miner.")
    parser.add_argument("--candidates-out", type=Path, default=DOCS / "global_packet_pipeline_candidates.csv")
    parser.add_argument("--chains-out", type=Path, default=DOCS / "global_packet_pipeline_chains.csv")
    parser.add_argument("--md-out", type=Path, default=DOCS / "global_packet_pipeline_mining.md")
    args = parser.parse_args()

    warnings: list[str] = []
    for rel in INPUT_FILES:
        if not (ROOT / rel).exists():
            warnings.append(f"WARNING: missing input file: {rel}")

    _manifest = load_json(ROOT / "docs/firmware_manifest.json", warnings)
    inventory = load_csv(ROOT / "docs/firmware_inventory.csv", warnings)
    branch_summary = load_csv(ROOT / "docs/branch_comparison_summary.csv", warnings)
    function_map = load_csv(ROOT / "docs/function_map.csv", warnings)
    basic_blocks = load_csv(ROOT / "docs/basic_block_map.csv", warnings)
    call_xref = load_csv(ROOT / "docs/call_xref.csv", warnings)
    xdata_confirmed = load_csv(ROOT / "docs/xdata_confirmed_access.csv", warnings)
    xdata_by_branch = load_csv(ROOT / "docs/xdata_map_by_branch.csv", warnings)
    disassembly = load_csv(ROOT / "docs/disassembly_index.csv", warnings)
    code_table = load_csv(ROOT / "docs/code_table_candidates.csv", warnings)
    string_index = load_csv(ROOT / "docs/string_index.csv", warnings)
    _scope = load_csv(ROOT / "docs/script_scope_matrix.csv", warnings)
    smoke = load_csv(ROOT / "docs/analysis_smoke_test_results.csv", warnings)
    a03_window = load_csv(ROOT / "docs/a03_a04_packet_window_writers.csv", warnings)

    checksum_by_branch: dict[str, int] = Counter()
    files_by_branch: dict[str, list[str]] = defaultdict(list)
    for row in inventory:
        branch = row.get("branch", "")
        if branch in TARGET_BRANCHES:
            files_by_branch[branch].append(row.get("file", ""))
            checksum_by_branch[branch] += to_int(row.get("checksum_errors", "0"))

    cluster_ranges: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for row in xdata_by_branch:
        branch = row.get("branch", "")
        if branch not in TARGET_BRANCHES:
            continue
        start = to_int(row.get("address_start", "0"))
        end = to_int(row.get("address_end", "0"))
        if start and end and end >= start:
            cluster_ranges[branch].append((start, end))

    fn_stats: dict[tuple[str, str, str], FunctionStat] = {}
    starts_by_file: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for row in function_map:
        branch = row.get("branch", "")
        if branch not in TARGET_BRANCHES:
            continue
        file = row.get("file", "")
        addr = row.get("function_addr", "")
        addr_int = to_int(addr)
        stat = FunctionStat(
            branch=branch,
            file=file,
            addr=addr,
            addr_int=addr_int,
            role=row.get("role_candidate", "unknown") or "unknown",
            confidence=row.get("confidence", "unknown") or "unknown",
            incoming_lcalls=to_int(row.get("incoming_lcalls", "0")),
            call_count=to_int(row.get("call_count", "0")),
            xdata_read_count=to_int(row.get("xdata_read_count", "0")),
            xdata_write_count=to_int(row.get("xdata_write_count", "0")),
            basic_block_count=to_int(row.get("basic_block_count", "0")),
            internal_block_count=to_int(row.get("internal_block_count", "0")),
            movc_count=to_int(row.get("movc_count", "0")),
        )
        fn_stats[(branch, file, addr)] = stat
        if addr_int:
            starts_by_file[file].append((addr_int, addr))

    for file, items in starts_by_file.items():
        starts_by_file[file] = sorted(items)

    # Map dynamic evidence rows to nearest function start in same file.
    for row in disassembly:
        file = row.get("file", "")
        branch = row.get("branch", "")
        if branch not in TARGET_BRANCHES:
            continue
        fn_addr = map_addr_to_function(to_int(row.get("code_addr", "0")), starts_by_file[file])
        if not fn_addr:
            continue
        stat = fn_stats.get((branch, file, fn_addr))
        if not stat:
            continue
        if (row.get("mnemonic", "").strip().upper() == "MOVC"):
            stat.movc_count += 1

    string_addr_by_file: dict[str, set[int]] = defaultdict(set)
    for row in string_index:
        file = row.get("file", "")
        branch = row.get("branch", "")
        if branch in TARGET_BRANCHES:
            string_addr_by_file[file].add(to_int(row.get("string_addr", "0")))

    for row in code_table:
        file = row.get("file", "")
        branch = row.get("branch", "")
        if branch not in TARGET_BRANCHES:
            continue
        fn_addr = map_addr_to_function(to_int(row.get("code_addr", "0")), starts_by_file[file])
        if not fn_addr:
            continue
        stat = fn_stats.get((branch, file, fn_addr))
        if stat:
            stat.string_refs += 1

    for row in disassembly:
        file = row.get("file", "")
        branch = row.get("branch", "")
        if branch not in TARGET_BRANCHES:
            continue
        tgt = to_int(row.get("target_addr", "0"))
        if tgt and tgt in string_addr_by_file.get(file, set()):
            fn_addr = map_addr_to_function(to_int(row.get("code_addr", "0")), starts_by_file[file])
            stat = fn_stats.get((branch, file, fn_addr or ""))
            if stat:
                stat.string_refs += 1

    for row in xdata_confirmed:
        file = row.get("file", "")
        branch = row.get("branch", "")
        if branch not in TARGET_BRANCHES:
            continue
        fn_addr = map_addr_to_function(to_int(row.get("code_addr", "0")), starts_by_file[file])
        stat = fn_stats.get((branch, file, fn_addr or ""))
        if not stat:
            continue
        dptr = to_int(row.get("dptr_addr", "0"))
        for start, end in cluster_ranges.get(branch, []):
            if start <= dptr <= end:
                stat.cluster_hits += 1
                break

    edges_out: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    edges_in: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in call_xref:
        branch = row.get("branch", "")
        if branch not in TARGET_BRANCHES:
            continue
        file = row.get("file", "")
        if (row.get("call_type", "").strip().lower()) not in {"lcall", "ljmp"}:
            continue
        src_fn = map_addr_to_function(to_int(row.get("code_addr", "0")), starts_by_file[file])
        tgt = to_int(row.get("target_addr", "0"))
        tgt_hex = f"0x{tgt:04X}" if tgt else ""
        if not src_fn or not tgt_hex:
            continue
        src_key = (branch, file, src_fn)
        tgt_key = (branch, file, tgt_hex)
        if tgt_key not in fn_stats:
            continue
        edges_out[src_key].add(tgt_hex)
        edges_in[tgt_key].add(src_fn)

    branch_degrees: dict[str, list[int]] = defaultdict(list)
    for key, stat in fn_stats.items():
        deg = len(edges_out.get(key, set())) + len(edges_in.get(key, set()))
        branch_degrees[stat.branch].append(deg)

    dense_threshold: dict[str, int] = {}
    for branch, values in branch_degrees.items():
        if not values:
            dense_threshold[branch] = 0
            continue
        if len(values) < 4:
            dense_threshold[branch] = max(values)
        else:
            dense_threshold[branch] = int(quantiles(values, n=4)[2])

    branch_top: dict[str, dict[str, list[FunctionStat]]] = defaultdict(lambda: defaultdict(list))
    candidate_rows: list[dict[str, str]] = []

    def add_candidate(stat: FunctionStat, candidate_type: str, score: float, note: str) -> None:
        conf = confidence_label(score, checksum_by_branch.get(stat.branch, 0))
        candidate_rows.append(
            {
                "branch": stat.branch,
                "file": stat.file,
                "function_addr": stat.addr,
                "candidate_type": candidate_type,
                "score": fmt_score(score),
                "confidence": conf,
                "role_candidate": stat.role,
                "basic_block_count": str(stat.basic_block_count),
                "internal_block_count": str(stat.internal_block_count),
                "incoming_lcalls": str(stat.incoming_lcalls),
                "call_count": str(stat.call_count),
                "xdata_read_count": str(stat.xdata_read_count),
                "xdata_write_count": str(stat.xdata_write_count),
                "movc_count": str(stat.movc_count),
                "string_refs": str(stat.string_refs),
                "cluster_hits": str(stat.cluster_hits),
                "call_hub_score": fmt_score(stat.call_hub_score),
                "writer_score": fmt_score(stat.writer_score),
                "reader_score": fmt_score(stat.reader_score),
                "table_score": fmt_score(stat.table_score),
                "notes": note,
            }
        )

    for key, stat in fn_stats.items():
        deg = len(edges_out.get(key, set())) + len(edges_in.get(key, set()))
        stat.dense_neighborhood = deg >= dense_threshold.get(stat.branch, 0) and deg > 0
        role_mul = ROLE_WEIGHT.get(stat.role, ROLE_WEIGHT["unknown"])
        stat.call_hub_score = role_mul * (
            0.04 * stat.incoming_lcalls + 0.03 * stat.call_count + 0.45 * deg + (0.35 if stat.dense_neighborhood else 0)
        )
        stat.writer_score = role_mul * (
            0.55 * stat.xdata_write_count + 0.12 * stat.basic_block_count + 0.15 * stat.cluster_hits + 0.08 * stat.call_count
        )
        stat.reader_score = role_mul * (
            0.55 * stat.xdata_read_count + 0.09 * stat.basic_block_count + 0.12 * stat.cluster_hits + 0.08 * stat.call_count
        )
        stat.table_score = role_mul * (
            0.42 * stat.movc_count + 0.48 * stat.string_refs + 0.12 * stat.call_count + (0.25 if stat.dense_neighborhood else 0)
        )
        stat.dispatcher_score = role_mul * (
            0.33 * stat.call_hub_score
            + 0.16 * stat.reader_score
            + 0.14 * stat.writer_score
            + 0.10 * stat.table_score
            + 0.015 * stat.internal_block_count
            + (0.4 if stat.role == "dispatcher_or_router" else 0.0)
        )
        stat.packet_service_score = role_mul * (
            0.25 * stat.reader_score
            + 0.25 * stat.writer_score
            + 0.15 * stat.call_hub_score
            + 0.15 * stat.table_score
            + 0.02 * stat.basic_block_count
            + (0.35 if stat.role in {"service_or_runtime_worker", "state_reader_or_packet_builder"} else 0.0)
        )

    by_branch: dict[str, list[FunctionStat]] = defaultdict(list)
    for stat in fn_stats.values():
        by_branch[stat.branch].append(stat)

    def top(stats: list[FunctionStat], key_name: str, n: int = 8) -> list[FunctionStat]:
        return sorted(stats, key=lambda s: getattr(s, key_name), reverse=True)[:n]

    for branch in TARGET_BRANCHES:
        stats = by_branch.get(branch, [])
        if not stats:
            continue
        branch_top[branch]["dispatcher"] = top(stats, "dispatcher_score")
        branch_top[branch]["packet_service"] = top(stats, "packet_service_score")
        branch_top[branch]["writer"] = top(stats, "writer_score")
        branch_top[branch]["reader"] = top(stats, "reader_score")
        branch_top[branch]["table"] = top(stats, "table_score")
        branch_top[branch]["hub"] = top(stats, "call_hub_score")

        for s in branch_top[branch]["dispatcher"]:
            add_candidate(s, "dispatcher_candidate", s.dispatcher_score, "global branch-wide score; no A03/A04-only address assumptions")
        for s in branch_top[branch]["packet_service"]:
            add_candidate(s, "packet_service_candidate", s.packet_service_score, "service/packet worker ranking")
        for s in branch_top[branch]["writer"]:
            add_candidate(s, "xdata_writer_candidate", s.writer_score, "writer-like behavior from global features")
        for s in branch_top[branch]["reader"]:
            add_candidate(s, "xdata_reader_candidate", s.reader_score, "reader-like behavior from global features")
        for s in branch_top[branch]["table"]:
            add_candidate(s, "table_string_candidate", s.table_score, "MOVC + table/string evidence")
        for s in branch_top[branch]["hub"]:
            add_candidate(s, "call_hub_candidate", s.call_hub_score, "incoming/outgoing call hub in branch-local graph")

    chain_rows: list[dict[str, str]] = []
    top_chain_for_branch: dict[str, list[dict[str, str]]] = defaultdict(list)
    for branch in TARGET_BRANCHES:
        stats = by_branch.get(branch, [])
        if not stats:
            continue
        stat_by_key = {(s.branch, s.file, s.addr): s for s in stats}
        branch_chains: list[tuple[float, dict[str, str]]] = []
        for s in stats:
            src_key = (s.branch, s.file, s.addr)
            for mid in edges_out.get(src_key, set()):
                mid_stat = stat_by_key.get((s.branch, s.file, mid))
                if not mid_stat:
                    continue
                if mid_stat.xdata_read_count + mid_stat.xdata_write_count <= 0:
                    continue
                for callee in edges_out.get((s.branch, s.file, mid), set()):
                    callee_stat = stat_by_key.get((s.branch, s.file, callee))
                    if not callee_stat:
                        continue
                    caller_ok = s.role in {"dispatcher_or_router", "service_or_runtime_worker"} or s.dispatcher_score >= 1.0
                    callee_ok = (
                        callee_stat.writer_score >= 0.6
                        or callee_stat.table_score >= 0.6
                        or callee_stat.role in {"service_or_runtime_worker", "state_update_worker", "dispatcher_or_router"}
                    )
                    if not caller_ok or not callee_ok:
                        continue
                    chain_score = 0.35 * s.dispatcher_score + 0.40 * mid_stat.packet_service_score + 0.25 * max(
                        callee_stat.writer_score, callee_stat.table_score, callee_stat.call_hub_score
                    )
                    note = "global static chain candidate; caller/service + core xdata + callee writer/table/service"
                    conf = confidence_label(chain_score, checksum_by_branch.get(branch, 0))
                    branch_chains.append(
                        (
                            chain_score,
                            {
                                "branch": branch,
                                "file": s.file,
                                "chain_rank": "0",
                                "caller_function": s.addr,
                                "core_function": mid_stat.addr,
                                "callee_function": callee_stat.addr,
                                "caller_role": s.role,
                                "core_role": mid_stat.role,
                                "callee_role": callee_stat.role,
                                "caller_score": fmt_score(s.dispatcher_score),
                                "core_score": fmt_score(mid_stat.packet_service_score),
                                "callee_score": fmt_score(max(callee_stat.writer_score, callee_stat.table_score)),
                                "chain_score": fmt_score(chain_score),
                                "confidence": conf,
                                "notes": note,
                            },
                        )
                    )

        branch_chains.sort(key=lambda x: x[0], reverse=True)
        dedup: set[tuple[str, str, str, str]] = set()
        ranked = 0
        for _, row in branch_chains:
            key = (row["file"], row["caller_function"], row["core_function"], row["callee_function"])
            if key in dedup:
                continue
            dedup.add(key)
            ranked += 1
            row["chain_rank"] = str(ranked)
            chain_rows.append(row)
            top_chain_for_branch[branch].append(row)
            if ranked >= 12:
                break

    args.candidates_out.parent.mkdir(parents=True, exist_ok=True)
    with args.candidates_out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CANDIDATE_FIELDS)
        writer.writeheader()
        writer.writerows(candidate_rows)

    with args.chains_out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CHAIN_FIELDS)
        writer.writeheader()
        writer.writerows(chain_rows)

    summary_by_branch = {row.get("branch", ""): row for row in branch_summary}
    smoke_passed = sum(1 for row in smoke if row.get("status") == "pass")
    smoke_total = len(smoke)

    rank_branch: list[tuple[float, str, str, str, str]] = []
    for branch in TARGET_BRANCHES:
        dispatch_avg = sum(s.dispatcher_score for s in branch_top.get(branch, {}).get("dispatcher", [])) / max(
            len(branch_top.get(branch, {}).get("dispatcher", [])), 1
        )
        chain_avg = sum(to_float(r.get("chain_score", "0")) for r in top_chain_for_branch.get(branch, [])[:5]) / max(
            len(top_chain_for_branch.get(branch, [])[:5]), 1
        )
        checksum = checksum_by_branch.get(branch, 0)
        total = dispatch_avg + chain_avg - (0.75 if checksum > 0 else 0.0)
        reasons = f"dispatcher_avg={dispatch_avg:.2f}, chain_avg={chain_avg:.2f}"
        risks = "checksum_error files reduce confidence" if checksum > 0 else "static-only evidence; runtime validation needed"
        top_funcs = ", ".join(s.addr for s in branch_top.get(branch, {}).get("packet_service", [])[:4]) or "n/a"
        rank_branch.append((total, branch, reasons, risks, top_funcs))

    rank_branch.sort(key=lambda x: x[0], reverse=True)

    md_lines: list[str] = []
    md_lines.append("# Global packet/runtime pipeline mining")
    md_lines.append("")
    md_lines.append("This report is **global branch-wide static analysis** and **not a packet format proof**.")
    md_lines.append("All conclusions are marked with confidence and may require runtime validation.")
    md_lines.append("")
    md_lines.append("## Scope")
    md_lines.append("")
    md_lines.append("Analyzed branches: A03_A04, 90CYE_DKS, 90CYE_v2_1, 90CYE_shifted_DKS, RTOS_service.")
    md_lines.append(
        f"Input evidence is sourced from smoke-tested pipeline artifacts (smoke pass {smoke_passed}/{smoke_total} commands)."
    )
    if warnings:
        md_lines.append("")
        md_lines.append("### Warnings")
        for w in warnings:
            md_lines.append(f"- {w}")

    label_to_key = {
        "Top runtime dispatcher candidates": "dispatcher",
        "Top packet/service worker candidates": "packet_service",
        "Top xdata writer candidates": "writer",
        "Top xdata reader candidates": "reader",
        "Top table/string/MOVC candidates": "table",
        "Top call hubs": "hub",
    }

    for branch in TARGET_BRANCHES:
        md_lines.append("")
        md_lines.append(f"## Branch: {branch}")
        bsum = summary_by_branch.get(branch, {})
        if bsum:
            md_lines.append(
                f"- branch confidence (from branch comparison): {bsum.get('confidence', 'unknown')}; checksum_error_count={bsum.get('checksum_error_count', '0')}"
            )
            md_lines.append(f"- xdata clusters: {bsum.get('xdata_cluster_summary', 'n/a')}")
        for label, key in label_to_key.items():
            md_lines.append("")
            md_lines.append(f"### {label}")
            items = branch_top.get(branch, {}).get(key, [])[:5]
            if not items:
                md_lines.append("- n/a")
                continue
            for i, s in enumerate(items, 1):
                score = getattr(s, f"{key}_score") if key not in {"dispatcher", "packet_service", "writer", "reader", "table", "hub"} else None
                if key == "dispatcher":
                    val = s.dispatcher_score
                elif key == "packet_service":
                    val = s.packet_service_score
                elif key == "writer":
                    val = s.writer_score
                elif key == "reader":
                    val = s.reader_score
                elif key == "table":
                    val = s.table_score
                else:
                    val = s.call_hub_score
                md_lines.append(
                    f"- {i}. {s.file}:{s.addr} score={val:.3f} confidence={confidence_label(val, checksum_by_branch.get(branch, 0))} role={s.role}"
                )

        md_lines.append("")
        md_lines.append("### Top candidate chains (caller -> core -> callee)")
        chains = top_chain_for_branch.get(branch, [])[:5]
        if not chains:
            md_lines.append("- n/a")
        for ch in chains:
            md_lines.append(
                f"- #{ch['chain_rank']} {ch['file']}: {ch['caller_function']} -> {ch['core_function']} -> {ch['callee_function']} "
                f"chain_score={ch['chain_score']} confidence={ch['confidence']}"
            )

    md_lines.append("")
    md_lines.append("## A03/A04 scoped notes")
    md_lines.append("- A03/A04-specific address evidence is **scoped** and is not used as a global criterion for all branches.")
    if a03_window:
        a04_writes = [r for r in a03_window if r.get("file") == "A04_28.PZU"]
        a03_writes = [r for r in a03_window if r.get("file") == "A03_26.PZU"]
        md_lines.append(
            f"- Known A04 packet-window direct writes (0x5003..0x5010 scope): {len(a04_writes)} confirmed static rows (scoped evidence)."
        )
        md_lines.append(
            f"- A03 direct packet-window writes in same scoped dataset: {len(a03_writes)} rows (currently none observed)."
        )
    else:
        md_lines.append("- A03/A04 packet-window writer CSV missing; scoped packet-window statement unavailable in this run.")

    md_lines.append("")
    md_lines.append("## RTOS_service scoped notes")
    md_lines.append("- Branch remains promising because it has multi-file runtime/service footprint and high call density.")
    md_lines.append("- However, checksum errors in part of RTOS_service files limit confidence for cross-file conclusions.")
    top_rtos_funcs = ", ".join(s.addr for s in branch_top.get("RTOS_service", {}).get("packet_service", [])[:5]) or "n/a"
    top_rtos_chains = "; ".join(
        f"{ch['caller_function']}->{ch['core_function']}->{ch['callee_function']}"
        for ch in top_chain_for_branch.get("RTOS_service", [])[:3]
    ) or "n/a"
    md_lines.append(f"- Prioritized RTOS_service candidate functions: {top_rtos_funcs}.")
    md_lines.append(f"- Prioritized RTOS_service chains: {top_rtos_chains}.")

    for branch in ["90CYE_DKS", "90CYE_v2_1"]:
        md_lines.append("")
        md_lines.append(f"## {branch} runtime-cluster notes")
        bsum = summary_by_branch.get(branch, {})
        md_lines.append(f"- Runtime clusters from branch map: {bsum.get('xdata_cluster_summary', 'n/a')}")
        best_writer = branch_top.get(branch, {}).get("writer", [])[:3]
        best_service = branch_top.get(branch, {}).get("packet_service", [])[:3]
        md_lines.append(
            "- Strong writer candidates: " + (", ".join(f"{s.file}:{s.addr}" for s in best_writer) if best_writer else "n/a")
        )
        md_lines.append(
            "- Strong service/runtime candidates: "
            + (", ".join(f"{s.file}:{s.addr}" for s in best_service) if best_service else "n/a")
        )

    md_lines.append("")
    md_lines.append("## Branch ranking for next deep reverse milestone")
    for idx, (_, branch, reason, risk, funcs) in enumerate(rank_branch, 1):
        md_lines.append(f"{idx}. **{branch}**")
        md_lines.append(f"   - reason: {reason}")
        md_lines.append(f"   - risks: {risk}")
        md_lines.append(f"   - recommended next concrete functions: {funcs}")

    args.md_out.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"Wrote {args.candidates_out.relative_to(ROOT)} rows={len(candidate_rows)}")
    print(f"Wrote {args.chains_out.relative_to(ROOT)} rows={len(chain_rows)}")
    print(f"Wrote {args.md_out.relative_to(ROOT)}")
    for w in warnings:
        print(w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
