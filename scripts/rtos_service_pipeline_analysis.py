#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
TARGET_BRANCH = "RTOS_service"
TARGET_FILES = ["ppkp2001 90cye01.PZU", "ppkp2012 a01.PZU", "ppkp2019 a02.PZU"]

INPUT_FILES = [
    "docs/firmware_manifest.json",
    "docs/firmware_inventory.csv",
    "docs/function_map.csv",
    "docs/basic_block_map.csv",
    "docs/call_xref.csv",
    "docs/xdata_confirmed_access.csv",
    "docs/xdata_map_by_branch.csv",
    "docs/disassembly_index.csv",
    "docs/code_table_candidates.csv",
    "docs/string_index.csv",
    "docs/global_packet_pipeline_candidates.csv",
    "docs/global_packet_pipeline_chains.csv",
    "docs/branch_comparison_summary.csv",
    "docs/analysis_smoke_test_results.csv",
]

FUNCTION_FIELDS = [
    "file",
    "valid_hex",
    "checksum_status",
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
    "rtos_core_hits",
    "service_flag_hits",
    "secondary_flag_hits",
    "arithmetic_hits",
    "notes",
]

CHAIN_FIELDS = [
    "file",
    "valid_hex",
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
    "rtos_core_hits",
    "service_flag_hits",
    "secondary_flag_hits",
    "confidence",
    "notes",
]

XDATA_ROLE_FIELDS = [
    "xdata_addr",
    "range_group",
    "files",
    "read_count",
    "write_count",
    "functions",
    "role_candidate",
    "confidence",
    "notes",
]

ARITH_METRICS = {"ADD", "ADDC", "SUBB", "INC", "DEC", "MUL", "DIV"}

RTOS_CORE = (0x6406, 0x6422)
SERVICE_FLAGS = (0x759C, 0x75AE)
SECONDARY_FLAGS = (0x769C, 0x76AA)
NEARBY_POINTS = {0x66EA, 0x6892, 0x6894, 0x75AA, 0x75AB, 0x76AA, 0x76AB}
NEARBY_RANGE = (0x6419, 0x6423)


@dataclass
class FnStat:
    file: str
    addr: str
    addr_int: int
    role: str
    incoming_lcalls: int
    call_count: int
    xread: int
    xwrite: int
    movc: int
    bbc: int
    ibc: int
    string_refs: int = 0
    arithmetic_hits: int = 0
    cluster_hits: int = 0
    rtos_hits: int = 0
    service_hits: int = 0
    secondary_hits: int = 0
    score: int = 0
    candidate_type: str = "xdata_reader_candidate"
    confidence: str = "unknown"


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


def to_int(v: str) -> int:
    t = (v or "").strip()
    if not t:
        return 0
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        return int(t)
    except ValueError:
        return 0


def is_true(v: str) -> bool:
    return (v or "").strip().lower() in {"true", "1", "yes"}


def map_addr(addr: int, starts: list[tuple[int, str]]) -> str | None:
    lo, hi = 0, len(starts) - 1
    best: str | None = None
    while lo <= hi:
        mid = (lo + hi) // 2
        s, fn = starts[mid]
        if addr < s:
            hi = mid - 1
        else:
            best = fn
            lo = mid + 1
    return best


def in_range(a: int, rg: tuple[int, int]) -> bool:
    return rg[0] <= a <= rg[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="RTOS_service branch-focused runtime/service pipeline analysis")
    parser.add_argument("--function-out", type=Path, default=DOCS / "rtos_service_function_candidates.csv")
    parser.add_argument("--chains-out", type=Path, default=DOCS / "rtos_service_pipeline_chains.csv")
    parser.add_argument("--xdata-out", type=Path, default=DOCS / "rtos_service_xdata_role_candidates.csv")
    parser.add_argument("--md-out", type=Path, default=DOCS / "rtos_service_pipeline_analysis.md")
    parser.add_argument("--plan-out", type=Path, default=DOCS / "rtos_service_next_deep_dive_plan.md")
    args = parser.parse_args()

    warnings: list[str] = []
    for rel in INPUT_FILES:
        if not (ROOT / rel).exists():
            warnings.append(f"WARNING: missing input file: {rel}")

    _manifest = load_json(ROOT / "docs/firmware_manifest.json", warnings)
    inventory = load_csv(ROOT / "docs/firmware_inventory.csv", warnings)
    function_map = load_csv(ROOT / "docs/function_map.csv", warnings)
    _bb = load_csv(ROOT / "docs/basic_block_map.csv", warnings)
    call_xref = load_csv(ROOT / "docs/call_xref.csv", warnings)
    xdata = load_csv(ROOT / "docs/xdata_confirmed_access.csv", warnings)
    xdata_by_branch = load_csv(ROOT / "docs/xdata_map_by_branch.csv", warnings)
    disasm = load_csv(ROOT / "docs/disassembly_index.csv", warnings)
    code_tbl = load_csv(ROOT / "docs/code_table_candidates.csv", warnings)
    string_idx = load_csv(ROOT / "docs/string_index.csv", warnings)
    global_candidates = load_csv(ROOT / "docs/global_packet_pipeline_candidates.csv", warnings)
    _global_chains = load_csv(ROOT / "docs/global_packet_pipeline_chains.csv", warnings)
    branch_summary = load_csv(ROOT / "docs/branch_comparison_summary.csv", warnings)
    smoke = load_csv(ROOT / "docs/analysis_smoke_test_results.csv", warnings)

    inv_by_file: dict[str, dict[str, str]] = {}
    for row in inventory:
        if row.get("branch") == TARGET_BRANCH and row.get("file") in TARGET_FILES:
            inv_by_file[row["file"]] = row

    starts_by_file: dict[str, list[tuple[int, str]]] = defaultdict(list)
    fn: dict[tuple[str, str], FnStat] = {}
    for row in function_map:
        if row.get("branch") != TARGET_BRANCH:
            continue
        file = row.get("file", "")
        if file not in TARGET_FILES:
            continue
        addr = row.get("function_addr", "")
        ai = to_int(addr)
        st = FnStat(
            file=file,
            addr=addr,
            addr_int=ai,
            role=row.get("role_candidate", "unknown") or "unknown",
            incoming_lcalls=to_int(row.get("incoming_lcalls", "0")),
            call_count=to_int(row.get("call_count", "0")),
            xread=to_int(row.get("xdata_read_count", "0")),
            xwrite=to_int(row.get("xdata_write_count", "0")),
            movc=to_int(row.get("movc_count", "0")),
            bbc=to_int(row.get("basic_block_count", "0")),
            ibc=to_int(row.get("internal_block_count", "0")),
        )
        fn[(file, addr)] = st
        if ai:
            starts_by_file[file].append((ai, addr))

    for file in list(starts_by_file):
        starts_by_file[file] = sorted(starts_by_file[file])

    string_addrs = {(r.get("file", ""), to_int(r.get("address", "0"))) for r in string_idx if r.get("branch") == TARGET_BRANCH}
    for row in code_tbl:
        if row.get("branch") != TARGET_BRANCH:
            continue
        file = row.get("file", "")
        caddr = to_int(row.get("code_addr", "0"))
        dptr = to_int(row.get("dptr_addr", "0"))
        faddr = map_addr(caddr, starts_by_file.get(file, []))
        if faddr and (file, dptr) in string_addrs and (file, faddr) in fn:
            fn[(file, faddr)].string_refs += 1

    # xdata hits per function + xdata-role aggregate seed
    xdata_agg: dict[int, dict[str, object]] = {}
    for row in xdata:
        if row.get("branch") != TARGET_BRANCH:
            continue
        file = row.get("file", "")
        caddr = to_int(row.get("code_addr", "0"))
        xaddr = to_int(row.get("dptr_addr", "0"))
        access = row.get("access_type", "")
        faddr = map_addr(caddr, starts_by_file.get(file, []))
        if faddr and (file, faddr) in fn:
            st = fn[(file, faddr)]
            is_hit = False
            if in_range(xaddr, RTOS_CORE):
                st.rtos_hits += 1
                is_hit = True
            if in_range(xaddr, SERVICE_FLAGS):
                st.service_hits += 1
                is_hit = True
            if in_range(xaddr, SECONDARY_FLAGS):
                st.secondary_hits += 1
                is_hit = True
            if in_range(xaddr, NEARBY_RANGE) or xaddr in NEARBY_POINTS:
                is_hit = True
            if is_hit:
                st.cluster_hits += 1

        if not xaddr:
            continue
        agg = xdata_agg.setdefault(
            xaddr,
            {
                "files": set(),
                "read": 0,
                "write": 0,
                "functions": set(),
                "roles": Counter(),
                "valid_seen": False,
            },
        )
        agg["files"].add(file)
        if access == "write":
            agg["write"] += 1
        else:
            agg["read"] += 1
        if faddr:
            agg["functions"].add(f"{file}:{faddr}")
            role = fn[(file, faddr)].role if (file, faddr) in fn else "unknown"
            agg["roles"][role] += 1
        inv = inv_by_file.get(file, {})
        if is_true(inv.get("valid_hex", "")) and to_int(inv.get("checksum_errors", "0")) == 0:
            agg["valid_seen"] = True

    for row in disasm:
        if row.get("branch") != TARGET_BRANCH:
            continue
        file = row.get("file", "")
        caddr = to_int(row.get("code_addr", "0"))
        faddr = map_addr(caddr, starts_by_file.get(file, []))
        if faddr and (file, faddr) in fn and (row.get("mnemonic", "").upper() in ARITH_METRICS):
            fn[(file, faddr)].arithmetic_hits += 1

    # score + candidate type
    probable_patterns: set[tuple[str, str, int, int, int]] = set()
    for st in fn.values():
        score = 0
        if st.rtos_hits > 0:
            score += 4
        if st.service_hits > 0:
            score += 4
        if st.secondary_hits > 0:
            score += 3
        if st.xwrite > 0:
            score += 2
        if st.xread > 0:
            score += 2
        if any(k in st.role.lower() for k in ("service", "runtime", "dispatcher", "packet")):
            score += 2
        if st.incoming_lcalls > 0:
            score += 1
        if st.call_count > 0:
            score += 1
        if st.movc > 0:
            score += 1
        if st.string_refs > 0:
            score += 1
        if st.arithmetic_hits > 0:
            score += 1
        st.score = score

        role_l = st.role.lower()
        if "dispatcher" in role_l:
            st.candidate_type = "dispatcher_candidate"
        elif "service" in role_l or "runtime" in role_l:
            st.candidate_type = "service_worker_candidate"
        elif st.xwrite > 0 and st.arithmetic_hits > 0:
            st.candidate_type = "state_update_candidate"
        elif st.xwrite > 0:
            st.candidate_type = "xdata_writer_candidate"
        elif st.movc > 0 or st.string_refs > 0 or "packet" in role_l:
            st.candidate_type = "table_string_candidate"
        elif st.incoming_lcalls > 0 and st.call_count > 3:
            st.candidate_type = "call_hub_candidate"
        else:
            st.candidate_type = "xdata_reader_candidate"

        inv = inv_by_file.get(st.file, {})
        valid = is_true(inv.get("valid_hex", "")) and to_int(inv.get("checksum_errors", "0")) == 0
        if score >= 8 and valid:
            st.confidence = "probable"
            probable_patterns.add((st.candidate_type, st.role, int(st.rtos_hits > 0), int(st.service_hits > 0), int(st.secondary_hits > 0)))
        elif score >= 5:
            st.confidence = "hypothesis"
        else:
            st.confidence = "unknown"

    # cap for checksum-error files unless same pattern exists in valid file
    for st in fn.values():
        inv = inv_by_file.get(st.file, {})
        if to_int(inv.get("checksum_errors", "0")) <= 0:
            continue
        if st.confidence == "probable":
            pat = (st.candidate_type, st.role, int(st.rtos_hits > 0), int(st.service_hits > 0), int(st.secondary_hits > 0))
            if pat not in probable_patterns:
                st.confidence = "hypothesis"

    rows = []
    for st in sorted(fn.values(), key=lambda x: (x.file, -x.score, x.addr_int)):
        inv = inv_by_file.get(st.file, {})
        checksum_status = "ok" if to_int(inv.get("checksum_errors", "0")) == 0 else "checksum_error"
        notes = []
        if checksum_status != "ok":
            notes.append("checksum_error_limits_confidence")
        if st.cluster_hits == 0:
            notes.append("no_rtos_cluster_hits")
        rows.append(
            {
                "file": st.file,
                "valid_hex": str(is_true(inv.get("valid_hex", ""))).lower(),
                "checksum_status": checksum_status,
                "function_addr": st.addr,
                "candidate_type": st.candidate_type,
                "score": str(st.score),
                "confidence": st.confidence,
                "role_candidate": st.role,
                "basic_block_count": str(st.bbc),
                "internal_block_count": str(st.ibc),
                "incoming_lcalls": str(st.incoming_lcalls),
                "call_count": str(st.call_count),
                "xdata_read_count": str(st.xread),
                "xdata_write_count": str(st.xwrite),
                "movc_count": str(st.movc),
                "string_refs": str(st.string_refs),
                "cluster_hits": str(st.cluster_hits),
                "rtos_core_hits": str(st.rtos_hits),
                "service_flag_hits": str(st.service_hits),
                "secondary_flag_hits": str(st.secondary_hits),
                "arithmetic_hits": str(st.arithmetic_hits),
                "notes": ";".join(notes),
            }
        )

    args.function_out.parent.mkdir(parents=True, exist_ok=True)
    with args.function_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FUNCTION_FIELDS)
        w.writeheader()
        w.writerows(rows)

    # graph + chains
    out_edges: dict[str, set[tuple[str, str]]] = defaultdict(set)
    in_edges: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in call_xref:
        if row.get("branch") != TARGET_BRANCH:
            continue
        file = row.get("file", "")
        if file not in TARGET_FILES:
            continue
        src_code = to_int(row.get("code_addr", "0"))
        src_fn = map_addr(src_code, starts_by_file.get(file, []))
        dst_fn = row.get("target_addr", "")
        if not src_fn or (file, dst_fn) not in fn:
            continue
        if row.get("call_type", "") not in {"LCALL", "LJMP"}:
            continue
        out_edges[file].add((src_fn, dst_fn))
        in_edges[file].add((dst_fn, src_fn))

    rank_rows = []
    for file in TARGET_FILES:
        fns = {a for (f, a) in fn if f == file}
        chains = []
        for core in fns:
            core_st = fn[(file, core)]
            if core_st.xread + core_st.xwrite <= 0:
                continue
            callers = [src for (dst, src) in in_edges[file] if dst == core]
            callees = [dst for (src, dst) in out_edges[file] if src == core]
            for caller in callers:
                for callee in callees:
                    c_st = fn[(file, caller)]
                    e_st = fn[(file, callee)]
                    role_sig = {c_st.candidate_type, e_st.candidate_type}
                    if not role_sig.intersection({"dispatcher_candidate", "service_worker_candidate", "call_hub_candidate"}):
                        continue
                    rtos_hits = c_st.rtos_hits + core_st.rtos_hits + e_st.rtos_hits
                    service_hits = c_st.service_hits + core_st.service_hits + e_st.service_hits
                    secondary_hits = c_st.secondary_hits + core_st.secondary_hits + e_st.secondary_hits
                    if (rtos_hits + service_hits + secondary_hits) <= 0:
                        continue
                    chain_score = c_st.score + core_st.score + e_st.score
                    confidence = "probable" if chain_score >= 24 else "hypothesis" if chain_score >= 15 else "unknown"
                    inv = inv_by_file.get(file, {})
                    if to_int(inv.get("checksum_errors", "0")) > 0 and confidence == "probable":
                        confidence = "hypothesis"
                    chains.append(
                        {
                            "file": file,
                            "valid_hex": str(is_true(inv.get("valid_hex", ""))).lower(),
                            "caller_function": caller,
                            "core_function": core,
                            "callee_function": callee,
                            "caller_role": c_st.role,
                            "core_role": core_st.role,
                            "callee_role": e_st.role,
                            "caller_score": str(c_st.score),
                            "core_score": str(core_st.score),
                            "callee_score": str(e_st.score),
                            "chain_score": str(chain_score),
                            "rtos_core_hits": str(rtos_hits),
                            "service_flag_hits": str(service_hits),
                            "secondary_flag_hits": str(secondary_hits),
                            "confidence": confidence,
                            "notes": "caller->core->callee static call chain candidate",
                        }
                    )

        chains.sort(key=lambda r: int(r["chain_score"]), reverse=True)
        for idx, row in enumerate(chains, start=1):
            row["chain_rank"] = str(idx)
            rank_rows.append(row)

    with args.chains_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CHAIN_FIELDS)
        w.writeheader()
        w.writerows(rank_rows)

    xrows = []
    for xaddr in sorted(xdata_agg):
        agg = xdata_agg[xaddr]
        if in_range(xaddr, RTOS_CORE):
            group = "rtos_core"
        elif in_range(xaddr, SERVICE_FLAGS):
            group = "service_flags"
        elif in_range(xaddr, SECONDARY_FLAGS):
            group = "secondary_flags"
        elif in_range(xaddr, NEARBY_RANGE) or xaddr in NEARBY_POINTS:
            group = "nearby_runtime"
        else:
            group = "other"
        roles = agg["roles"]
        top_role = roles.most_common(1)[0][0] if roles else "unknown"
        total = int(agg["read"]) + int(agg["write"])
        conf = "probable" if total >= 4 and bool(agg["valid_seen"]) else "hypothesis" if total >= 2 else "unknown"
        if not bool(agg["valid_seen"]) and conf == "probable":
            conf = "hypothesis"
        notes = "xdata address aggregated across RTOS_service files"
        if not bool(agg["valid_seen"]):
            notes += "; checksum-only evidence present"
        xrows.append(
            {
                "xdata_addr": f"0x{xaddr:04X}",
                "range_group": group,
                "files": ";".join(sorted(agg["files"])),
                "read_count": str(agg["read"]),
                "write_count": str(agg["write"]),
                "functions": ";".join(sorted(agg["functions"])),
                "role_candidate": top_role,
                "confidence": conf,
                "notes": notes,
            }
        )

    with args.xdata_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=XDATA_ROLE_FIELDS)
        w.writeheader()
        w.writerows(xrows)

    # Markdown synthesis
    by_type: dict[str, list[FnStat]] = defaultdict(list)
    by_conf: dict[str, int] = Counter()
    for st in fn.values():
        by_type[st.candidate_type].append(st)
        by_conf[st.confidence] += 1
    for k in by_type:
        by_type[k].sort(key=lambda s: s.score, reverse=True)

    bs = next((r for r in branch_summary if r.get("branch") == TARGET_BRANCH), None)
    a03 = next((r for r in branch_summary if r.get("branch") == "A03_A04"), None)

    top_chains = sorted(rank_rows, key=lambda r: int(r["chain_score"]), reverse=True)[:10]
    top_functions = sorted(fn.values(), key=lambda s: s.score, reverse=True)[:8]
    smoke_pass = sum(1 for r in smoke if r.get("status") == "pass")
    smoke_total = len(smoke)

    md = []
    md.append("# RTOS_service branch-focused runtime/service pipeline analysis")
    md.append("")
    md.append("## Почему выбрана ветка RTOS_service")
    md.append("- По branch-level сравнению ветка RTOS_service остаётся приоритетом для следующего крупного этапа runtime/service reverse.")
    if bs:
        md.append(
            f"- summary: files={bs.get('files','')}, valid_hex={bs.get('valid_hex_count','')}, checksum_errors={bs.get('checksum_error_count','')}, packet_like_function_count={bs.get('packet_like_function_count','')}, writer_like_function_count={bs.get('writer_like_function_count','')}."
        )
    md.append("")
    md.append("## Файлы ветки и checksum статус")
    for f in TARGET_FILES:
        inv = inv_by_file.get(f, {})
        md.append(f"- {f}: valid_hex={inv.get('valid_hex','unknown')}, checksum_errors={inv.get('checksum_errors','unknown')}.")
    md.append("")
    md.append("## Почему checksum-error ограничивает confidence")
    md.append("- В этом отчёте метка `confirmed` не используется для кандидатов и цепочек.")
    md.append("- Для checksum_error файлов confidence ограничен уровнем hypothesis, кроме случаев повторяющегося паттерна из valid_hex файла.")
    md.append("- Поэтому результаты для ppkp2012/ppkp2019 трактуются как вероятностные и требуют ручной трассировки в валидном образе.")
    md.append("")
    md.append("## XDATA-кластеры ветки RTOS_service")
    md.append("- rtos_core: 0x6406..0x6422")
    md.append("- service_flags: 0x759C..0x75AE")
    md.append("- secondary_flags: 0x769C..0x76AA")
    md.append("- nearby_runtime: 0x6419..0x6423, 0x66EA, 0x6892, 0x6894, 0x75AA, 0x75AB, 0x76AA, 0x76AB")
    md.append("")

    def add_top(title: str, key: str) -> None:
        md.append(f"## {title}")
        items = by_type.get(key, [])[:10]
        if not items:
            md.append("- нет кандидатов")
        else:
            for st in items:
                md.append(
                    f"- {st.file}:{st.addr} score={st.score} confidence={st.confidence} role={st.role} hits(core/service/secondary)={st.rtos_hits}/{st.service_hits}/{st.secondary_hits}."
                )
        md.append("")

    add_top("Top dispatcher candidates", "dispatcher_candidate")
    add_top("Top service worker candidates", "service_worker_candidate")
    add_top("Top xdata writer candidates", "xdata_writer_candidate")
    add_top("Top table/string candidates", "table_string_candidate")

    md.append("## Top pipeline chains")
    if top_chains:
        for row in top_chains:
            md.append(
                f"- {row['file']} rank={row['chain_rank']}: {row['caller_function']} -> {row['core_function']} -> {row['callee_function']}, chain_score={row['chain_score']}, confidence={row['confidence']}, hits={row['rtos_core_hits']}/{row['service_flag_hits']}/{row['secondary_flag_hits']}."
            )
    else:
        md.append("- цепочки не выделены по текущим ограничениям.")
    md.append("")

    md.append("## Какие функции стоит трассировать вручную первыми")
    for st in top_functions[:5]:
        md.append(
            f"- {st.file}:{st.addr} ({st.candidate_type}) — score={st.score}, core/service/secondary={st.rtos_hits}/{st.service_hits}/{st.secondary_hits}, xread/xwrite={st.xread}/{st.xwrite}."
        )
    md.append("")

    md.append("## confirmed / probable / hypothesis / unknown")
    md.append("- confirmed: не присваивается в рамках этого branch-focused этапа.")
    md.append(f"- probable: {by_conf.get('probable', 0)}")
    md.append(f"- hypothesis: {by_conf.get('hypothesis', 0)}")
    md.append(f"- unknown: {by_conf.get('unknown', 0)}")
    md.append("")

    md.append("## Что нельзя считать доказанным")
    md.append("- Нельзя считать восстановленным packet format.")
    md.append("- Нельзя считать доказанной семантику runtime/service state только по статическому XDATA-паттерну.")
    md.append("- Нельзя переносить адреса между RTOS_service и A03/A04 как прямые аналоги.")
    md.append("")

    md.append("## Сравнение с A03/A04 (только архитектурный уровень)")
    if a03 and bs:
        md.append(
            f"- A03_A04 packet_like_function_count={a03.get('packet_like_function_count','')}, RTOS_service={bs.get('packet_like_function_count','')} — обе ветки содержат крупные packet/runtime кластеры, но с разной адресной топологией."
        )
        md.append(
            f"- A03_A04 writer_like_function_count={a03.get('writer_like_function_count','')}, RTOS_service={bs.get('writer_like_function_count','')} — RTOS_service даёт более плотный service/runtime call hub слой."
        )
    md.append("- Сопоставление делается по ролям (dispatcher/service/writer), а не по адресному переносу.")
    md.append("")

    md.append("## Следующий практический milestone")
    md.append("- Выполнить deep-dive 3–5 функций из top score в valid_hex файле ppkp2001, затем проверить устойчивость выводов в checksum_error образах как secondary evidence.")
    md.append(f"- Smoke-test baseline на момент анализа: {smoke_pass}/{smoke_total} pass.")
    if warnings:
        md.append("")
        md.append("## Warnings")
        for w in warnings:
            md.append(f"- {w}")

    args.md_out.write_text("\n".join(md) + "\n", encoding="utf-8")

    # next deep dive plan
    picks = sorted(fn.values(), key=lambda s: s.score, reverse=True)[:5]
    plan = ["# RTOS_service next deep-dive plan", "", "## Цель", "Выбрать 3–5 функций RTOS_service для немедленного глубокого разбора runtime/service pipeline.", ""]
    for st in picks:
        plan.append(f"## Функция {st.file}:{st.addr}")
        plan.append(f"- Почему выбрана: высокий интегральный score={st.score}, candidate_type={st.candidate_type}, confidence={st.confidence}.")
        x_checks = []
        if st.rtos_hits:
            x_checks.append("0x6406..0x6422")
        if st.service_hits:
            x_checks.append("0x759C..0x75AE")
        if st.secondary_hits:
            x_checks.append("0x769C..0x76AA")
        if not x_checks:
            x_checks.append("nearby_runtime: 0x6419..0x6423 / 0x66EA / 0x6892 / 0x6894 / 0x75AA / 0x75AB / 0x76AA / 0x76AB")
        plan.append(f"- Какие XDATA-адреса проверить: {', '.join(x_checks)}.")
        neighbors = [r for r in rank_rows if r['file'] == st.file and (r['caller_function'] == st.addr or r['core_function'] == st.addr or r['callee_function'] == st.addr)]
        if neighbors:
            n = neighbors[0]
            plan.append(f"- Какие вызовы вокруг важны: {n['caller_function']} -> {n['core_function']} -> {n['callee_function']}.")
        else:
            plan.append("- Какие вызовы вокруг важны: проверить входящие/исходящие LCALL/LJMP на глубину 1-2.")
        plan.append("- Что искать: очередь, статус, событие, буфер, таблица, checksum-like арифметика.")
        plan.append("")
    plan.append("## Критерий успеха")
    plan.append("- Успех: для каждой выбранной функции получена воспроизводимая роль в caller->core->callee пайплайне и зафиксирована привязка к конкретным XDATA runtime/service state кандидатам без заявлений о полном восстановлении packet format.")
    args.plan_out.write_text("\n".join(plan) + "\n", encoding="utf-8")

    print(f"Wrote {args.function_out.relative_to(ROOT)}")
    print(f"Wrote {args.chains_out.relative_to(ROOT)}")
    print(f"Wrote {args.xdata_out.relative_to(ROOT)}")
    print(f"Wrote {args.md_out.relative_to(ROOT)}")
    print(f"Wrote {args.plan_out.relative_to(ROOT)}")
    if warnings:
        print(f"Warnings: {len(warnings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
