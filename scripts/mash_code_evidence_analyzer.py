#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

CANDIDATE_FIELDS = [
    "branch",
    "file",
    "function_addr",
    "evidence_type",
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
    "conditional_branch_count",
    "loop_like_score",
    "bit_operation_count",
    "immediate_hits",
    "xdata_hits",
    "related_calls",
    "notes",
]

CHAIN_FIELDS = [
    "branch",
    "file",
    "chain_rank",
    "caller_function",
    "core_function",
    "callee_function",
    "caller_evidence",
    "core_evidence",
    "callee_evidence",
    "chain_score",
    "confidence",
    "notes",
]

CONDITIONAL = {"CJNE", "SUBB", "JC", "JNC", "JB", "JNB", "JZ", "JNZ"}
LOOP_OPS = {"DJNZ", "INC", "DEC", "SJMP", "AJMP", "LJMP", "JNZ", "JZ", "CJNE"}
BIT_OPS = {"SETB", "CLR", "ANL", "ORL", "XRL"}


@dataclass
class FnStat:
    branch: str
    file: str
    function_addr: str
    role_candidate: str
    basic_block_count: int
    internal_block_count: int
    incoming_lcalls: int
    call_count: int
    xdata_read_count: int
    xdata_write_count: int
    movc_count: int
    conditional_branch_count: int = 0
    loop_like_score: int = 0
    bit_operation_count: int = 0
    immediate_hits: set[str] = field(default_factory=set)
    xdata_hits: set[str] = field(default_factory=set)
    related_calls: set[str] = field(default_factory=set)


def load_csv(path: Path, warnings: list[str]) -> list[dict[str, str]]:
    if not path.exists():
        warnings.append(f"missing file: {path.relative_to(ROOT)}")
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def to_int(value: str) -> int:
    text = (value or "").strip()
    if not text:
        return 0
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return 0


def fmt_score(v: float) -> str:
    return f"{v:.3f}"


def confidence_for(score: float) -> str:
    if score >= 4.0:
        return "medium"
    if score >= 2.2:
        return "low"
    return "hypothesis"


def map_addr_to_fn(addr: int, starts: list[tuple[int, str]]) -> str | None:
    lo, hi = 0, len(starts) - 1
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
    parser = argparse.ArgumentParser(description="MASH/address-loop code evidence analyzer.")
    parser.add_argument("--out-csv", type=Path, default=DOCS / "mash_code_evidence_candidates.csv")
    parser.add_argument("--out-chains", type=Path, default=DOCS / "mash_candidate_chains.csv")
    parser.add_argument("--out-md", type=Path, default=DOCS / "mash_code_evidence_analysis.md")
    args = parser.parse_args()

    warnings: list[str] = []
    targets = load_csv(DOCS / "mash_code_search_targets.csv", warnings)
    supported = load_csv(DOCS / "supported_sensor_evidence.csv", warnings)
    function_map = load_csv(DOCS / "function_map.csv", warnings)
    basic_block = load_csv(DOCS / "basic_block_map.csv", warnings)
    disassembly = load_csv(DOCS / "disassembly_index.csv", warnings)
    call_xref = load_csv(DOCS / "call_xref.csv", warnings)
    xdata_confirmed = load_csv(DOCS / "xdata_confirmed_access.csv", warnings)
    _code_table = load_csv(DOCS / "code_table_candidates.csv", warnings)
    _string_index = load_csv(DOCS / "string_index.csv", warnings)
    _xdata_map = load_csv(DOCS / "xdata_map_by_branch.csv", warnings)
    pipeline_candidates = load_csv(DOCS / "global_packet_pipeline_candidates.csv", warnings)
    pipeline_chains = load_csv(DOCS / "global_packet_pipeline_chains.csv", warnings)

    fn_stats: dict[tuple[str, str, str], FnStat] = {}
    starts_by_file: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for row in function_map:
        key = (row.get("branch", ""), row.get("file", ""), row.get("function_addr", ""))
        stat = FnStat(
            branch=key[0],
            file=key[1],
            function_addr=key[2],
            role_candidate=row.get("role_candidate", "unknown") or "unknown",
            basic_block_count=to_int(row.get("basic_block_count", "0")),
            internal_block_count=to_int(row.get("internal_block_count", "0")),
            incoming_lcalls=to_int(row.get("incoming_lcalls", "0")),
            call_count=to_int(row.get("call_count", "0")),
            xdata_read_count=to_int(row.get("xdata_read_count", "0")),
            xdata_write_count=to_int(row.get("xdata_write_count", "0")),
            movc_count=to_int(row.get("movc_count", "0")),
        )
        fn_stats[key] = stat
        addr_i = to_int(key[2])
        if addr_i:
            starts_by_file[key[1]].append((addr_i, key[2]))

    for file in list(starts_by_file):
        starts_by_file[file].sort()

    for row in basic_block:
        branch, file = row.get("branch", ""), row.get("file", "")
        parent = row.get("parent_function_candidate", "")
        stat = fn_stats.get((branch, file, parent))
        if not stat:
            continue
        ends = (row.get("ends_with", "") or "").upper()
        if ends in CONDITIONAL:
            stat.conditional_branch_count += 1
        if ends in LOOP_OPS:
            stat.loop_like_score += 1

    for row in disassembly:
        branch, file = row.get("branch", ""), row.get("file", "")
        addr = to_int(row.get("code_addr", "0"))
        fn = map_addr_to_fn(addr, starts_by_file.get(file, []))
        if not fn:
            continue
        stat = fn_stats.get((branch, file, fn))
        if not stat:
            continue
        mnem = (row.get("mnemonic", "") or "").upper()
        ops = (row.get("operands", "") or "").upper()
        if mnem in CONDITIONAL:
            stat.conditional_branch_count += 1
        if mnem in LOOP_OPS:
            stat.loop_like_score += 1
        if mnem in BIT_OPS or " C" in ops or "BIT" in ops:
            stat.bit_operation_count += 1
        imm_map = {"0x01": ["#0X01", "#01H"], "0x63": ["#0X63", "#63H"], "0x9F": ["#0X9F", "#9FH"], "0xA0": ["#0XA0", "#0A0H", "#A0H"]}
        for canon, pats in imm_map.items():
            if any(p in ops for p in pats):
                stat.immediate_hits.add(canon)

    for row in xdata_confirmed:
        branch, file = row.get("branch", ""), row.get("file", "")
        addr = to_int(row.get("code_addr", "0"))
        fn = map_addr_to_fn(addr, starts_by_file.get(file, []))
        if not fn:
            continue
        stat = fn_stats.get((branch, file, fn))
        if not stat:
            continue
        dptr = row.get("dptr_addr", "")
        if dptr:
            stat.xdata_hits.add(dptr)

    for row in call_xref:
        branch, file = row.get("branch", ""), row.get("file", "")
        addr = to_int(row.get("code_addr", "0"))
        fn = map_addr_to_fn(addr, starts_by_file.get(file, []))
        if not fn:
            continue
        stat = fn_stats.get((branch, file, fn))
        if not stat:
            continue
        tgt = row.get("target_addr", "")
        if tgt:
            stat.related_calls.add(tgt)

    pipeline_tag: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in pipeline_candidates:
        key = (row.get("branch", ""), row.get("file", ""), row.get("function_addr", ""))
        pipeline_tag[key].add(row.get("candidate_type", "pipeline"))

    candidates: list[dict[str, str]] = []
    evidence_by_fn: dict[tuple[str, str, str], list[str]] = defaultdict(list)

    for key, stat in fn_stats.items():
        evidence_scores: list[tuple[str, float, str]] = []
        immediate_count = len(stat.immediate_hits)
        if immediate_count >= 2 and stat.conditional_branch_count >= 2:
            score = 1.2 + immediate_count * 0.8 + min(stat.loop_like_score, 8) * 0.2
            note = "address-range immediates + conditionals near loop-like control"
            evidence_scores.append(("address_range_candidate", score, note))
        if stat.loop_like_score >= 6 and stat.call_count >= 3:
            score = 1.4 + min(stat.loop_like_score, 14) * 0.3 + min(stat.call_count, 20) * 0.08
            note = "loop-heavy function with repeated calls (polling hypothesis)"
            evidence_scores.append(("polling_loop_candidate", score, note))
        if stat.bit_operation_count >= 2 and stat.xdata_write_count >= 1:
            score = 1.3 + min(stat.bit_operation_count, 12) * 0.25 + min(stat.xdata_write_count, 8) * 0.3
            note = "bit operations with XDATA writes (LED/control hypothesis)"
            evidence_scores.append(("led_control_candidate", score, note))
        if stat.xdata_write_count >= 2 and stat.conditional_branch_count >= 4 and stat.role_candidate in {
            "state_update_worker",
            "state_reader_or_packet_builder",
            "service_or_runtime_worker",
        }:
            score = 1.5 + min(stat.xdata_write_count, 10) * 0.25 + min(stat.conditional_branch_count, 20) * 0.08
            note = "state/fault candidate: XDATA writes + conditional updates"
            evidence_scores.append(("alarm_fault_status_candidate", score, note))
        if stat.xdata_write_count >= 1 and stat.bit_operation_count >= 1 and stat.role_candidate in {
            "state_update_worker",
            "service_or_runtime_worker",
            "unknown",
        }:
            score = 1.1 + min(stat.bit_operation_count, 8) * 0.15 + min(stat.xdata_write_count, 6) * 0.2
            note = "isolator-status hypothesis (bit flags + XDATA flags), no direct marker"
            evidence_scores.append(("isolator_status_candidate", score, note))
        if stat.call_count >= 4 and stat.xdata_write_count >= 1 and stat.role_candidate in {
            "dispatcher_or_router",
            "service_or_runtime_worker",
            "state_update_worker",
        }:
            score = 1.3 + min(stat.call_count, 20) * 0.1 + min(stat.xdata_write_count, 8) * 0.15
            note = "event-queue candidate based on call density + state writes"
            evidence_scores.append(("event_queue_candidate", score, note))
        if key in pipeline_tag and stat.call_count >= 3:
            score = 1.6 + len(pipeline_tag[key]) * 0.6 + min(stat.call_count, 20) * 0.08
            note = "packet export integration via global packet pipeline overlap"
            evidence_scores.append(("packet_export_candidate", score, note))
        if stat.role_candidate == "dispatcher_or_router" and stat.call_count >= 5 and stat.loop_like_score >= 4:
            score = 1.7 + min(stat.call_count, 20) * 0.09 + min(stat.loop_like_score, 12) * 0.2
            note = "common dispatcher candidate for MASH/address-loop"
            evidence_scores.append(("common_mash_dispatcher_candidate", score, note))

        for ev_type, score, note in evidence_scores:
            conf = confidence_for(score)
            if ev_type in {"isolator_status_candidate", "common_mash_dispatcher_candidate"} and conf == "medium":
                conf = "low"
            row = {
                "branch": stat.branch,
                "file": stat.file,
                "function_addr": stat.function_addr,
                "evidence_type": ev_type,
                "score": fmt_score(score),
                "confidence": conf,
                "role_candidate": stat.role_candidate,
                "basic_block_count": str(stat.basic_block_count),
                "internal_block_count": str(stat.internal_block_count),
                "incoming_lcalls": str(stat.incoming_lcalls),
                "call_count": str(stat.call_count),
                "xdata_read_count": str(stat.xdata_read_count),
                "xdata_write_count": str(stat.xdata_write_count),
                "movc_count": str(stat.movc_count),
                "conditional_branch_count": str(stat.conditional_branch_count),
                "loop_like_score": str(stat.loop_like_score),
                "bit_operation_count": str(stat.bit_operation_count),
                "immediate_hits": ";".join(sorted(stat.immediate_hits)),
                "xdata_hits": ";".join(sorted(stat.xdata_hits)[:12]),
                "related_calls": ";".join(sorted(stat.related_calls)[:12]),
                "notes": note,
            }
            candidates.append(row)
            evidence_by_fn[key].append(ev_type)

    candidates.sort(key=lambda r: (r["branch"], r["file"], -float(r["score"]), r["function_addr"], r["evidence_type"]))
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CANDIDATE_FIELDS)
        w.writeheader()
        w.writerows(candidates)

    call_edges: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    for row in call_xref:
        if (row.get("call_type", "") or "").upper() != "LCALL":
            continue
        branch, file = row.get("branch", ""), row.get("file", "")
        caller = map_addr_to_fn(to_int(row.get("code_addr", "0")), starts_by_file.get(file, []))
        callee = row.get("target_addr", "")
        if caller and callee:
            call_edges[(branch, file)].append((caller, callee))

    edge_set: dict[tuple[str, str], set[tuple[str, str]]] = {k: set(v) for k, v in call_edges.items()}
    chains: list[dict[str, str]] = []

    # seed from global pipeline chains + local evidence
    for row in pipeline_chains:
        k_branch, k_file = row.get("branch", ""), row.get("file", "")
        caller = row.get("caller_function", "")
        core = row.get("core_function", "")
        callee = row.get("callee_function", "")
        caller_e = ",".join(sorted(evidence_by_fn.get((k_branch, k_file, caller), []))) or "none"
        core_e = ",".join(sorted(evidence_by_fn.get((k_branch, k_file, core), []))) or "none"
        callee_e = ",".join(sorted(evidence_by_fn.get((k_branch, k_file, callee), []))) or "none"
        if core_e == "none":
            continue
        score = 1.8
        score += 1.0 if "common_mash_dispatcher_candidate" in caller_e else 0.2
        score += 1.0 if "polling_loop_candidate" in core_e else 0.3
        score += 0.8 if ("event_queue_candidate" in callee_e or "packet_export_candidate" in callee_e) else 0.2
        conf = confidence_for(score)
        chains.append(
            {
                "branch": k_branch,
                "file": k_file,
                "chain_rank": "0",
                "caller_function": caller,
                "core_function": core,
                "callee_function": callee,
                "caller_evidence": caller_e,
                "core_evidence": core_e,
                "callee_evidence": callee_e,
                "chain_score": fmt_score(score),
                "confidence": conf,
                "notes": "chain fused from global pipeline and mash evidence (hypothesis)",
            }
        )

    # local dispatcher->core->callee by calls
    for (branch, file), edges in edge_set.items():
        callers = defaultdict(set)
        for a, b in edges:
            callers[a].add(b)
        for caller, mids in callers.items():
            for core in mids:
                if core not in callers:
                    continue
                for callee in callers[core]:
                    caller_e = set(evidence_by_fn.get((branch, file, caller), []))
                    core_e = set(evidence_by_fn.get((branch, file, core), []))
                    callee_e = set(evidence_by_fn.get((branch, file, callee), []))
                    if "common_mash_dispatcher_candidate" not in caller_e and "polling_loop_candidate" not in core_e:
                        continue
                    if not ({"event_queue_candidate", "packet_export_candidate"} & callee_e):
                        continue
                    score = 2.1 + 0.9 * len(caller_e) + 1.1 * len(core_e) + 0.7 * len(callee_e)
                    if branch == "A03_A04" and any(x in {"0x329C", "0x329D"} for x in set().union(caller_e, core_e, callee_e)):
                        score += 0.2
                    conf = confidence_for(score)
                    chains.append(
                        {
                            "branch": branch,
                            "file": file,
                            "chain_rank": "0",
                            "caller_function": caller,
                            "core_function": core,
                            "callee_function": callee,
                            "caller_evidence": ",".join(sorted(caller_e)) or "none",
                            "core_evidence": ",".join(sorted(core_e)) or "none",
                            "callee_evidence": ",".join(sorted(callee_e)) or "none",
                            "chain_score": fmt_score(score),
                            "confidence": conf,
                            "notes": "local call chain: dispatcher->polling/state->event|packet candidate",
                        }
                    )

    uniq = {}
    for row in chains:
        key = (row["branch"], row["file"], row["caller_function"], row["core_function"], row["callee_function"])
        if key not in uniq or float(row["chain_score"]) > float(uniq[key]["chain_score"]):
            uniq[key] = row
    chains = sorted(uniq.values(), key=lambda r: (r["branch"], r["file"], -float(r["chain_score"])))
    for idx, row in enumerate(chains, 1):
        row["chain_rank"] = str(idx)

    with args.out_chains.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CHAIN_FIELDS)
        w.writeheader()
        w.writerows(chains)

    top_by_branch: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in candidates:
        if len(top_by_branch[row["branch"]]) < 7:
            top_by_branch[row["branch"]].append(row)

    address_hits = [r for r in candidates if r["evidence_type"] == "address_range_candidate"]
    polling_hits = [r for r in candidates if r["evidence_type"] == "polling_loop_candidate"]
    led_hits = [r for r in candidates if r["evidence_type"] == "led_control_candidate"]
    event_packet_hits = [r for r in candidates if r["evidence_type"] in {"event_queue_candidate", "packet_export_candidate"}]

    md_lines: list[str] = []
    md_lines.append("# MASH/address-loop code evidence analysis")
    md_lines.append("")
    md_lines.append("## Что искали по PDF")
    for row in targets:
        md_lines.append(f"- {row.get('target','')}: {row.get('why_search','')} (expected pattern: {row.get('expected_code_pattern','')}, confidence={row.get('confidence','')}).")
    md_lines.append("")
    md_lines.append("## Document evidence vs code evidence vs hypothesis")
    md_lines.append("- **Document evidence:** IP212-200 22051E/22051EI, System Sensor 200AP/200+, адреса 01-159, LED from panel, short-circuit isolator (from PDF seed data).")
    md_lines.append("- **Code evidence (this pass):** ranked candidates by branch/file/function for address-range constants, polling loops, bit+XDATA LED/status patterns, event queue and packet-export integration.")
    md_lines.append("- **Hypothesis only:** isolator-specific behavior and full System Sensor protocol reconstruction remain hypothesis until direct textual/protocol markers are found.")
    md_lines.append("")
    md_lines.append("## Top candidates по веткам")
    for branch in sorted(top_by_branch):
        md_lines.append(f"### {branch}")
        for row in top_by_branch[branch]:
            md_lines.append(
                f"- {row['file']}:{row['function_addr']} — {row['evidence_type']} score={row['score']} confidence={row['confidence']} (role={row['role_candidate']}; calls={row['call_count']}; loops={row['loop_like_score']})."
            )
    md_lines.append("")

    def section_filter(title: str, branch_filter: str) -> None:
        md_lines.append(f"## {title}")
        subset = [r for r in candidates if r["branch"] == branch_filter][:10]
        if not subset:
            md_lines.append("- Нет явных кандидатов в текущих CSV (hypothesis gap).")
            return
        for r in subset:
            md_lines.append(f"- {r['file']}:{r['function_addr']} {r['evidence_type']} score={r['score']} confidence={r['confidence']}.")
        md_lines.append("")

    section_filter("Отдельно A03/A04 candidates", "A03_A04")
    section_filter("Отдельно RTOS_service candidates", "RTOS_service")

    md_lines.append("## Проверка ключевых признаков")
    md_lines.append(f"- Адресный диапазон 1..159: {'есть кандидаты' if address_hits else 'не найдено'} (count={len(address_hits)}).")
    md_lines.append(f"- Polling-loop candidates: {'есть' if polling_hits else 'не найдено'} (count={len(polling_hits)}).")
    md_lines.append(f"- LED/bit-operation candidates: {'есть' if led_hits else 'не найдено'} (count={len(led_hits)}).")
    md_lines.append(f"- Event/packet integration candidates: {'есть' if event_packet_hits else 'не найдено'} (count={len(event_packet_hits)}).")
    md_lines.append("")

    md_lines.append("## Функции для следующего deep-dive")
    for row in sorted(candidates, key=lambda r: -float(r["score"]))[:12]:
        md_lines.append(
            f"- {row['branch']} {row['file']}:{row['function_addr']} ({row['evidence_type']}, score={row['score']}, confidence={row['confidence']}) — проверить ручным disasm/xref chain.")
    md_lines.append("")
    md_lines.append("## Почему это всё ещё не полное восстановление System Sensor 200AP/200+")
    md_lines.append("- Нет прямых строковых/табличных маркеров протокола 200AP/200+.")
    md_lines.append("- Candidate scoring основан на структурных паттернах (loops/xdata/calls), что остаётся косвенным evidence.")
    md_lines.append("- Isolator path и точные packet formats пока отмечены как hypothesis.")
    md_lines.append("")
    if warnings:
        md_lines.append("## Warnings")
        for w in warnings:
            md_lines.append(f"- {w}")

    args.out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"[ok] wrote {args.out_csv.relative_to(ROOT)} rows={len(candidates)}")
    print(f"[ok] wrote {args.out_chains.relative_to(ROOT)} rows={len(chains)}")
    print(f"[ok] wrote {args.out_md.relative_to(ROOT)}")
    if warnings:
        for w in warnings:
            print(f"[warning] {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
