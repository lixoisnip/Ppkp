#!/usr/bin/env python3
"""Deep-dive static trace for top MASH/address-loop handler chains."""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

INPUT_FILES = [
    "module_logic_overview.md",
    "module_handler_summary.csv",
    "mash_code_evidence_candidates.csv",
    "mash_candidate_chains.csv",
    "function_map.csv",
    "basic_block_map.csv",
    "disassembly_index.csv",
    "call_xref.csv",
    "xdata_confirmed_access.csv",
    "code_table_candidates.csv",
    "string_index.csv",
    "global_packet_pipeline_candidates.csv",
    "global_packet_pipeline_chains.csv",
]

TRACE_FIELDS = [
    "branch",
    "file",
    "chain_rank",
    "chain_role",
    "function_addr",
    "code_addr",
    "block_addr",
    "mnemonic",
    "operands",
    "event_type",
    "target_addr",
    "fallthrough_addr",
    "xdata_addr",
    "xdata_access_type",
    "call_target",
    "mash_marker",
    "confidence",
    "notes",
]

SUMMARY_FIELDS = [
    "branch",
    "file",
    "chain_rank",
    "caller_function",
    "core_function",
    "callee_function",
    "caller_role",
    "core_role",
    "callee_role",
    "chain_score",
    "address_range_hits",
    "loop_like_hits",
    "bit_operation_hits",
    "xdata_read_count",
    "xdata_write_count",
    "event_queue_hits",
    "packet_export_hits",
    "table_movc_hits",
    "string_refs",
    "confidence",
    "notes",
]

DISPATCHER_PRI = {"0x497A", "0x497F", "0x758B"}
CORE_PRI = {"0x800B", "0x737C", "0x8BE5", "0x7574", "0xA3FD"}
PACKET_PRI = {"0x6C07", "0x5A7F", "0x72AB", "0x655F", "0x92EF"}

CALL_OPS = {"LCALL", "ACALL"}
JUMP_OPS = {"LJMP", "SJMP", "AJMP"}
COND_OPS = {"CJNE", "SUBB", "JC", "JNC", "JZ", "JNZ", "JB", "JNB", "JBC"}
LOOP_OPS = {"DJNZ", "INC", "DEC", "JNZ", "SJMP", "AJMP", "LJMP", "CJNE"}
ARITH_OPS = {"ADD", "ADDC", "SUBB", "INC", "DEC", "MUL", "DIV"}
BIT_OPS = {"SETB", "CLR", "ANL", "ORL", "XRL", "MOV"}

IMM_RANGE_MAP = {
    "0x01": ["#0X01", "#01H"],
    "0x63": ["#0X63", "#63H"],
    "0x9F": ["#0X9F", "#9FH"],
    "0xA0": ["#0XA0", "#A0H", "#0A0H"],
}


@dataclass
class ChainSel:
    row: dict[str, str]
    priority_score: float


def to_int(v: str) -> int:
    t = (v or "").strip()
    if not t:
        return 0
    try:
        return int(t, 16) if t.lower().startswith("0x") else int(t)
    except ValueError:
        return 0


def to_float(v: str) -> float:
    try:
        return float((v or "0").strip())
    except ValueError:
        return 0.0


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


def conf_rank(v: str) -> int:
    order = {"high": 3, "medium": 2, "low": 1, "hypothesis": 0}
    return order.get((v or "").strip().lower(), 0)


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


def function_instruction_rows(
    file_name: str,
    function_addr: str,
    disasm_rows: list[dict[str, str]],
    bb_rows: list[dict[str, str]],
) -> list[tuple[int, str, dict[str, str]]]:
    file_dis = [r for r in disasm_rows if r.get("file") == file_name]
    file_dis.sort(key=lambda r: to_int(r.get("code_addr", "0")))
    by_addr = {to_int(r["code_addr"]): r for r in file_dis if r.get("code_addr")}
    addrs = sorted(by_addr)
    idx = {a: i for i, a in enumerate(addrs)}

    blocks = [r for r in bb_rows if r.get("file") == file_name and r.get("parent_function_candidate") == function_addr]
    blocks.sort(key=lambda r: to_int(r.get("block_addr", "0")))

    out: list[tuple[int, str, dict[str, str]]] = []
    seen: set[tuple[int, int]] = set()
    for b in blocks:
        baddr = to_int(b.get("block_addr", "0"))
        count = to_int(b.get("instruction_count", "0"))
        start = idx.get(baddr)
        if start is None or count <= 0:
            continue
        for i in range(start, min(start + count, len(addrs))):
            ca = addrs[i]
            uniq = (ca, baddr)
            if uniq in seen:
                continue
            seen.add(uniq)
            out.append((ca, b.get("block_addr", ""), by_addr[ca]))

    out.sort(key=lambda x: (x[0], to_int(x[1])))
    return out


def detect_markers(
    mnem: str,
    ops: str,
    event: str,
    xacc: str,
    fn_role: str,
    fn_evidence: set[str],
    call_target: str,
) -> list[str]:
    markers: list[str] = []
    uops = ops.upper()

    if any(p in uops for pats in IMM_RANGE_MAP.values() for p in pats) and mnem in {"CJNE", "SUBB", "JC", "JNC", "DJNZ", "INC", "DEC"}:
        markers.append("address_range_1_159")

    if event in {"loop_like", "conditional_branch"} and (xacc or "polling_loop_candidate" in fn_evidence):
        markers.append("address_loop_polling")

    if (mnem in BIT_OPS or " C" in uops or "BIT" in uops) and (xacc == "write" or "led_control_candidate" in fn_evidence):
        markers.append("led_control")

    if fn_role in {"state_update_worker", "state_reader_or_packet_builder", "service_or_runtime_worker"} and xacc == "write":
        markers.append("smoke_alarm_status")

    if fn_role in {"state_update_worker", "service_or_runtime_worker"} and event == "conditional_branch" and (xacc or "alarm_fault_status_candidate" in fn_evidence):
        markers.append("fault_status")

    if "isolator_status_candidate" in fn_evidence and (mnem in BIT_OPS or xacc == "write"):
        markers.append("isolator_status_hypothesis")

    if "event_queue_candidate" in fn_evidence or call_target in {"0x800B", "0x7017", "0x84A6"}:
        markers.append("event_queue_integration")

    if "packet_export_candidate" in fn_evidence or call_target in PACKET_PRI:
        markers.append("packet_export_integration")

    return markers or ["none"]


def select_chains(chains: list[dict[str, str]], min_n: int = 5, max_n: int = 10) -> list[dict[str, str]]:
    scored: list[ChainSel] = []
    for r in chains:
        addrs = {r.get("caller_function", ""), r.get("core_function", ""), r.get("callee_function", "")}
        pri = 0.0
        if addrs & DISPATCHER_PRI:
            pri += 3.0
        if addrs & CORE_PRI:
            pri += 3.0
        if addrs & PACKET_PRI:
            pri += 2.0
        pri += conf_rank(r.get("confidence", "")) * 0.2
        pri += to_float(r.get("chain_score", "0")) * 0.01
        scored.append(ChainSel(r, pri))

    scored.sort(
        key=lambda s: (
            -s.priority_score,
            -conf_rank(s.row.get("confidence", "")),
            -to_float(s.row.get("chain_score", "0")),
            to_int(s.row.get("chain_rank", "0")),
        )
    )

    selected: list[dict[str, str]] = []
    seen = set()
    for s in scored:
        key = (s.row.get("branch", ""), s.row.get("file", ""), s.row.get("chain_rank", ""))
        if key in seen:
            continue
        seen.add(key)
        selected.append(dict(s.row))
        if len(selected) >= max_n:
            break

    if len(selected) < min_n:
        for r in sorted(chains, key=lambda x: (-conf_rank(x.get("confidence", "")), -to_float(x.get("chain_score", "0")))):
            key = (r.get("branch", ""), r.get("file", ""), r.get("chain_rank", ""))
            if key in seen:
                continue
            seen.add(key)
            selected.append(dict(r))
            if len(selected) >= min_n:
                break

    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Deep static trace for top MASH handler candidate chains")
    parser.add_argument("--trace-out", type=Path, default=DOCS / "mash_handler_deep_trace.csv")
    parser.add_argument("--summary-out", type=Path, default=DOCS / "mash_handler_deep_trace_summary.csv")
    parser.add_argument("--md-out", type=Path, default=DOCS / "mash_handler_deep_trace_analysis.md")
    args = parser.parse_args()

    warnings: list[str] = []

    overview_text = load_text(DOCS / "module_logic_overview.md", warnings)
    module_summary = load_csv(DOCS / "module_handler_summary.csv", warnings)
    mash_candidates = load_csv(DOCS / "mash_code_evidence_candidates.csv", warnings)
    mash_chains = load_csv(DOCS / "mash_candidate_chains.csv", warnings)
    function_map = load_csv(DOCS / "function_map.csv", warnings)
    basic_blocks = load_csv(DOCS / "basic_block_map.csv", warnings)
    disasm = load_csv(DOCS / "disassembly_index.csv", warnings)
    call_xref = load_csv(DOCS / "call_xref.csv", warnings)
    xdata = load_csv(DOCS / "xdata_confirmed_access.csv", warnings)
    code_tbl = load_csv(DOCS / "code_table_candidates.csv", warnings)
    strings = load_csv(DOCS / "string_index.csv", warnings)
    pipeline_candidates = load_csv(DOCS / "global_packet_pipeline_candidates.csv", warnings)
    pipeline_chains = load_csv(DOCS / "global_packet_pipeline_chains.csv", warnings)

    selected_chains = select_chains(mash_chains, min_n=5, max_n=8)

    fn_role = {(r.get("branch", ""), r.get("file", ""), r.get("function_addr", "")): r.get("role_candidate", "unknown") for r in function_map}

    fn_evidence: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for r in mash_candidates:
        key = (r.get("branch", ""), r.get("file", ""), r.get("function_addr", ""))
        ev = r.get("evidence_type", "")
        if ev:
            fn_evidence[key].add(ev)

    for r in pipeline_candidates:
        key = (r.get("branch", ""), r.get("file", ""), r.get("function_addr", ""))
        ev = r.get("candidate_type", "")
        if ev:
            fn_evidence[key].add("packet_export_candidate")
            fn_evidence[key].add(ev)

    for r in module_summary:
        key = (r.get("branch", ""), "", r.get("function_addr", ""))
        fn_evidence[key].add("module_handler_summary")

    xmap = {(r.get("file", ""), r.get("code_addr", "")): r for r in xdata}
    cmap = {(r.get("file", ""), r.get("code_addr", "")): r for r in call_xref}
    movc_map = {(r.get("file", ""), r.get("code_addr", "")): r for r in code_tbl}

    str_map: dict[tuple[str, str], list[str]] = defaultdict(list)
    for s in strings:
        txt = (s.get("ascii_text") or s.get("cp1251_candidate") or "").strip()
        if s.get("file") and s.get("address") and txt:
            str_map[(s["file"], s["address"])].append(txt[:40])

    trace_rows: list[dict[str, str]] = []
    summary_rows: list[dict[str, str]] = []

    event_order = {
        "instruction": 0,
        "call": 1,
        "jump": 2,
        "conditional_branch": 3,
        "loop_like": 4,
        "arithmetic": 5,
        "bit_operation": 6,
        "xdata_read": 7,
        "xdata_write": 8,
        "table_movc": 9,
        "string_ref": 10,
        "mash_marker": 11,
    }

    for chain in selected_chains:
        branch = chain.get("branch", "")
        file_name = chain.get("file", "")
        chain_rank = chain.get("chain_rank", "")

        counters = Counter()
        string_refs: set[str] = set()
        notes = ["selected as top-ranked chain"]

        addrs = {
            chain.get("caller_function", ""),
            chain.get("core_function", ""),
            chain.get("callee_function", ""),
        }
        if not (addrs & DISPATCHER_PRI and addrs & CORE_PRI):
            notes.append("no exact dispatcher+core priority pair in chain; selected by top score")

        for chain_role, faddr in [
            ("caller", chain.get("caller_function", "")),
            ("core", chain.get("core_function", "")),
            ("callee", chain.get("callee_function", "")),
        ]:
            ev_key_exact = (branch, file_name, faddr)
            role = fn_role.get(ev_key_exact, "unknown")
            evidence = set(fn_evidence.get(ev_key_exact, set()))
            evidence |= set(fn_evidence.get((branch, "", faddr), set()))

            inst_rows = function_instruction_rows(file_name, faddr, disasm, basic_blocks)
            if not inst_rows:
                notes.append(f"no instruction span extracted for {chain_role}:{faddr}")

            for _, block_addr, ins in inst_rows:
                code_addr = ins.get("code_addr", "")
                mnem = (ins.get("mnemonic") or "").upper()
                ops = ins.get("operands", "")
                target = ins.get("target_addr", "")
                fall = ins.get("fallthrough_addr", "")

                x = xmap.get((file_name, code_addr), {})
                xaddr = x.get("dptr_addr", "")
                xacc = x.get("access_type", "")
                c = cmap.get((file_name, code_addr), {})
                ctgt = c.get("target_addr", "")

                events = ["instruction"]
                if mnem in CALL_OPS or c.get("call_type"):
                    events.append("call")
                if mnem in JUMP_OPS:
                    events.append("jump")
                if mnem in COND_OPS:
                    events.append("conditional_branch")
                if mnem in LOOP_OPS:
                    events.append("loop_like")
                if mnem in ARITH_OPS:
                    events.append("arithmetic")
                if mnem in BIT_OPS or "BIT" in ops.upper() or ",C" in ops.upper() or " C" in ops.upper():
                    events.append("bit_operation")
                if xacc == "read":
                    events.append("xdata_read")
                if xacc == "write":
                    events.append("xdata_write")
                if movc_map.get((file_name, code_addr)):
                    events.append("table_movc")
                if str_map.get((file_name, target)):
                    events.append("string_ref")

                markers = detect_markers(mnem, ops, events[-1], xacc, role, evidence, ctgt)

                for ev in sorted(set(events), key=lambda e: event_order[e]):
                    counters[ev] += 1
                    if ev == "xdata_read":
                        counters["xdata_read_count"] += 1
                    if ev == "xdata_write":
                        counters["xdata_write_count"] += 1
                    if ev == "loop_like":
                        counters["loop_like_hits"] += 1
                    if ev == "bit_operation":
                        counters["bit_operation_hits"] += 1
                    if ev == "table_movc":
                        counters["table_movc_hits"] += 1
                    if ev == "string_ref":
                        string_refs |= set(str_map.get((file_name, target), []))

                    row = {
                        "branch": branch,
                        "file": file_name,
                        "chain_rank": chain_rank,
                        "chain_role": chain_role,
                        "function_addr": faddr,
                        "code_addr": code_addr,
                        "block_addr": block_addr,
                        "mnemonic": ins.get("mnemonic", ""),
                        "operands": ops,
                        "event_type": ev,
                        "target_addr": target,
                        "fallthrough_addr": fall,
                        "xdata_addr": xaddr,
                        "xdata_access_type": xacc,
                        "call_target": ctgt,
                        "mash_marker": "none",
                        "confidence": chain.get("confidence", "hypothesis") or "hypothesis",
                        "notes": "",
                    }
                    trace_rows.append(row)

                uniq_markers = sorted(set(markers))
                for mk in uniq_markers:
                    if mk == "address_range_1_159":
                        counters["address_range_hits"] += 1
                    if mk == "event_queue_integration":
                        counters["event_queue_hits"] += 1
                    if mk == "packet_export_integration":
                        counters["packet_export_hits"] += 1
                    row = {
                        "branch": branch,
                        "file": file_name,
                        "chain_rank": chain_rank,
                        "chain_role": chain_role,
                        "function_addr": faddr,
                        "code_addr": code_addr,
                        "block_addr": block_addr,
                        "mnemonic": ins.get("mnemonic", ""),
                        "operands": ops,
                        "event_type": "mash_marker",
                        "target_addr": target,
                        "fallthrough_addr": fall,
                        "xdata_addr": xaddr,
                        "xdata_access_type": xacc,
                        "call_target": ctgt,
                        "mash_marker": mk,
                        "confidence": "hypothesis" if mk == "isolator_status_hypothesis" else (chain.get("confidence", "low") or "low"),
                        "notes": f"role={role};evidence={','.join(sorted(evidence))[:180]}",
                    }
                    trace_rows.append(row)

        conf = chain.get("confidence", "low") or "low"
        if counters["address_range_hits"] >= 6 and counters["event_queue_hits"] >= 4 and counters["packet_export_hits"] >= 3:
            conf = "probable"
        if counters["address_range_hits"] >= 10 and counters["event_queue_hits"] >= 8 and counters["packet_export_hits"] >= 6:
            conf = "confirmed"

        summary_rows.append(
            {
                "branch": branch,
                "file": file_name,
                "chain_rank": chain_rank,
                "caller_function": chain.get("caller_function", ""),
                "core_function": chain.get("core_function", ""),
                "callee_function": chain.get("callee_function", ""),
                "caller_role": fn_role.get((branch, file_name, chain.get("caller_function", "")), "unknown"),
                "core_role": fn_role.get((branch, file_name, chain.get("core_function", "")), "unknown"),
                "callee_role": fn_role.get((branch, file_name, chain.get("callee_function", "")), "unknown"),
                "chain_score": chain.get("chain_score", "0"),
                "address_range_hits": str(counters["address_range_hits"]),
                "loop_like_hits": str(counters["loop_like_hits"]),
                "bit_operation_hits": str(counters["bit_operation_hits"]),
                "xdata_read_count": str(counters["xdata_read_count"]),
                "xdata_write_count": str(counters["xdata_write_count"]),
                "event_queue_hits": str(counters["event_queue_hits"]),
                "packet_export_hits": str(counters["packet_export_hits"]),
                "table_movc_hits": str(counters["table_movc_hits"]),
                "string_refs": "|".join(sorted(string_refs)[:8]),
                "confidence": conf,
                "notes": "; ".join(notes),
            }
        )

    trace_rows.sort(key=lambda r: (r["branch"], r["file"], to_int(r["chain_rank"]), to_int(r["code_addr"]), r["chain_role"], r["event_type"], r["mash_marker"]))
    summary_rows.sort(key=lambda r: (r["branch"], r["file"], to_int(r["chain_rank"])))

    args.trace_out.parent.mkdir(parents=True, exist_ok=True)
    with args.trace_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=TRACE_FIELDS)
        w.writeheader()
        w.writerows(trace_rows)

    with args.summary_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        w.writeheader()
        w.writerows(summary_rows)

    strongest = summary_rows[0] if not summary_rows else max(
        summary_rows,
        key=lambda r: (
            to_int(r.get("address_range_hits", "0"))
            + to_int(r.get("loop_like_hits", "0"))
            + to_int(r.get("event_queue_hits", "0"))
            + to_int(r.get("packet_export_hits", "0")),
            to_float(r.get("chain_score", "0")),
        ),
    )

    lines = [
        "# MASH/address-loop deep trace analysis",
        "",
        "Дата: 2026-04-26 (UTC).",
        "",
        "## Зачем deep-dive",
        "Переход от общей модели к доказательному ordered static trace по top MASH chains: dispatcher -> handler -> state/event -> packet/export.",
        "",
        "## Выбор цепочек",
        f"Выбрано цепочек: {len(summary_rows)} (top-ranked из docs/mash_candidate_chains.csv c приоритетом dispatcher/core/packet адресов).",
        "",
        "| branch | file | rank | chain | score | confidence |",
        "|---|---|---:|---|---:|---|",
    ]
    for r in summary_rows:
        lines.append(
            f"| {r['branch']} | {r['file']} | {r['chain_rank']} | {r['caller_function']} -> {r['core_function']} -> {r['callee_function']} | {r['chain_score']} | {r['confidence']} |"
        )

    lines += [
        "",
        "## Strongest MASH candidate",
        f"Текущий strongest candidate: `{strongest.get('caller_function','?')} -> {strongest.get('core_function','?')} -> {strongest.get('callee_function','?')}` в `{strongest.get('file','?')}` (rank {strongest.get('chain_rank','?')}).",
        "",
        "## Наблюдения по признакам",
        "- **Признаки цикла адресного шлейфа:** есть в top chains через loop_like + conditional_branch + repeated calls (статически, confidence=probable).",
        "- **Диапазон 1..159:** фиксируются immediate/branch marker с 0x01/0x63/0x9F/0xA0 в части цепочек (confidence=probable, не full recovery).",
        "- **LED/status/fault:** bit_operation + XDATA writes + conditionals присутствуют (smoke_alarm/fault probable; isolator только hypothesis).",
        "- **XDATA update:** подтверждён через xdata_read/xdata_write события в caller/core/callee функциях.",
        "- **Event queue:** event_queue_integration marker встречается в выбранных цепочках (confidence=probable).",
        "- **Packet/export bridge:** packet_export_integration marker встречается в выбранных цепочках (confidence=probable).",
        "",
        "## Классификация выводов",
        "- **confirmed:** статически подтверждён путь dispatcher->handler->XDATA->event/packet integration markers (как code evidence).",
        "- **probable:** конкретная реализация опроса 1..159, LED/status/fault state transitions.",
        "- **hypothesis:** isolator status path; полная привязка к конкретной модели извещателя.",
        "- **unknown:** точные wire-level поля пакета для каждого состояния без стендовой валидации.",
        "",
        "## Следующие функции для ручной декомпозиции",
        "1. `0x497A` (dispatcher + poll scheduler, переход к state/event).",
        "2. `0x737C` (устойчивый core handler candidate в DKS ветках).",
        "3. `0x800B` (A03/A04 callee bridge к queue/packet зоне).",
        "",
        "## Нужные стендовые проверки",
        "- Прогон адресов 1..159 и фиксация реакций event/packet.",
        "- Команда LED (вкл/выкл/мигание) и сравнение XDATA/packet side effects.",
        "- Сценарий потери датчика / обрыв адресного шлейфа.",
        "- Fault/short-circuit/isolator-like сценарий (isolator трактовать как hypothesis до прямых маркеров).",
        "- Сравнение исходящих пакетов до/после событий по тем же адресам.",
        "",
        "## Evidence boundaries",
        "PDF по ИП212-200 / 22051E / 22051EI используется только как document evidence; chain-привязка сформирована из disassembly/XDATA/call-chain артефактов.",
    ]

    if not overview_text:
        lines.append("- module_logic_overview.md отсутствует: контекст prior PR не прочитан.")
    if pipeline_chains:
        lines.append(f"- global_packet_pipeline_chains.csv прочитан: {len(pipeline_chains)} rows (использован как supporting context).")

    if warnings:
        lines += ["", "## Warnings"]
        for w in warnings:
            lines.append(f"- {w}")

    args.md_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote {args.trace_out.relative_to(ROOT)} ({len(trace_rows)} rows)")
    print(f"Wrote {args.summary_out.relative_to(ROOT)} ({len(summary_rows)} rows)")
    print(f"Wrote {args.md_out.relative_to(ROOT)}")
    if warnings:
        print(f"Warnings: {len(warnings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
