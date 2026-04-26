#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

ZONE_FIELDS = [
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
    "conditional_branch_count",
    "bit_operation_count",
    "arithmetic_hits",
    "zone_marker_hits",
    "possible_zone_table_hits",
    "related_calls",
    "notes",
]

OUTPUT_FIELDS = [
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
    "conditional_branch_count",
    "bit_operation_count",
    "output_marker_hits",
    "control_action_hits",
    "event_input_hits",
    "packet_export_hits",
    "related_calls",
    "notes",
]

CHAIN_FIELDS = [
    "branch",
    "file",
    "chain_rank",
    "sensor_or_module_function",
    "zone_logic_function",
    "event_function",
    "output_control_function",
    "packet_export_function",
    "chain_score",
    "confidence",
    "zone_evidence",
    "output_evidence",
    "notes",
]

CONDITIONAL = {"CJNE", "SUBB", "JC", "JNC", "JZ", "JNZ", "JB", "JNB"}
BIT_OPS = {"ANL", "ORL", "XRL", "SETB", "CLR"}
ARITH_OPS = {"ADD", "ADDC", "SUBB", "INC", "DEC", "MUL", "DIV", "CJNE"}
ZONE_MARKERS = ["зона", "zone", "логика", "logic", "пожар", "неисправ", "внимание", "адрес", "датчик", "включ", "отключ"]
OUTPUT_MARKERS = ["реле", "relay", "выход", "output", "задвиж", "valve", "control", "управ", "сирена", "оповещ", "пуск", "стоп", "вкл", "выкл", "on", "off"]


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
    bit_operation_count: int = 0
    arithmetic_hits: int = 0
    zone_marker_hits: int = 0
    output_marker_hits: int = 0
    control_action_hits: int = 0
    event_input_hits: int = 0
    packet_export_hits: int = 0
    table_hits: int = 0
    string_refs: set[str] = field(default_factory=set)
    related_calls: set[str] = field(default_factory=set)
    notes: set[str] = field(default_factory=set)


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


def score_confidence(score: float) -> str:
    if score >= 10:
        return "medium"
    if score >= 6:
        return "low"
    return "hypothesis"


def map_addr_to_fn(addr: int, starts: list[tuple[int, str]]) -> str | None:
    lo, hi = 0, len(starts) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        start, fn = starts[mid]
        if addr < start:
            hi = mid - 1
        else:
            best = fn
            lo = mid + 1
    return best


def choose_zone_type(s: FnStat) -> str:
    if s.movc_count >= 1 and s.table_hits >= 1:
        return "zone_table_candidate"
    if s.table_hits >= 1 and s.xdata_read_count >= 2:
        return "sensor_to_zone_mapping_candidate"
    if s.role_candidate == "state_update_worker" and s.xdata_write_count >= 2:
        return "zone_state_update_candidate"
    if s.role_candidate == "dispatcher_or_router" and s.conditional_branch_count >= 8:
        return "zone_logic_candidate"
    if s.event_input_hits >= 1:
        return "zone_event_candidate"
    if s.zone_marker_hits >= 1 and s.call_count >= 3:
        return "menu_zone_logic_candidate"
    return "unknown_zone_related"


def choose_output_type(s: FnStat) -> str:
    if s.role_candidate == "dispatcher_or_router" and s.call_count >= 8:
        return "output_module_dispatcher_candidate"
    if s.output_marker_hits >= 2 and s.xdata_write_count >= 2:
        return "relay_output_candidate"
    if s.output_marker_hits >= 1 and "valve" in " ".join(s.string_refs).lower():
        return "valve_control_candidate"
    if s.output_marker_hits >= 1 and ("сирена" in " ".join(s.string_refs).lower() or "оповещ" in " ".join(s.string_refs).lower()):
        return "siren_or_notification_output_candidate"
    if s.control_action_hits >= 1 and s.xdata_read_count >= 2 and s.xdata_write_count >= 1:
        return "actuator_feedback_candidate"
    if s.xdata_write_count >= 2 and s.conditional_branch_count >= 6:
        return "output_state_update_candidate"
    if s.packet_export_hits >= 1:
        return "output_packet_export_candidate"
    return "unknown_output_related"


def main() -> int:
    parser = argparse.ArgumentParser(description="Zone/output-control semantic candidate analyzer.")
    parser.add_argument("--out-zone", type=Path, default=DOCS / "zone_logic_candidates.csv")
    parser.add_argument("--out-output", type=Path, default=DOCS / "output_control_candidates.csv")
    parser.add_argument("--out-chains", type=Path, default=DOCS / "zone_to_output_chains.csv")
    parser.add_argument("--out-md", type=Path, default=DOCS / "zone_output_logic_analysis.md")
    args = parser.parse_args()

    warnings: list[str] = []
    _module_overview = (DOCS / "module_logic_overview.md").read_text(encoding="utf-8") if (DOCS / "module_logic_overview.md").exists() else ""
    if not _module_overview:
        warnings.append("missing file: docs/module_logic_overview.md")
    module_summary = load_csv(DOCS / "module_handler_summary.csv", warnings)
    mash_summary = load_csv(DOCS / "mash_handler_deep_trace_summary.csv", warnings)
    mash_trace = load_csv(DOCS / "mash_handler_deep_trace.csv", warnings)
    function_map = load_csv(DOCS / "function_map.csv", warnings)
    basic_block = load_csv(DOCS / "basic_block_map.csv", warnings)
    disassembly = load_csv(DOCS / "disassembly_index.csv", warnings)
    call_xref = load_csv(DOCS / "call_xref.csv", warnings)
    xdata_confirmed = load_csv(DOCS / "xdata_confirmed_access.csv", warnings)
    code_table = load_csv(DOCS / "code_table_candidates.csv", warnings)
    string_index = load_csv(DOCS / "string_index.csv", warnings)
    pipeline_candidates = load_csv(DOCS / "global_packet_pipeline_candidates.csv", warnings)
    pipeline_chains = load_csv(DOCS / "global_packet_pipeline_chains.csv", warnings)
    _xdata_map = load_csv(DOCS / "xdata_map_by_branch.csv", warnings)

    fn_stats: dict[tuple[str, str, str], FnStat] = {}
    starts_by_file: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for row in function_map:
        key = (row.get("branch", ""), row.get("file", ""), row.get("function_addr", ""))
        fn_stats[key] = FnStat(
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
        addr_i = to_int(key[2])
        if addr_i:
            starts_by_file[key[1]].append((addr_i, key[2]))
    for file in starts_by_file:
        starts_by_file[file].sort()

    for row in basic_block:
        key = (row.get("branch", ""), row.get("file", ""), row.get("parent_function_candidate", ""))
        stat = fn_stats.get(key)
        if not stat:
            continue
        ends = (row.get("ends_with", "") or "").upper()
        if ends in CONDITIONAL:
            stat.conditional_branch_count += 1

    for row in disassembly:
        branch, file = row.get("branch", ""), row.get("file", "")
        fn = map_addr_to_fn(to_int(row.get("code_addr", "0")), starts_by_file.get(file, []))
        if not fn:
            continue
        stat = fn_stats.get((branch, file, fn))
        if not stat:
            continue
        mnem = (row.get("mnemonic", "") or "").upper()
        operands = (row.get("operands", "") or "")
        if mnem in CONDITIONAL:
            stat.conditional_branch_count += 1
        if mnem in BIT_OPS:
            stat.bit_operation_count += 1
        if mnem in ARITH_OPS:
            stat.arithmetic_hits += 1
        lo = f"{mnem} {operands}".lower()
        if any(x in lo for x in ["#0x01", "#01h", "#0x02", "#02h", "#0x03", "#03h", "#0x04", "#04h"]):
            stat.table_hits += 1

    for row in xdata_confirmed:
        branch, file = row.get("branch", ""), row.get("file", "")
        fn = map_addr_to_fn(to_int(row.get("code_addr", "0")), starts_by_file.get(file, []))
        if fn and (branch, file, fn) in fn_stats:
            fn_stats[(branch, file, fn)].notes.add(f"xdata:{row.get('dptr_addr', '')}")

    for row in code_table:
        key = (row.get("branch", ""), row.get("file", ""), row.get("code_addr", ""))
        branch, file, code_addr = key
        fn = map_addr_to_fn(to_int(code_addr), starts_by_file.get(file, []))
        if fn and (branch, file, fn) in fn_stats:
            fn_stats[(branch, file, fn)].table_hits += 2

    for row in string_index:
        text = " ".join([row.get("ascii_text", ""), row.get("cp1251_candidate", ""), row.get("notes", "")]).strip()
        if not text:
            continue
        lower = text.lower()
        branch, file = row.get("branch", ""), row.get("file", "")
        fn = map_addr_to_fn(to_int(row.get("address", "0")), starts_by_file.get(file, []))
        if not fn:
            continue
        stat = fn_stats.get((branch, file, fn))
        if not stat:
            continue
        if any(m in lower for m in ZONE_MARKERS):
            stat.zone_marker_hits += 1
            stat.string_refs.add(text[:80])
        if any(m in lower for m in OUTPUT_MARKERS):
            stat.output_marker_hits += 1
            stat.string_refs.add(text[:80])

    for row in module_summary:
        key = (row.get("branch", ""), "", row.get("function_addr", ""))
        for k, stat in fn_stats.items():
            if k[0] == key[0] and k[2] == key[2]:
                note = f"module:{row.get('module_type', '')}/{row.get('handler_role', '')}"
                stat.notes.add(note)
                if "маш" in row.get("module_type", "").lower() or "address" in row.get("module_type", "").lower():
                    stat.zone_marker_hits += 1
                if "управ" in row.get("handler_role", "").lower() or "output" in row.get("handler_role", "").lower():
                    stat.output_marker_hits += 1

    for row in mash_summary:
        b = row.get("branch", "")
        f = row.get("file", "")
        for col in ["caller_function", "core_function", "callee_function"]:
            fn = row.get(col, "")
            stat = fn_stats.get((b, f, fn))
            if not stat:
                continue
            stat.event_input_hits += to_int(row.get("event_queue_hits", "0"))
            stat.packet_export_hits += to_int(row.get("packet_export_hits", "0"))
            stat.bit_operation_count += to_int(row.get("bit_operation_hits", "0"))

    for row in mash_trace:
        b = row.get("branch", "")
        f = row.get("file", "")
        fn = row.get("function_addr", "")
        stat = fn_stats.get((b, f, fn))
        if not stat:
            continue
        et = (row.get("event_type", "") or "").lower()
        if "bit" in et:
            stat.bit_operation_count += 1
        if "call" in et:
            stat.event_input_hits += 1

    pipeline_by_fn: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in pipeline_candidates:
        key = (row.get("branch", ""), row.get("file", ""), row.get("function_addr", ""))
        ctype = row.get("candidate_type", "")
        pipeline_by_fn[key].add(ctype)
        stat = fn_stats.get(key)
        if not stat:
            continue
        if "event" in ctype:
            stat.event_input_hits += 1
        if "packet_export" in ctype or "service" in ctype:
            stat.packet_export_hits += 1
        if "writer" in ctype:
            stat.control_action_hits += 1

    for row in call_xref:
        branch, file = row.get("branch", ""), row.get("file", "")
        src_fn = map_addr_to_fn(to_int(row.get("code_addr", "0")), starts_by_file.get(file, []))
        target = row.get("target_addr", "")
        if not src_fn:
            continue
        stat = fn_stats.get((branch, file, src_fn))
        if stat and target:
            stat.related_calls.add(target)

    zone_rows: list[dict[str, str]] = []
    output_rows: list[dict[str, str]] = []
    zone_set: set[tuple[str, str, str]] = set()
    output_set: set[tuple[str, str, str]] = set()

    for key, s in fn_stats.items():
        zone_score = (
            s.zone_marker_hits * 2.0
            + s.table_hits * 1.2
            + min(s.conditional_branch_count, 30) * 0.12
            + min(s.bit_operation_count, 30) * 0.12
            + min(s.xdata_read_count, 20) * 0.16
            + min(s.xdata_write_count, 20) * 0.16
            + min(s.arithmetic_hits, 40) * 0.06
            + (1.2 if s.role_candidate in {"dispatcher_or_router", "state_update_worker", "table_string_candidate", "state_reader_or_packet_builder"} else 0)
        )
        if zone_score >= 4.5:
            zone_set.add(key)
            zone_rows.append(
                {
                    "branch": s.branch,
                    "file": s.file,
                    "function_addr": s.function_addr,
                    "candidate_type": choose_zone_type(s),
                    "score": fmt_score(zone_score),
                    "confidence": score_confidence(zone_score),
                    "role_candidate": s.role_candidate,
                    "basic_block_count": str(s.basic_block_count),
                    "internal_block_count": str(s.internal_block_count),
                    "incoming_lcalls": str(s.incoming_lcalls),
                    "call_count": str(s.call_count),
                    "xdata_read_count": str(s.xdata_read_count),
                    "xdata_write_count": str(s.xdata_write_count),
                    "movc_count": str(s.movc_count),
                    "string_refs": " | ".join(sorted(s.string_refs)[:5]),
                    "conditional_branch_count": str(s.conditional_branch_count),
                    "bit_operation_count": str(s.bit_operation_count),
                    "arithmetic_hits": str(s.arithmetic_hits),
                    "zone_marker_hits": str(s.zone_marker_hits),
                    "possible_zone_table_hits": str(s.table_hits),
                    "related_calls": "|".join(sorted(s.related_calls)[:10]),
                    "notes": "; ".join(sorted(s.notes)[:8]),
                }
            )

        output_score = (
            s.output_marker_hits * 2.0
            + min(s.xdata_write_count, 20) * 0.30
            + min(s.bit_operation_count, 40) * 0.14
            + min(s.control_action_hits, 15) * 0.8
            + min(s.event_input_hits, 15) * 0.25
            + min(s.packet_export_hits, 15) * 0.35
            + min(s.conditional_branch_count, 30) * 0.08
            + (1.0 if s.role_candidate in {"dispatcher_or_router", "state_update_worker", "state_reader_or_packet_builder"} else 0)
        )
        if output_score >= 4.5:
            output_set.add(key)
            output_rows.append(
                {
                    "branch": s.branch,
                    "file": s.file,
                    "function_addr": s.function_addr,
                    "candidate_type": choose_output_type(s),
                    "score": fmt_score(output_score),
                    "confidence": score_confidence(output_score),
                    "role_candidate": s.role_candidate,
                    "basic_block_count": str(s.basic_block_count),
                    "internal_block_count": str(s.internal_block_count),
                    "incoming_lcalls": str(s.incoming_lcalls),
                    "call_count": str(s.call_count),
                    "xdata_read_count": str(s.xdata_read_count),
                    "xdata_write_count": str(s.xdata_write_count),
                    "movc_count": str(s.movc_count),
                    "string_refs": " | ".join(sorted(s.string_refs)[:5]),
                    "conditional_branch_count": str(s.conditional_branch_count),
                    "bit_operation_count": str(s.bit_operation_count),
                    "output_marker_hits": str(s.output_marker_hits),
                    "control_action_hits": str(s.control_action_hits),
                    "event_input_hits": str(s.event_input_hits),
                    "packet_export_hits": str(s.packet_export_hits),
                    "related_calls": "|".join(sorted(s.related_calls)[:10]),
                    "notes": "; ".join(sorted(s.notes)[:8]),
                }
            )

    zone_rows.sort(key=lambda r: (r["branch"], r["file"], -float(r["score"]), r["function_addr"]))
    output_rows.sort(key=lambda r: (r["branch"], r["file"], -float(r["score"]), r["function_addr"]))

    chains: list[dict[str, str]] = []
    rank = 1
    for row in pipeline_chains:
        b = row.get("branch", "")
        f = row.get("file", "")
        sensor = row.get("caller_function", "")
        core = row.get("core_function", "")
        callee = row.get("callee_function", "")

        zone_fn = core if (b, f, core) in zone_set else (sensor if (b, f, sensor) in zone_set else "")
        out_fn = callee if (b, f, callee) in output_set else (core if (b, f, core) in output_set else "")

        event_fn = ""
        packet_fn = ""
        for fn in [sensor, core, callee]:
            tags = pipeline_by_fn.get((b, f, fn), set())
            if not event_fn and any("event" in t for t in tags):
                event_fn = fn
            if not packet_fn and any("packet_export" in t or "service" in t for t in tags):
                packet_fn = fn

        parts_missing = [
            p for p, v in {
                "zone_logic": zone_fn,
                "event": event_fn,
                "output_control": out_fn,
                "packet_export": packet_fn,
            }.items() if not v
        ]
        chain_score = to_int(row.get("chain_score", "0")) + (4 - len(parts_missing)) * 2
        conf = "medium" if len(parts_missing) <= 1 else "low" if len(parts_missing) <= 2 else "hypothesis"
        note = "full_chain" if not parts_missing else f"partial_chain missing: {', '.join(parts_missing)}"

        chains.append(
            {
                "branch": b,
                "file": f,
                "chain_rank": str(rank),
                "sensor_or_module_function": sensor,
                "zone_logic_function": zone_fn,
                "event_function": event_fn,
                "output_control_function": out_fn,
                "packet_export_function": packet_fn,
                "chain_score": fmt_score(float(chain_score)),
                "confidence": conf,
                "zone_evidence": "zone_candidate" if zone_fn else "none",
                "output_evidence": "output_candidate" if out_fn else "none",
                "notes": note,
            }
        )
        rank += 1

    chains.sort(key=lambda r: (r["branch"], r["file"], -float(r["chain_score"])))

    args.out_zone.parent.mkdir(parents=True, exist_ok=True)
    with args.out_zone.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=ZONE_FIELDS)
        w.writeheader()
        w.writerows(zone_rows)
    with args.out_output.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
        w.writeheader()
        w.writerows(output_rows)
    with args.out_chains.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CHAIN_FIELDS)
        w.writeheader()
        w.writerows(chains)

    top_zone = zone_rows[:10]
    top_output = output_rows[:10]
    top_chains = chains[:10]
    direct_zone_strings = any(int(r.get("zone_marker_hits", "0") or 0) > 0 for r in zone_rows)
    direct_output_strings = any(int(r.get("output_marker_hits", "0") or 0) > 0 for r in output_rows)

    md = []
    md.append("# Zone/output-control logic analysis\n")
    md.append("Дата: 2026-04-26 (UTC).\n")
    md.append("\n## 1) Зачем нужен анализ зон и выходов\n")
    md.append("Чтобы восстановить прикладную логику прибора: от датчика/адреса и логики зоны до события, включения внешних устройств и экспорта состояния.\n")
    md.append("\n## 2) Предполагаемая прикладная схема\n")
    md.append("`датчик -> номер датчика -> зона -> логика зоны -> событие -> выходной модуль -> реле/задвижка/оповещение -> packet/export`.\n")
    md.append("\n## 3) Признаки зон\n")
    md.append("Top zone candidates (code evidence):\n")
    for r in top_zone:
        md.append(f"- {r['branch']} {r['file']} {r['function_addr']} ({r['candidate_type']}), score={r['score']}, confidence={r['confidence']}.\n")
    md.append("\n## 4) Кандидаты таблицы датчик -> зона\n")
    mapping = [r for r in zone_rows if r["candidate_type"] in {"sensor_to_zone_mapping_candidate", "zone_table_candidate"}][:8]
    if mapping:
        for r in mapping:
            md.append(f"- {r['branch']} {r['file']} {r['function_addr']} ({r['candidate_type']}), table_hits={r['possible_zone_table_hits']}, movc={r['movc_count']}, confidence={r['confidence']}.\n")
    else:
        md.append("- Явных сильных кандидатов sensor->zone table не найдено; текущий статус: hypothesis.\n")

    md.append("\n## 5) Кандидаты логики зоны из меню\n")
    menu = [r for r in zone_rows if r["candidate_type"] == "menu_zone_logic_candidate"][:8]
    if menu:
        for r in menu:
            md.append(f"- {r['branch']} {r['file']} {r['function_addr']}, confidence={r['confidence']}.\n")
    else:
        md.append("- Прямых menu-zone маркеров недостаточно; только косвенные state/dispatcher признаки (hypothesis).\n")

    md.append("\n## 6) Функции, похожие на обработчики зон\n")
    for r in [x for x in top_zone if x["candidate_type"] in {"zone_logic_candidate", "zone_state_update_candidate", "zone_event_candidate"}][:10]:
        md.append(f"- {r['branch']} {r['file']} {r['function_addr']} ({r['candidate_type']}) score={r['score']} confidence={r['confidence']}.\n")

    md.append("\n## 7) Функции, похожие на модули выходных сигналов\n")
    for r in top_output:
        md.append(f"- {r['branch']} {r['file']} {r['function_addr']} ({r['candidate_type']}) score={r['score']} confidence={r['confidence']}.\n")

    md.append("\n## 8) Цепочки от зоны к выходу\n")
    for r in top_chains:
        md.append(
            f"- {r['branch']} {r['file']}: {r['sensor_or_module_function']} -> {r['zone_logic_function'] or '?'} -> {r['event_function'] or '?'} -> {r['output_control_function'] or '?'} -> {r['packet_export_function'] or '?'}; {r['notes']}; confidence={r['confidence']}.\n"
        )

    md.append("\n## 9) Статусы confirmed / probable / hypothesis / unknown\n")
    md.append("- confirmed (code evidence): есть устойчивые branch-specific кандидаты zone/output и partial chain к packet/export.\n")
    md.append("- probable: часть функций совмещает признаки zone-state/event/output write path.\n")
    md.append("- hypothesis: точное восстановление zone menu-logic правил (AND/OR/1-of-2/2-of-2/delay) и точные map-таблицы sensor->zone.\n")
    md.append("- unknown: окончательная привязка конкретных реле/задвижек/исполнителей к конкретным XDATA-флагам без стенда.\n")

    md.append("\n## 10) Следующий ручной deep-dive\n")
    for r in (top_zone[:5] + top_output[:5]):
        md.append(f"- {r['branch']} {r['file']} {r['function_addr']} ({r['candidate_type']}), confidence={r['confidence']}.\n")

    md.append("\n## 11) Нужные стендовые проверки\n")
    md.append("- назначить датчик в зону 1;\n- назначить датчик в зону 2;\n- изменить логику зоны в меню;\n- вызвать пожар одного датчика;\n- вызвать пожар двух датчиков;\n- проверить включение реле;\n- проверить управление задвижкой;\n- проверить отключение/включение зоны;\n- сравнить исходящие пакеты.\n")

    md.append("\n## Warnings\n")
    if warnings:
        for w in warnings:
            md.append(f"- {w}\n")
    else:
        md.append("- none\n")

    md.append("\n## Прямые строковые маркеры\n")
    if not direct_zone_strings:
        md.append("- Прямых строк `зона/zone/логика` в используемом индексe недостаточно для уверенной идентификации (честно: не найдено как strong evidence).\n")
    if not direct_output_strings:
        md.append("- Прямых строк `реле/выход/задвижка` в используемом индексe недостаточно для уверенной идентификации (честно: не найдено как strong evidence).\n")

    args.out_md.write_text("".join(md), encoding="utf-8")

    print(f"Wrote {args.out_zone.relative_to(ROOT)} ({len(zone_rows)} rows)")
    print(f"Wrote {args.out_output.relative_to(ROOT)} ({len(output_rows)} rows)")
    print(f"Wrote {args.out_chains.relative_to(ROOT)} ({len(chains)} rows)")
    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
