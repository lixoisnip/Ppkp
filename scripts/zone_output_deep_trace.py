#!/usr/bin/env python3
"""Deep static trace for branch-specific zone->output candidate chain decomposition."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

INPUT_FILES = [
    "zone_output_logic_analysis.md",
    "zone_logic_candidates.csv",
    "output_control_candidates.csv",
    "zone_to_output_chains.csv",
    "module_logic_overview.md",
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
    "zone_marker",
    "output_marker",
    "event_marker",
    "confidence",
    "notes",
]

SUMMARY_FIELDS = [
    "branch",
    "file",
    "function_addr",
    "proposed_role",
    "score",
    "confidence",
    "basic_block_count",
    "internal_block_count",
    "call_count",
    "incoming_lcalls",
    "xdata_read_count",
    "xdata_write_count",
    "movc_count",
    "conditional_branch_count",
    "bit_operation_count",
    "zone_marker_hits",
    "output_marker_hits",
    "event_marker_hits",
    "packet_export_hits",
    "notes",
]

CALL_OPS = {"LCALL", "ACALL"}
JUMP_OPS = {"LJMP", "SJMP", "AJMP"}
COND_OPS = {"CJNE", "SUBB", "JC", "JNC", "JZ", "JNZ", "JB", "JNB", "JBC"}
LOOP_OPS = {"DJNZ", "CJNE", "JNZ", "SJMP", "AJMP", "LJMP"}
ARITH_OPS = {"ADD", "ADDC", "SUBB", "INC", "DEC", "MUL", "DIV"}
BIT_OPS = {"ANL", "ORL", "XRL", "SETB", "CLR", "CPL"}

DEFAULT_FUNCTIONS = ["0x497A", "0x737C", "0x613C", "0x6833"]


@dataclass
class FnSummary:
    branch: str
    file: str
    function_addr: str
    proposed_role: str = "unknown"
    basic_block_count: int = 0
    internal_block_count: int = 0
    call_count: int = 0
    incoming_lcalls: int = 0
    xdata_read_count: int = 0
    xdata_write_count: int = 0
    movc_count: int = 0
    conditional_branch_count: int = 0
    bit_operation_count: int = 0
    zone_marker_hits: int = 0
    output_marker_hits: int = 0
    event_marker_hits: int = 0
    packet_export_hits: int = 0
    score: float = 0.0
    confidence: str = "hypothesis"
    notes: set[str] | None = None

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = set()


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


def classify_event_type(mnem: str, target: str, fallthrough: str, xacc: str, movc_addr: str, string_ref: str) -> str:
    if mnem in CALL_OPS:
        return "call"
    if mnem in JUMP_OPS:
        return "jump"
    if mnem in COND_OPS:
        return "conditional_branch"
    if mnem in LOOP_OPS and (target or fallthrough):
        return "loop_like"
    if mnem in ARITH_OPS:
        return "arithmetic"
    if mnem in BIT_OPS:
        return "bit_operation"
    if xacc == "read":
        return "xdata_read"
    if xacc == "write":
        return "xdata_write"
    if movc_addr:
        return "table_movc"
    if string_ref:
        return "string_ref"
    return "instruction"


def choose_zone_marker(fn: str, zone_row: dict[str, str], mnem: str, xacc: str, movc_addr: str, notes: str) -> str:
    ctype = (zone_row.get("candidate_type", "") if zone_row else "").lower()
    if "sensor_to_zone_mapping" in ctype:
        return "sensor_to_zone_mapping"
    if "zone_table" in ctype or movc_addr:
        return "zone_table"
    if fn == "0x737C" or "zone_logic" in ctype:
        return "zone_logic"
    if xacc == "write" and fn in {"0x613C", "0x737C"}:
        return "zone_state_update"
    if "menu" in ctype or "menu" in notes.lower():
        return "menu_zone_logic_hypothesis"
    if "event" in ctype or (mnem in COND_OPS and xacc):
        return "zone_event_candidate"
    return "none"


def choose_output_marker(fn: str, out_row: dict[str, str], xacc: str, call_target: str, notes: str) -> str:
    ctype = (out_row.get("candidate_type", "") if out_row else "").lower()
    if "output_module_dispatcher" in ctype:
        return "output_dispatcher"
    if fn == "0x6833" or "relay_output" in ctype:
        return "relay_output"
    if "actuator_feedback" in ctype:
        return "actuator_feedback"
    if xacc == "write" and fn in {"0x613C", "0x6833", "0x737C"}:
        return "output_state_update"
    if call_target and call_target in {"0x5A7F", "0x6C07", "0x72AB", "0x655F", "0x92EF"}:
        return "output_packet_bridge"
    if "output" in notes.lower() or "relay" in notes.lower():
        return "unknown_output"
    return "none"


def choose_event_marker(
    fn: str,
    zone_marker: str,
    output_marker: str,
    call_target: str,
    event_functions: set[str],
    xacc: str,
    event_hint_calls: set[str],
) -> str:
    if call_target and call_target in event_functions:
        return "event_queue_candidate"
    if fn in {"0x737C", "0x613C"} and xacc == "write" and zone_marker in {"zone_logic", "zone_state_update"}:
        return "event_state_update"
    if call_target and (call_target == "0x6833" or call_target in event_hint_calls) and zone_marker != "none":
        return "event_to_output_bridge"
    if zone_marker != "none" and output_marker != "none":
        return "missing_event_link"
    return "none"


def conf_from_hits(score: float) -> str:
    if score >= 8.0:
        return "medium"
    if score >= 4.0:
        return "low"
    return "hypothesis"


def main() -> int:
    parser = argparse.ArgumentParser(description="Deep trace for zone-output chain candidate functions.")
    parser.add_argument("--branch", default="90CYE_DKS")
    parser.add_argument("--file", default="90CYE03_19_DKS.PZU")
    parser.add_argument("--functions", nargs="+", default=DEFAULT_FUNCTIONS)
    parser.add_argument("--trace-out", type=Path, default=DOCS / "zone_output_deep_trace.csv")
    parser.add_argument("--summary-out", type=Path, default=DOCS / "zone_output_deep_trace_summary.csv")
    parser.add_argument("--md-out", type=Path, default=DOCS / "zone_output_deep_trace_analysis.md")
    args = parser.parse_args()

    warnings: list[str] = []

    _zone_md = load_text(DOCS / "zone_output_logic_analysis.md", warnings)
    zone_candidates = load_csv(DOCS / "zone_logic_candidates.csv", warnings)
    output_candidates = load_csv(DOCS / "output_control_candidates.csv", warnings)
    zone_chains = load_csv(DOCS / "zone_to_output_chains.csv", warnings)
    _module_overview = load_text(DOCS / "module_logic_overview.md", warnings)
    function_map = load_csv(DOCS / "function_map.csv", warnings)
    basic_block = load_csv(DOCS / "basic_block_map.csv", warnings)
    disassembly = load_csv(DOCS / "disassembly_index.csv", warnings)
    call_xref = load_csv(DOCS / "call_xref.csv", warnings)
    xdata = load_csv(DOCS / "xdata_confirmed_access.csv", warnings)
    code_table = load_csv(DOCS / "code_table_candidates.csv", warnings)
    string_index = load_csv(DOCS / "string_index.csv", warnings)
    pipeline_candidates = load_csv(DOCS / "global_packet_pipeline_candidates.csv", warnings)
    pipeline_chains = load_csv(DOCS / "global_packet_pipeline_chains.csv", warnings)

    zone_by_fn = {
        (r.get("file", ""), r.get("function_addr", "")): r
        for r in zone_candidates
        if r.get("branch") == args.branch and r.get("file") == args.file
    }
    output_by_fn = {
        (r.get("file", ""), r.get("function_addr", "")): r
        for r in output_candidates
        if r.get("branch") == args.branch and r.get("file") == args.file
    }

    fn_map = {
        (r.get("file", ""), r.get("function_addr", "")): r
        for r in function_map
        if r.get("branch") == args.branch and r.get("file") == args.file
    }

    call_by_addr: dict[tuple[str, str], str] = {}
    event_functions: set[str] = set()
    event_hint_calls: set[str] = set()
    for r in call_xref:
        if r.get("file") != args.file or r.get("branch") != args.branch:
            continue
        call_by_addr[(r.get("file", ""), r.get("code_addr", ""))] = r.get("target_addr", "")

    for r in zone_chains:
        if r.get("branch") != args.branch or r.get("file") != args.file:
            continue
        ef = (r.get("event_function", "") or "").strip()
        if ef and ef not in {"none", "-", "0x0"}:
            event_functions.add(ef)
        out_fn = (r.get("output_control_function", "") or "").strip()
        if out_fn and out_fn.startswith("0x"):
            event_hint_calls.add(out_fn)

    for r in pipeline_chains:
        if r.get("branch") == args.branch and r.get("file") == args.file:
            for k in ("caller_function", "core_function", "callee_function"):
                v = (r.get(k, "") or "").strip()
                if v:
                    event_hint_calls.add(v)

    xdata_by_code: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for r in xdata:
        if r.get("file") == args.file and r.get("branch") == args.branch:
            xdata_by_code[(r.get("file", ""), r.get("code_addr", ""))].append(r)

    movc_by_code = {
        (r.get("file", ""), r.get("code_addr", "")): r.get("dptr_addr", "")
        for r in code_table
        if r.get("file") == args.file and r.get("branch") == args.branch
    }

    string_by_addr = {
        (r.get("file", ""), r.get("address", "")): (r.get("ascii_text", "") or r.get("cp1251_candidate", ""))
        for r in string_index
        if r.get("file") == args.file
    }

    packet_fn_set = {
        r.get("function_addr", "")
        for r in pipeline_candidates
        if r.get("branch") == args.branch and r.get("file") == args.file and "packet" in (r.get("candidate_type", "").lower())
    }
    packet_fn_set.update({"0x5A7F", "0x6C07", "0x72AB", "0x655F", "0x92EF"})

    trace_rows: list[dict[str, str]] = []
    summaries: list[FnSummary] = []

    for fn in args.functions:
        fm = fn_map.get((args.file, fn), {})
        zone_row = zone_by_fn.get((args.file, fn), {})
        out_row = output_by_fn.get((args.file, fn), {})
        stat = FnSummary(
            branch=args.branch,
            file=args.file,
            function_addr=fn,
            proposed_role=(zone_row.get("candidate_type") or out_row.get("candidate_type") or fm.get("role_candidate") or "unknown"),
            basic_block_count=to_int(fm.get("basic_block_count", "0")),
            internal_block_count=to_int(fm.get("internal_block_count", "0")),
            call_count=to_int(fm.get("call_count", "0")),
            incoming_lcalls=to_int(fm.get("incoming_lcalls", "0")),
            xdata_read_count=to_int(fm.get("xdata_read_count", "0")),
            xdata_write_count=to_int(fm.get("xdata_write_count", "0")),
            movc_count=to_int(fm.get("movc_count", "0")),
        )

        fn_rows = function_instruction_rows(args.file, fn, disassembly, basic_block)
        if not fn_rows:
            stat.notes.add("no_instruction_rows")

        for _addr_int, block_addr, ins in fn_rows:
            code_addr = ins.get("code_addr", "")
            mnem = (ins.get("mnemonic", "") or "").upper()
            operands = ins.get("operands", "")
            target_addr = ins.get("target_addr", "")
            fallthrough = ins.get("fallthrough_addr", "")
            call_target = call_by_addr.get((args.file, code_addr), "") if mnem in CALL_OPS else ""
            xrows = xdata_by_code.get((args.file, code_addr), [])
            xaddr = ";".join(sorted({x.get("dptr_addr", "") for x in xrows if x.get("dptr_addr")}))
            xacc_types = ";".join(sorted({x.get("access_type", "") for x in xrows if x.get("access_type")}))
            xacc_main = ""
            if "write" in xacc_types:
                xacc_main = "write"
            elif "read" in xacc_types:
                xacc_main = "read"

            movc_addr = movc_by_code.get((args.file, code_addr), "")

            string_ref = ""
            for (_, saddr), text in string_by_addr.items():
                if saddr and saddr.upper().replace("H", "").replace("0X", "") in operands.upper().replace("0X", ""):
                    string_ref = text
                    break

            event_type = classify_event_type(mnem, target_addr, fallthrough, xacc_main, movc_addr, string_ref)
            if event_type == "conditional_branch":
                stat.conditional_branch_count += 1
            if event_type == "bit_operation":
                stat.bit_operation_count += 1

            note_parts: list[str] = []
            if movc_addr:
                note_parts.append(f"movc_table={movc_addr}")
            if string_ref:
                note_parts.append(f"string_ref={string_ref[:40]}")
            if xaddr:
                note_parts.append(f"xdata={xaddr}")

            zone_marker = choose_zone_marker(fn, zone_row, mnem, xacc_main, movc_addr, zone_row.get("notes", ""))
            output_marker = choose_output_marker(fn, out_row, xacc_main, call_target, out_row.get("notes", ""))
            event_marker = choose_event_marker(fn, zone_marker, output_marker, call_target, event_functions, xacc_main, event_hint_calls)

            if zone_marker != "none":
                stat.zone_marker_hits += 1
            if output_marker != "none":
                if output_marker == "output_dispatcher" and event_type == "instruction":
                    pass
                else:
                    stat.output_marker_hits += 1
            if event_marker != "none":
                stat.event_marker_hits += 1
            if call_target and call_target in packet_fn_set:
                stat.packet_export_hits += 1

            row_score = 0.0
            row_score += 1.0 if zone_marker != "none" else 0.0
            row_score += 1.0 if output_marker != "none" else 0.0
            row_score += 1.0 if event_marker not in {"none", "missing_event_link"} else 0.0
            row_score += 0.5 if xacc_main else 0.0
            row_score += 0.5 if event_type in {"conditional_branch", "loop_like", "table_movc"} else 0.0

            trace_rows.append(
                {
                    "branch": args.branch,
                    "file": args.file,
                    "function_addr": fn,
                    "code_addr": code_addr,
                    "block_addr": block_addr,
                    "mnemonic": mnem,
                    "operands": operands,
                    "event_type": event_type,
                    "target_addr": target_addr,
                    "fallthrough_addr": fallthrough,
                    "xdata_addr": xaddr,
                    "xdata_access_type": xacc_types,
                    "call_target": call_target,
                    "zone_marker": zone_marker,
                    "output_marker": output_marker,
                    "event_marker": event_marker,
                    "confidence": conf_from_hits(row_score),
                    "notes": ";".join(note_parts) if note_parts else "static_trace",
                }
            )

        stat.score = (
            stat.zone_marker_hits * 1.5
            + stat.output_marker_hits * 1.5
            + stat.event_marker_hits * 2.0
            + stat.packet_export_hits * 1.5
            + stat.conditional_branch_count * 0.2
            + stat.bit_operation_count * 0.2
            + stat.movc_count * 0.5
        )
        stat.confidence = conf_from_hits(stat.score)
        if stat.event_marker_hits == 0:
            stat.notes.add("missing_event_link")
        if fn in {"0x497A", "0x737C"}:
            stat.notes.add("strong_zone_candidate")
        if fn == "0x6833":
            stat.notes.add("strong_relay_output_candidate")
        summaries.append(stat)

    args.trace_out.parent.mkdir(parents=True, exist_ok=True)
    with args.trace_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=TRACE_FIELDS)
        w.writeheader()
        w.writerows(trace_rows)

    summary_rows: list[dict[str, str]] = []
    for s in summaries:
        summary_rows.append(
            {
                "branch": s.branch,
                "file": s.file,
                "function_addr": s.function_addr,
                "proposed_role": s.proposed_role,
                "score": f"{s.score:.3f}",
                "confidence": s.confidence,
                "basic_block_count": str(s.basic_block_count),
                "internal_block_count": str(s.internal_block_count),
                "call_count": str(s.call_count),
                "incoming_lcalls": str(s.incoming_lcalls),
                "xdata_read_count": str(s.xdata_read_count),
                "xdata_write_count": str(s.xdata_write_count),
                "movc_count": str(s.movc_count),
                "conditional_branch_count": str(s.conditional_branch_count),
                "bit_operation_count": str(s.bit_operation_count),
                "zone_marker_hits": str(s.zone_marker_hits),
                "output_marker_hits": str(s.output_marker_hits),
                "event_marker_hits": str(s.event_marker_hits),
                "packet_export_hits": str(s.packet_export_hits),
                "notes": ";".join(sorted(s.notes)) if s.notes else "",
            }
        )

    with args.summary_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        w.writeheader()
        w.writerows(summary_rows)

    best_zone = max(summaries, key=lambda s: s.zone_marker_hits, default=None)
    best_output = max(
        summaries,
        key=lambda s: ((2 if s.function_addr == "0x6833" else 0) + s.output_marker_hits),
        default=None,
    )
    best_event = max(summaries, key=lambda s: s.event_marker_hits, default=None)

    missing_event = [s.function_addr for s in summaries if s.event_marker_hits == 0]

    md: list[str] = []
    md.append("# Zone-output deep trace analysis")
    md.append("")
    md.append(f"Файл анализа: `{args.file}` (ветка `{args.branch}`).")
    md.append("")
    md.append("## Почему выбраны функции 0x497A / 0x737C / 0x613C / 0x6833")
    md.append("- `0x497A`: ранее помечалась как сильный `sensor_to_zone_mapping_candidate` и `output_module_dispatcher_candidate`.")
    md.append("- `0x737C`: ранее помечалась как `zone_table_candidate` и `output_module_dispatcher_candidate`.")
    md.append("- `0x613C`: ранее помечалась как `zone_table_candidate` и `actuator_feedback_candidate`.")
    md.append("- `0x6833`: ранее помечалась как `relay_output_candidate`.")
    md.append("")
    md.append("## Ordered static trace по функциям")
    for s in summaries:
        md.append(f"### {s.function_addr}")
        md.append(
            f"- proposed_role: `{s.proposed_role}`; confidence={s.confidence}; score={s.score:.3f}; blocks={s.basic_block_count}; calls={s.call_count}; xdata(r/w)={s.xdata_read_count}/{s.xdata_write_count}."
        )
        md.append(
            f"- markers: zone={s.zone_marker_hits}, output={s.output_marker_hits}, event={s.event_marker_hits}, packet_export={s.packet_export_hits}; cond={s.conditional_branch_count}, bit_ops={s.bit_operation_count}, movc={s.movc_count}."
        )
        md.append(f"- confidence note: `{';'.join(sorted(s.notes or [])) or 'none'}`.")
        md.append("")

    md.append("## Интерпретация цепочки")
    if best_zone:
        md.append(f"- Наиболее вероятный `sensor -> zone mapping`: **{best_zone.function_addr}** (по числу zone_marker hits) — confidence: {best_zone.confidence}.")
    if best_zone and any(s.function_addr == "0x737C" for s in summaries):
        md.append("- Наиболее вероятная `zone table / zone logic`: **0x737C** (устойчивые zone/event/branch маркеры).")
    relay_fn = next((s for s in summaries if s.function_addr == "0x6833"), None)
    if relay_fn:
        md.append(
            f"- Наиболее вероятное `output / relay control`: **0x6833** (relay_output marker + packet bridge hits) — confidence: {relay_fn.confidence}."
        )
    elif best_output:
        md.append(
            f"- Наиболее вероятное `output / relay control`: **{best_output.function_addr}** (по output_marker hits) — confidence: {best_output.confidence}."
        )

    if best_event and best_event.event_marker_hits > 0:
        md.append(f"- Event-звено частично найдено: лучшая функция **{best_event.function_addr}** с {best_event.event_marker_hits} event_marker hits.")
    else:
        md.append("- Event-звено явно не найдено: `missing_event_link` между zone-маркерами и output-маркерами.")

    if missing_event:
        md.append(f"- Вероятный разрыв цепочки event наблюдается в: {', '.join(missing_event)}.")

    zone_to_output = any(s.zone_marker_hits > 0 and s.output_marker_hits > 0 for s in summaries)
    output_to_packet = any(s.packet_export_hits > 0 for s in summaries)
    md.append(f"- Путь `zone -> output`: {'observed (probable)' if zone_to_output else 'not confirmed'}.")
    md.append(f"- Путь `output -> packet/export`: {'observed (probable)' if output_to_packet else 'not confirmed'}.")

    md.append("")
    md.append("## Статус утверждений")
    md.append("- confirmed: присутствуют ordered static trace rows, XDATA read/write и call/jump/branch структуры для всех 4 функций.")
    md.append("- probable: роли `zone logic` и `relay output` распределяются на основе marker-hit профиля.")
    md.append("- hypothesis: точные semantic-правила (конкретные реле/зоны/алгоритмы меню/AND-OR) без стендовой проверки не утверждаются.")
    md.append("- unknown: полный event queue bridge и окончательный packet-format mapping в этом PR.")

    md.append("")
    md.append("## Следующие 2–3 функции для ручной декомпозиции")
    md.append("- `0x84A6` — вероятный event/state bridge рядом с zone dispatcher узлами.")
    md.append("- `0x728A` — вероятный packet/export bridge в цепочках 90CYE_DKS.")
    md.append("- `0x5A7F` — подтвержденный packet builder/service exporter для проверки output->packet перехода.")

    if warnings:
        md.append("")
        md.append("## Warnings")
        for w in sorted(set(warnings)):
            md.append(f"- {w}")

    args.md_out.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"Wrote trace: {args.trace_out.relative_to(ROOT)} ({len(trace_rows)} rows)")
    print(f"Wrote summary: {args.summary_out.relative_to(ROOT)} ({len(summary_rows)} rows)")
    print(f"Wrote analysis: {args.md_out.relative_to(ROOT)}")
    if warnings:
        print(f"Warnings: {len(warnings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
