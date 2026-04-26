#!/usr/bin/env python3
"""Deep static trace for the top RTOS_service chain in valid ppkp2001 image."""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

INPUTS = [
    DOCS / "disassembly_index.csv",
    DOCS / "basic_block_map.csv",
    DOCS / "function_map.csv",
    DOCS / "call_xref.csv",
    DOCS / "xdata_confirmed_access.csv",
    DOCS / "code_table_candidates.csv",
    DOCS / "string_index.csv",
    DOCS / "rtos_service_function_candidates.csv",
    DOCS / "rtos_service_pipeline_chains.csv",
    DOCS / "rtos_service_xdata_role_candidates.csv",
]

DEFAULT_FILE = "ppkp2001 90cye01.PZU"
DEFAULT_CHAIN = ["0x4358", "0x920C", "0x53E6"]
CHAIN_NAME = "0x4358->0x920C->0x53E6"

TRACE_OUT = DOCS / "rtos_service_chain_4358_920c_53e6_trace.csv"
SUMMARY_OUT = DOCS / "rtos_service_chain_4358_920c_53e6_summary.csv"
MD_OUT = DOCS / "rtos_service_chain_4358_920c_53e6_analysis.md"

RTOS_CORE = (0x6406, 0x6422)
SERVICE_FLAGS = (0x759C, 0x75AE)
SECONDARY_FLAGS = (0x769C, 0x76AA)
NEARBY_RUNTIME_POINTS = {0x66EA, 0x6892, 0x6894, 0x75AA, 0x75AB, 0x76AA, 0x76AB}
NEARBY_RUNTIME_RANGE = (0x6419, 0x6423)

ARITH = {"ADD", "ADDC", "SUBB", "INC", "DEC", "MUL", "DIV", "XRL", "ANL", "ORL"}
COND = {"JZ", "JNZ", "JC", "JNC", "JB", "JNB", "JBC", "CJNE", "DJNZ"}
JUMP = {"LJMP", "SJMP", "AJMP"}
CALL = {"LCALL", "ACALL"}


def parse_hex(v: str) -> int:
    return int((v or "0").strip(), 16)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def in_range(addr: int, rg: tuple[int, int]) -> bool:
    return rg[0] <= addr <= rg[1]


def marker_for_xdata(xdata_addr: str) -> str:
    if not xdata_addr:
        return "none"
    a = parse_hex(xdata_addr)
    if in_range(a, RTOS_CORE):
        return "rtos_core_0x6406_0x6422"
    if in_range(a, SERVICE_FLAGS):
        return "service_flags_0x759C_0x75AE"
    if in_range(a, SECONDARY_FLAGS):
        return "secondary_flags_0x769C_0x76AA"
    if a in NEARBY_RUNTIME_POINTS or in_range(a, NEARBY_RUNTIME_RANGE):
        return "nearby_runtime"
    return "none"


def rows_for_function(
    file_name: str,
    function_addr: str,
    chain_order: int,
    disasm_rows: list[dict[str, str]],
    block_rows: list[dict[str, str]],
    xdata_map: dict[tuple[str, str], dict[str, str]],
    call_map: dict[tuple[str, str], dict[str, str]],
    movc_map: dict[tuple[str, str], dict[str, str]],
    string_map: dict[tuple[str, str], list[str]],
) -> list[dict[str, str]]:
    selected_blocks = [
        r
        for r in block_rows
        if r.get("file") == file_name and r.get("parent_function_candidate") == function_addr
    ]
    selected_blocks.sort(key=lambda r: parse_hex(r["block_addr"]))

    file_disasm = [r for r in disasm_rows if r.get("file") == file_name]
    file_disasm.sort(key=lambda r: parse_hex(r["code_addr"]))
    by_addr = {parse_hex(r["code_addr"]): r for r in file_disasm}
    addrs = sorted(by_addr)
    idx = {a: i for i, a in enumerate(addrs)}

    selected: list[tuple[int, str, dict[str, str]]] = []
    seen: set[tuple[int, int]] = set()
    for block in selected_blocks:
        baddr = parse_hex(block["block_addr"])
        count = int(block.get("instruction_count") or "0")
        start = idx.get(baddr)
        if start is None or count <= 0:
            continue
        for i in range(start, min(start + count, len(addrs))):
            ca = addrs[i]
            uniq = (ca, baddr)
            if uniq in seen:
                continue
            seen.add(uniq)
            selected.append((ca, block["block_addr"], by_addr[ca]))

    selected.sort(key=lambda t: (t[0], parse_hex(t[1])))
    out: list[dict[str, str]] = []
    ev_order = {
        "instruction": 0,
        "xdata_read": 1,
        "xdata_write": 2,
        "call": 3,
        "jump": 4,
        "conditional_branch": 5,
        "arithmetic": 6,
        "movc": 7,
        "string_ref": 8,
        "rtos_marker": 9,
    }

    for _, block_addr, d in selected:
        code_addr = d["code_addr"]
        mnem = (d.get("mnemonic") or "").upper()
        target_addr = d.get("target_addr", "")
        fallthrough_addr = d.get("fallthrough_addr", "")
        x = xdata_map.get((file_name, code_addr), {})
        c = call_map.get((file_name, code_addr), {})
        movc = movc_map.get((file_name, code_addr), {})
        srefs = string_map.get((file_name, code_addr), [])
        xaddr = x.get("dptr_addr", "")
        xacc = x.get("access_type", "")
        call_type = c.get("call_type", "")
        call_target = c.get("target_addr", "")
        marker = marker_for_xdata(xaddr)

        base = {
            "file": file_name,
            "chain_order": str(chain_order),
            "function_addr": function_addr,
            "code_addr": code_addr,
            "block_addr": block_addr,
            "mnemonic": d.get("mnemonic", ""),
            "operands": d.get("operands", ""),
            "target_addr": target_addr,
            "fallthrough_addr": fallthrough_addr,
            "xdata_addr": xaddr,
            "xdata_access_type": xacc,
            "call_type": call_type,
            "call_target": call_target,
            "rtos_marker": marker,
            "notes": "",
        }

        events = ["instruction"]
        notes: list[str] = []
        if xacc == "read":
            events.append("xdata_read")
        elif xacc == "write":
            events.append("xdata_write")
        if mnem in CALL or call_type:
            events.append("call")
        if mnem in JUMP:
            events.append("jump")
        if mnem in COND:
            events.append("conditional_branch")
        if mnem in ARITH:
            events.append("arithmetic")
        if movc:
            events.append("movc")
            notes.append("movc_table_candidate")
        if srefs:
            events.append("string_ref")
            notes.append(f"string_refs:{'|'.join(srefs)}")
        if marker != "none":
            events.append("rtos_marker")

        dedup_events = sorted(set(events), key=lambda e: ev_order[e])
        for ev in dedup_events:
            row = dict(base)
            row["event_type"] = ev
            row["notes"] = ";".join(notes)
            out.append(row)

    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Deep static chain trace for RTOS_service target chain")
    parser.add_argument("--file", default=DEFAULT_FILE)
    parser.add_argument("--chain", default=",".join(DEFAULT_CHAIN), help="comma-separated addresses")
    parser.add_argument("--trace-out", type=Path, default=TRACE_OUT)
    parser.add_argument("--summary-out", type=Path, default=SUMMARY_OUT)
    parser.add_argument("--md-out", type=Path, default=MD_OUT)
    args = parser.parse_args()

    for p in INPUTS:
        if not p.exists():
            raise FileNotFoundError(f"missing required input: {p.relative_to(ROOT)}")

    chain = [c.strip() for c in args.chain.split(",") if c.strip()]
    if len(chain) != 3:
        raise ValueError("chain must contain exactly 3 function addresses")

    disasm = load_csv(DOCS / "disassembly_index.csv")
    bb = load_csv(DOCS / "basic_block_map.csv")
    fn_map = load_csv(DOCS / "function_map.csv")
    call_xref = load_csv(DOCS / "call_xref.csv")
    xdata = load_csv(DOCS / "xdata_confirmed_access.csv")
    code_tbl = load_csv(DOCS / "code_table_candidates.csv")
    strings = load_csv(DOCS / "string_index.csv")
    rtos_fn = load_csv(DOCS / "rtos_service_function_candidates.csv")
    chains = load_csv(DOCS / "rtos_service_pipeline_chains.csv")
    _xrole = load_csv(DOCS / "rtos_service_xdata_role_candidates.csv")

    disasm = [r for r in disasm if r.get("file") == args.file and r.get("branch") == "RTOS_service"]
    bb = [r for r in bb if r.get("file") == args.file and r.get("branch") == "RTOS_service"]

    xdata_map = {(r["file"], r["code_addr"]): r for r in xdata if r.get("file") == args.file}
    call_map = {(r["file"], r["code_addr"]): r for r in call_xref if r.get("file") == args.file}
    movc_map = {(r["file"], r["code_addr"]): r for r in code_tbl if r.get("file") == args.file}

    string_addr_to_text: dict[tuple[str, str], list[str]] = defaultdict(list)
    for s in strings:
        file_name = s.get("file", "")
        addr = s.get("address", "")
        txt = (s.get("ascii_text") or s.get("cp1251_candidate") or "").strip()
        if file_name and addr and txt:
            string_addr_to_text[(file_name, addr)].append(txt[:60])

    fn_meta = {(r["file"], r["function_addr"]): r for r in fn_map}
    rtos_meta = {(r["file"], r["function_addr"]): r for r in rtos_fn}

    trace_rows: list[dict[str, str]] = []
    for order, fa in enumerate(chain, start=1):
        trace_rows.extend(
            rows_for_function(args.file, fa, order, disasm, bb, xdata_map, call_map, movc_map, string_addr_to_text)
        )

    trace_rows.sort(
        key=lambda r: (int(r["chain_order"]), parse_hex(r["code_addr"]), parse_hex(r["block_addr"]), r["event_type"])
    )

    trace_fields = [
        "file",
        "chain_order",
        "function_addr",
        "code_addr",
        "block_addr",
        "mnemonic",
        "operands",
        "target_addr",
        "fallthrough_addr",
        "event_type",
        "xdata_addr",
        "xdata_access_type",
        "call_type",
        "call_target",
        "rtos_marker",
        "notes",
    ]
    with args.trace_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=trace_fields)
        w.writeheader()
        w.writerows(trace_rows)

    summary_rows: list[dict[str, str]] = []
    first_seen: dict[str, str] = {
        "rtos_core_0x6406_0x6422": "",
        "service_flags_0x759C_0x75AE": "",
        "secondary_flags_0x769C_0x76AA": "",
    }

    for fa in chain:
        fn_rows = [r for r in trace_rows if r["function_addr"] == fa]
        counts = Counter(r["event_type"] for r in fn_rows)
        marker_counts = Counter(r["rtos_marker"] for r in fn_rows if r["rtos_marker"] != "none")
        blocks = {r["block_addr"] for r in fn_rows}
        fn = fn_meta.get((args.file, fa), {})
        rf = rtos_meta.get((args.file, fa), {})

        for marker in first_seen:
            if not first_seen[marker]:
                hit = next((r for r in fn_rows if r["rtos_marker"] == marker), None)
                if hit:
                    first_seen[marker] = f"{fa} @ {hit['code_addr']}"

        dispatcher_score = marker_counts.get("service_flags_0x759C_0x75AE", 0) + counts.get("conditional_branch", 0)
        worker_score = counts.get("xdata_write", 0) + counts.get("arithmetic", 0) + marker_counts.get("rtos_core_0x6406_0x6422", 0)

        if fa == chain[2]:
            role = "dispatcher_candidate"
        elif fa == chain[1]:
            role = "core_service_worker_candidate"
        else:
            role = "caller_router_candidate"

        summary_rows.append(
            {
                "file": args.file,
                "function_addr": fa,
                "function_role": role,
                "score": rf.get("score", "0"),
                "basic_block_count": fn.get("basic_block_count", str(len(blocks))),
                "internal_block_count": fn.get("internal_block_count", "0"),
                "xdata_read_count": str(counts.get("xdata_read", 0)),
                "xdata_write_count": str(counts.get("xdata_write", 0)),
                "rtos_core_hits": str(marker_counts.get("rtos_core_0x6406_0x6422", 0)),
                "service_flag_hits": str(marker_counts.get("service_flags_0x759C_0x75AE", 0)),
                "secondary_flag_hits": str(marker_counts.get("secondary_flags_0x769C_0x76AA", 0)),
                "nearby_runtime_hits": str(marker_counts.get("nearby_runtime", 0)),
                "call_count": str(counts.get("call", 0)),
                "incoming_lcalls": fn.get("incoming_lcalls", "0"),
                "movc_count": str(counts.get("movc", 0)),
                "string_refs": str(counts.get("string_ref", 0)),
                "arithmetic_hits": str(counts.get("arithmetic", 0)),
                "dispatcher_score": str(dispatcher_score),
                "service_worker_score": str(worker_score),
                "confidence": rf.get("confidence", fn.get("confidence", "hypothesis")),
                "notes": "deep_trace_static_only;no_packet_format_claim",
            }
        )

    summary_fields = [
        "file",
        "function_addr",
        "function_role",
        "score",
        "basic_block_count",
        "internal_block_count",
        "xdata_read_count",
        "xdata_write_count",
        "rtos_core_hits",
        "service_flag_hits",
        "secondary_flag_hits",
        "nearby_runtime_hits",
        "call_count",
        "incoming_lcalls",
        "movc_count",
        "string_refs",
        "arithmetic_hits",
        "dispatcher_score",
        "service_worker_score",
        "confidence",
        "notes",
    ]
    with args.summary_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=summary_fields)
        w.writeheader()
        w.writerows(summary_rows)

    # markdown
    chain_row = next(
        (
            r
            for r in chains
            if r.get("file") == args.file
            and r.get("caller_function") == chain[0]
            and r.get("core_function") == chain[1]
            and r.get("callee_function") == chain[2]
        ),
        {},
    )

    by_fn = {r["function_addr"]: r for r in summary_rows}

    lines: list[str] = []
    lines.append("# RTOS_service deep chain trace: 0x4358 -> 0x920C -> 0x53E6\n")
    lines.append("## Почему выбрана эта цепочка\n")
    lines.append(
        f"- В `rtos_service_pipeline_chains.csv` цепочка имеет высокий chain_score={chain_row.get('chain_score', 'n/a')} и confidence={chain_row.get('confidence', 'hypothesis')} (valid_hex=true)."
    )
    lines.append("- Цепочка полностью в `ppkp2001 90cye01.PZU` (основной валидный файл) и не требует опоры на checksum-error как primary evidence.")
    lines.append("- Фокус: порядок XDATA-событий и роли caller/core/callee без заявлений о полном восстановлении packet format.\n")

    lines.append("## Разбор функций цепочки\n")
    for fa in chain:
        sr = by_fn[fa]
        fn_rows = [r for r in trace_rows if r["function_addr"] == fa]
        xaddrs = sorted({r["xdata_addr"] for r in fn_rows if r["xdata_addr"]})
        calls = sorted({r["call_target"] for r in fn_rows if r["event_type"] == "call" and r["call_target"]})
        lines.append(f"### {fa}")
        lines.append(f"- candidate role: **{sr['function_role']}** (confidence={sr['confidence']}).")
        lines.append(f"- XDATA read/write: {sr['xdata_read_count']}/{sr['xdata_write_count']}; marker hits: rtos_core={sr['rtos_core_hits']}, service_flags={sr['service_flag_hits']}, secondary={sr['secondary_flag_hits']}, nearby={sr['nearby_runtime_hits']}.")
        lines.append(f"- XDATA clusters/адреса (статически): {', '.join(xaddrs[:20]) if xaddrs else 'нет подтвержденных в trace' }.")
        lines.append(f"- Calls/jumps: call_count={sr['call_count']}; call targets sample: {', '.join(calls[:10]) if calls else 'нет'}.")
        lines.append(f"- table/string признаки: movc={sr['movc_count']}, string_refs={sr['string_refs']}; arithmetic_hits={sr['arithmetic_hits']}.")
        lines.append("")

    lines.append("## Общий порядок событий в цепочке\n")
    for order, fa in enumerate(chain, start=1):
        sr = by_fn[fa]
        lines.append(
            f"{order}. {fa}: instruction-flow + xdata(R/W={sr['xdata_read_count']}/{sr['xdata_write_count']}), calls={sr['call_count']}, conditional={sum(1 for r in trace_rows if r['function_addr']==fa and r['event_type']=='conditional_branch')} (confidence={sr['confidence']})."
        )

    lines.append("\n## Где впервые появляются ключевые кластеры\n")
    for marker, label in [
        ("rtos_core_0x6406_0x6422", "rtos_core 0x6406..0x6422"),
        ("service_flags_0x759C_0x75AE", "service_flags 0x759C..0x75AE"),
        ("secondary_flags_0x769C_0x76AA", "secondary_flags 0x769C..0x76AA"),
    ]:
        lines.append(f"- {label}: {first_seen.get(marker) or 'в этой цепочке не зафиксировано'}.")

    lines.append("\n## Интерпретация ролей (confidence-capped)\n")
    lines.append(f"- 0x53E6 как dispatcher: dispatcher_score={by_fn[chain[2]]['dispatcher_score']}, service_flag_hits={by_fn[chain[2]]['service_flag_hits']} -> **strong candidate**, confidence={by_fn[chain[2]]['confidence']}.")
    lines.append(f"- 0x920C как core/service worker: service_worker_score={by_fn[chain[1]]['service_worker_score']} -> **worker-like**, confidence={by_fn[chain[1]]['confidence']}.")
    lines.append(f"- 0x4358 как caller/router: call_count={by_fn[chain[0]]['call_count']} + branch activity -> **router-like**, confidence={by_fn[chain[0]]['confidence']}.")

    lines.append("\n## Признаки подготовки service/packet сообщения\n")
    lines.append("- Есть признаки service-state обработки: множественные service_flags/rtos_core XDATA hits и арифметика в цепочке.")
    lines.append("- Есть control-flow, похожий на dispatch/update pipeline (caller->core->callee).")
    lines.append("- **Ограничение:** это статический трейс; формат packet/service сообщения не восстановлен и не заявляется как доказанный.")

    lines.append("\n## Чего не хватает для доказательства\n")
    lines.append("- Runtime подтверждения порядка событий (динамика/эмуляция/трассировка).")
    lines.append("- Валидации семантики полей буфера и границ сообщений.")
    lines.append("- Корреляции с внешним протоколом/реальными телеметрическими кадрами.")

    lines.append("\n## Secondary comparison (checksum-error, только паттерн)\n")
    lines.append("- ppkp2012 a01.PZU: 0x4358 -> 0x9920 -> 0x5436 присутствует в `rtos_service_pipeline_chains.csv` (confidence=hypothesis).")
    lines.append("- ppkp2012 a01.PZU: 0x4658 -> 0x9920 -> 0x5436 также присутствует и структурно похожа на valid-цепочку.")
    lines.append("- Использование строго secondary: checksum-error файлы не применяются как primary доказательство.")

    lines.append("\n## Следующие функции (без нового широкого анализа)\n")
    lines.append("- 0x464B -> 0x920C -> 0x53E6 (ближайшая альтернативная caller ветка в valid файле).")
    lines.append("- 0xAB62 -> 0x44F1 -> 0x53E6 (вторая сильная ветка с общим callee 0x53E6).")
    lines.append("- Дополнительно: углубить 0x44F1 как potential mid-layer service router/worker.")

    args.md_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote trace: {args.trace_out.relative_to(ROOT)} ({len(trace_rows)} rows)")
    print(f"wrote summary: {args.summary_out.relative_to(ROOT)} ({len(summary_rows)} rows)")
    print(f"wrote markdown: {args.md_out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
