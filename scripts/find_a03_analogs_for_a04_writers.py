#!/usr/bin/env python3
"""Find structural A03 analogs for A04 packet-window writer functions."""

from __future__ import annotations

import csv
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

FUNCTION_MAP = DOCS / "function_map.csv"
BASIC_BLOCK_MAP = DOCS / "basic_block_map.csv"
DISASM_INDEX = DOCS / "disassembly_index.csv"
XDATA_CONFIRMED = DOCS / "xdata_confirmed_access.csv"
CALL_XREF = DOCS / "call_xref.csv"
PACKET_WRITERS = DOCS / "a03_a04_packet_window_writers.csv"

OUT_CSV = DOCS / "a03_analogs_for_a04_packet_writers.csv"
OUT_MD = DOCS / "a03_analogs_for_a04_packet_writers.md"

BRANCH = "A03_A04"
A03_FILE = "A03_26.PZU"
A04_FILE = "A04_28.PZU"
A04_REFERENCES = {"0x497A", "0x89C9"}
PIPELINE_ADDRS = {0x3298, 0x3299, 0x329C, 0x329D, 0x4DB6, 0x4FD7, 0x4FD8}
CHAIN_ADDRS = {0x8904, 0x8A2E, 0xA900}
ARITH_MNEMONICS = {"ADD", "ADDC", "SUBB", "XRL", "ANL", "ORL", "INC", "DEC"}


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def parse_hex(value: str) -> int:
    return int(value, 16)


def safe_int(value: str) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def tokenize_role(role: str) -> set[str]:
    return {t for t in role.lower().replace("-", "_").split("_") if t and t != "unknown"}


def close_score(a: int, b: int) -> float:
    diff = abs(a - b)
    if diff == 0:
        return 1.0
    if diff <= 1:
        return 0.75
    if diff <= 3:
        return 0.5
    if diff <= 7:
        return 0.25
    return 0.0


def get_confidence(score: float) -> str:
    if score >= 8:
        return "probable"
    if score >= 4:
        return "hypothesis"
    return "unknown"


def main() -> None:
    function_rows = [r for r in load_csv(FUNCTION_MAP) if r.get("branch") == BRANCH]
    _ = [r for r in load_csv(BASIC_BLOCK_MAP) if r.get("branch") == BRANCH]
    disasm_rows = [r for r in load_csv(DISASM_INDEX) if r.get("branch") == BRANCH]
    xdata_rows = [r for r in load_csv(XDATA_CONFIRMED) if r.get("branch") == BRANCH]
    call_rows = [r for r in load_csv(CALL_XREF) if r.get("branch") == BRANCH and r.get("call_type") == "LCALL"]
    writer_rows = [r for r in load_csv(PACKET_WRITERS) if r.get("branch") == BRANCH and r.get("file") == A04_FILE]

    functions: dict[tuple[str, str], dict[str, object]] = {}
    ranges: dict[str, list[tuple[int, int, str]]] = defaultdict(list)

    for row in function_rows:
        key = (row["file"], row["function_addr"])
        start = parse_hex(row["function_addr"])
        size = max(safe_int(row.get("size_estimate", "0")), 1)
        ranges[row["file"]].append((start, start + size, row["function_addr"]))
        functions[key] = {
            "file": row["file"],
            "function_addr": row["function_addr"],
            "role_candidate": row.get("role_candidate", "unknown") or "unknown",
            "basic_block_count": safe_int(row.get("basic_block_count", "0")),
            "internal_block_count": safe_int(row.get("internal_block_count", "0")),
            "call_count": safe_int(row.get("call_count", "0")),
            "incoming_lcalls": safe_int(row.get("incoming_lcalls", "0")),
            "xdata_read_count": safe_int(row.get("xdata_read_count", "0")),
            "xdata_write_count": safe_int(row.get("xdata_write_count", "0")),
            "arithmetic_hits": 0,
            "a03_pipeline_hits": 0,
            "near_known_a03_chain": "no",
        }

    for file_name in ranges:
        ranges[file_name].sort(key=lambda x: x[0])

    def find_function(file_name: str, code_addr: int) -> str | None:
        for start, end, faddr in ranges.get(file_name, []):
            if start <= code_addr < end:
                return faddr
        return None

    for row in disasm_rows:
        file_name = row["file"]
        faddr = find_function(file_name, parse_hex(row["code_addr"]))
        if not faddr:
            continue
        if row.get("mnemonic", "").upper() in ARITH_MNEMONICS:
            functions[(file_name, faddr)]["arithmetic_hits"] += 1

    for row in xdata_rows:
        file_name = row["file"]
        faddr = find_function(file_name, parse_hex(row["code_addr"]))
        if not faddr:
            continue
        if parse_hex(row["dptr_addr"]) in PIPELINE_ADDRS:
            functions[(file_name, faddr)]["a03_pipeline_hits"] += 1

    adj: dict[int, set[int]] = defaultdict(set)
    incoming_counts: dict[int, int] = defaultdict(int)
    for row in call_rows:
        if row["file"] != A03_FILE:
            continue
        src = parse_hex(row["code_addr"])
        dst = parse_hex(row["target_addr"])
        src_f = find_function(A03_FILE, src)
        if not src_f:
            continue
        src_fn = parse_hex(src_f)
        adj[src_fn].add(dst)
        adj[dst].add(src_fn)
        incoming_counts[dst] += 1

    dist: dict[int, int] = {}
    dq: deque[int] = deque()
    for addr in CHAIN_ADDRS:
        dist[addr] = 0
        dq.append(addr)
    while dq:
        cur = dq.popleft()
        for nxt in adj.get(cur, set()):
            if nxt not in dist:
                dist[nxt] = dist[cur] + 1
                dq.append(nxt)

    a04_ref: dict[str, dict[str, object]] = {}
    for row in writer_rows:
        f = row["function_addr"]
        if f not in A04_REFERENCES or f in a04_ref:
            continue
        a04_ref[f] = {
            "role_candidate": row.get("role_candidate", "unknown") or "unknown",
            "basic_block_count": safe_int(row.get("basic_block_count", "0")),
            "internal_block_count": safe_int(row.get("internal_block_count", "0")),
            "call_count": safe_int(row.get("call_count", "0")),
            "incoming_lcalls": safe_int(row.get("incoming_lcalls", "0")),
            "xdata_read_count": functions[(A04_FILE, f)]["xdata_read_count"],
            "xdata_write_count": functions[(A04_FILE, f)]["xdata_write_count"],
            "arithmetic_hits": safe_int(row.get("nearby_arithmetic_hits", "0")),
        }

    rows_out: list[dict[str, str]] = []
    for (file_name, faddr), m in functions.items():
        if file_name != A03_FILE:
            continue
        fn_int = parse_hex(faddr)
        min_dist = dist.get(fn_int, 99)
        near_chain = "yes" if min_dist <= 2 else "no"
        m["near_known_a03_chain"] = near_chain

        for ref_fn, ref in sorted(a04_ref.items(), key=lambda x: parse_hex(x[0])):
            score = 0.0
            role = str(m["role_candidate"])
            ref_role = str(ref["role_candidate"])
            if role == ref_role and role != "unknown":
                score += 2.0
            else:
                overlap = tokenize_role(role) & tokenize_role(ref_role)
                if overlap:
                    score += 1.0

            for k in [
                "basic_block_count",
                "internal_block_count",
                "call_count",
                "incoming_lcalls",
                "xdata_read_count",
                "xdata_write_count",
                "arithmetic_hits",
            ]:
                score += close_score(int(m[k]), int(ref[k]))

            if int(m["a03_pipeline_hits"]) > 0:
                score += 1.0
            if int(m["arithmetic_hits"]) > 0:
                score += 1.0
            if min_dist == 1:
                score += 2.0
            elif min_dist == 2:
                score += 1.0

            notes = []
            if min_dist <= 2:
                notes.append(f"chain_distance={min_dist}")
            if incoming_counts.get(fn_int, 0):
                notes.append(f"incoming_lcall_xref={incoming_counts[fn_int]}")
            if int(m["a03_pipeline_hits"]):
                notes.append("pipeline_xdata_hit")
            if int(m["arithmetic_hits"]):
                notes.append("arith_present")

            rows_out.append(
                {
                    "reference_file": A04_FILE,
                    "reference_function": ref_fn,
                    "a03_file": A03_FILE,
                    "a03_function": faddr,
                    "similarity_score": f"{score:.2f}",
                    "role_candidate": str(m["role_candidate"]),
                    "basic_block_count": str(m["basic_block_count"]),
                    "internal_block_count": str(m["internal_block_count"]),
                    "call_count": str(m["call_count"]),
                    "incoming_lcalls": str(m["incoming_lcalls"]),
                    "xdata_read_count": str(m["xdata_read_count"]),
                    "xdata_write_count": str(m["xdata_write_count"]),
                    "arithmetic_hits": str(m["arithmetic_hits"]),
                    "a03_pipeline_hits": str(m["a03_pipeline_hits"]),
                    "near_known_a03_chain": near_chain,
                    "confidence": get_confidence(score),
                    "notes": "; ".join(notes),
                }
            )

    rows_out.sort(
        key=lambda r: (
            r["reference_function"],
            -float(r["similarity_score"]),
            -safe_int(r["a03_pipeline_hits"]),
            r["a03_function"],
        )
    )

    fieldnames = [
        "reference_file",
        "reference_function",
        "a03_file",
        "a03_function",
        "similarity_score",
        "role_candidate",
        "basic_block_count",
        "internal_block_count",
        "call_count",
        "incoming_lcalls",
        "xdata_read_count",
        "xdata_write_count",
        "arithmetic_hits",
        "a03_pipeline_hits",
        "near_known_a03_chain",
        "confidence",
        "notes",
    ]
    with OUT_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_out)

    top_by_ref: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows_out:
        if len(top_by_ref[row["reference_function"]]) < 8:
            top_by_ref[row["reference_function"]].append(row)

    def render_top(ref_fn: str) -> str:
        lines = [f"### Top A03 candidates for A04:{ref_fn}"]
        for row in top_by_ref.get(ref_fn, [])[:5]:
            lines.append(
                "- "
                f"A03:{row['a03_function']} score={row['similarity_score']} confidence={row['confidence']} "
                f"pipeline_hits={row['a03_pipeline_hits']} near_chain={row['near_known_a03_chain']} "
                f"role={row['role_candidate']}"
            )
        return "\n".join(lines)

    md = f"""# A03 analogs for A04 packet-window writer functions

Этот документ нужен, чтобы выбрать функции A03 для следующей трассировки, когда в A03 нет confirmed write в 0x5003..0x5010.

Прямого совпадения по write в packet-window недостаточно: часть логики может быть вынесена в соседние worker/dispatcher функции, поэтому мы используем structural similarity по function-map, xdata-паттернам и call-neighborhood.

{render_top('0x497A')}

{render_top('0x89C9')}

## Связь с цепочкой A03 0xA900 -> 0x8904 -> 0x8A2E

- Метка `near_known_a03_chain=yes` означает расстояние в call-neighborhood <=2 от этой цепочки.
- Это индикатор приоритета трассировки, но не доказательство packet format.

## Следующие кандидаты для трассировки

- В первую очередь: кандидаты `confidence=probable` и `near_known_a03_chain=yes`.
- Затем: `confidence=hypothesis` с ненулевым `a03_pipeline_hits`.

**Важно:** это structural similarity analysis, не финальное доказательство соответствия packet формату.
"""
    OUT_MD.write_text(md, encoding="utf-8")


if __name__ == "__main__":
    main()
