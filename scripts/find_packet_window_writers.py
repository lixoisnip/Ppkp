#!/usr/bin/env python3
"""Find A03/A04 functions that confirmed-write packet window 0x5003..0x5010."""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

FUNCTION_MAP = DOCS / "function_map.csv"
BASIC_BLOCK_MAP = DOCS / "basic_block_map.csv"
DISASM_INDEX = DOCS / "disassembly_index.csv"
XDATA_CONFIRMED = DOCS / "xdata_confirmed_access.csv"
CALL_XREF = DOCS / "call_xref.csv"
OUT = DOCS / "a03_a04_packet_window_writers.csv"

TARGET_BRANCH = "A03_A04"
TARGET_FILES = {"A03_26.PZU", "A04_28.PZU"}
PACKET_MIN = 0x5003
PACKET_MAX = 0x5010
QUEUE_ADDRS = {0x329C}
SELECTOR_ADDRS = {0x329D}
AUX_ADDRS = {0x3298, 0x3299, 0x32A0, 0x32A1, 0x32A2, 0x4DAC, 0x4DB6, 0x4FD7, 0x4FD8}
ARITHMETIC_MNEMONICS = {"ADD", "ADDC", "SUBB", "XRL", "ANL", "ORL", "INC", "DEC"}


def parse_hex(value: str) -> int:
    return int(value, 16)


def safe_int(value: str) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def in_scope(row: dict[str, str]) -> bool:
    return row.get("branch") == TARGET_BRANCH and row.get("file") in TARGET_FILES


def find_function(function_ranges: dict[str, list[tuple[int, int, str]]], file_name: str, code_addr: int) -> str | None:
    for start, end, func_addr in function_ranges.get(file_name, []):
        if start <= code_addr < end:
            return func_addr
    return None


def find_block(block_starts: dict[tuple[str, str], list[int]], file_name: str, function_addr: str, code_addr: int) -> str:
    starts = block_starts.get((file_name, function_addr), [])
    candidate: int | None = None
    for start in starts:
        if start <= code_addr:
            candidate = start
        else:
            break
    return f"0x{candidate:04X}" if candidate is not None else ""


def main() -> None:
    function_rows = [r for r in load_csv(FUNCTION_MAP) if in_scope(r)]
    block_rows = [r for r in load_csv(BASIC_BLOCK_MAP) if in_scope(r)]
    disasm_rows = [r for r in load_csv(DISASM_INDEX) if in_scope(r)]
    xdata_rows = [r for r in load_csv(XDATA_CONFIRMED) if in_scope(r)]
    call_rows = [r for r in load_csv(CALL_XREF) if in_scope(r)]

    function_ranges: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    function_meta: dict[tuple[str, str], dict[str, str]] = {}
    for row in function_rows:
        faddr = row["function_addr"]
        start = parse_hex(faddr)
        size = max(safe_int(row.get("size_estimate", "0")), 1)
        function_ranges[row["file"]].append((start, start + size, faddr))
        function_meta[(row["file"], faddr)] = row
    for file_name in function_ranges:
        function_ranges[file_name].sort(key=lambda x: x[0])

    block_starts: dict[tuple[str, str], list[int]] = defaultdict(list)
    for row in block_rows:
        parent = row.get("parent_function_candidate", "")
        if not parent:
            continue
        block_starts[(row["file"], parent)].append(parse_hex(row["block_addr"]))
    for key in list(block_starts.keys()):
        block_starts[key].sort()

    incoming_lcalls: dict[tuple[str, str], int] = defaultdict(int)
    for row in call_rows:
        if row.get("call_type") == "LCALL":
            incoming_lcalls[(row["file"], row["target_addr"])] += 1

    queue_hits: dict[tuple[str, str], int] = defaultdict(int)
    selector_hits: dict[tuple[str, str], int] = defaultdict(int)
    aux_hits: dict[tuple[str, str], int] = defaultdict(int)
    for row in xdata_rows:
        code_addr = parse_hex(row["code_addr"])
        dptr_addr = parse_hex(row["dptr_addr"])
        func_addr = find_function(function_ranges, row["file"], code_addr)
        if not func_addr:
            continue
        key = (row["file"], func_addr)
        if dptr_addr in QUEUE_ADDRS:
            queue_hits[key] += 1
        if dptr_addr in SELECTOR_ADDRS:
            selector_hits[key] += 1
        if dptr_addr in AUX_ADDRS:
            aux_hits[key] += 1

    arithmetic_hits: dict[tuple[str, str], int] = defaultdict(int)
    for row in disasm_rows:
        mnemonic = row.get("mnemonic", "").upper()
        if mnemonic not in ARITHMETIC_MNEMONICS:
            continue
        code_addr = parse_hex(row["code_addr"])
        func_addr = find_function(function_ranges, row["file"], code_addr)
        if not func_addr:
            continue
        arithmetic_hits[(row["file"], func_addr)] += 1

    out_rows: list[dict[str, str]] = []
    for row in xdata_rows:
        if row.get("access_type") != "write":
            continue
        xdata_addr = parse_hex(row["dptr_addr"])
        if not (PACKET_MIN <= xdata_addr <= PACKET_MAX):
            continue

        file_name = row["file"]
        code_addr = parse_hex(row["code_addr"])
        function_addr = find_function(function_ranges, file_name, code_addr)
        if not function_addr:
            continue
        key = (file_name, function_addr)
        meta = function_meta.get(key, {})

        q_hits = queue_hits.get(key, 0)
        s_hits = selector_hits.get(key, 0)
        a_hits = aux_hits.get(key, 0)
        ar_hits = arithmetic_hits.get(key, 0)

        confidence = "probable" if (q_hits or s_hits or a_hits or ar_hits) else "hypothesis"
        notes = ["static-only: confirmed xdata write in packet-window"]
        if q_hits:
            notes.append("queue-near")
        if s_hits:
            notes.append("selector-near")
        if a_hits:
            notes.append("aux-near")
        if ar_hits:
            notes.append("arithmetic-near")

        out_rows.append(
            {
                "file": file_name,
                "branch": row["branch"],
                "function_addr": function_addr,
                "code_addr": f"0x{code_addr:04X}",
                "block_addr": find_block(block_starts, file_name, function_addr, code_addr),
                "xdata_addr": f"0x{xdata_addr:04X}",
                "xdata_access_type": row["access_type"],
                "role_candidate": meta.get("role_candidate", "unknown") or "unknown",
                "incoming_lcalls": str(incoming_lcalls.get(key, safe_int(meta.get("incoming_lcalls", "0")))),
                "call_count": str(safe_int(meta.get("call_count", "0"))),
                "basic_block_count": str(safe_int(meta.get("basic_block_count", "0"))),
                "internal_block_count": str(safe_int(meta.get("internal_block_count", "0"))),
                "nearby_queue_hits": str(q_hits),
                "nearby_selector_hits": str(s_hits),
                "nearby_aux_hits": str(a_hits),
                "nearby_arithmetic_hits": str(ar_hits),
                "confidence": confidence,
                "notes": "; ".join(notes),
            }
        )

    out_rows.sort(
        key=lambda r: (
            r["file"],
            parse_hex(r["function_addr"]),
            parse_hex(r["code_addr"]),
        )
    )

    fieldnames = [
        "file",
        "branch",
        "function_addr",
        "code_addr",
        "block_addr",
        "xdata_addr",
        "xdata_access_type",
        "role_candidate",
        "incoming_lcalls",
        "call_count",
        "basic_block_count",
        "internal_block_count",
        "nearby_queue_hits",
        "nearby_selector_hits",
        "nearby_aux_hits",
        "nearby_arithmetic_hits",
        "confidence",
        "notes",
    ]

    with OUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    print(f"Wrote {len(out_rows)} rows to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
