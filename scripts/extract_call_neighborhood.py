#!/usr/bin/env python3
"""Extract local call-neighborhood around A03/A04 packet-builder candidates."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

FUNCTION_MAP = DOCS / "function_map.csv"
CALL_XREF = DOCS / "call_xref.csv"
DISASSEMBLY_INDEX = DOCS / "disassembly_index.csv"
BASIC_BLOCK_MAP = DOCS / "basic_block_map.csv"
XDATA_CONFIRMED = DOCS / "xdata_confirmed_access.csv"
CODE_TABLE_CANDIDATES = DOCS / "code_table_candidates.csv"
OUT_CSV = DOCS / "a03_a04_packet_call_neighborhood.csv"

DEFAULT_TARGETS = [("A04_28.PZU", "0x889F"), ("A03_26.PZU", "0x8904")]

PACKET_MIN = 0x5003
PACKET_MAX = 0x5010
QUEUE_ADDRS = {0x329C}
SELECTOR_ADDRS = {0x329D}
SNAPSHOT_ADDRS = {0x3110, 0x3128}
OBJECT_TABLE_BASE = 0x343D
OBJECT_TABLE_RADIUS = 0x10
AUX_ADDRS = {
    0x3298,
    0x3299,
    0x32A0,
    0x32A1,
    0x32A2,
    0x4DAC,
    0x4DB6,
    0x4FD7,
    0x4FD8,
    0x500C,
    0x500D,
}


def parse_hex(value: str) -> int:
    return int(value, 16)


def canonical_hex(value: str) -> str:
    return f"0x{parse_hex(value):04X}"


def safe_int(value: str) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def build_function_ranges(function_rows: list[dict[str, str]]) -> dict[str, list[tuple[int, int, str]]]:
    ranges: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    for row in function_rows:
        start = parse_hex(row["function_addr"])
        size = max(safe_int(row.get("size_estimate", "0")), 1)
        ranges[row["file"]].append((start, start + size, row["function_addr"]))
    for file_name in ranges:
        ranges[file_name].sort(key=lambda x: x[0])
    return ranges


def find_function_addr(function_ranges: dict[str, list[tuple[int, int, str]]], file_name: str, code_addr: int) -> str | None:
    for start, end, faddr in function_ranges.get(file_name, []):
        if start <= code_addr < end:
            return faddr
    return None


def collect_neighbor_hits(
    function_rows: list[dict[str, str]],
    function_ranges: dict[str, list[tuple[int, int, str]]],
    xdata_rows: list[dict[str, str]],
) -> dict[tuple[str, str], dict[str, int | set[int]]]:
    hits: dict[tuple[str, str], dict[str, int | set[int]]] = {}
    for row in function_rows:
        hits[(row["file"], row["function_addr"])] = {
            "packet_xdata_hits": 0,
            "queue_hits": 0,
            "selector_hits": 0,
            "snapshot_hits": 0,
            "object_table_hits": 0,
            "aux_hits": set(),
        }

    for row in xdata_rows:
        file_name = row["file"]
        code_addr = parse_hex(row["code_addr"])
        dptr_addr = parse_hex(row["dptr_addr"])
        faddr = find_function_addr(function_ranges, file_name, code_addr)
        if faddr is None:
            continue
        k = (file_name, faddr)
        if k not in hits:
            continue
        h = hits[k]
        if PACKET_MIN <= dptr_addr <= PACKET_MAX:
            h["packet_xdata_hits"] = int(h["packet_xdata_hits"]) + 1
        if dptr_addr in QUEUE_ADDRS:
            h["queue_hits"] = int(h["queue_hits"]) + 1
        if dptr_addr in SELECTOR_ADDRS:
            h["selector_hits"] = int(h["selector_hits"]) + 1
        if dptr_addr in SNAPSHOT_ADDRS:
            h["snapshot_hits"] = int(h["snapshot_hits"]) + 1
        if abs(dptr_addr - OBJECT_TABLE_BASE) <= OBJECT_TABLE_RADIUS:
            h["object_table_hits"] = int(h["object_table_hits"]) + 1
        if dptr_addr in AUX_ADDRS:
            aux_set = h["aux_hits"]
            assert isinstance(aux_set, set)
            aux_set.add(dptr_addr)

    return hits


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", dest="file_name", help="Single target file (e.g. A04_28.PZU)")
    parser.add_argument("--function", dest="function_addr", help="Single target function (e.g. 0x889F)")
    parser.add_argument("--depth", type=int, default=1, help="Neighborhood depth (currently 1 is supported)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    function_rows = load_csv(FUNCTION_MAP)
    call_rows = load_csv(CALL_XREF)
    _ = load_csv(DISASSEMBLY_INDEX)
    block_rows = load_csv(BASIC_BLOCK_MAP)
    xdata_rows = load_csv(XDATA_CONFIRMED)
    _ = load_csv(CODE_TABLE_CANDIDATES)

    if args.file_name or args.function_addr:
        if not (args.file_name and args.function_addr):
            raise SystemExit("Both --file and --function must be provided together")
        normalized = args.function_addr
        if not normalized.lower().startswith("0x"):
            normalized = f"0x{normalized}"
        targets = [(args.file_name, canonical_hex(normalized))]
    else:
        targets = [(f, canonical_hex(a)) for f, a in DEFAULT_TARGETS]

    if args.depth != 1:
        print(f"[warn] depth={args.depth} requested; current implementation extracts depth=1 local neighborhood")

    fn_map = {(r["file"], r["function_addr"]): r for r in function_rows}
    function_ranges = build_function_ranges(function_rows)
    hit_map = collect_neighbor_hits(function_rows, function_ranges, xdata_rows)

    calls_by_target: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    calls_by_caller: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in call_rows:
        if row.get("call_type") != "LCALL":
            continue
        calls_by_target[(row["file"], row["target_addr"])].append(row)
        caller = find_function_addr(function_ranges, row["file"], parse_hex(row["code_addr"]))
        if caller is not None:
            calls_by_caller[(row["file"], caller)].append(row)

    blocks_by_parent: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in block_rows:
        parent = row.get("parent_function_candidate")
        if parent:
            blocks_by_parent[(row["file"], parent)].append(row)

    out_rows: list[dict[str, str]] = []

    def build_row(
        *,
        file_name: str,
        target_function: str,
        direction: str,
        neighbor_function: str,
        call_addr: str,
        call_type: str,
        notes: str,
        confidence: str,
    ) -> dict[str, str]:
        neighbor_row = fn_map.get((file_name, neighbor_function), {})
        neighbor_hits = hit_map.get((file_name, neighbor_function), {})
        aux_hits = neighbor_hits.get("aux_hits", set()) if neighbor_hits else set()
        aux_note = ""
        if isinstance(aux_hits, set) and aux_hits:
            aux_note = "aux_hits=" + ",".join(sorted(f"0x{x:04X}" for x in aux_hits))
        full_notes = "; ".join(x for x in [notes, aux_note] if x)

        return {
            "file": file_name,
            "target_function": target_function,
            "direction": direction,
            "neighbor_function": neighbor_function,
            "call_addr": call_addr,
            "call_type": call_type,
            "neighbor_role_candidate": neighbor_row.get("role_candidate", "unknown") or "unknown",
            "neighbor_basic_block_count": str(safe_int(neighbor_row.get("basic_block_count", "0"))),
            "neighbor_internal_block_count": str(safe_int(neighbor_row.get("internal_block_count", "0"))),
            "neighbor_xdata_read_count": str(safe_int(neighbor_row.get("xdata_read_count", "0"))),
            "neighbor_xdata_write_count": str(safe_int(neighbor_row.get("xdata_write_count", "0"))),
            "neighbor_movc_count": str(safe_int(neighbor_row.get("movc_count", "0"))),
            "packet_xdata_hits": str(int(neighbor_hits.get("packet_xdata_hits", 0))),
            "queue_hits": str(int(neighbor_hits.get("queue_hits", 0))),
            "selector_hits": str(int(neighbor_hits.get("selector_hits", 0))),
            "snapshot_hits": str(int(neighbor_hits.get("snapshot_hits", 0))),
            "object_table_hits": str(int(neighbor_hits.get("object_table_hits", 0))),
            "confidence": confidence,
            "notes": full_notes,
        }

    for file_name, target_function in targets:
        for row in sorted(calls_by_target.get((file_name, target_function), []), key=lambda r: parse_hex(r["code_addr"])):
            caller_function = find_function_addr(function_ranges, file_name, parse_hex(row["code_addr"]))
            if caller_function is None:
                continue
            out_rows.append(
                build_row(
                    file_name=file_name,
                    target_function=target_function,
                    direction="incoming",
                    neighbor_function=caller_function,
                    call_addr=row["code_addr"],
                    call_type="LCALL",
                    notes="caller->target LCALL",
                    confidence="high",
                )
            )

        for row in sorted(calls_by_caller.get((file_name, target_function), []), key=lambda r: parse_hex(r["code_addr"])):
            out_rows.append(
                build_row(
                    file_name=file_name,
                    target_function=target_function,
                    direction="outgoing",
                    neighbor_function=row["target_addr"],
                    call_addr=row["code_addr"],
                    call_type="LCALL",
                    notes="target->callee LCALL",
                    confidence="high",
                )
            )

        for block in sorted(blocks_by_parent.get((file_name, target_function), []), key=lambda r: parse_hex(r["block_addr"])):
            ends_with = block.get("ends_with", "")
            if ends_with in {"LJMP", "SJMP"}:
                out_rows.append(
                    build_row(
                        file_name=file_name,
                        target_function=target_function,
                        direction="internal_jump",
                        neighbor_function=block.get("target_addr", "") or block["block_addr"],
                        call_addr=block["block_addr"],
                        call_type=ends_with,
                        notes=f"parent={block.get('parent_function_candidate','')}",
                        confidence=block.get("confidence", "unknown"),
                    )
                )
            elif ends_with == "conditional_branch":
                target_addr = block.get("target_addr", "")
                out_rows.append(
                    build_row(
                        file_name=file_name,
                        target_function=target_function,
                        direction="conditional_branch",
                        neighbor_function=target_addr or block["block_addr"],
                        call_addr=block["block_addr"],
                        call_type="conditional_branch",
                        notes=f"fallthrough={block.get('fallthrough_addr','')}; parent={block.get('parent_function_candidate','')}",
                        confidence=block.get("confidence", "hypothesis"),
                    )
                )

    out_rows.sort(key=lambda r: (r["file"], parse_hex(r["target_function"]), r["direction"], r["call_addr"]))

    fieldnames = [
        "file",
        "target_function",
        "direction",
        "neighbor_function",
        "call_addr",
        "call_type",
        "neighbor_role_candidate",
        "neighbor_basic_block_count",
        "neighbor_internal_block_count",
        "neighbor_xdata_read_count",
        "neighbor_xdata_write_count",
        "neighbor_movc_count",
        "packet_xdata_hits",
        "queue_hits",
        "selector_hits",
        "snapshot_hits",
        "object_table_hits",
        "confidence",
        "notes",
    ]

    with OUT_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    print(f"Wrote {len(out_rows)} rows to {OUT_CSV.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
