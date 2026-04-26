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
OUT_DEPTH2_CSV = DOCS / "a03_a04_packet_call_neighborhood_depth2.csv"

DEFAULT_TARGETS = [("A04_28.PZU", "0x889F"), ("A03_26.PZU", "0x8904")]
DEFAULT_DEPTH2_TARGETS = [("A04_28.PZU", "0x89C9"), ("A03_26.PZU", "0x8A2E")]

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
CHECKSUM_MNEMONICS = {"ADD", "ADDC", "SUBB", "XRL", "ANL", "ORL"}


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


def normalize_targets(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(f, canonical_hex(a)) for f, a in items]


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
            "sensitive_write_hits": 0,
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
        if row.get("access_type") == "write" and (
            PACKET_MIN <= dptr_addr <= PACKET_MAX or dptr_addr in QUEUE_ADDRS or dptr_addr in SELECTOR_ADDRS
        ):
            h["sensitive_write_hits"] = int(h["sensitive_write_hits"]) + 1

    return hits


def collect_checksum_arithmetic_hits(
    function_ranges: dict[str, list[tuple[int, int, str]]], disasm_rows: list[dict[str, str]]
) -> dict[tuple[str, str], int]:
    arith_hits: dict[tuple[str, str], int] = defaultdict(int)
    for row in disasm_rows:
        mnemonic = (row.get("mnemonic") or "").upper()
        if mnemonic not in CHECKSUM_MNEMONICS:
            continue
        faddr = find_function_addr(function_ranges, row["file"], parse_hex(row["code_addr"]))
        if faddr is None:
            continue
        arith_hits[(row["file"], faddr)] += 1
    return arith_hits


def checksum_like_label(
    file_name: str,
    function_addr: str,
    hit_map: dict[tuple[str, str], dict[str, int | set[int]]],
    arithmetic_hits: dict[tuple[str, str], int],
) -> str:
    key = (file_name, function_addr)
    has_arithmetic = arithmetic_hits.get(key, 0) > 0
    sensitive_writes = int(hit_map.get(key, {}).get("sensitive_write_hits", 0))
    if has_arithmetic and sensitive_writes > 0:
        return "true"
    return "unknown"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", dest="file_name", help="Single target file (e.g. A04_28.PZU)")
    parser.add_argument("--function", dest="function_addr", help="Single target function (e.g. 0x889F)")
    parser.add_argument("--depth", type=int, default=1, help="Neighborhood depth (1 or 2)")
    parser.add_argument("--output", help="Output CSV path (default depends on depth)")
    return parser.parse_args()


def collect_depth_nodes(
    *,
    file_name: str,
    target_function: str,
    depth: int,
    calls_by_target: dict[tuple[str, str], list[dict[str, str]]],
    calls_by_caller: dict[tuple[str, str], list[dict[str, str]]],
    function_ranges: dict[str, list[tuple[int, int, str]]],
) -> dict[str, int]:
    levels = {target_function: 0}
    frontier = {target_function}
    for d in range(1, depth + 1):
        next_frontier: set[str] = set()
        for fn in frontier:
            for row in calls_by_target.get((file_name, fn), []):
                caller = find_function_addr(function_ranges, file_name, parse_hex(row["code_addr"]))
                if caller and caller not in levels:
                    levels[caller] = d
                    next_frontier.add(caller)
            for row in calls_by_caller.get((file_name, fn), []):
                callee = row["target_addr"]
                if callee not in levels:
                    levels[callee] = d
                    next_frontier.add(callee)
        frontier = next_frontier
        if not frontier:
            break
    return levels


def main() -> None:
    args = parse_args()

    function_rows = load_csv(FUNCTION_MAP)
    call_rows = load_csv(CALL_XREF)
    disasm_rows = load_csv(DISASSEMBLY_INDEX)
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
        targets = normalize_targets(DEFAULT_DEPTH2_TARGETS if args.depth == 2 else DEFAULT_TARGETS)

    fn_map = {(r["file"], r["function_addr"]): r for r in function_rows}
    function_ranges = build_function_ranges(function_rows)
    hit_map = collect_neighbor_hits(function_rows, function_ranges, xdata_rows)
    arithmetic_hits = collect_checksum_arithmetic_hits(function_ranges, disasm_rows)

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

    depth_nodes_map: dict[tuple[str, str], dict[str, int]] = {}
    for file_name, target_function in targets:
        depth_nodes_map[(file_name, target_function)] = collect_depth_nodes(
            file_name=file_name,
            target_function=target_function,
            depth=args.depth,
            calls_by_target=calls_by_target,
            calls_by_caller=calls_by_caller,
            function_ranges=function_ranges,
        )

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
        checksum_note = f"checksum_like={checksum_like_label(file_name, neighbor_function, hit_map, arithmetic_hits)}"
        full_notes = "; ".join(x for x in [notes, aux_note, checksum_note] if x)

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
        depth_nodes = depth_nodes_map[(file_name, target_function)]
        target_row = build_row(
            file_name=file_name,
            target_function=target_function,
            direction="target",
            neighbor_function=target_function,
            call_addr=target_function,
            call_type="self",
            notes="target node",
            confidence="high",
        )
        if args.depth > 1:
            target_row["depth_level"] = "0"
        out_rows.append(target_row)

        for row in sorted(calls_by_target.get((file_name, target_function), []), key=lambda r: parse_hex(r["code_addr"])):
            caller_function = find_function_addr(function_ranges, file_name, parse_hex(row["code_addr"]))
            if caller_function is None:
                continue
            candidate = build_row(
                file_name=file_name,
                target_function=target_function,
                direction="incoming",
                neighbor_function=caller_function,
                call_addr=row["code_addr"],
                call_type="LCALL",
                notes="caller->target LCALL",
                confidence="high",
            )
            if args.depth > 1:
                if caller_function not in depth_nodes:
                    continue
                candidate["depth_level"] = str(depth_nodes[caller_function])
            out_rows.append(candidate)

        for row in sorted(calls_by_caller.get((file_name, target_function), []), key=lambda r: parse_hex(r["code_addr"])):
            callee = row["target_addr"]
            candidate = build_row(
                file_name=file_name,
                target_function=target_function,
                direction="outgoing",
                neighbor_function=callee,
                call_addr=row["code_addr"],
                call_type="LCALL",
                notes="target->callee LCALL",
                confidence="high",
            )
            if args.depth > 1:
                if callee not in depth_nodes:
                    continue
                candidate["depth_level"] = str(depth_nodes[callee])
            out_rows.append(candidate)

        if args.depth > 1:
            first_neighbors = {f for f, lvl in depth_nodes.items() if lvl == 1}
            for neighbor_function in sorted(first_neighbors, key=parse_hex):
                for row in sorted(calls_by_target.get((file_name, neighbor_function), []), key=lambda r: parse_hex(r["code_addr"])):
                    caller_function = find_function_addr(function_ranges, file_name, parse_hex(row["code_addr"]))
                    if caller_function is None or caller_function == target_function:
                        continue
                    if depth_nodes.get(caller_function) != 2:
                        continue
                    out_rows.append(
                        {
                            **build_row(
                                file_name=file_name,
                                target_function=target_function,
                                direction="incoming_depth2",
                                neighbor_function=caller_function,
                                call_addr=row["code_addr"],
                                call_type="LCALL",
                                notes=f"caller->depth1({neighbor_function}) LCALL",
                                confidence="high",
                            ),
                            "depth_level": "2",
                        }
                    )
                for row in sorted(calls_by_caller.get((file_name, neighbor_function), []), key=lambda r: parse_hex(r["code_addr"])):
                    callee = row["target_addr"]
                    if callee == target_function:
                        continue
                    if depth_nodes.get(callee) != 2:
                        continue
                    out_rows.append(
                        {
                            **build_row(
                                file_name=file_name,
                                target_function=target_function,
                                direction="outgoing_depth2",
                                neighbor_function=callee,
                                call_addr=row["code_addr"],
                                call_type="LCALL",
                                notes=f"depth1({neighbor_function})->callee LCALL",
                                confidence="high",
                            ),
                            "depth_level": "2",
                        }
                    )

        for block in sorted(blocks_by_parent.get((file_name, target_function), []), key=lambda r: parse_hex(r["block_addr"])):
            ends_with = block.get("ends_with", "")
            if ends_with in {"LJMP", "SJMP"}:
                candidate = build_row(
                    file_name=file_name,
                    target_function=target_function,
                    direction="internal_jump",
                    neighbor_function=block.get("target_addr", "") or block["block_addr"],
                    call_addr=block["block_addr"],
                    call_type=ends_with,
                    notes=f"parent={block.get('parent_function_candidate','')}",
                    confidence=block.get("confidence", "unknown"),
                )
                if args.depth > 1:
                    candidate["depth_level"] = "1"
                out_rows.append(candidate)
            elif ends_with == "conditional_branch":
                target_addr = block.get("target_addr", "")
                candidate = build_row(
                    file_name=file_name,
                    target_function=target_function,
                    direction="conditional_branch",
                    neighbor_function=target_addr or block["block_addr"],
                    call_addr=block["block_addr"],
                    call_type="conditional_branch",
                    notes=f"fallthrough={block.get('fallthrough_addr','')}; parent={block.get('parent_function_candidate','')}",
                    confidence=block.get("confidence", "hypothesis"),
                )
                if args.depth > 1:
                    candidate["depth_level"] = "1"
                out_rows.append(candidate)

    out_rows.sort(
        key=lambda r: (
            r["file"],
            parse_hex(r["target_function"]),
            int(r.get("depth_level", "0")),
            r["direction"],
            parse_hex(r["call_addr"]),
            parse_hex(r["neighbor_function"]),
        )
    )

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
    if args.depth > 1:
        fieldnames.append("depth_level")

    out_path = Path(args.output) if args.output else (OUT_DEPTH2_CSV if args.depth == 2 else OUT_CSV)

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    try:
        shown_path = out_path.relative_to(ROOT)
    except ValueError:
        shown_path = out_path
    print(f"Wrote {len(out_rows)} rows to {shown_path}")


if __name__ == "__main__":
    main()
