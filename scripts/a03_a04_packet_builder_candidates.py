#!/usr/bin/env python3
"""Rank A03/A04 packet builder/runtime packet writer candidates."""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

FUNCTION_MAP = DOCS / "function_map.csv"
XDATA_CONFIRMED = DOCS / "xdata_confirmed_access.csv"
CODE_TABLE_CANDIDATES = DOCS / "code_table_candidates.csv"
CALL_XREF = DOCS / "call_xref.csv"
BASIC_BLOCK_MAP = DOCS / "basic_block_map.csv"
OUT = DOCS / "a03_a04_packet_builder_candidates.csv"

TARGET_BRANCH = "A03_A04"
TARGET_FILES = {"A03_26.PZU", "A04_28.PZU"}

SNAPSHOT_ADDRS = {0x3110, 0x3128}
QUEUE_ADDRS = {0x329C}
SELECTOR_ADDRS = {0x329D}
PIPELINE_EXTRA_ADDRS = {0x3298, 0x32A2}
PACKET_XDATA_MIN = 0x5003
PACKET_XDATA_MAX = 0x5010
OBJECT_TABLE_BASE = 0x343D
OBJECT_TABLE_NEAR_RADIUS = 0x10


def parse_hex(value: str) -> int:
    return int(value, 16)


def safe_int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def in_target_scope(row: dict[str, str]) -> bool:
    return row.get("branch") == TARGET_BRANCH and row.get("file") in TARGET_FILES


def find_function(function_ranges: dict[str, list[tuple[int, int, str]]], file_name: str, code_addr: int) -> str | None:
    for start, end, func_addr in function_ranges.get(file_name, []):
        if start <= code_addr < end:
            return func_addr
    return None


def main() -> None:
    function_rows = [r for r in load_csv(FUNCTION_MAP) if in_target_scope(r)]
    _ = [r for r in load_csv(CODE_TABLE_CANDIDATES) if in_target_scope(r)]
    call_rows = [r for r in load_csv(CALL_XREF) if in_target_scope(r)]
    block_rows = [r for r in load_csv(BASIC_BLOCK_MAP) if in_target_scope(r)]
    xdata_rows = [r for r in load_csv(XDATA_CONFIRMED) if in_target_scope(r)]

    function_ranges: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    metrics: dict[tuple[str, str], dict[str, object]] = {}

    for row in function_rows:
        file_name = row["file"]
        faddr = row["function_addr"]
        start = parse_hex(faddr)
        size = safe_int(row.get("size_estimate", "0"))
        end = start + max(size, 1)
        function_ranges[file_name].append((start, end, faddr))
        metrics[(file_name, faddr)] = {
            "file": file_name,
            "function_addr": faddr,
            "role_candidate": row.get("role_candidate", "unknown") or "unknown",
            "basic_block_count": safe_int(row.get("basic_block_count", "0")),
            "internal_block_count": safe_int(row.get("internal_block_count", "0")),
            "incoming_lcalls": safe_int(row.get("incoming_lcalls", "0")),
            "call_count": safe_int(row.get("call_count", "0")),
            "xdata_read_count": safe_int(row.get("xdata_read_count", "0")),
            "xdata_write_count": safe_int(row.get("xdata_write_count", "0")),
            "movc_count": safe_int(row.get("movc_count", "0")),
            "packet_xdata_hits": 0,
            "queue_hits": 0,
            "selector_hits": 0,
            "snapshot_hits": 0,
            "object_table_hits": 0,
            "pipeline_extra_hits": 0,
            "block_parent_hits": 0,
            "call_xref_incoming_lcalls": 0,
            "notes": [],
        }

    for file_name in function_ranges:
        function_ranges[file_name].sort(key=lambda x: x[0])

    for row in call_rows:
        if row.get("call_type") != "LCALL":
            continue
        target = row.get("target_addr")
        key = (row["file"], target)
        if key in metrics:
            metrics[key]["call_xref_incoming_lcalls"] = metrics[key]["call_xref_incoming_lcalls"] + 1

    for row in block_rows:
        parent = row.get("parent_function_candidate")
        key = (row["file"], parent)
        if parent and key in metrics:
            metrics[key]["block_parent_hits"] = metrics[key]["block_parent_hits"] + 1

    for row in xdata_rows:
        file_name = row["file"]
        code_addr = parse_hex(row["code_addr"])
        dptr_addr = parse_hex(row["dptr_addr"])
        func_addr = find_function(function_ranges, file_name, code_addr)
        if not func_addr:
            continue
        m = metrics[(file_name, func_addr)]

        if PACKET_XDATA_MIN <= dptr_addr <= PACKET_XDATA_MAX:
            m["packet_xdata_hits"] += 1
        if dptr_addr in QUEUE_ADDRS:
            m["queue_hits"] += 1
        if dptr_addr in SELECTOR_ADDRS:
            m["selector_hits"] += 1
        if dptr_addr in SNAPSHOT_ADDRS:
            m["snapshot_hits"] += 1
        if abs(dptr_addr - OBJECT_TABLE_BASE) <= OBJECT_TABLE_NEAR_RADIUS:
            m["object_table_hits"] += 1
        if dptr_addr in PIPELINE_EXTRA_ADDRS:
            m["pipeline_extra_hits"] += 1

    out_rows: list[dict[str, str]] = []
    for m in metrics.values():
        score = 0
        if m["packet_xdata_hits"] > 0:
            score += 3
        if m["queue_hits"] > 0:
            score += 3
        if m["selector_hits"] > 0:
            score += 3
        if m["snapshot_hits"] > 0:
            score += 2
        if m["object_table_hits"] > 0:
            score += 2
        if m["xdata_write_count"] > 0:
            score += 1
        if m["xdata_read_count"] > 0:
            score += 1
        if m["incoming_lcalls"] > 0:
            score += 1
        role = str(m["role_candidate"]).lower()
        if any(token in role for token in ("packet", "service", "dispatcher")):
            score += 1

        if score >= 6:
            confidence = "probable"
        elif score >= 3:
            confidence = "hypothesis"
        else:
            confidence = "unknown"

        notes = []
        if m["queue_hits"]:
            notes.append("queue@0x329C")
        if m["selector_hits"]:
            notes.append("selector@0x329D")
        if m["snapshot_hits"]:
            notes.append("snapshot@0x3110/0x3128")
        if m["packet_xdata_hits"]:
            notes.append("packet_window@0x5003-0x5010")
        if m["object_table_hits"]:
            notes.append("object_table_near@0x343D")
        if m["pipeline_extra_hits"]:
            notes.append("aux@0x3298/0x32A2")
        if m["call_xref_incoming_lcalls"]:
            notes.append(f"call_xref_lcalls={m['call_xref_incoming_lcalls']}")
        if m["block_parent_hits"]:
            notes.append(f"bb_parent_hits={m['block_parent_hits']}")

        out_rows.append(
            {
                "file": str(m["file"]),
                "function_addr": str(m["function_addr"]),
                "role_candidate": str(m["role_candidate"]),
                "basic_block_count": str(m["basic_block_count"]),
                "internal_block_count": str(m["internal_block_count"]),
                "incoming_lcalls": str(m["incoming_lcalls"]),
                "call_count": str(m["call_count"]),
                "xdata_read_count": str(m["xdata_read_count"]),
                "xdata_write_count": str(m["xdata_write_count"]),
                "movc_count": str(m["movc_count"]),
                "packet_xdata_hits": str(m["packet_xdata_hits"]),
                "queue_hits": str(m["queue_hits"]),
                "selector_hits": str(m["selector_hits"]),
                "snapshot_hits": str(m["snapshot_hits"]),
                "object_table_hits": str(m["object_table_hits"]),
                "score": str(score),
                "confidence": confidence,
                "notes": "; ".join(notes),
            }
        )

    out_rows.sort(
        key=lambda r: (
            -safe_int(r["score"]),
            -safe_int(r["packet_xdata_hits"]),
            -safe_int(r["queue_hits"]),
            -safe_int(r["selector_hits"]),
            r["file"],
            parse_hex(r["function_addr"]),
        )
    )

    fieldnames = [
        "file",
        "function_addr",
        "role_candidate",
        "basic_block_count",
        "internal_block_count",
        "incoming_lcalls",
        "call_count",
        "xdata_read_count",
        "xdata_write_count",
        "movc_count",
        "packet_xdata_hits",
        "queue_hits",
        "selector_hits",
        "snapshot_hits",
        "object_table_hits",
        "score",
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
