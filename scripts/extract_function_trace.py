#!/usr/bin/env python3
"""Extract static per-instruction traces for top A03/A04 packet-builder candidates."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

DISASM_INDEX = DOCS / "disassembly_index.csv"
BASIC_BLOCK_MAP = DOCS / "basic_block_map.csv"
XDATA_CONFIRMED = DOCS / "xdata_confirmed_access.csv"
CODE_TABLE_CANDIDATES = DOCS / "code_table_candidates.csv"
CALL_XREF = DOCS / "call_xref.csv"
OUT_CSV = DOCS / "a03_a04_top_packet_function_trace.csv"

DEFAULT_TARGETS: list[tuple[str, str]] = [
    ("A04_28.PZU", "0x889F"),
    ("A03_26.PZU", "0x8904"),
]


@dataclass(frozen=True)
class Target:
    file: str
    function_addr: str


def parse_hex(value: str) -> int:
    return int(value, 16)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", dest="file_name", help="Firmware image name, e.g. A04_28.PZU")
    parser.add_argument("--function", dest="function_addr", help="Function entry, e.g. 0x889F")
    return parser.parse_args()


def get_targets(args: argparse.Namespace) -> list[Target]:
    if bool(args.file_name) ^ bool(args.function_addr):
        raise SystemExit("--file and --function must be passed together")
    if args.file_name and args.function_addr:
        return [Target(file=args.file_name, function_addr=args.function_addr)]
    return [Target(file=f, function_addr=fn) for f, fn in DEFAULT_TARGETS]


def collect_block_instructions(
    disasm_rows: list[dict[str, str]],
    block_rows: list[dict[str, str]],
    target: Target,
) -> list[dict[str, str]]:
    file_disasm = [r for r in disasm_rows if r["file"] == target.file]
    file_disasm.sort(key=lambda r: parse_hex(r["code_addr"]))

    addr_to_row = {parse_hex(r["code_addr"]): r for r in file_disasm}
    sorted_addrs = sorted(addr_to_row)
    addr_index = {addr: i for i, addr in enumerate(sorted_addrs)}

    selected_blocks = [
        r
        for r in block_rows
        if r["file"] == target.file and r.get("parent_function_candidate") == target.function_addr
    ]
    selected_blocks.sort(key=lambda r: parse_hex(r["block_addr"]))

    selected_rows: list[dict[str, str]] = []
    for block in selected_blocks:
        block_addr = parse_hex(block["block_addr"])
        inst_count = int(block.get("instruction_count") or "0")
        start_idx = addr_index.get(block_addr)
        if start_idx is None or inst_count <= 0:
            continue
        for idx in range(start_idx, min(start_idx + inst_count, len(sorted_addrs))):
            code_addr = sorted_addrs[idx]
            row = dict(addr_to_row[code_addr])
            row["block_addr"] = block["block_addr"]
            selected_rows.append(row)
    return selected_rows


def main() -> None:
    args = parse_args()
    targets = get_targets(args)

    disasm_rows = load_csv(DISASM_INDEX)
    block_rows = load_csv(BASIC_BLOCK_MAP)
    xdata_rows = load_csv(XDATA_CONFIRMED)
    movc_rows = load_csv(CODE_TABLE_CANDIDATES)
    call_rows = load_csv(CALL_XREF)

    xdata_map = {(r["file"], r["code_addr"]): r for r in xdata_rows}
    movc_map = {(r["file"], r["code_addr"]): r for r in movc_rows}
    call_map = {(r["file"], r["code_addr"]): r for r in call_rows}

    output_rows: list[dict[str, str]] = []
    for target in targets:
        for row in collect_block_instructions(disasm_rows, block_rows, target):
            code_addr = row["code_addr"]
            key = (target.file, code_addr)
            xdata = xdata_map.get(key)
            movc = movc_map.get(key)
            call = call_map.get(key)

            notes: list[str] = []
            if xdata:
                notes.append("xdata")
            if movc:
                notes.append("movc")

            output_rows.append(
                {
                    "file": target.file,
                    "function_addr": target.function_addr,
                    "code_addr": code_addr,
                    "block_addr": row.get("block_addr", ""),
                    "mnemonic": row.get("mnemonic", ""),
                    "operands": row.get("operands", ""),
                    "target_addr": row.get("target_addr", ""),
                    "fallthrough_addr": row.get("fallthrough_addr", ""),
                    "xdata_addr": xdata.get("dptr_addr", "") if xdata else "",
                    "xdata_access_type": xdata.get("access_type", "") if xdata else "",
                    "call_type": call.get("call_type", "") if call else "",
                    "call_target": call.get("target_addr", "") if call else "",
                    "notes": ";".join(notes),
                }
            )

    output_rows.sort(key=lambda r: (r["file"], parse_hex(r["function_addr"]), parse_hex(r["code_addr"])))

    fieldnames = [
        "file",
        "function_addr",
        "code_addr",
        "block_addr",
        "mnemonic",
        "operands",
        "target_addr",
        "fallthrough_addr",
        "xdata_addr",
        "xdata_access_type",
        "call_type",
        "call_target",
        "notes",
    ]

    with OUT_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"wrote {len(output_rows)} rows -> {OUT_CSV.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
