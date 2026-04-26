#!/usr/bin/env python3
"""Extract ordered static traces for A03/A04 packet pipeline candidate chains."""

from __future__ import annotations

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
FUNCTION_MAP = DOCS / "function_map.csv"
OUT_CSV = DOCS / "a03_a04_packet_pipeline_chain_trace.csv"

DEFAULT_CHAINS: list[tuple[str, str, list[str]]] = [
    ("A04_28.PZU", "A04_chain", ["0xB310", "0x889F", "0x89C9"]),
    ("A03_26.PZU", "A03_chain", ["0xA900", "0x8904", "0x8A2E"]),
]

ARITH_MNEMONICS = {"ADD", "ADDC", "SUBB", "XRL", "ANL", "ORL", "INC", "DEC"}

QUEUE_ADDR = 0x329C
SELECTOR_ADDR = 0x329D
PACKET_WINDOW = set(range(0x5003, 0x5011))
AUX_3298_3299 = {0x3298, 0x3299}
AUX_32A0_32A2 = {0x32A0, 0x32A1, 0x32A2}
AUX_4DAC_GROUP = {0x4DAC, 0x4DB6, 0x4FD7, 0x4FD8}


@dataclass(frozen=True)
class ChainFunction:
    file: str
    chain_name: str
    chain_order: int
    function_addr: str


def parse_hex(value: str) -> int:
    return int(value, 16)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def packet_marker_for_addr(xdata_addr: str) -> str:
    if not xdata_addr:
        return "none"
    addr = parse_hex(xdata_addr)
    if addr == QUEUE_ADDR:
        return "queue_0x329C"
    if addr == SELECTOR_ADDR:
        return "selector_0x329D"
    if addr in PACKET_WINDOW:
        return "packet_window_0x5003_0x5010"
    if addr in AUX_3298_3299:
        return "aux_0x3298_0x3299"
    if addr in AUX_32A0_32A2:
        return "aux_0x32A0_0x32A1_0x32A2"
    if addr in AUX_4DAC_GROUP:
        return "aux_0x4DAC_0x4DB6_0x4FD7_0x4FD8"
    return "none"


def event_type_for_row(mnemonic: str, xdata_access_type: str, call_type: str, target_addr: str, movc: bool, marker: str) -> str:
    if marker != "none":
        return "packet_marker"
    if xdata_access_type == "read":
        return "xdata_read"
    if xdata_access_type == "write":
        return "xdata_write"
    if call_type:
        return "call"
    m = mnemonic.upper()
    if m in ARITH_MNEMONICS:
        return "arithmetic"
    if movc:
        return "movc"
    if target_addr and m.startswith("J"):
        return "jump"
    if target_addr and m in {"CJNE", "DJNZ", "SJMP", "LJMP", "AJMP"}:
        return "jump"
    return "instruction"


def collect_function_instructions(
    disasm_rows: list[dict[str, str]],
    block_rows: list[dict[str, str]],
    target: ChainFunction,
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
    seen: set[tuple[int, int]] = set()
    for block in selected_blocks:
        block_addr = parse_hex(block["block_addr"])
        inst_count = int(block.get("instruction_count") or "0")
        start_idx = addr_index.get(block_addr)
        if start_idx is None or inst_count <= 0:
            continue
        for idx in range(start_idx, min(start_idx + inst_count, len(sorted_addrs))):
            code_addr = sorted_addrs[idx]
            uniq = (code_addr, parse_hex(block["block_addr"]))
            if uniq in seen:
                continue
            seen.add(uniq)
            row = dict(addr_to_row[code_addr])
            row["block_addr"] = block["block_addr"]
            selected_rows.append(row)

    selected_rows.sort(key=lambda r: (parse_hex(r["code_addr"]), parse_hex(r["block_addr"])))
    return selected_rows


def main() -> None:
    disasm_rows = load_csv(DISASM_INDEX)
    block_rows = load_csv(BASIC_BLOCK_MAP)
    xdata_rows = load_csv(XDATA_CONFIRMED)
    movc_rows = load_csv(CODE_TABLE_CANDIDATES)
    call_rows = load_csv(CALL_XREF)
    function_rows = load_csv(FUNCTION_MAP)

    xdata_map = {(r["file"], r["code_addr"]): r for r in xdata_rows}
    movc_map = {(r["file"], r["code_addr"]): r for r in movc_rows}
    call_map = {(r["file"], r["code_addr"]): r for r in call_rows}
    function_map = {(r["file"], r["function_addr"]): r for r in function_rows}

    targets: list[ChainFunction] = []
    for file_name, chain_name, funcs in DEFAULT_CHAINS:
        for i, function_addr in enumerate(funcs, start=1):
            targets.append(
                ChainFunction(
                    file=file_name,
                    chain_name=chain_name,
                    chain_order=i,
                    function_addr=function_addr,
                )
            )

    output_rows: list[dict[str, str]] = []
    for target in targets:
        fn_meta = function_map.get((target.file, target.function_addr), {})
        fn_conf = fn_meta.get("confidence", "")
        for row in collect_function_instructions(disasm_rows, block_rows, target):
            code_addr = row["code_addr"]
            key = (target.file, code_addr)
            xdata = xdata_map.get(key)
            movc = movc_map.get(key)
            call = call_map.get(key)

            xdata_addr = xdata.get("dptr_addr", "") if xdata else ""
            xdata_access_type = xdata.get("access_type", "") if xdata else ""
            call_type = call.get("call_type", "") if call else ""
            call_target = call.get("target_addr", "") if call else ""
            packet_marker = packet_marker_for_addr(xdata_addr)
            event_type = event_type_for_row(
                mnemonic=row.get("mnemonic", ""),
                xdata_access_type=xdata_access_type,
                call_type=call_type,
                target_addr=row.get("target_addr", ""),
                movc=bool(movc),
                marker=packet_marker,
            )

            notes: list[str] = []
            if movc:
                notes.append("movc_candidate")
            if fn_conf:
                notes.append(f"function_confidence:{fn_conf}")

            output_rows.append(
                {
                    "file": target.file,
                    "chain_name": target.chain_name,
                    "chain_order": str(target.chain_order),
                    "function_addr": target.function_addr,
                    "code_addr": code_addr,
                    "block_addr": row.get("block_addr", ""),
                    "mnemonic": row.get("mnemonic", ""),
                    "operands": row.get("operands", ""),
                    "target_addr": row.get("target_addr", ""),
                    "fallthrough_addr": row.get("fallthrough_addr", ""),
                    "event_type": event_type,
                    "xdata_addr": xdata_addr,
                    "xdata_access_type": xdata_access_type,
                    "call_type": call_type,
                    "call_target": call_target,
                    "packet_marker": packet_marker,
                    "notes": ";".join(notes),
                }
            )

    output_rows.sort(
        key=lambda r: (
            r["file"],
            r["chain_name"],
            int(r["chain_order"]),
            parse_hex(r["code_addr"]),
            parse_hex(r["block_addr"]),
        )
    )

    fieldnames = [
        "file",
        "chain_name",
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
        "packet_marker",
        "notes",
    ]

    with OUT_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"wrote {len(output_rows)} rows -> {OUT_CSV.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
