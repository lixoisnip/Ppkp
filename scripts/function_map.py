#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

DISASM_CSV = Path("docs/disassembly_index.csv")
CALL_XREF_CSV = Path("docs/call_xref.csv")
XDATA_CSV = Path("docs/xdata_confirmed_access.csv")
CODE_TABLE_CSV = Path("docs/code_table_candidates.csv")
BASIC_BLOCK_CSV = Path("docs/basic_block_map.csv")
OUT_CSV = Path("docs/function_map.csv")

READ_EVIDENCE = {"confirmed_xdata_read", "offset_read"}
WRITE_EVIDENCE = {"confirmed_xdata_write", "offset_write"}


def parse_hex(value: str) -> int:
    return int(value, 16)


def parse_bool(value: str) -> bool:
    return value.strip().lower() == "true"


def evidence_label(evidence: set[str]) -> str:
    if evidence == {"entry_vector"}:
        return "entry_vector"
    if evidence == {"call_target"}:
        return "call_target"
    if evidence == {"basic_block_entry"}:
        return "basic_block_entry"
    return "mixed"


def infer_role(
    basic_block_count: int,
    incoming_lcalls: int,
    incoming_ljmps: int,
    incoming_sjmps: int,
    call_count: int,
    ret_count: int,
    xdata_read_count: int,
    xdata_write_count: int,
    movc_count: int,
) -> str:
    if basic_block_count >= 6 and call_count >= 4:
        return "dispatcher_or_router"
    if xdata_write_count >= 3:
        return "state_update_worker"
    if xdata_read_count >= 3 and xdata_write_count <= 1:
        return "state_reader_or_packet_builder"
    if movc_count >= 2:
        return "code_table_or_ui_worker"
    return "unknown"


def infer_confidence(
    incoming_lcalls: int,
    incoming_ljmps: int,
    incoming_sjmps: int,
    xdata_read_count: int,
    xdata_write_count: int,
    movc_count: int,
) -> str:
    total_incoming = incoming_lcalls + incoming_ljmps + incoming_sjmps
    if total_incoming > 0 and (xdata_read_count + xdata_write_count + movc_count) > 0:
        return "probable"
    if total_incoming > 0:
        return "hypothesis"
    return "unknown"


def main() -> int:
    instructions: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    function_evidence: dict[tuple[str, str], dict[int, set[str]]] = defaultdict(lambda: defaultdict(set))
    incoming_counts: dict[tuple[str, str], dict[int, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"LCALL": 0, "LJMP": 0, "SJMP": 0})
    )

    with DISASM_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["file"], row["branch"])
            addr = parse_hex(row["code_addr"])
            length = int(row["length"])
            instructions[key].append(
                {
                    "addr": addr,
                    "end": addr + max(1, length),
                    "mnemonic": row["mnemonic"],
                    "reachable": parse_bool(row["is_reachable"]),
                }
            )
            if row["source"] == "entry_vector":
                function_evidence[key][addr].add("entry_vector")

    with CALL_XREF_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if not parse_bool(row["target_in_code_range"]):
                continue
            key = (row["file"], row["branch"])
            target = parse_hex(row["target_addr"])
            call_type = row["call_type"]

            if call_type == "LCALL":
                function_evidence[key][target].add("call_target")
            if call_type in {"LCALL", "LJMP", "SJMP"}:
                incoming_counts[key][target][call_type] += 1

    blocks_by_key: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    with BASIC_BLOCK_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["file"], row["branch"])
            block_addr = parse_hex(row["block_addr"])
            block_type = row["block_type"]
            parent_candidate = row["parent_function_candidate"].strip()
            parent_addr = parse_hex(parent_candidate) if parent_candidate else None
            blocks_by_key[key].append(
                {
                    "block_addr": block_addr,
                    "block_type": block_type,
                    "parent_addr": parent_addr,
                }
            )
            if block_type == "function_entry":
                function_evidence[key][block_addr].add("basic_block_entry")

    xdata_by_key: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    with XDATA_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            xdata_by_key[(row["file"], row["branch"])].append(
                {
                    "addr": parse_hex(row["code_addr"]),
                    "evidence_type": row["evidence_type"],
                }
            )

    movc_by_key: dict[tuple[str, str], list[int]] = defaultdict(list)
    with CODE_TABLE_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            movc_by_key[(row["file"], row["branch"])].append(parse_hex(row["code_addr"]))

    rows_out: list[list[object]] = []
    for key in sorted(function_evidence.keys()):
        file_name, branch = key
        inst_rows = sorted(instructions.get(key, []), key=lambda item: item["addr"])
        if not inst_rows:
            continue

        candidate_functions = sorted(function_evidence[key].keys())
        max_end = max(item["end"] for item in inst_rows)

        for index, func_addr in enumerate(candidate_functions):
            next_addr = candidate_functions[index + 1] if index + 1 < len(candidate_functions) else max_end
            if next_addr <= func_addr:
                next_addr = func_addr + 1

            func_insts = [
                item
                for item in inst_rows
                if func_addr <= int(item["addr"]) < next_addr and bool(item["reachable"])
            ]

            ret_count = sum(1 for item in func_insts if item["mnemonic"] in {"RET", "RETI"})
            call_count = sum(1 for item in func_insts if item["mnemonic"] in {"LCALL", "LJMP", "SJMP"})

            xdata_read_count = 0
            xdata_write_count = 0
            for item in xdata_by_key.get(key, []):
                if func_addr <= int(item["addr"]) < next_addr:
                    evidence_type = str(item["evidence_type"])
                    if evidence_type in READ_EVIDENCE:
                        xdata_read_count += 1
                    if evidence_type in WRITE_EVIDENCE:
                        xdata_write_count += 1

            movc_count = sum(1 for addr in movc_by_key.get(key, []) if func_addr <= addr < next_addr)
            basic_blocks = [
                block for block in blocks_by_key.get(key, []) if block["parent_addr"] == func_addr
            ]
            basic_block_count = len(basic_blocks)
            internal_block_count = sum(1 for block in basic_blocks if block["block_type"] != "function_entry")

            incoming = incoming_counts[key][func_addr]
            role_candidate = infer_role(
                basic_block_count=basic_block_count,
                incoming_lcalls=incoming["LCALL"],
                incoming_ljmps=incoming["LJMP"],
                incoming_sjmps=incoming["SJMP"],
                call_count=call_count,
                ret_count=ret_count,
                xdata_read_count=xdata_read_count,
                xdata_write_count=xdata_write_count,
                movc_count=movc_count,
            )
            confidence = infer_confidence(
                incoming_lcalls=incoming["LCALL"],
                incoming_ljmps=incoming["LJMP"],
                incoming_sjmps=incoming["SJMP"],
                xdata_read_count=xdata_read_count,
                xdata_write_count=xdata_write_count,
                movc_count=movc_count,
            )

            rows_out.append(
                [
                    file_name,
                    branch,
                    f"0x{func_addr:04X}",
                    evidence_label(function_evidence[key][func_addr]),
                    incoming["LCALL"],
                    incoming["LJMP"],
                    incoming["SJMP"],
                    next_addr - func_addr,
                    ret_count,
                    call_count,
                    xdata_read_count,
                    xdata_write_count,
                    movc_count,
                    basic_block_count,
                    internal_block_count,
                    role_candidate,
                    confidence,
                ]
            )

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "file",
                "branch",
                "function_addr",
                "entry_evidence",
                "incoming_lcalls",
                "incoming_ljmps",
                "incoming_sjmps",
                "size_estimate",
                "ret_count",
                "call_count",
                "xdata_read_count",
                "xdata_write_count",
                "movc_count",
                "basic_block_count",
                "internal_block_count",
                "role_candidate",
                "confidence",
            ]
        )
        for row in sorted(rows_out, key=lambda r: (r[0], r[1], parse_hex(str(r[2])))):
            writer.writerow(row)

    print(f"Generated: {OUT_CSV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
