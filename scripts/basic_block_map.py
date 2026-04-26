#!/usr/bin/env python3
from __future__ import annotations

import csv
from bisect import bisect_left, bisect_right
from collections import defaultdict
from pathlib import Path

DISASM_CSV = Path("docs/disassembly_index.csv")
CALL_XREF_CSV = Path("docs/call_xref.csv")
FUNCTION_MAP_CSV = Path("docs/function_map.csv")
OUT_CSV = Path("docs/basic_block_map.csv")

TERMINATORS = {"RET", "RETI", "LJMP", "SJMP"}
CONDITIONAL_JUMPS = {"CJNE", "JZ", "JNZ", "JNB", "JC", "JNC", "DJNZ", "JB", "JBC"}


def parse_hex(value: str) -> int:
    return int(value, 16)


def parse_bool(value: str) -> bool:
    return value.strip().lower() == "true"


def fmt_hex(value: int | None) -> str:
    if value is None:
        return ""
    return f"0x{value:04X}"


def main() -> int:
    instructions_by_key: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    block_addrs_by_key: dict[tuple[str, str], set[int]] = defaultdict(set)
    conditional_targets_by_key: dict[tuple[str, str], set[int]] = defaultdict(set)
    entry_vectors_by_key: dict[tuple[str, str], set[int]] = defaultdict(set)
    incoming_by_key: dict[tuple[str, str], dict[int, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"LCALL": 0, "LJMP": 0, "SJMP": 0})
    )

    with DISASM_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["file"], row["branch"])
            addr = parse_hex(row["code_addr"])
            mnemonic = row["mnemonic"].strip().upper()
            target_addr = parse_hex(row["target_addr"]) if row["target_addr"] else None
            fallthrough_addr = parse_hex(row["fallthrough_addr"]) if row["fallthrough_addr"] else None
            reachable = parse_bool(row["is_reachable"])

            instructions_by_key[key].append(
                {
                    "addr": addr,
                    "mnemonic": mnemonic,
                    "target_addr": target_addr,
                    "fallthrough_addr": fallthrough_addr,
                    "reachable": reachable,
                }
            )

            if row["source"] == "entry_vector":
                entry_vectors_by_key[key].add(addr)
                block_addrs_by_key[key].add(addr)

            if mnemonic in CONDITIONAL_JUMPS:
                if target_addr is not None:
                    conditional_targets_by_key[key].add(target_addr)
                    block_addrs_by_key[key].add(target_addr)
                if fallthrough_addr is not None:
                    block_addrs_by_key[key].add(fallthrough_addr)

    with CALL_XREF_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if not parse_bool(row["target_in_code_range"]):
                continue
            key = (row["file"], row["branch"])
            call_type = row["call_type"].strip().upper()
            target = parse_hex(row["target_addr"])

            block_addrs_by_key[key].add(target)
            if call_type in {"LCALL", "LJMP", "SJMP"}:
                incoming_by_key[key][target][call_type] += 1

    function_addrs_by_key: dict[tuple[str, str], list[int]] = defaultdict(list)
    function_info_by_key: dict[tuple[str, str], dict[int, dict[str, object]]] = defaultdict(dict)
    with FUNCTION_MAP_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["file"], row["branch"])
            addr = parse_hex(row["function_addr"])
            function_addrs_by_key[key].append(addr)
            function_info_by_key[key][addr] = {
                "entry_evidence": row["entry_evidence"],
                "incoming_lcalls": int(row["incoming_lcalls"]),
            }

    out_rows: list[list[object]] = []

    for key in sorted(block_addrs_by_key.keys()):
        file_name, branch = key
        inst_rows = sorted(
            [item for item in instructions_by_key.get(key, []) if bool(item["reachable"])],
            key=lambda item: int(item["addr"]),
        )
        if not inst_rows:
            continue

        by_addr = {int(item["addr"]): item for item in inst_rows}
        sorted_inst_addrs = sorted(by_addr.keys())
        function_addrs = sorted(set(function_addrs_by_key.get(key, [])))

        for block_addr in sorted(block_addrs_by_key[key]):
            entry_evidence = ""
            if block_addr in function_info_by_key[key]:
                entry_evidence = str(function_info_by_key[key][block_addr]["entry_evidence"])
            if not entry_evidence and block_addr in entry_vectors_by_key[key]:
                entry_evidence = "entry_vector"

            incoming = incoming_by_key[key][block_addr]
            incoming_lcalls = incoming["LCALL"]
            incoming_ljmps = incoming["LJMP"]
            incoming_sjmps = incoming["SJMP"]

            is_entry_vector = entry_evidence == "entry_vector" or block_addr in entry_vectors_by_key[key]

            if incoming_lcalls > 0 or is_entry_vector:
                block_type = "function_entry"
            elif block_addr in conditional_targets_by_key[key]:
                block_type = "conditional_branch_block"
            elif incoming_ljmps + incoming_sjmps > 0 and incoming_lcalls == 0:
                block_type = "internal_jump_block"
            else:
                block_type = "unknown_block"

            if block_addr in function_addrs and (incoming_lcalls > 0 or is_entry_vector):
                parent_candidate = block_addr
            else:
                idx = bisect_right(function_addrs, block_addr) - 1
                parent_candidate = function_addrs[idx] if idx >= 0 else None

            next_block = None
            for candidate in sorted(block_addrs_by_key[key]):
                if candidate > block_addr:
                    next_block = candidate
                    break

            instruction_count = 0
            ends_with = "unknown"
            target_addr = None
            fallthrough_addr = None

            if block_addr in by_addr:
                start_idx = bisect_left(sorted_inst_addrs, block_addr)

                for i in range(start_idx, len(sorted_inst_addrs)):
                    addr = sorted_inst_addrs[i]
                    if addr < block_addr:
                        continue
                    if next_block is not None and addr >= next_block:
                        ends_with = "fallthrough"
                        break

                    row = by_addr[addr]
                    instruction_count += 1
                    mnemonic = str(row["mnemonic"])
                    target_addr = row["target_addr"] if row["target_addr"] is not None else target_addr
                    fallthrough_addr = row["fallthrough_addr"] if row["fallthrough_addr"] is not None else fallthrough_addr

                    if mnemonic in {"RET", "RETI", "LJMP", "SJMP"}:
                        ends_with = mnemonic
                        break
                    if mnemonic in CONDITIONAL_JUMPS:
                        ends_with = "conditional_branch"
                        break
                else:
                    if instruction_count > 0:
                        ends_with = "unknown"

            if block_type == "function_entry" and (incoming_lcalls > 0 or is_entry_vector):
                confidence = "probable"
            elif block_type in {"internal_jump_block", "conditional_branch_block"}:
                confidence = "hypothesis"
            else:
                confidence = "unknown"

            out_rows.append(
                [
                    file_name,
                    branch,
                    fmt_hex(block_addr),
                    block_type,
                    entry_evidence,
                    fmt_hex(parent_candidate),
                    incoming_lcalls,
                    incoming_ljmps,
                    incoming_sjmps,
                    instruction_count,
                    ends_with,
                    fmt_hex(target_addr),
                    fmt_hex(fallthrough_addr),
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
                "block_addr",
                "block_type",
                "entry_evidence",
                "parent_function_candidate",
                "incoming_lcalls",
                "incoming_ljmps",
                "incoming_sjmps",
                "instruction_count",
                "ends_with",
                "target_addr",
                "fallthrough_addr",
                "confidence",
            ]
        )
        for row in sorted(out_rows, key=lambda r: (r[0], r[1], parse_hex(str(r[2])))):
            writer.writerow(row)

    print(f"Generated: {OUT_CSV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
