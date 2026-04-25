#!/usr/bin/env python3
from __future__ import annotations

from collections import deque
from pathlib import Path
import argparse
import csv

from pzu_common import discover_pzu_files, infer_branch, load_intel_hex, vector_entrypoints


CODE_START = 0x4000
CODE_END = 0xC000
MAX_INSTRUCTIONS = 5000

ENTRY_VECTOR_KEYS = (
    "vector_4000",
    "vector_4006",
    "vector_400C",
    "vector_4012",
    "vector_4018",
    "vector_401E",
)

# 8051 instruction-length table (covers full 0x00..0xFF opcode space).
# Used for unknown-mnemonic fallback decoding with reliable instruction sizes.
LEN_TABLE: dict[int, int] = {i: 1 for i in range(0x100)}

# 2-byte opcode families
for op in (
    0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xA1, 0xB1,
    0xC1, 0xD1, 0xE1, 0xF1,
):
    LEN_TABLE[op] = 2

for start_op in (0x05, 0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85, 0x95, 0xA5, 0xB5, 0xC5, 0xD5, 0xE5, 0xF5):
    LEN_TABLE[start_op] = 2

for start_op in (0x06, 0x16, 0x26, 0x36, 0x46, 0x56, 0x66, 0x76, 0x86, 0x96, 0xA6, 0xB6, 0xC6, 0xD6, 0xE6, 0xF6):
    LEN_TABLE[start_op] = 1

for start_op in (0x07, 0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77, 0x87, 0x97, 0xA7, 0xB7, 0xC7, 0xD7, 0xE7, 0xF7):
    LEN_TABLE[start_op] = 1

# Explicit multi-byte opcodes
for op in (0x02, 0x10, 0x12, 0x20, 0x30, 0x43, 0x53, 0x63, 0x75, 0x85, 0x90, 0xA5):
    LEN_TABLE[op] = 3

for op in (
    0x04, 0x14, 0x24, 0x34, 0x44, 0x54, 0x64, 0x74, 0x84, 0x94, 0xA4, 0xB4, 0xC4, 0xD4, 0xE4, 0xF4,
    0x03, 0x13, 0x23, 0x33, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xA2, 0xB2, 0xC2, 0xD2, 0xE2, 0xF2,
    0x00, 0x22, 0x32, 0x73, 0x83, 0x93, 0xA3, 0xD3,
):
    LEN_TABLE[op] = 1

for op in (
    0x40, 0x50, 0x60, 0x70, 0x80,
    0xB0,
    0xC0, 0xD0,
    0xE0, 0xF0,
):
    LEN_TABLE[op] = 2

# 2-byte relative jumps and conditional branches
for op in list(range(0x40, 0x80)) + [0x80, 0xB4, 0xB5] + list(range(0xB6, 0xC0)):
    LEN_TABLE[op] = 2

# MOV Rn,#imm and CJNE forms
for op in range(0x78, 0x80):
    LEN_TABLE[op] = 2
for op in range(0xB8, 0xC0):
    LEN_TABLE[op] = 3

# ACALL/AJMP pages
for op in range(0x01, 0x100, 0x10):
    LEN_TABLE[op] = 2
for op in range(0x11, 0x100, 0x10):
    LEN_TABLE[op] = 2

# Direct bit operations
for op in (0x20, 0x30):
    LEN_TABLE[op] = 3
for op in (0x10,):
    LEN_TABLE[op] = 3
for op in (0xA0, 0xB0, 0x92, 0xB2, 0xC2, 0xD2):
    LEN_TABLE[op] = 2

# Arithmetic/logical immediate and direct variants
for op in (
    0x24, 0x25, 0x26, 0x27,
    0x34, 0x35, 0x36, 0x37,
    0x44, 0x45, 0x46, 0x47,
    0x54, 0x55, 0x56, 0x57,
    0x64, 0x65, 0x66, 0x67,
):
    LEN_TABLE[op] = 2

# MOV variants
LEN_TABLE[0x75] = 3
LEN_TABLE[0x85] = 3
for op in (0x76, 0x77, 0x86, 0x87):
    LEN_TABLE[op] = 2
for op in range(0x88, 0x90):
    LEN_TABLE[op] = 2
LEN_TABLE[0x90] = 3
for op in (0xA6, 0xA7, 0xB6, 0xB7):
    LEN_TABLE[op] = 2

# Decrement-and-jump forms
for op in range(0xD8, 0xE0):
    LEN_TABLE[op] = 2




def in_code(addr: int) -> bool:
    return CODE_START <= addr < CODE_END


def _signed8(v: int) -> int:
    return v - 0x100 if v & 0x80 else v


def _hex_addr(addr: int | None) -> str:
    return "" if addr is None else f"0x{addr:04X}"


def _decode(mem: bytearray, addr: int) -> dict[str, object]:
    op = mem[addr]

    if op == 0x02:
        target = (mem[addr + 1] << 8) | mem[addr + 2]
        return {
            "mnemonic": "LJMP",
            "operands": f"0x{target:04X}",
            "length": 3,
            "target_addr": target,
            "fallthrough": None,
            "confidence": "high",
            "stop": True,
        }
    if op == 0x12:
        target = (mem[addr + 1] << 8) | mem[addr + 2]
        return {
            "mnemonic": "LCALL",
            "operands": f"0x{target:04X}",
            "length": 3,
            "target_addr": target,
            "fallthrough": addr + 3,
            "confidence": "high",
            "stop": False,
        }
    if op == 0x80:
        rel = _signed8(mem[addr + 1])
        target = (addr + 2 + rel) & 0xFFFF
        return {
            "mnemonic": "SJMP",
            "operands": f"{rel:+d}",
            "length": 2,
            "target_addr": target,
            "fallthrough": None,
            "confidence": "high",
            "stop": True,
        }
    if op == 0x22:
        return {
            "mnemonic": "RET",
            "operands": "",
            "length": 1,
            "target_addr": None,
            "fallthrough": None,
            "confidence": "high",
            "stop": True,
        }
    if op == 0x32:
        return {
            "mnemonic": "RETI",
            "operands": "",
            "length": 1,
            "target_addr": None,
            "fallthrough": None,
            "confidence": "high",
            "stop": True,
        }
    if op == 0x90:
        imm = (mem[addr + 1] << 8) | mem[addr + 2]
        return {
            "mnemonic": "MOV",
            "operands": f"DPTR,#0x{imm:04X}",
            "length": 3,
            "target_addr": None,
            "fallthrough": addr + 3,
            "confidence": "high",
            "stop": False,
        }
    if op == 0xE0:
        return {
            "mnemonic": "MOVX",
            "operands": "A,@DPTR",
            "length": 1,
            "target_addr": None,
            "fallthrough": addr + 1,
            "confidence": "high",
            "stop": False,
        }
    if op == 0xF0:
        return {
            "mnemonic": "MOVX",
            "operands": "@DPTR,A",
            "length": 1,
            "target_addr": None,
            "fallthrough": addr + 1,
            "confidence": "high",
            "stop": False,
        }
    if op == 0x93:
        return {
            "mnemonic": "MOVC",
            "operands": "A,@A+DPTR",
            "length": 1,
            "target_addr": None,
            "fallthrough": addr + 1,
            "confidence": "high",
            "stop": False,
        }
    if op == 0xA3:
        return {
            "mnemonic": "INC",
            "operands": "DPTR",
            "length": 1,
            "target_addr": None,
            "fallthrough": addr + 1,
            "confidence": "high",
            "stop": False,
        }
    if op == 0x00:
        return {
            "mnemonic": "NOP",
            "operands": "",
            "length": 1,
            "target_addr": None,
            "fallthrough": addr + 1,
            "confidence": "high",
            "stop": False,
        }

    length = LEN_TABLE[op]
    confidence = "medium"
    return {
        "mnemonic": "UNK",
        "operands": "",
        "length": length,
        "target_addr": None,
        "fallthrough": addr + length,
        "confidence": confidence,
        "stop": False,
    }


def _opcode_hex(mem: bytearray, addr: int, length: int) -> str:
    return " ".join(f"{mem[addr + i]:02X}" for i in range(length) if addr + i < CODE_END)


def _entry_targets(mem: bytearray) -> set[int]:
    vectors = vector_entrypoints(mem)
    out: set[int] = set()
    for key in ENTRY_VECTOR_KEYS:
        raw = vectors.get(key, "")
        if raw.startswith("0x"):
            out.add(int(raw, 16))
    return {addr for addr in out if in_code(addr)}


def disassemble_reachable(mem: bytearray, max_instructions: int = MAX_INSTRUCTIONS) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    starts = _entry_targets(mem)
    queue: deque[int] = deque(sorted(starts))
    visited: set[int] = set()

    while queue and len(rows) < max_instructions:
        addr = queue.popleft()
        pc = addr

        while in_code(pc) and pc not in visited and len(rows) < max_instructions:
            insn = _decode(mem, pc)
            length = int(insn["length"])
            visited.add(pc)

            target = int(insn["target_addr"]) if insn["target_addr"] is not None else None
            fallthrough = int(insn["fallthrough"]) if insn["fallthrough"] is not None else None

            if target is not None and in_code(target) and target not in visited:
                queue.append(target)

            row = {
                "code_addr": f"0x{pc:04X}",
                "opcode_hex": _opcode_hex(mem, pc, length),
                "mnemonic": str(insn["mnemonic"]),
                "operands": str(insn["operands"]),
                "length": str(length),
                "target_addr": _hex_addr(target if target is not None and in_code(target) else None),
                "fallthrough_addr": _hex_addr(fallthrough if fallthrough is not None and in_code(fallthrough) else None),
                "is_reachable": "True",
                "source": "entry_vector" if pc in starts else "flow",
                "confidence": str(insn["confidence"]),
            }
            rows.append(row)

            if bool(insn["stop"]):
                break

            if fallthrough is None or not in_code(fallthrough):
                break

            pc = fallthrough

    return rows


def main() -> int:
    p = argparse.ArgumentParser(description="Generate minimal reachable 8051 disassembly index for *.PZU images.")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--out", type=Path, default=Path("docs/disassembly_index.csv"))
    p.add_argument("--max-instructions", type=int, default=MAX_INSTRUCTIONS)
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    total_instructions = 0
    low_confidence = 0
    medium_confidence = 0
    high_confidence = 0

    with args.out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "file",
                "branch",
                "code_addr",
                "opcode_hex",
                "mnemonic",
                "operands",
                "length",
                "target_addr",
                "fallthrough_addr",
                "is_reachable",
                "source",
                "confidence",
            ]
        )

        for path in files:
            mem, _ = load_intel_hex(path)
            branch = infer_branch(path.name)
            for row in disassemble_reachable(mem, max_instructions=args.max_instructions):
                w.writerow(
                    [
                        path.name,
                        branch,
                        row["code_addr"],
                        row["opcode_hex"],
                        row["mnemonic"],
                        row["operands"],
                        row["length"],
                        row["target_addr"],
                        row["fallthrough_addr"],
                        row["is_reachable"],
                        row["source"],
                        row["confidence"],
                    ]
                )
                total_instructions += 1
                if row["confidence"] == "low":
                    low_confidence += 1
                elif row["confidence"] == "medium":
                    medium_confidence += 1
                elif row["confidence"] == "high":
                    high_confidence += 1

    print(f"Generated: {args.out}")
    print(f"total instructions: {total_instructions}")
    print(f"low confidence instructions: {low_confidence}")
    print(f"medium confidence instructions: {medium_confidence}")
    print(f"high confidence instructions: {high_confidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
