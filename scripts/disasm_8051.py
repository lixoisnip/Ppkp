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

# Minimal 8051 instruction-length table (fallback for unsupported opcodes).
# Unknown opcodes default to length=1 with low confidence.
MIN_LEN_TABLE: dict[int, int] = {
    0x00: 1,
    0x01: 2,
    0x02: 3,
    0x03: 1,
    0x04: 1,
    0x05: 2,
    0x06: 1,
    0x07: 1,
    0x08: 1,
    0x09: 1,
    0x0A: 1,
    0x0B: 1,
    0x0C: 1,
    0x0D: 1,
    0x0E: 1,
    0x0F: 1,
    0x10: 3,
    0x11: 2,
    0x12: 3,
    0x13: 1,
    0x14: 1,
    0x15: 2,
    0x20: 3,
    0x21: 2,
    0x22: 1,
    0x23: 1,
    0x24: 2,
    0x25: 2,
    0x30: 3,
    0x31: 2,
    0x32: 1,
    0x33: 1,
    0x34: 2,
    0x35: 2,
    0x40: 2,
    0x50: 2,
    0x60: 2,
    0x70: 2,
    0x73: 1,
    0x74: 2,
    0x75: 3,
    0x80: 2,
    0x81: 2,
    0x82: 2,
    0x83: 1,
    0x84: 1,
    0x85: 3,
    0x86: 2,
    0x87: 2,
    0x88: 2,
    0x89: 2,
    0x8A: 2,
    0x8B: 2,
    0x8C: 2,
    0x8D: 2,
    0x8E: 2,
    0x8F: 2,
    0x90: 3,
    0x92: 2,
    0x93: 1,
    0x94: 2,
    0x95: 2,
    0xA0: 2,
    0xA2: 2,
    0xA3: 1,
    0xB0: 2,
    0xB2: 2,
    0xC0: 2,
    0xC2: 2,
    0xD0: 2,
    0xD2: 2,
    0xE0: 1,
    0xE2: 1,
    0xE4: 1,
    0xF0: 1,
    0xF2: 1,
    0xF4: 1,
}


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

    length = MIN_LEN_TABLE.get(op, 1)
    confidence = "medium" if op in MIN_LEN_TABLE else "low"
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

    print(f"Generated: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
