#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import csv
from pathlib import Path

from scripts.pzu_common import load_intel_hex


@dataclass
class CodeImage:
    firmware_file: str
    source: str
    bytes_by_addr: dict[int, int]
    reliable_bytes: bool = True
    notes: str = ""

    def get_byte(self, addr: int) -> int:
        return self.bytes_by_addr.get(addr & 0xFFFF, 0xFF)

    def get_window(self, start: int, size: int) -> list[int]:
        return [self.get_byte(start + i) for i in range(size)]


def load_code_image(path: Path | str) -> CodeImage:
    p = Path(path)
    if p.suffix.upper() == ".PZU":
        mem, _stats = load_intel_hex(p)
        return CodeImage(
            firmware_file=p.name,
            source="pzu_intel_hex",
            bytes_by_addr={i: b for i, b in enumerate(mem)},
            reliable_bytes=True,
        )
    if p.suffix.lower() == ".csv":
        return load_from_disassembly_index(p, firmware_file="")
    raise ValueError(f"Unsupported code image source: {p}")


def load_from_disassembly_index(csv_path: Path | str, firmware_file: str) -> CodeImage:
    path = Path(csv_path)
    bytes_by_addr: dict[int, int] = {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            row_file = (row.get("file") or "").strip()
            if firmware_file and row_file != firmware_file:
                continue
            code_addr = row.get("code_addr", "")
            op_hex = (row.get("opcode_hex") or "").strip()
            if not code_addr or not op_hex:
                continue
            try:
                base = int(code_addr, 16)
            except ValueError:
                continue
            parts = [p for p in op_hex.split() if p]
            for i, part in enumerate(parts):
                try:
                    bytes_by_addr[(base + i) & 0xFFFF] = int(part, 16)
                except ValueError:
                    continue

    return CodeImage(
        firmware_file=firmware_file or path.name,
        source="disassembly_index",
        bytes_by_addr=bytes_by_addr,
        reliable_bytes=False,
        notes=(
            "Loaded from disassembly CSV opcode_hex windows. Useful for constrained tracing when full byte-extraction "
            "is unavailable; coverage and ordering may be incomplete."
        ),
    )
