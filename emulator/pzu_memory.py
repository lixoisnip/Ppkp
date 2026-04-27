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

    def metadata(self) -> dict[str, str]:
        if not self.bytes_by_addr:
            return {
                "firmware_file": self.firmware_file,
                "min_code_addr": "",
                "max_code_addr": "",
                "has_0x4000": "False",
                "has_0x4100": "False",
                "reset_vector_bytes": "",
                "entrypoint_candidate": "",
                "confidence": "unsupported",
                "notes": "empty_code_image",
            }
        addrs = sorted(self.bytes_by_addr.keys())
        has_4000 = 0x4000 in self.bytes_by_addr
        has_4100 = 0x4100 in self.bytes_by_addr
        reset = [self.get_byte(0x4000 + i) for i in range(3)] if has_4000 else []
        entrypoint = ""
        confidence = "hypothesis"
        notes = []
        if len(reset) == 3 and reset[0] == 0x02:
            entry = (reset[1] << 8) | reset[2]
            entrypoint = f"0x{entry:04X}"
            notes.append("reset_ljmp_detected")
            if entry == 0x4100:
                confidence = "external_analysis"
        else:
            notes.append("reset_not_ljmp_or_missing")
        coverage_ok = addrs[0] <= 0x4000 <= addrs[-1] and addrs[0] <= 0xBFFF <= addrs[-1]
        notes.append(f"covers_0x4000_0xBFFF={coverage_ok}")
        return {
            "firmware_file": self.firmware_file,
            "min_code_addr": f"0x{addrs[0]:04X}",
            "max_code_addr": f"0x{addrs[-1]:04X}",
            "has_0x4000": str(has_4000),
            "has_0x4100": str(has_4100),
            "reset_vector_bytes": " ".join(f"{b:02X}" for b in reset),
            "entrypoint_candidate": entrypoint,
            "confidence": confidence,
            "notes": ";".join(notes),
        }


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
