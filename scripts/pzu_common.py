#!/usr/bin/env python3
"""Common utilities for parsing and analyzing Intel HEX (*.PZU) firmware images."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json
import re
from typing import Iterable


PZU_GLOB = "*.PZU"
ASCII_RE = re.compile(rb"[\x20-\x7E]{4,}")


@dataclass
class PzuStats:
    file: str
    size_bytes: int
    sha256: str
    valid_hex: bool
    checksum_errors: int
    data_records: int
    data_bytes: int
    min_addr: int | None
    max_addr: int | None
    non_ff_bytes: int
    ascii_markers: list[str]

    def to_json(self) -> dict:
        d = asdict(self)
        if self.min_addr is not None:
            d["addr_range"] = f"0x{self.min_addr:04X}-0x{self.max_addr:04X}"
        else:
            d["addr_range"] = None
        return d


def discover_pzu_files(root: Path) -> list[Path]:
    return sorted(root.glob(PZU_GLOB), key=lambda p: p.name.lower())


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def load_intel_hex(path: Path) -> tuple[bytearray, PzuStats]:
    mem = bytearray([0xFF] * 0x10000)
    valid = True
    checksum_errors = 0
    data_records = 0
    data_bytes = 0
    min_addr: int | None = None
    max_addr: int | None = None

    for ln, raw in enumerate(path.read_text(errors="ignore").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if not line.startswith(":"):
            valid = False
            continue
        payload = line[1:]
        if len(payload) % 2 != 0:
            valid = False
            continue
        try:
            rec = bytes.fromhex(payload)
        except ValueError:
            valid = False
            continue
        if (sum(rec) & 0xFF) != 0:
            checksum_errors += 1
            valid = False
        ll = rec[0]
        addr = (rec[1] << 8) | rec[2]
        rtype = rec[3]
        data = rec[4 : 4 + ll]
        if len(data) != ll:
            valid = False
            continue
        if rtype == 0x00:
            data_records += 1
            data_bytes += ll
            mem[addr : addr + ll] = data
            lo = addr
            hi = addr + ll - 1
            min_addr = lo if min_addr is None else min(min_addr, lo)
            max_addr = hi if max_addr is None else max(max_addr, hi)

    non_ff = sum(1 for b in mem if b != 0xFF)
    strings = sorted({m.group().decode("ascii", errors="ignore") for m in ASCII_RE.finditer(bytes(mem))})
    markers = [s for s in strings if len(s.strip()) >= 4][:30]
    stats = PzuStats(
        file=path.name,
        size_bytes=path.stat().st_size,
        sha256=_sha256(path),
        valid_hex=valid,
        checksum_errors=checksum_errors,
        data_records=data_records,
        data_bytes=data_bytes,
        min_addr=min_addr,
        max_addr=max_addr,
        non_ff_bytes=non_ff,
        ascii_markers=markers,
    )
    return mem, stats


def infer_family(name: str) -> str:
    up = name.upper()
    if up.startswith("90CYE"):
        return "90CYE"
    if up.startswith("PPKP") and "90CYE" in up:
        return "PPKP-90CYE"
    if up.startswith("A03"):
        return "A03"
    if up.startswith("A04"):
        return "A04"
    if up.startswith("PPKP"):
        return "PPKP"
    return "OTHER"


def normalize_name(name: str) -> str:
    return name.rsplit(".", 1)[0]


def dump_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def extract_xdata_refs(mem: bytearray, start: int = 0x4000, end: int = 0xC000) -> dict[int, dict[str, int]]:
    refs: dict[int, dict[str, int]] = {}
    i = start
    while i < end - 4:
        # MOV DPTR,#imm16 ; MOVX A,@DPTR
        if mem[i] == 0x90 and mem[i + 3] == 0xE0:
            addr = (mem[i + 1] << 8) | mem[i + 2]
            refs.setdefault(addr, {"read": 0, "write": 0})["read"] += 1
            i += 4
            continue
        # MOV DPTR,#imm16 ; MOVX @DPTR,A
        if mem[i] == 0x90 and mem[i + 3] == 0xF0:
            addr = (mem[i + 1] << 8) | mem[i + 2]
            refs.setdefault(addr, {"read": 0, "write": 0})["write"] += 1
            i += 4
            continue
        i += 1
    return refs


def to_rows(mapping: dict[int, dict[str, int]]) -> Iterable[tuple[int, int, int]]:
    for addr in sorted(mapping):
        rw = mapping[addr]
        yield addr, rw["read"], rw["write"]
