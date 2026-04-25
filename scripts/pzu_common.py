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

VECTOR_ADDRS = (0x4000, 0x4006, 0x400C, 0x4012, 0x4018, 0x401E)


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


def normalize_name(name: str) -> str:
    return name.rsplit(".", 1)[0]


def infer_branch(name: str) -> str:
    stem = normalize_name(name).upper()
    if stem in {"A03_26", "A04_28"}:
        return "A03_A04"
    if stem in {"90CYE03_19_DKS", "90CYE04_19_DKS"}:
        return "90CYE_DKS"
    if stem in {"90CYE03_19_2 V2_1", "90CYE04_19_2 V2_1"}:
        return "90CYE_v2_1"
    if stem == "90CYE02_27 DKS":
        return "90CYE_shifted_DKS"
    if stem in {"PPKP2001 90CYE01", "PPKP2012 A01", "PPKP2019 A02"}:
        return "RTOS_service"

    if stem.startswith("90CYE"):
        return "90CYE_generic"
    if stem.startswith("A03") or stem.startswith("A04"):
        return "A03_A04"
    if stem.startswith("PPKP"):
        return "RTOS_service"
    return "OTHER"


def infer_family(name: str) -> str:
    branch = infer_branch(name)
    if branch == "RTOS_service":
        return "RTOS_service_family"
    return branch


def dump_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def vector_entrypoints(mem: bytearray) -> dict[str, str]:
    out: dict[str, str] = {}
    for addr in VECTOR_ADDRS:
        key = f"vector_{addr:04X}"
        if mem[addr] == 0x02:
            target = (mem[addr + 1] << 8) | mem[addr + 2]
            out[key] = f"0x{target:04X}"
        else:
            out[key] = " ".join(f"{mem[addr + i]:02X}" for i in range(3))
    return out


def _add_ref(refs: dict[int, dict[str, int]], addr: int, access: str) -> None:
    bucket = refs.setdefault(addr, {"read": 0, "write": 0})
    if access in bucket:
        bucket[access] += 1


def extract_xdata_refs(mem: bytearray, start: int = 0x4000, end: int = 0xC000) -> dict[int, dict[str, int]]:
    refs: dict[int, dict[str, int]] = {}
    i = start
    while i < end - 6:
        if mem[i] != 0x90:
            i += 1
            continue

        addr = (mem[i + 1] << 8) | mem[i + 2]
        op = mem[i + 3]
        if op == 0xE0:
            _add_ref(refs, addr, "read")
            i += 4
            continue
        if op == 0xF0:
            _add_ref(refs, addr, "write")
            i += 4
            continue
        if op == 0xA3 and mem[i + 4] == 0xE0:
            _add_ref(refs, addr + 1, "read")
            i += 5
            continue
        if op == 0xA3 and mem[i + 4] == 0xF0:
            _add_ref(refs, addr + 1, "write")
            i += 5
            continue
        i += 1
    return refs


def extract_xdata_refs_detailed(mem: bytearray, start: int = 0x4000, end: int = 0xC000) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    i = start
    while i < end - 6:
        if mem[i] != 0x90:
            i += 1
            continue

        addr = (mem[i + 1] << 8) | mem[i + 2]
        op = mem[i + 3]

        def push(code_addr: int, dptr_addr: int, access_type: str, next_bytes: str, confidence: str) -> None:
            rows.append(
                {
                    "code_addr": code_addr,
                    "dptr_addr": dptr_addr & 0xFFFF,
                    "access_type": access_type,
                    "next_bytes": next_bytes,
                    "confidence": confidence,
                }
            )

        if op == 0xE0:
            push(i, addr, "read", "E0", "high")
            i += 4
            continue
        if op == 0xF0:
            push(i, addr, "write", "F0", "high")
            i += 4
            continue
        if op == 0xA3 and mem[i + 4] == 0xE0:
            push(i, addr + 1, "offset_read", "A3 E0", "high")
            i += 5
            continue
        if op == 0xA3 and mem[i + 4] == 0xF0:
            push(i, addr + 1, "offset_write", "A3 F0", "high")
            i += 5
            continue
        if op == 0x93:
            push(i, addr, "movc", "93", "medium")
            i += 4
            continue
        if op == 0x12:
            tgt = (mem[i + 4] << 8) | mem[i + 5]
            push(i, addr, "lcall", f"12 {tgt:04X}", "medium")
            i += 6
            continue
        if op == 0x02:
            tgt = (mem[i + 4] << 8) | mem[i + 5]
            push(i, addr, "ljmp", f"02 {tgt:04X}", "medium")
            i += 6
            continue

        i += 1
    return rows


def to_rows(mapping: dict[int, dict[str, int]]) -> Iterable[tuple[int, int, int]]:
    for addr in sorted(mapping):
        rw = mapping[addr]
        yield addr, rw["read"], rw["write"]
