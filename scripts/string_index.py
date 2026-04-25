#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import csv

from pzu_common import discover_pzu_files, infer_branch, load_intel_hex


CODE_START = 0x4000
CODE_END = 0xC000
MIN_LEN = 4


def is_candidate_byte(b: int) -> bool:
    if b in (0x09, 0x0A, 0x0D):
        return True
    if 0x20 <= b <= 0x7E:
        return True
    if b in (0xA8, 0xB8):
        return True
    if 0xC0 <= b <= 0xFF:
        return True
    return False


def decode_ascii(buf: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in buf)


def decode_cp1251(buf: bytes) -> tuple[str, bool]:
    try:
        text = buf.decode("cp1251")
    except UnicodeDecodeError:
        return "", False
    has_cyr = any("А" <= ch <= "я" or ch in "Ёё" for ch in text)
    return text, has_cyr


def extract_movc_bases(mem: bytearray, start: int = CODE_START, end: int = CODE_END) -> set[int]:
    out: set[int] = set()
    for i in range(start, end - 3):
        if mem[i] == 0x90 and mem[i + 3] == 0x93:
            addr = (mem[i + 1] << 8) | mem[i + 2]
            if CODE_START <= addr < CODE_END:
                out.add(addr)
    return out


def read_printable_blob(mem: bytearray, addr: int, limit: int = 96) -> bytes:
    buf = bytearray()
    for i in range(limit):
        a = addr + i
        if a >= CODE_END:
            break
        b = mem[a]
        if b in (0x00, 0xFF):
            break
        if not is_candidate_byte(b):
            break
        buf.append(b)
    return bytes(buf)


def extract_strings(mem: bytearray, start: int = CODE_START, end: int = CODE_END) -> list[tuple[int, bytes]]:
    out: dict[int, bytes] = {}

    # Primary source: MOVC-referenced tables/strings
    for base in extract_movc_bases(mem, start, end):
        blob = read_printable_blob(mem, base)
        if len(blob) >= MIN_LEN:
            out[base] = blob

    # Fallback source: plain ASCII-like NUL-terminated spans in CODE
    i = start
    while i < end - MIN_LEN:
        if not (0x20 <= mem[i] <= 0x7E):
            i += 1
            continue
        s = i
        while i < end and (0x20 <= mem[i] <= 0x7E):
            i += 1
        if i < end and mem[i] in (0x00, 0xFF):
            chunk = bytes(mem[s:i])
            if len(chunk) >= 6:
                out.setdefault(s, chunk)
        i += 1

    return sorted(out.items(), key=lambda x: x[0])


def main() -> int:
    p = argparse.ArgumentParser(description="Extract ASCII/CP1251-like string candidates from CODE area 0x4000..0xBFFF")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--out", type=Path, default=Path("docs/string_index.csv"))
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    with args.out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "branch", "address", "raw_hex", "ascii_text", "cp1251_candidate", "notes"])

        for path in files:
            mem, _st = load_intel_hex(path)
            branch = infer_branch(path.name)
            for addr, blob in extract_strings(mem):
                ascii_text = decode_ascii(blob)
                cp1251_text, has_cyr = decode_cp1251(blob)

                if has_cyr:
                    notes = "cp1251_like"
                elif all(0x20 <= b <= 0x7E for b in blob):
                    notes = "ascii_only"
                elif any(0xC0 <= b <= 0xFF or b in (0xA8, 0xB8) for b in blob):
                    notes = "extended_single_byte"
                else:
                    notes = "mixed_printable"

                w.writerow(
                    [
                        path.name,
                        branch,
                        f"0x{addr:04X}",
                        " ".join(f"{b:02X}" for b in blob),
                        ascii_text,
                        cp1251_text if has_cyr else "",
                        notes,
                    ]
                )

    print(f"Generated: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
