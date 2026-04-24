#!/usr/bin/env python3
"""Compare Intel HEX (*.PZU) images and print equal/different address windows.

Usage:
  python3 scripts/compare_pzu_variants.py A03_26.PZU A04_28.PZU
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Tuple


def load_intel_hex(path: Path, strict_checksum: bool = False) -> List[int]:
    mem = [0xFF] * 0x10000
    for ln, raw in enumerate(path.read_text(errors="ignore").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if not line.startswith(":"):
            raise ValueError(f"{path}: line {ln}: not Intel HEX")
        rec = bytes.fromhex(line[1:])
        if strict_checksum and (sum(rec) & 0xFF) != 0:
            raise ValueError(f"{path}: line {ln}: checksum mismatch")
        ll = rec[0]
        addr = (rec[1] << 8) | rec[2]
        rtype = rec[3]
        data = rec[4 : 4 + ll]
        if rtype == 0x00:
            mem[addr : addr + ll] = data
    return mem


def build_segments(m1: List[int], m2: List[int], start: int, end: int) -> List[Tuple[int, int, bool]]:
    segments: List[Tuple[int, int, bool]] = []
    state = m1[start] == m2[start]
    seg_start = start
    for addr in range(start + 1, end):
        now = m1[addr] == m2[addr]
        if now != state:
            segments.append((seg_start, addr - 1, state))
            seg_start = addr
            state = now
    segments.append((seg_start, end - 1, state))
    return segments


def summarize(m1: List[int], m2: List[int], start: int, end: int) -> None:
    total = end - start
    equal = sum(1 for a in range(start, end) if m1[a] == m2[a])
    print(f"range: 0x{start:04X}-0x{end-1:04X}")
    print(f"equal bytes: {equal}/{total} ({equal/total*100:.2f}%)")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image_a", type=Path)
    p.add_argument("image_b", type=Path)
    p.add_argument("--start", type=lambda x: int(x, 0), default=0x4000)
    p.add_argument("--end", type=lambda x: int(x, 0), default=0xC000)
    p.add_argument("--min-run", type=int, default=16)
    args = p.parse_args()

    m1 = load_intel_hex(args.image_a, strict_checksum=False)
    m2 = load_intel_hex(args.image_b, strict_checksum=False)

    summarize(m1, m2, args.start, args.end)
    segments = build_segments(m1, m2, args.start, args.end)

    print("\nEqual windows:")
    for s, e, is_equal in segments:
        if is_equal and (e - s + 1) >= args.min_run:
            print(f"  0x{s:04X}-0x{e:04X} len={e-s+1}")

    print("\nDifferent windows:")
    for s, e, is_equal in segments:
        if (not is_equal) and (e - s + 1) >= args.min_run:
            print(f"  0x{s:04X}-0x{e:04X} len={e-s+1}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
