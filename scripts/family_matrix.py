#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import csv

from pzu_common import discover_pzu_files, infer_family, load_intel_hex


def similarity(a: bytearray, b: bytearray, start: int = 0x4000, end: int = 0xC000) -> float:
    total = end - start
    eq = 0
    for i in range(start, end):
        if a[i] == b[i]:
            eq += 1
    return (eq / total) * 100.0


def main() -> int:
    p = argparse.ArgumentParser(description="Generate firmware family similarity matrix.")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--out", type=Path, default=Path("docs/firmware_family_matrix.csv"))
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    loaded = []
    for path in files:
        mem, _st = load_intel_hex(path)
        loaded.append((path.name, infer_family(path.name), mem))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file_a", "family_a", "file_b", "family_b", "similarity_pct_4000_BFFF"])
        for i, (na, fa, ma) in enumerate(loaded):
            for j in range(i + 1, len(loaded)):
                nb, fb, mb = loaded[j]
                w.writerow([na, fa, nb, fb, f"{similarity(ma, mb):.4f}"])

    print(f"Generated: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
