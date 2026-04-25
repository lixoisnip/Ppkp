#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import csv

from pzu_common import discover_pzu_files, extract_xdata_refs, load_intel_hex, to_rows


def main() -> int:
    p = argparse.ArgumentParser(description="Generate XDATA cross reference CSV for all *.PZU images.")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--out", type=Path, default=Path("docs/xdata_xref.csv"))
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "xdata_addr_hex", "read_count", "write_count", "total_refs"])
        for path in files:
            mem, _st = load_intel_hex(path)
            refs = extract_xdata_refs(mem)
            for addr, r, wr in to_rows(refs):
                w.writerow([path.name, f"0x{addr:04X}", r, wr, r + wr])

    print(f"Generated: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
