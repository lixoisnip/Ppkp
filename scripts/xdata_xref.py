#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import csv

from pzu_common import (
    discover_pzu_files,
    extract_xdata_refs,
    extract_xdata_refs_detailed,
    infer_branch,
    load_intel_hex,
    to_rows,
)


def main() -> int:
    p = argparse.ArgumentParser(description="Generate XDATA cross reference CSV for all *.PZU images.")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--out", type=Path, default=Path("docs/xdata_xref.csv"))
    p.add_argument("--detailed", type=Path, default=Path("docs/xdata_xref_detailed.csv"))
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as f_agg, args.detailed.open(
        "w", newline="", encoding="utf-8"
    ) as f_det:
        w_agg = csv.writer(f_agg)
        w_agg.writerow(["file", "xdata_addr_hex", "read_count", "write_count", "total_refs"])

        w_det = csv.writer(f_det)
        w_det.writerow(["file", "branch", "code_addr", "dptr_addr", "access_type", "next_bytes", "confidence"])

        for path in files:
            mem, _st = load_intel_hex(path)
            refs = extract_xdata_refs(mem)
            for addr, r, wr in to_rows(refs):
                w_agg.writerow([path.name, f"0x{addr:04X}", r, wr, r + wr])

            for row in extract_xdata_refs_detailed(mem):
                w_det.writerow(
                    [
                        path.name,
                        infer_branch(path.name),
                        f"0x{int(row['code_addr']):04X}",
                        f"0x{int(row['dptr_addr']):04X}",
                        row["access_type"],
                        row["next_bytes"],
                        row["confidence"],
                    ]
                )

    print(f"Generated: {args.out}")
    print(f"Generated: {args.detailed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
