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
    p.add_argument("--confirmed", type=Path, default=Path("docs/xdata_confirmed_access.csv"))
    p.add_argument("--pointer-args", type=Path, default=Path("docs/dptr_pointer_args.csv"))
    p.add_argument("--code-table", type=Path, default=Path("docs/code_table_candidates.csv"))
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as f_agg, args.detailed.open(
        "w", newline="", encoding="utf-8"
    ) as f_det, args.confirmed.open("w", newline="", encoding="utf-8") as f_conf, args.pointer_args.open(
        "w", newline="", encoding="utf-8"
    ) as f_ptr, args.code_table.open("w", newline="", encoding="utf-8") as f_code:
        w_agg = csv.writer(f_agg)
        w_agg.writerow(["file", "xdata_addr_hex", "read_count", "write_count", "total_refs"])

        w_det = csv.writer(f_det)
        w_det.writerow(["file", "branch", "code_addr", "dptr_addr", "access_type", "next_bytes", "confidence"])

        w_conf = csv.writer(f_conf)
        w_conf.writerow(
            [
                "file",
                "branch",
                "code_addr",
                "dptr_addr",
                "evidence_type",
                "access_type",
                "next_bytes",
                "confidence",
            ]
        )

        w_ptr = csv.writer(f_ptr)
        w_ptr.writerow(["file", "branch", "code_addr", "dptr_addr", "target_addr", "evidence_type", "confidence"])

        w_code = csv.writer(f_code)
        w_code.writerow(["file", "branch", "code_addr", "dptr_addr", "evidence_type", "next_bytes", "confidence"])

        for path in files:
            mem, _st = load_intel_hex(path)
            refs = extract_xdata_refs(mem)
            for addr, r, wr in to_rows(refs):
                w_agg.writerow([path.name, f"0x{addr:04X}", r, wr, r + wr])

            for row in extract_xdata_refs_detailed(mem):
                code_addr = f"0x{int(row['code_addr']):04X}"
                dptr_addr = f"0x{int(row['dptr_addr']):04X}"
                w_det.writerow(
                    [
                        path.name,
                        infer_branch(path.name),
                        code_addr,
                        dptr_addr,
                        row["access_type"],
                        row["next_bytes"],
                        row["confidence"],
                    ]
                )

                access_type = str(row["access_type"])
                if access_type in {"read", "write", "offset_read", "offset_write"}:
                    evidence = {
                        "read": "confirmed_xdata_read",
                        "write": "confirmed_xdata_write",
                        "offset_read": "confirmed_xdata_offset_access",
                        "offset_write": "confirmed_xdata_offset_access",
                    }[access_type]
                    w_conf.writerow(
                        [
                            path.name,
                            infer_branch(path.name),
                            code_addr,
                            dptr_addr,
                            evidence,
                            access_type,
                            row["next_bytes"],
                            row["confidence"],
                        ]
                    )
                elif access_type == "lcall":
                    target = f"0x{str(row['next_bytes']).split()[-1]}"
                    w_ptr.writerow(
                        [
                            path.name,
                            infer_branch(path.name),
                            code_addr,
                            dptr_addr,
                            target,
                            "probable_pointer_argument",
                            row["confidence"],
                        ]
                    )
                elif access_type == "movc":
                    w_code.writerow(
                        [
                            path.name,
                            infer_branch(path.name),
                            code_addr,
                            dptr_addr,
                            "code_table_or_string_candidate",
                            row["next_bytes"],
                            row["confidence"],
                        ]
                    )

    print(f"Generated: {args.out}")
    print(f"Generated: {args.detailed}")
    print(f"Generated: {args.confirmed}")
    print(f"Generated: {args.pointer_args}")
    print(f"Generated: {args.code_table}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
