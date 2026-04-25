#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import csv

from pzu_common import discover_pzu_files, dump_json, infer_family, load_intel_hex, normalize_name


def main() -> int:
    p = argparse.ArgumentParser(description="Generate firmware manifest JSON and inventory CSV.")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--manifest", type=Path, default=Path("docs/firmware_manifest.json"))
    p.add_argument("--inventory", type=Path, default=Path("docs/firmware_inventory.csv"))
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    items = []
    for path in files:
        _m, st = load_intel_hex(path)
        obj = st.to_json()
        obj["family"] = infer_family(st.file)
        obj["stem"] = normalize_name(st.file)
        items.append(obj)

    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    dump_json(args.manifest, {"generated_at_utc": "2026-04-25", "count": len(items), "firmware": items})

    with args.inventory.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "file",
            "family",
            "valid_hex",
            "checksum_errors",
            "data_records",
            "data_bytes",
            "addr_range",
            "sha256",
        ])
        for it in items:
            w.writerow([
                it["file"],
                it["family"],
                it["valid_hex"],
                it["checksum_errors"],
                it["data_records"],
                it["data_bytes"],
                it["addr_range"],
                it["sha256"],
            ])

    print(f"Generated: {args.manifest}")
    print(f"Generated: {args.inventory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
