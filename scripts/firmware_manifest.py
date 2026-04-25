#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import argparse
import csv

from pzu_common import (
    discover_pzu_files,
    dump_json,
    infer_branch,
    infer_family,
    load_intel_hex,
    normalize_name,
    vector_entrypoints,
)


def main() -> int:
    p = argparse.ArgumentParser(description="Generate firmware manifest JSON and inventory CSV.")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--manifest", type=Path, default=Path("docs/firmware_manifest.json"))
    p.add_argument("--inventory", type=Path, default=Path("docs/firmware_inventory.csv"))
    p.add_argument("--vectors", type=Path, default=Path("docs/vector_entrypoints.csv"))
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    items = []
    vector_rows = []
    for path in files:
        mem, st = load_intel_hex(path)
        vecs = vector_entrypoints(mem)
        obj = st.to_json()
        obj["family"] = infer_family(st.file)
        obj["branch"] = infer_branch(st.file)
        obj["stem"] = normalize_name(st.file)
        obj.update(vecs)
        items.append(obj)

        vector_rows.append(
            [
                st.file,
                st.valid_hex,
                vecs["vector_4000"],
                vecs["vector_4006"],
                vecs["vector_400C"],
                vecs["vector_4012"],
                vecs["vector_4018"],
                vecs["vector_401E"],
                infer_branch(st.file),
            ]
        )

    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).date().isoformat()
    dump_json(args.manifest, {"generated_at_utc": generated_at, "count": len(items), "firmware": items})

    with args.inventory.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "file",
            "family",
            "branch",
            "valid_hex",
            "checksum_errors",
            "data_records",
            "data_bytes",
            "addr_range",
            "sha256",
        ])
        for it in items:
            w.writerow(
                [
                    it["file"],
                    it["family"],
                    it["branch"],
                    it["valid_hex"],
                    it["checksum_errors"],
                    it["data_records"],
                    it["data_bytes"],
                    it["addr_range"],
                    it["sha256"],
                ]
            )

    with args.vectors.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "file",
                "valid_hex",
                "vector_4000",
                "vector_4006",
                "vector_400C",
                "vector_4012",
                "vector_4018",
                "vector_401E",
                "branch_hint",
            ]
        )
        w.writerows(vector_rows)

    print(f"Generated: {args.manifest}")
    print(f"Generated: {args.inventory}")
    print(f"Generated: {args.vectors}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
