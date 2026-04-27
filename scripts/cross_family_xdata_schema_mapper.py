#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

TARGET_BRANCHES = {"90CYE_shifted_DKS", "90CYE_v2_1", "A03_A04", "RTOS_service"}


def load_csv(name: str) -> list[dict[str, str]]:
    p = DOCS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def h2i(v: str) -> int:
    try:
        return int(v, 16)
    except Exception:
        return -1


def conf(kind: str) -> str:
    return {
        "exact": "confirmed",
        "shifted": "probable",
        "family_specific": "hypothesis",
        "none": "unknown",
    }[kind]


def main() -> int:
    ap = argparse.ArgumentParser(description="Map DKS XDATA clusters into other firmware families")
    ap.add_argument("--out-md", type=Path, default=DOCS / "cross_family_xdata_schema_map.md")
    ap.add_argument("--out-csv", type=Path, default=DOCS / "cross_family_xdata_schema_map.csv")
    ap.add_argument("--out-unresolved", type=Path, default=DOCS / "cross_family_xdata_unresolved.csv")
    args = ap.parse_args()

    dks = [r for r in load_csv("dks_xdata_lifecycle_matrix.csv") if r.get("branch") == "90CYE_DKS"]
    xref = load_csv("xdata_confirmed_access.csv")

    refs = {(r.get("cluster", "unknown"), r.get("xdata_addr", "")) for r in dks if r.get("xdata_addr")}
    file_branch = {}
    file_addr_access: defaultdict[str, defaultdict[int, set[str]]] = defaultdict(lambda: defaultdict(set))
    file_addr_funcs: defaultdict[str, defaultdict[int, set[str]]] = defaultdict(lambda: defaultdict(set))
    for r in xref:
        f = r.get("file", "")
        b = r.get("branch", "")
        if not f or b not in TARGET_BRANCHES:
            continue
        file_branch[f] = b
        addr = h2i(r.get("dptr_addr", ""))
        if addr < 0:
            continue
        file_addr_access[f][addr].add(r.get("access_type", ""))
        file_addr_funcs[f][addr].add(r.get("code_addr", ""))

    rows: list[dict[str, str]] = []
    unresolved: list[dict[str, str]] = []

    for cluster, ref_addr_hex in sorted(refs):
        ref_addr = h2i(ref_addr_hex)
        for f in sorted(file_addr_access):
            best_kind = "none"
            best_addr = None
            if ref_addr in file_addr_access[f]:
                best_kind, best_addr = "exact", ref_addr
            else:
                shifted = ref_addr + 0xF4
                if shifted in file_addr_access[f]:
                    best_kind, best_addr = "shifted", shifted
                else:
                    nearby = [a for a in file_addr_access[f] if abs(a - ref_addr) <= 0x20]
                    if nearby:
                        best_kind, best_addr = "family_specific", min(nearby, key=lambda a: abs(a - ref_addr))
            if best_kind == "none":
                unresolved.append(
                    {
                        "reference_cluster": cluster,
                        "reference_xdata": ref_addr_hex,
                        "target_branch": file_branch[f],
                        "target_file": f,
                        "reason": "no exact/shifted/nearby candidate",
                        "next_step": "manual trace around top function analogs",
                    }
                )
                continue

            acc = "/".join(sorted(file_addr_access[f][best_addr]))
            funcs = "|".join(sorted(file_addr_funcs[f][best_addr])[:12])
            basis = "xdata_pattern_match" if best_kind in {"exact", "shifted"} else "hypothesis"
            rows.append(
                {
                    "reference_cluster": cluster,
                    "reference_xdata": ref_addr_hex,
                    "target_branch": file_branch[f],
                    "target_file": f,
                    "target_xdata_candidate": f"0x{best_addr:04X}",
                    "access_pattern": acc,
                    "functions_using": funcs,
                    "it_matches": "yes" if best_kind != "family_specific" else "partial",
                    "basis": basis,
                    "confidence": conf(best_kind),
                    "notes": "shift +0xF4 treated as shifted_DKS-style hint only" if best_kind == "shifted" else "",
                }
            )

    with args.out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "reference_cluster",
                "reference_xdata",
                "target_branch",
                "target_file",
                "target_xdata_candidate",
                "access_pattern",
                "functions_using",
                "it_matches",
                "basis",
                "confidence",
                "notes",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    with args.out_unresolved.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["reference_cluster", "reference_xdata", "target_branch", "target_file", "reason", "next_step"])
        w.writeheader()
        w.writerows(unresolved)

    by_kind = defaultdict(int)
    for r in rows:
        by_kind[r["confidence"]] += 1
    md = [
        "# Cross-family XDATA schema map",
        "",
        "This report maps DKS lifecycle clusters into non-DKS families using address conservation and shifted patterns.",
        "",
        "## Summary",
        f"- mapped rows: {len(rows)}",
        f"- unresolved rows: {len(unresolved)}",
        "",
        "## Confidence distribution",
    ]
    for k, v in sorted(by_kind.items()):
        md.append(f"- {k}: {v}")
    md.extend([
        "",
        "## Interpretation rules",
        "- Conserved address != guaranteed semantic identity.",
        "- Shifted or nearby clusters stay probable/hypothesis until callgraph+runtime confirmation.",
    ])
    args.out_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"Wrote {args.out_csv.relative_to(ROOT)} ({len(rows)} rows)")
    print(f"Wrote {args.out_unresolved.relative_to(ROOT)} ({len(unresolved)} rows)")
    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
