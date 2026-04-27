#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
REF_VALS = ["0x01", "0x02", "0x03", "0x04", "0x05", "0x07", "0x08", "0x7E", "0xFF"]


def load_csv(name: str) -> list[dict[str, str]]:
    p = DOCS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def main() -> int:
    ap = argparse.ArgumentParser(description="Cross-family enum/state comparator")
    ap.add_argument("--out-md", type=Path, default=DOCS / "cross_family_enum_state_comparison.md")
    ap.add_argument("--out-matrix", type=Path, default=DOCS / "cross_family_enum_state_matrix.csv")
    ap.add_argument("--out-div", type=Path, default=DOCS / "cross_family_enum_state_divergences.csv")
    args = ap.parse_args()

    dks = load_csv("dks_enum_state_matrix.csv")
    enum_map = load_csv("enum_branch_value_map.csv")

    ref_meaning = {}
    for r in dks:
        v = r.get("enum_value", "")
        if v and v not in ref_meaning:
            ref_meaning[v] = r.get("probable_meaning", "unknown")

    rows: list[dict[str, str]] = []
    family_vals: defaultdict[str, set[str]] = defaultdict(set)
    for r in enum_map:
        v = r.get("candidate_value", "")
        if not v:
            continue
        b = r.get("branch", "")
        family_vals[b].add(v)
        rows.append(
            {
                "enum_value": v,
                "reference_meaning": ref_meaning.get(v, "unknown"),
                "branch": b,
                "file": r.get("file", ""),
                "function_addr": r.get("function_addr", ""),
                "xdata_addr": "-",
                "branch_context": r.get("comparison_instruction", ""),
                "downstream_path": r.get("downstream_path", ""),
                "confidence": r.get("confidence", "unknown"),
                "evidence_level": "enum_branch_value_map",
                "notes": "reference meaning is DKS-local; cross-family meaning not asserted",
            }
        )

    rows.sort(key=lambda x: (x["enum_value"], x["branch"], x["file"], x["function_addr"]))
    with args.out_matrix.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "enum_value",
                "reference_meaning",
                "branch",
                "file",
                "function_addr",
                "xdata_addr",
                "branch_context",
                "downstream_path",
                "confidence",
                "evidence_level",
                "notes",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    divs: list[dict[str, str]] = []
    branches = sorted(family_vals)
    for v in sorted(set(REF_VALS) | {r["enum_value"] for r in rows}):
        seen = [b for b in branches if v in family_vals[b]]
        divs.append(
            {
                "enum_value": v,
                "seen_in_branches": "|".join(seen),
                "missing_in_branches": "|".join([b for b in branches if b not in seen]),
                "reference_meaning": ref_meaning.get(v, "unknown"),
                "divergence_type": "shared" if len(seen) == len(branches) and branches else ("family_specific" if len(seen) <= 1 else "partial_shared"),
                "notes": "operational meaning remains branch-local unless independently validated",
            }
        )
    with args.out_div.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["enum_value", "seen_in_branches", "missing_in_branches", "reference_meaning", "divergence_type", "notes"])
        w.writeheader()
        w.writerows(divs)

    md = [
        "# Cross-family enum/state comparison",
        "",
        "This report compares enum vocabulary presence, not physical meaning.",
        "",
        f"- matrix rows: {len(rows)}",
        f"- divergence rows: {len(divs)}",
        "",
        "## DKS reference values",
        "- " + ", ".join(REF_VALS),
        "",
        "## Guardrails",
        "- Shared value bytes do not automatically imply shared behavior.",
        "- Family-specific values are preserved as family-specific until runtime evidence appears.",
    ]
    args.out_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"Wrote {args.out_matrix.relative_to(ROOT)} ({len(rows)} rows)")
    print(f"Wrote {args.out_div.relative_to(ROOT)} ({len(divs)} rows)")
    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
