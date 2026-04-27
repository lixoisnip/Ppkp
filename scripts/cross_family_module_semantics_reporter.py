#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

MODULES = [
    "CPU/runtime core",
    "keyboard/display/menu/front panel",
    "MASH",
    "MDS",
    "MUP",
    "PVK",
    "MVK",
    "input signal board",
    "packet/export",
    "output/action",
    "object/status layer",
    "unknown modules",
]


def load_csv(name: str) -> list[dict[str, str]]:
    p = DOCS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def map_module_type(v: str) -> str:
    s = (v or "").lower()
    if "cpu" in s:
        return "CPU/runtime core"
    if "keyboard" in s or "display" in s or "front" in s:
        return "keyboard/display/menu/front panel"
    if "mash" in s or "маш" in s:
        return "MASH"
    if "mds" in s:
        return "MDS"
    if "mup" in s:
        return "MUP"
    if "pvk" in s:
        return "PVK"
    if "mvk" in s:
        return "MVK"
    if "input" in s:
        return "input signal board"
    if "packet" in s:
        return "packet/export"
    if "output" in s:
        return "output/action"
    if "object" in s or "status" in s:
        return "object/status layer"
    return "unknown modules"


def main() -> int:
    ap = argparse.ArgumentParser(description="Consolidated cross-family module semantics report")
    ap.add_argument("--out-md", type=Path, default=DOCS / "cross_family_module_semantics.md")
    ap.add_argument("--out-matrix", type=Path, default=DOCS / "cross_family_module_semantics_matrix.csv")
    ap.add_argument("--out-unknowns", type=Path, default=DOCS / "cross_family_module_semantics_unknowns.csv")
    args = ap.parse_args()

    pres = load_csv("module_presence_matrix.csv")
    handlers = load_csv("module_handler_summary.csv")
    arch = load_csv("firmware_architecture_matrix.csv")

    application_notes = {(r.get("branch", ""), r.get("file", "")): r.get("probable_device_family", "unknown") for r in arch}

    strongest: defaultdict[tuple[str, str, str], list[str]] = defaultdict(list)
    conf_by_key: dict[tuple[str, str, str], str] = {}
    for r in pres:
        key = (r.get("branch", ""), r.get("file", ""), map_module_type(r.get("module_type", "")))
        strongest[key].append(r.get("strongest_function", ""))
        conf_by_key[key] = r.get("confidence", "unknown")

    for r in handlers:
        b = r.get("branch", "")
        fn = r.get("function_addr", "")
        mt = map_module_type(r.get("module_type", ""))
        files = {x.get("file", "") for x in pres if x.get("branch") == b}
        for f in files:
            strongest[(b, f, mt)].append(fn)

    rows: list[dict[str, str]] = []
    unknowns: list[dict[str, str]] = []
    all_files = sorted({(r.get("branch", ""), r.get("file", "")) for r in pres})
    for b, f in all_files:
        for m in MODULES:
            key = (b, f, m)
            funcs = sorted({x for x in strongest.get(key, []) if x})
            presence = "present" if funcs else "unknown"
            conf = conf_by_key.get(key, "unknown") if funcs else "unknown"
            analog = "yes" if any(x in {"0x497A", "0x497F", "0x5A7F", "0x6833", "0x758B", "0x53E6", "0xAB62"} for x in funcs) else "no"
            row = {
                "branch": b,
                "file": f,
                "module_type": m,
                "presence_evidence": presence,
                "strongest_functions": "|".join(funcs[:8]),
                "analog_to_dks": analog,
                "confidence": conf,
                "evidence_level": "callgraph_match" if funcs else "unknown",
                "application_notes": application_notes.get((b, f), "unknown"),
                "unknowns": "needs deeper isolation" if not funcs else "",
                "next_static_step": "manual deep trace" if funcs else "expand candidate scan",
                "next_external_evidence_needed": "bench module isolation for semantics",
            }
            rows.append(row)
            if not funcs:
                unknowns.append(
                    {
                        "branch": b,
                        "file": f,
                        "module_type": m,
                        "unknown_reason": "no strong static function candidate",
                        "next_static_step": "cross-check with function analog map + xdata map",
                        "next_external_evidence_needed": "module-level runtime trace or docs",
                    }
                )

    with args.out_matrix.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "branch",
                "file",
                "module_type",
                "presence_evidence",
                "strongest_functions",
                "analog_to_dks",
                "confidence",
                "evidence_level",
                "application_notes",
                "unknowns",
                "next_static_step",
                "next_external_evidence_needed",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    with args.out_unknowns.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["branch", "file", "module_type", "unknown_reason", "next_static_step", "next_external_evidence_needed"])
        w.writeheader()
        w.writerows(unknowns)

    family_counts = defaultdict(int)
    for r in rows:
        if r["presence_evidence"] == "present":
            family_counts[r["branch"]] += 1
    md = [
        "# Cross-family module semantics",
        "",
        "Per-family module map generated from module_presence_matrix + module_handler_summary + architecture matrix.",
        "",
        "## Family presence counts",
    ]
    for b, c in sorted(family_counts.items()):
        md.append(f"- {b}: {c} present module rows")
    md.extend(
        [
            "",
            "## Guardrails",
            "- Module presence is not converted into physical semantics without direct evidence.",
            "- DKS analog tags indicate structural adjacency only.",
        ]
    )
    args.out_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"Wrote {args.out_matrix.relative_to(ROOT)} ({len(rows)} rows)")
    print(f"Wrote {args.out_unknowns.relative_to(ROOT)} ({len(unknowns)} rows)")
    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
