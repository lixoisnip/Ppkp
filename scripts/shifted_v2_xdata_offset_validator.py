#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

TARGET_FILES = {
    "90CYE_shifted_DKS": ["90CYE02_27 DKS.PZU"],
    "90CYE_v2_1": ["90CYE03_19_2 v2_1.PZU", "90CYE04_19_2 v2_1.PZU"],
}

DKS_CLUSTERS: list[tuple[str, list[int]]] = [
    ("cluster_3010_301B", list(range(0x3010, 0x301C))),
    ("cluster_30E7", [0x30E7]),
    ("cluster_30E9", [0x30E9]),
    ("cluster_30EA_30F9", list(range(0x30EA, 0x30FA))),
    ("cluster_315B", [0x315B]),
    ("cluster_3181", [0x3181]),
    ("cluster_31BF", [0x31BF]),
    ("cluster_3640", [0x3640]),
    ("cluster_364B", [0x364B]),
    ("cluster_36D3_36FD", list(range(0x36D3, 0x36FE))),
]


def load_csv(name: str) -> list[dict[str, str]]:
    p = DOCS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def parse_hex(v: str) -> int:
    try:
        return int(v, 16)
    except Exception:
        return -1


def fhex(v: int) -> str:
    return f"0x{v:04X}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate shifted_DKS + v2_1 XDATA offset/divergence against DKS clusters")
    ap.add_argument("--out-md", type=Path, default=DOCS / "shifted_v2_xdata_offset_validation.md")
    ap.add_argument("--out-matrix", type=Path, default=DOCS / "shifted_v2_xdata_offset_matrix.csv")
    ap.add_argument("--out-anchors", type=Path, default=DOCS / "shifted_v2_function_anchor_map.csv")
    ap.add_argument("--out-div", type=Path, default=DOCS / "shifted_v2_schema_divergence.csv")
    args = ap.parse_args()

    xmap = load_csv("cross_family_xdata_schema_map.csv")
    fan = load_csv("cross_family_function_analogs.csv")

    map_rows: list[dict[str, str]] = []
    div_rows: list[dict[str, str]] = []

    for target_branch, files in TARGET_FILES.items():
        for cluster_name, refs in DKS_CLUSTERS:
            candidates = [
                r
                for r in xmap
                if r.get("target_branch") == target_branch and r.get("target_file") in files and parse_hex(r.get("reference_xdata", "")) in refs
            ]
            by_file: dict[str, list[dict[str, str]]] = {}
            for c in candidates:
                by_file.setdefault(c.get("target_file", ""), []).append(c)

            for tf in files:
                rows = by_file.get(tf, [])
                if not rows:
                    for ref in refs[:1]:
                        map_rows.append(
                            {
                                "reference_branch": "90CYE_DKS",
                                "target_branch": target_branch,
                                "reference_file": "90CYE03_19_DKS.PZU",
                                "target_file": tf,
                                "reference_xdata": fhex(ref),
                                "target_xdata": "",
                                "cluster": cluster_name,
                                "offset_delta": "",
                                "match_type": "unknown",
                                "confidence": "unknown",
                                "evidence_level": "unknown",
                                "reference_functions": "",
                                "target_functions": "",
                                "notes": "No direct mapping row in current static artifacts",
                            }
                        )
                    div_rows.append(
                        {
                            "branch": target_branch,
                            "file": tf,
                            "cluster": cluster_name,
                            "reference_pattern": "DKS cluster static map",
                            "target_pattern": "missing_or_unresolved",
                            "divergence_type": "unknown",
                            "severity": "medium",
                            "notes": "Needs deeper function-scoped XDATA trace",
                        }
                    )
                    continue

                deltas = []
                tgt_addrs = []
                refs_seen = []
                funcs = []
                for r in rows:
                    rx = parse_hex(r.get("reference_xdata", ""))
                    tx = parse_hex(r.get("target_xdata_candidate", ""))
                    if rx >= 0 and tx >= 0:
                        deltas.append(tx - rx)
                        tgt_addrs.append(tx)
                        refs_seen.append(rx)
                    funcs.extend((r.get("functions_using", "").split("|") if r.get("functions_using") else []))

                if deltas and len(set(deltas)) == 1:
                    mtype = "constant_offset"
                    delta = str(deltas[0])
                    conf = "probable"
                    ev = "xdata_pattern_match"
                elif deltas and any(d == 0 for d in deltas):
                    mtype = "partial_cluster_match"
                    delta = "mixed"
                    conf = "hypothesis"
                    ev = "manual_static"
                else:
                    mtype = "divergent"
                    delta = "mixed_or_none"
                    conf = "hypothesis"
                    ev = "manual_static"

                map_rows.append(
                    {
                        "reference_branch": "90CYE_DKS",
                        "target_branch": target_branch,
                        "reference_file": "90CYE03_19_DKS.PZU",
                        "target_file": tf,
                        "reference_xdata": fhex(min(refs_seen) if refs_seen else refs[0]),
                        "target_xdata": fhex(min(tgt_addrs)) if tgt_addrs else "",
                        "cluster": cluster_name,
                        "offset_delta": delta,
                        "match_type": mtype,
                        "confidence": conf,
                        "evidence_level": ev,
                        "reference_functions": "0x5A7F|0x6833|0x737C",
                        "target_functions": "|".join(sorted(set(f for f in funcs if f))),
                        "notes": "Family-specific mapping; no DKS physical semantic transfer",
                    }
                )
                div_rows.append(
                    {
                        "branch": target_branch,
                        "file": tf,
                        "cluster": cluster_name,
                        "reference_pattern": "contiguous DKS cluster",
                        "target_pattern": mtype,
                        "divergence_type": "shifted" if mtype == "constant_offset" else mtype,
                        "severity": "low" if mtype == "constant_offset" else "medium",
                        "notes": "Static-only evidence",
                    }
                )

    for tf in TARGET_FILES["90CYE_shifted_DKS"]:
        map_rows.append(
            {
                "reference_branch": "90CYE_DKS",
                "target_branch": "90CYE_shifted_DKS",
                "reference_file": "90CYE03_19_DKS.PZU",
                "target_file": tf,
                "reference_xdata": "0x3104",
                "target_xdata": "0x3104",
                "cluster": "shifted_object_status_probe",
                "offset_delta": "0",
                "match_type": "exact_same_addr",
                "confidence": "hypothesis",
                "evidence_level": "manual_static",
                "reference_functions": "0x673C",
                "target_functions": "0x673C",
                "notes": "0x3104 persists in shifted_DKS; treated as object-status pattern candidate only",
            }
        )

    anchor_rows: list[dict[str, str]] = []
    anchors = ["0x497A", "0x737C", "0x613C", "0x84A6", "0x728A", "0x6833", "0x5A7F", "0x7922", "0x597F", "0x7DC2"]
    for r in fan:
        if r.get("reference_function") not in anchors:
            continue
        if r.get("target_branch") not in {"90CYE_shifted_DKS", "90CYE_v2_1"}:
            continue
        anchor_rows.append(
            {
                "target_branch": r.get("target_branch", ""),
                "target_file": r.get("target_file", ""),
                "reference_function": r.get("reference_function", ""),
                "target_function": r.get("candidate_function", ""),
                "role_candidate": r.get("reference_role", "analog candidate"),
                "match_type": r.get("match_type", "unknown"),
                "confidence": r.get("confidence", "unknown"),
                "evidence_level": r.get("match_type", "unknown"),
                "xdata_overlap": r.get("xdata_overlap", ""),
                "callgraph_overlap": r.get("callgraph_overlap", ""),
                "notes": "Analog candidate only unless fingerprint-level evidence",
            }
        )

    for out, fields, rows in [
        (
            args.out_matrix,
            [
                "reference_branch",
                "target_branch",
                "reference_file",
                "target_file",
                "reference_xdata",
                "target_xdata",
                "cluster",
                "offset_delta",
                "match_type",
                "confidence",
                "evidence_level",
                "reference_functions",
                "target_functions",
                "notes",
            ],
            map_rows,
        ),
        (
            args.out_anchors,
            [
                "target_branch",
                "target_file",
                "reference_function",
                "target_function",
                "role_candidate",
                "match_type",
                "confidence",
                "evidence_level",
                "xdata_overlap",
                "callgraph_overlap",
                "notes",
            ],
            anchor_rows,
        ),
        (
            args.out_div,
            [
                "branch",
                "file",
                "cluster",
                "reference_pattern",
                "target_pattern",
                "divergence_type",
                "severity",
                "notes",
            ],
            div_rows,
        ),
    ]:
        with out.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

    conserved = sum(1 for r in map_rows if r["match_type"] in {"exact_same_addr", "constant_offset"})
    divergent = sum(1 for r in map_rows if r["match_type"] in {"divergent", "unknown"})
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    md = f"""# Shifted_DKS + v2_1 XDATA offset validation

Generated: {stamp}

## Scope and guardrails
- Families analyzed: 90CYE_shifted_DKS and 90CYE_v2_1 against DKS structural references.
- DKS semantics are **not** transferred; only address/callgraph/XDATA patterns are compared.
- Evidence levels: exact_fingerprint, near_fingerprint, callgraph_match, xdata_pattern_match, string_marker_match, manual_static, hypothesis, unknown.

## Key answers
- Conserved/offset cluster rows: {conserved}
- Divergent/unknown rows: {divergent}
- 90CYE02 @0x3104: retained as shifted object-status pattern candidate, not confirmed semantic parity.
- v2_1 branch appears as analog-capable structural family in selected anchors, with divergence in part of the XDATA schema.

## Which clusters are conserved / offset / divergent?
See `shifted_v2_xdata_offset_matrix.csv` and `shifted_v2_schema_divergence.csv`.

## Function anchor mapping
See `shifted_v2_function_anchor_map.csv` for function-level structural analog candidates.
"""
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    print(f"Wrote {args.out_matrix.relative_to(ROOT)} ({len(map_rows)} rows)")
    print(f"Wrote {args.out_anchors.relative_to(ROOT)} ({len(anchor_rows)} rows)")
    print(f"Wrote {args.out_div.relative_to(ROOT)} ({len(div_rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
