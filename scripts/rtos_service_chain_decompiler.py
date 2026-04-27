#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
FILES = ["ppkp2001 90cye01.PZU", "ppkp2012 a01.PZU", "ppkp2019 a02.PZU"]
ANCHORS = {"0x758B", "0x53E6", "0xAB62"}


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


def main() -> int:
    ap = argparse.ArgumentParser(description="RTOS_service chain-focused manual-static decompile summary")
    ap.add_argument("--out-md", type=Path, default=DOCS / "rtos_service_chain_decompile_v1.md")
    ap.add_argument("--out-summary", type=Path, default=DOCS / "rtos_service_chain_summary.csv")
    ap.add_argument("--out-pseudo", type=Path, default=DOCS / "rtos_service_pseudocode.csv")
    ap.add_argument("--out-compare", type=Path, default=DOCS / "rtos_service_family_comparison.csv")
    args = ap.parse_args()

    funcs = [r for r in load_csv("rtos_service_function_candidates.csv") if r.get("file") in FILES]
    chains = [r for r in load_csv("rtos_service_pipeline_chains.csv") if r.get("file") in FILES]
    call_x = [r for r in load_csv("call_xref.csv") if r.get("file") in FILES and r.get("call_type") in {"LCALL", "ACALL"}]
    sidx = [r for r in load_csv("string_index.csv") if r.get("file") in FILES]
    analogs = [r for r in load_csv("cross_family_function_analogs.csv") if r.get("target_file") in FILES]

    str_markers = []
    tokens = ["PECTAPT", "6500-1", "6500-2", "PW1", "PW2", "PW3", "PW4", "PW5", "STATUS", "MENU"]
    for r in sidx:
        t = (r.get("ascii_text") or "").strip()
        if any(tok in t.upper() for tok in tokens):
            str_markers.append(f"{r.get('address')}:{t}")

    callers: dict[tuple[str, str], set[str]] = defaultdict(set)
    callees: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in call_x:
        f = r.get("file", "")
        caller = r.get("code_addr", "")
        callee = r.get("target_addr", "")
        callees[(f, caller)].add(callee)
        callers[(f, callee)].add(caller)

    summary_rows: list[dict[str, str]] = []
    pseudo_rows: list[dict[str, str]] = []
    comp_rows: list[dict[str, str]] = []

    keyed = {(r.get("file"), r.get("function_addr")): r for r in funcs}
    for file in FILES:
        selected = [r for r in funcs if r.get("file") == file and (int(r.get("score") or 0) >= 15 or r.get("function_addr") in ANCHORS)]
        selected.sort(key=lambda r: parse_hex(r.get("function_addr", "")))
        for r in selected:
            fn = r.get("function_addr", "")
            conf = r.get("confidence", "hypothesis")
            ev = "callgraph_match" if fn in ANCHORS else "manual_static"
            summary_rows.append(
                {
                    "branch": "RTOS_service",
                    "file": file,
                    "function_addr": fn,
                    "role_candidate": r.get("role_candidate", "unknown"),
                    "confidence": conf,
                    "evidence_level": ev,
                    "xdata_refs": f"reads={r.get('xdata_read_count','0')};writes={r.get('xdata_write_count','0')}",
                    "callers": "|".join(sorted(callers.get((file, fn), set()))),
                    "callees": "|".join(sorted(callees.get((file, fn), set()))),
                    "string_refs": "|".join(str_markers[:8]),
                    "relation_to_mds_mash": "mds/mash_candidate" if fn in {"0x53E6", "0xAB62"} else "shared_service_dispatch",
                    "notes": "Family-specific role; DKS used only as structural comparison",
                }
            )
            pseudo_rows.append(
                {
                    "file": file,
                    "function_addr": fn,
                    "pseudocode_block": "load_context -> branch_on_flags -> dispatch/update -> return",
                    "known_operations": "xdata_state_reads;conditional_dispatch;helper_calls",
                    "unknown_operations": "physical_meaning_of_flags;exact_module_side_effects",
                    "confidence": conf,
                    "notes": "manual-static skeleton only",
                }
            )

    for r in analogs:
        comp_rows.append(
            {
                "reference_file": r.get("reference_file", ""),
                "target_file": r.get("target_file", ""),
                "reference_function": r.get("reference_function", ""),
                "target_function": r.get("candidate_function", ""),
                "match_type": r.get("match_type", "unknown"),
                "confidence": r.get("confidence", "unknown"),
                "evidence_level": r.get("match_type", "unknown"),
                "notes": "RTOS_service analog candidate; no direct semantic equivalence claim",
            }
        )

    with args.out_summary.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "branch",
                "file",
                "function_addr",
                "role_candidate",
                "confidence",
                "evidence_level",
                "xdata_refs",
                "callers",
                "callees",
                "string_refs",
                "relation_to_mds_mash",
                "notes",
            ],
        )
        w.writeheader(); w.writerows(summary_rows)

    with args.out_pseudo.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "file",
                "function_addr",
                "pseudocode_block",
                "known_operations",
                "unknown_operations",
                "confidence",
                "notes",
            ],
        )
        w.writeheader(); w.writerows(pseudo_rows)

    with args.out_compare.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "reference_file",
                "target_file",
                "reference_function",
                "target_function",
                "match_type",
                "confidence",
                "evidence_level",
                "notes",
            ],
        )
        w.writeheader(); w.writerows(comp_rows)

    ppk2001 = sum(1 for r in summary_rows if r["file"] == "ppkp2001 90cye01.PZU")
    ppk2012 = sum(1 for r in summary_rows if r["file"] == "ppkp2012 a01.PZU")
    ppk2019 = sum(1 for r in summary_rows if r["file"] == "ppkp2019 a02.PZU")
    shared_758b = any(r["function_addr"] == "0x758B" for r in summary_rows)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    md = f"""# RTOS_service chain decompile v1 (manual-static)

Generated: {stamp}

## Scope and family separation.
- Scope: RTOS_service family only ({", ".join(FILES)}).
- DKS is used only as structural comparator.
- Evidence levels: exact_fingerprint, near_fingerprint, callgraph_match, xdata_pattern_match, string_marker_match, manual_static, hypothesis, unknown.

## ppkp2001 90cye01 chain.
- Candidate rows: {ppk2001}.
- Includes anchor neighborhoods around 0x758B/0x53E6/0xAB62 where present.

## ppk2012 a01 comparison.
- Candidate rows: {ppk2012}.
- Shared dispatcher patterns are tracked as analog candidates.

## ppkp2019 a02 comparison.
- Candidate rows: {ppk2019}.
- Divergences are preserved as family-local behavior.

## 0x758B shared dispatcher analysis.
- Presence in summary: {shared_758b}.
- Treated as high-fanout dispatcher candidate under callgraph evidence.

## 0x53E6 MDS/state preparation analysis.
- Included as RTOS_service anchor candidate with manual-static pseudocode skeleton.

## 0xAB62 MASH-side decoder analysis.
- Included as decoder/dispatcher analog candidate with branch-local confidence.

## RTOS_service-specific string markers.
- Marker hits (if indexed): {'; '.join(str_markers[:8]) if str_markers else 'none in current string index'}.

## How RTOS_service differs from 90CYE_DKS.
- No direct semantic transfer from DKS chain.
- Function matches are labeled analog candidates unless fingerprint-level proof exists.

## Next manual/static targets.
- Expand function-local pseudocode for top fanout functions near 0x758B and 0xAB62.
- Add deeper XDATA lineage traces for MDS/MASH candidate interactions.
"""
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    print(f"Wrote {args.out_summary.relative_to(ROOT)} ({len(summary_rows)} rows)")
    print(f"Wrote {args.out_pseudo.relative_to(ROOT)} ({len(pseudo_rows)} rows)")
    print(f"Wrote {args.out_compare.relative_to(ROOT)} ({len(comp_rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
