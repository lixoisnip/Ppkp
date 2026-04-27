#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

REF_BRANCH = "90CYE_DKS"
REF_FILE = "90CYE03_19_DKS.PZU"
TARGET_FILES = {
    "90CYE02_27 DKS.PZU",
    "90CYE03_19_2 v2_1.PZU",
    "90CYE04_19_2 v2_1.PZU",
    "A03_26.PZU",
    "A04_28.PZU",
    "ppkp2001 90cye01.PZU",
    "ppkp2012 a01.PZU",
    "ppkp2019 a02.PZU",
}
REF_FUNCS = [
    ("0x497A", "shared runtime/state dispatcher"),
    ("0x737C", "zone/object logic"),
    ("0x613C", "state latch/updater"),
    ("0x84A6", "mode/event bridge"),
    ("0x728A", "mode gate"),
    ("0x6833", "output-start entry"),
    ("0x5A7F", "packet/export bridge"),
    ("0x7922", "table/state reader helper"),
    ("0x597F", "condition-check helper"),
    ("0x7DC2", "downstream output/service transition"),
]


@dataclass
class FFeat:
    size: int
    call_count: int
    xr: int
    xw: int


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


def confidence(score: float) -> str:
    if score >= 0.88:
        return "confirmed"
    if score >= 0.68:
        return "probable"
    if score >= 0.50:
        return "hypothesis"
    return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description="Map DKS reference functions to cross-family analogs")
    ap.add_argument("--out-md", type=Path, default=DOCS / "cross_family_function_analogs.md")
    ap.add_argument("--out-csv", type=Path, default=DOCS / "cross_family_function_analogs.csv")
    ap.add_argument("--out-unmatched", type=Path, default=DOCS / "cross_family_unmatched_dks_functions.csv")
    args = ap.parse_args()

    fmap = load_csv("function_map.csv")
    calls = load_csv("call_xref.csv")
    xacc = load_csv("xdata_confirmed_access.csv")
    enum_rows = load_csv("enum_branch_value_map.csv")

    fstats: dict[tuple[str, str], FFeat] = {}
    by_file_funcs: defaultdict[str, list[str]] = defaultdict(list)
    for r in fmap:
        key = (r.get("file", ""), r.get("function_addr", ""))
        fstats[key] = FFeat(
            size=int(r.get("size_estimate", "0") or 0),
            call_count=int(r.get("call_count", "0") or 0),
            xr=int(r.get("xdata_read_count", "0") or 0),
            xw=int(r.get("xdata_write_count", "0") or 0),
        )
        if r.get("file"):
            by_file_funcs[r["file"]].append(r.get("function_addr", ""))

    callee_set: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    caller_set: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    for r in calls:
        f = r.get("file", "")
        code = r.get("code_addr", "")
        tgt = r.get("target_addr", "")
        if not f or not code or not tgt:
            continue
        caller_set[(f, tgt)].add(code)
        fn = by_file_funcs.get(f, [])
        if fn:
            for cand in fn:
                ai = h2i(cand)
                ci = h2i(code)
                if ai >= 0 and ci >= ai and ci < ai + 0x400:
                    callee_set[(f, cand)].add(tgt)

    xset: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    for r in xacc:
        f = r.get("file", "")
        dptr = r.get("dptr_addr", "")
        code = r.get("code_addr", "")
        if not f or not code or not dptr:
            continue
        fn = by_file_funcs.get(f, [])
        for cand in fn:
            ai = h2i(cand)
            ci = h2i(code)
            if ai >= 0 and ci >= ai and ci < ai + 0x400:
                xset[(f, cand)].add(dptr)

    enum_set: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    for r in enum_rows:
        enum_set[(r.get("file", ""), r.get("function_addr", ""))].add(r.get("candidate_value", ""))

    rows: list[dict[str, str]] = []
    unmatched: list[dict[str, str]] = []

    for rf, role in REF_FUNCS:
        rkey = (REF_FILE, rf)
        rfeat = fstats.get(rkey, FFeat(0, 0, 0, 0))
        rcalls = callee_set.get(rkey, set())
        rcallers = caller_set.get(rkey, set())
        rx = xset.get(rkey, set())
        re = enum_set.get(rkey, set())

        matched_any = False
        for tf in sorted(TARGET_FILES):
            best = None
            for cand in by_file_funcs.get(tf, []):
                cfeat = fstats.get((tf, cand), FFeat(0, 0, 0, 0))
                if cfeat.size == 0:
                    continue
                shift = abs(h2i(cand) - h2i(rf))
                shift_score = 1.0 if shift == 0 else (0.95 if shift <= 5 else (0.75 if shift <= 0x30 else 0.3))
                size_score = 1.0 - min(1.0, abs(cfeat.size - rfeat.size) / max(1, rfeat.size or 1))
                callcnt_score = 1.0 - min(1.0, abs(cfeat.call_count - rfeat.call_count) / max(1, rfeat.call_count or 1))
                xcnt_score = 1.0 - min(1.0, abs((cfeat.xr + cfeat.xw) - (rfeat.xr + rfeat.xw)) / max(1, (rfeat.xr + rfeat.xw) or 1))
                xc = xset.get((tf, cand), set())
                x_ov = len(rx & xc) / max(1, len(rx | xc))
                cc = callee_set.get((tf, cand), set())
                c_ov = len(rcalls & cc) / max(1, len(rcalls | cc))
                cr = caller_set.get((tf, cand), set())
                caller_ov = min(1.0, len(cr) / max(1, len(rcallers))) if rcallers else 0.0
                ee = enum_set.get((tf, cand), set())
                e_ov = len(re & ee) / max(1, len(re | ee)) if re or ee else 0.0

                score = (
                    0.24 * shift_score
                    + 0.16 * size_score
                    + 0.13 * callcnt_score
                    + 0.11 * xcnt_score
                    + 0.18 * x_ov
                    + 0.13 * c_ov
                    + 0.03 * caller_ov
                    + 0.02 * e_ov
                )
                item = (score, cand, x_ov, c_ov, e_ov, shift)
                if best is None or item[0] > best[0]:
                    best = item

            if best is None:
                continue
            score, cand, xov, cov, eov, shift = best
            if score < 0.45:
                continue
            matched_any = True
            if shift == 0 and score >= 0.9:
                mt = "exact_fingerprint"
            elif shift <= 5 and score >= 0.75:
                mt = "near_fingerprint"
            elif cov >= 0.45:
                mt = "callgraph_match"
            elif xov >= 0.35:
                mt = "xdata_pattern_match"
            elif eov > 0:
                mt = "chain_adjacency"
            else:
                mt = "hypothesis"
            rows.append(
                {
                    "reference_branch": REF_BRANCH,
                    "reference_file": REF_FILE,
                    "reference_function": rf,
                    "reference_role": role,
                    "target_branch": next((r.get("branch", "") for r in fmap if r.get("file") == tf), "unknown"),
                    "target_file": tf,
                    "candidate_function": cand,
                    "match_type": mt,
                    "match_score": f"{score:.3f}",
                    "confidence": confidence(score),
                    "evidence_summary": f"shift={shift}, size/calls/xdata profile + callgraph/xdata overlap",
                    "xdata_overlap": "|".join(sorted(rx & xset.get((tf, cand), set())))[:300],
                    "callgraph_overlap": "|".join(sorted(callee_set.get((REF_FILE, rf), set()) & callee_set.get((tf, cand), set())))[:300],
                    "string_or_table_overlap": "-",
                    "notes": "DKS reference used as structural template only; no semantic transfer",
                }
            )
        if not matched_any:
            unmatched.append(
                {
                    "reference_branch": REF_BRANCH,
                    "reference_file": REF_FILE,
                    "reference_function": rf,
                    "reference_role": role,
                    "status": "no_candidate_over_threshold",
                    "notes": "no candidate score >= 0.45 across non-DKS families",
                }
            )

    rows.sort(key=lambda r: (r["reference_function"], r["target_file"]))
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "reference_branch",
                "reference_file",
                "reference_function",
                "reference_role",
                "target_branch",
                "target_file",
                "candidate_function",
                "match_type",
                "match_score",
                "confidence",
                "evidence_summary",
                "xdata_overlap",
                "callgraph_overlap",
                "string_or_table_overlap",
                "notes",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    with args.out_unmatched.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["reference_branch", "reference_file", "reference_function", "reference_role", "status", "notes"])
        w.writeheader()
        w.writerows(unmatched)

    by_branch = defaultdict(int)
    for r in rows:
        by_branch[r["target_branch"]] += 1
    md = [
        "# Cross-family function analogs",
        "",
        "Evidence levels used: exact_fingerprint, near_fingerprint, callgraph_match, xdata_pattern_match, chain_adjacency, hypothesis.",
        "",
        "## Coverage summary",
        "",
        f"- DKS reference functions: {len(REF_FUNCS)}",
        f"- Analog rows: {len(rows)}",
        f"- Unmatched references: {len(unmatched)}",
        "",
        "## Rows by target branch",
    ]
    for b, c in sorted(by_branch.items()):
        md.append(f"- {b}: {c}")
    md.extend([
        "",
        "## Notes",
        "- DKS chain is a reference pattern, not proof for non-DKS semantics.",
        "- Output must be combined with xdata and module reports before interpretation.",
    ])
    args.out_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"Wrote {args.out_csv.relative_to(ROOT)} ({len(rows)} rows)")
    print(f"Wrote {args.out_unmatched.relative_to(ROOT)} ({len(unmatched)} rows)")
    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
