#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
TARGET_BRANCHES = {"A03_A04", "90CYE_v2_1", "90CYE_shifted_DKS", "RTOS_service"}


def load_csv(name: str) -> list[dict[str, str]]:
    p = DOCS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare packet/export and output-action structures across families")
    ap.add_argument("--out-md", type=Path, default=DOCS / "cross_family_packet_output_comparison.md")
    ap.add_argument("--out-bridge", type=Path, default=DOCS / "cross_family_packet_bridge_candidates.csv")
    ap.add_argument("--out-action", type=Path, default=DOCS / "cross_family_output_action_candidates.csv")
    ap.add_argument("--out-format", type=Path, default=DOCS / "cross_family_packet_format_variants.csv")
    args = ap.parse_args()

    analogs = load_csv("cross_family_function_analogs.csv")
    calls = load_csv("call_xref.csv")
    xacc = load_csv("xdata_confirmed_access.csv")

    fan_in: defaultdict[tuple[str, str], int] = defaultdict(int)
    for r in calls:
        fan_in[(r.get("file", ""), r.get("target_addr", ""))] += 1

    movx_write04: defaultdict[tuple[str, str], int] = defaultdict(int)
    for r in xacc:
        if r.get("access_type") in {"write", "offset_write"}:
            movx_write04[(r.get("file", ""), r.get("code_addr", ""))] += 1

    bridge_rows: list[dict[str, str]] = []
    action_rows: list[dict[str, str]] = []

    for r in analogs:
        b = r.get("target_branch", "")
        if b not in TARGET_BRANCHES:
            continue
        analog_to = r.get("reference_function", "")
        f = r.get("target_file", "")
        fn = r.get("candidate_function", "")
        if analog_to == "0x5A7F":
            bridge_rows.append(
                {
                    "branch": b,
                    "file": f,
                    "function_addr": fn,
                    "analog_to": analog_to,
                    "role_candidate": "packet/export bridge analog",
                    "fan_in": str(fan_in.get((f, fn), 0)),
                    "post_call_movx_pattern": "unknown_static",
                    "xdata_context": r.get("xdata_overlap", ""),
                    "confidence": r.get("confidence", "unknown"),
                    "evidence": r.get("match_type", "hypothesis"),
                    "notes": "No physical packet semantics inferred",
                }
            )
        if analog_to in {"0x6833", "0x7922", "0x597F", "0x7DC2"}:
            action_rows.append(
                {
                    "branch": b,
                    "file": f,
                    "function_addr": fn,
                    "analog_to": analog_to,
                    "write_value": "0x04_candidate" if movx_write04.get((f, fn), 0) > 0 else "unknown",
                    "xdata_target_pattern": r.get("xdata_overlap", ""),
                    "precondition_helper": "candidate" if analog_to in {"0x597F", "0x7922"} else "-",
                    "downstream_helper": "candidate" if analog_to == "0x7DC2" else "-",
                    "packet_followup": "yes" if fan_in.get((f, fn), 0) > 0 else "unknown",
                    "possible_action_role": "output/action structural analog",
                    "confidence": r.get("confidence", "unknown"),
                    "evidence": r.get("match_type", "hypothesis"),
                    "notes": "0x04 write meaning remains unknown without bench evidence",
                }
            )

    variants: list[dict[str, str]] = []
    by_branch = defaultdict(lambda: {"bridge": 0, "action": 0})
    for r in bridge_rows:
        by_branch[r["branch"]]["bridge"] += 1
    for r in action_rows:
        by_branch[r["branch"]]["action"] += 1
    for b, d in sorted(by_branch.items()):
        variants.append(
            {
                "branch": b,
                "bridge_candidates": str(d["bridge"]),
                "output_action_candidates": str(d["action"]),
                "model_variant": "shared_like" if d["bridge"] and d["action"] else ("packet_only_or_unknown" if d["bridge"] else "different_or_missing"),
                "confidence": "probable" if d["bridge"] and d["action"] else "hypothesis",
                "notes": "Structural summary only; packet format remains unresolved",
            }
        )

    for path, fields, rows in [
        (args.out_bridge, ["branch", "file", "function_addr", "analog_to", "role_candidate", "fan_in", "post_call_movx_pattern", "xdata_context", "confidence", "evidence", "notes"], bridge_rows),
        (args.out_action, ["branch", "file", "function_addr", "analog_to", "write_value", "xdata_target_pattern", "precondition_helper", "downstream_helper", "packet_followup", "possible_action_role", "confidence", "evidence", "notes"], action_rows),
        (args.out_format, ["branch", "bridge_candidates", "output_action_candidates", "model_variant", "confidence", "notes"], variants),
    ]:
        with path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

    md = [
        "# Cross-family packet/output comparison",
        "",
        "Questions addressed:",
        "- Is 0x5A7F-like bridge shared?",
        "- Is output-start pattern shared?",
        "- Is write value 0x04 visible in structural analogs?",
        "",
        "## Summary",
        f"- packet bridge candidates: {len(bridge_rows)}",
        f"- output/action candidates: {len(action_rows)}",
        f"- format/model variant rows: {len(variants)}",
        "",
        "Interpretation is intentionally conservative and family-specific.",
    ]
    args.out_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"Wrote {args.out_bridge.relative_to(ROOT)} ({len(bridge_rows)} rows)")
    print(f"Wrote {args.out_action.relative_to(ROOT)} ({len(action_rows)} rows)")
    print(f"Wrote {args.out_format.relative_to(ROOT)} ({len(variants)} rows)")
    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
