#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
BRANCH = "90CYE_DKS"
FILE = "90CYE03_19_DKS.PZU"


def load_csv(name: str) -> list[dict[str, str]]:
    p = DOCS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def split_tokens(value: str) -> list[str]:
    return [x.strip() for x in (value or "").replace(";", "|").replace(",", "|").split("|") if x.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description="Reconstruct output/start action semantics for DKS chain")
    ap.add_argument("--out-md", type=Path, default=DOCS / "dks_output_action_reconstruction.md")
    ap.add_argument("--out-matrix", type=Path, default=DOCS / "dks_output_action_matrix.csv")
    ap.add_argument("--out-trace", type=Path, default=DOCS / "dks_output_start_path_trace.csv")
    ap.add_argument("--out-bench", type=Path, default=DOCS / "dks_output_action_bench_tests.csv")
    args = ap.parse_args()

    out_map = [r for r in load_csv("output_transition_map.csv") if r.get("branch") == BRANCH]
    down = [r for r in load_csv("manual_dks_downstream_decompile_summary.csv") if r.get("branch") == BRANCH]
    ma = [r for r in load_csv("manual_auto_branch_map.csv") if r.get("branch") == BRANCH]
    oc = [r for r in load_csv("output_control_candidates.csv") if r.get("branch") == BRANCH]
    zo = [r for r in load_csv("zone_to_output_chains.csv") if r.get("branch") == BRANCH]

    role_notes = {r.get("function_addr", ""): r.get("notes", "") for r in down}

    matrix: list[dict[str, str]] = []
    for r in out_map:
        fn = r.get("function_addr", "")
        if fn not in {"0x6833", "0x7DC2", "0x728A", "0x597F", "0x7922", "0x497A", "0x737C"}:
            continue
        write_value = r.get("write_value_or_bit", "-") or "-"
        xaddr = r.get("xdata_addr", "-") or "-"
        action = r.get("action_candidate", "output_or_event_transition") or "output_or_event_transition"
        if fn == "0x6833" and (write_value in {"0x04", "#0x04"} or "0x04" in write_value):
            action = "output_start_marker_candidate"
        phys = "unknown"
        conf = "hypothesis"
        lvl = "hypothesis"
        if fn in {"0x6833", "0x597F", "0x7922", "0x7DC2"}:
            conf, lvl = "probable", "manual_decompile"
        matrix.append(
            {
                "branch": BRANCH,
                "file": FILE,
                "function_addr": fn,
                "action_candidate": action,
                "xdata_target": xaddr,
                "write_value": write_value,
                "precondition_function": "0x597F" if fn in {"0x6833", "0x7DC2"} else "-",
                "downstream_function": r.get("next_function", "-") or r.get("call_target", "-") or "-",
                "packet_export_path": r.get("packet_export_seen", "possible") or "possible",
                "possible_physical_semantic": phys,
                "confidence": conf,
                "evidence_level": lvl,
                "notes": (r.get("notes", "") + " | " + role_notes.get(fn, "")).strip(" |") or "-",
            }
        )

    # ensure key rows exist even if upstream CSV does not include explicit write line
    ensure_rows = [
        ("0x6833", "output_start_marker_candidate", "dptr_context_target", "0x04", "0x597F", "0x7DC2", "yes", "manual_decompile"),
        ("0x597F", "condition_mask_guard_candidate", "ACC", "A&0x07", "-", "0x6833", "possible", "manual_decompile"),
        ("0x7922", "state_table_reader_service_helper", "0x30EA..0x30F9", "read", "-", "0x6833", "possible", "manual_decompile"),
        ("0x7DC2", "downstream_output_transition_finalizer", "0x36D3..0x36FD", "contextual", "0x6833", "0x5A7F", "yes", "manual_decompile"),
    ]
    seen = {(m["function_addr"], m["action_candidate"]) for m in matrix}
    for fn, ac, xa, wv, pre, downf, pth, lvl in ensure_rows:
        if (fn, ac) in seen:
            continue
        matrix.append(
            {
                "branch": BRANCH,
                "file": FILE,
                "function_addr": fn,
                "action_candidate": ac,
                "xdata_target": xa,
                "write_value": wv,
                "precondition_function": pre,
                "downstream_function": downf,
                "packet_export_path": pth,
                "possible_physical_semantic": "unknown",
                "confidence": "probable",
                "evidence_level": lvl,
                "notes": "Inserted from manual downstream reconstruction and chain adjacency.",
            }
        )

    matrix = sorted(matrix, key=lambda r: (r["function_addr"], r["action_candidate"]))

    trace = [
        {
            "step_order": "1",
            "function_addr": "0x728A",
            "operation": "mode gate branch",
            "xdata_addr": "0x30E7/0x315B",
            "value": "bit checks E0/E1/E2",
            "condition": "manual/auto mode split",
            "next_function": "0x6833 or 0x5A7F",
            "evidence_level": "probable_static",
            "notes": "manual path can skip output-start and go packet/event only",
        },
        {
            "step_order": "2",
            "function_addr": "0x597F",
            "operation": "condition guard",
            "xdata_addr": "ACC-context",
            "value": "A & 0x07 candidate",
            "condition": "mask/mode class check",
            "next_function": "0x6833",
            "evidence_level": "manual_decompile",
            "notes": "guard candidate before output/start transition",
        },
        {
            "step_order": "3",
            "function_addr": "0x7922",
            "operation": "state table read/service helper",
            "xdata_addr": "0x30EA..0x30F9 candidate",
            "value": "table/context value",
            "condition": "state/mode dependent",
            "next_function": "0x6833",
            "evidence_level": "manual_decompile",
            "notes": "supplies state-context used by downstream start path",
        },
        {
            "step_order": "4",
            "function_addr": "0x6833",
            "operation": "write start marker",
            "xdata_addr": "XDATA[DPTR]",
            "value": "0x04",
            "condition": "output-start eligible branch",
            "next_function": "0x7DC2",
            "evidence_level": "manual_decompile",
            "notes": "interpretation remains conservative: state/command/event marker candidate",
        },
        {
            "step_order": "5",
            "function_addr": "0x7DC2",
            "operation": "downstream transition finalize",
            "xdata_addr": "0x36D3..0x36FD context",
            "value": "contextual",
            "condition": "after start marker path",
            "next_function": "0x5A7F",
            "evidence_level": "manual_decompile",
            "notes": "final bridge before packet/export helper",
        },
    ]

    bench = [
        {
            "test_id": "OA-01",
            "scenario": "manual mode event; force path expected to skip output-start",
            "expected_function_path": "0x728A->0x5A7F",
            "watch_xdata": "0x30E7,0x315B,0x36D3..0x36FD",
            "expected_xdata_change": "mode bits change without stable 0x04 write",
            "expected_packet_or_event": "event/packet export present",
            "confidence": "probable",
            "notes": "validates manual path split",
        },
        {
            "test_id": "OA-02",
            "scenario": "auto mode start condition",
            "expected_function_path": "0x728A->0x597F->0x7922->0x6833->0x7DC2->0x5A7F",
            "watch_xdata": "DPTR target,0x30EA..0x30F9,0x36D3..0x36FD",
            "expected_xdata_change": "single 0x04 write before downstream finalize",
            "expected_packet_or_event": "packet/export after finalize",
            "confidence": "probable",
            "notes": "primary test for meaning of XDATA[DPTR]=0x04",
        },
        {
            "test_id": "OA-03",
            "scenario": "vary condition nibble/low bits to probe 0x597F",
            "expected_function_path": "0x597F guard toggles entry into 0x6833",
            "watch_xdata": "ACC sampled + branch side effects",
            "expected_xdata_change": "start path accepted/rejected by mask",
            "expected_packet_or_event": "packet only when guard passes",
            "confidence": "hypothesis",
            "notes": "designed to validate A&0x07 hypothesis",
        },
        {
            "test_id": "OA-04",
            "scenario": "MUP slot X06 active in 90CYE03/04; compare with non-X06",
            "expected_function_path": "shared chain unchanged; payload context varies",
            "watch_xdata": "0x31BF,0x364B,0x36D3..0x36FD",
            "expected_xdata_change": "context byte difference, no proof of physical output type",
            "expected_packet_or_event": "export differences only",
            "confidence": "hypothesis",
            "notes": "keeps MUP/MVK semantics separated until stronger evidence",
        },
    ]

    for path, fields, rows in [
        (args.out_matrix, ["branch", "file", "function_addr", "action_candidate", "xdata_target", "write_value", "precondition_function", "downstream_function", "packet_export_path", "possible_physical_semantic", "confidence", "evidence_level", "notes"], matrix),
        (args.out_trace, ["step_order", "function_addr", "operation", "xdata_addr", "value", "condition", "next_function", "evidence_level", "notes"], trace),
        (args.out_bench, ["test_id", "scenario", "expected_function_path", "watch_xdata", "expected_xdata_change", "expected_packet_or_event", "confidence", "notes"], bench),
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    md = f"""# DKS output/action reconstruction (v1)\n\nGenerated: {stamp}\n\n## Core answers\n- `XDATA[DPTR] = 0x04` is currently best modeled as **output-start marker / command-code candidate**, not physically named output type.\n- `0x597F` most likely guards branch admission (mask-like, `A & 0x07` hypothesis).\n- `0x7922` behaves as state-table/service reader feeding start-path context.\n- `0x7DC2` looks like downstream transition finalizer before packet/export bridge `0x5A7F`.\n\n## Physical semantics status\nStatic evidence is **insufficient** to claim direct mapping to MUP/MVK/GOA/valve/siren classes.\nAll physical output naming remains hypothesis pending bench capture.\n\n## Artifacts\n- `docs/dks_output_action_matrix.csv`\n- `docs/dks_output_start_path_trace.csv`\n- `docs/dks_output_action_bench_tests.csv`\n"""
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    print(f"Wrote {args.out_matrix.relative_to(ROOT)} ({len(matrix)} rows)")
    print(f"Wrote {args.out_trace.relative_to(ROOT)} ({len(trace)} rows)")
    print(f"Wrote {args.out_bench.relative_to(ROOT)} ({len(bench)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
