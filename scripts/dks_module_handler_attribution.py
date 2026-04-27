#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

TARGET_FUNCS = ["0x497A", "0x737C", "0x613C", "0x84A6", "0x728A", "0x6833", "0x5A7F", "0x673C", "0x758B", "0x53E6", "0xAB62"]


def load_csv(name: str) -> list[dict[str, str]]:
    p = DOCS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def split_tokens(v: str) -> list[str]:
    return [x.strip() for x in (v or "").replace(";", "|").replace(",", "|").split("|") if x.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description="Refine DKS module slot to handler attribution")
    ap.add_argument("--out-md", type=Path, default=DOCS / "dks_module_handler_attribution.md")
    ap.add_argument("--out-matrix", type=Path, default=DOCS / "dks_module_handler_attribution_matrix.csv")
    ap.add_argument("--out-unresolved", type=Path, default=DOCS / "dks_module_unresolved_handlers.csv")
    args = ap.parse_args()

    real = load_csv("dks_real_configuration_evidence.csv")
    deep = load_csv("dks_module_deep_trace_candidates.csv")
    slot_summary = load_csv("dks_module_slot_summary.csv")
    man_mod = load_csv("manual_dks_module_decompile_summary.csv")
    man_down = load_csv("manual_dks_downstream_decompile_summary.csv")

    manual_roles = {r.get("function_addr", ""): r for r in (man_mod + man_down)}

    by_slot: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for r in deep:
        key = (r.get("branch", ""), r.get("file", ""), r.get("slot", ""))
        by_slot[key].append(r)

    matrix: list[dict[str, str]] = []
    unresolved: list[dict[str, str]] = []

    for row in real:
        branch = row.get("branch", "")
        file = row.get("firmware_file", "")
        slot = row.get("slot", "")
        mod = row.get("module_label", "")
        key = (branch, file, slot)
        candidates = by_slot.get(key, [])
        if not candidates:
            # fallback by branch+slot
            for k, vv in by_slot.items():
                if k[0] == branch and k[2] == slot:
                    candidates.extend(vv)

        selected = [c for c in candidates if c.get("function_addr") in TARGET_FUNCS]
        if not selected and candidates:
            selected = sorted(candidates, key=lambda x: x.get("score", "0"), reverse=True)[:2]

        if not selected:
            unresolved.append(
                {
                    "branch": branch,
                    "file": file,
                    "screen_slot": slot,
                    "module_label": mod,
                    "reason_unresolved": "no direct deep-trace candidates for this slot in current dataset",
                    "candidate_functions": "-",
                    "next_static_step": "expand call-neighborhood from slot-linked setup code",
                    "next_bench_step": "slot-isolated activity capture on event/state transitions",
                    "notes": row.get("notes", "-") or "-",
                }
            )
            continue

        for cand in selected:
            fn = cand.get("function_addr", "")
            role = cand.get("candidate_role", "unknown")
            lvl = "chain_adjacency"
            conf = "hypothesis"
            reason = []
            if fn in {"0x497A", "0x613C", "0x737C", "0x84A6", "0x728A", "0x6833", "0x5A7F"}:
                role = "shared_dispatch_or_bridge"
                reason.append("shared chain function appears across multiple module contexts")
                conf, lvl = "probable", "manual_decompile"
            if fn in {"0x673C", "0x758B", "0x53E6", "0xAB62"}:
                conf, lvl = "probable", "probable_static"
                reason.append("function repeatedly appears in module-focused traces")
            if fn in manual_roles:
                role = manual_roles[fn].get("manual_role", manual_roles[fn].get("new_manual_role", role))
                conf = "probable" if conf == "hypothesis" else conf
                lvl = "manual_decompile"
                reason.append("manual decompile role available")

            matrix.append(
                {
                    "branch": branch,
                    "file": file,
                    "screen_slot": slot,
                    "module_label": mod,
                    "function_addr": fn,
                    "handler_role_candidate": role,
                    "attribution_confidence": conf,
                    "evidence_sources": cand.get("evidence_sources", "screen_configuration|chain_adjacency"),
                    "evidence_level": lvl,
                    "reason": "; ".join(reason) if reason else "trace-level candidate",
                    "unknowns": "exclusive ownership not proven" if fn in {"0x497A", "0x613C"} else "physical semantic unknown",
                    "next_validation": "bench isolate slot activity and correlate XDATA+call path",
                }
            )

    # unresolved from slot summary statuses
    for r in slot_summary:
        if r.get("function_resolution_status", "") in {"unresolved", "partial"}:
            unresolved.append(
                {
                    "branch": r.get("branch", ""),
                    "file": r.get("file", ""),
                    "screen_slot": r.get("slot", ""),
                    "module_label": r.get("module_label", ""),
                    "reason_unresolved": r.get("notes", "partial mapping"),
                    "candidate_functions": r.get("strongest_function_candidates", "-"),
                    "next_static_step": "manual decompile highest-score candidate and nearest callers",
                    "next_bench_step": "toggle slot module and watch chain entrypoints",
                    "notes": "taken from dks_module_slot_summary",
                }
            )

    # de-dup
    ded = {}
    for m in matrix:
        ded[(m["branch"], m["file"], m["screen_slot"], m["module_label"], m["function_addr"])] = m
    matrix = sorted(ded.values(), key=lambda x: (x["branch"], x["screen_slot"], x["function_addr"]))

    dedu = {}
    for u in unresolved:
        dedu[(u["branch"], u["file"], u["screen_slot"], u["module_label"])]=u
    unresolved = sorted(dedu.values(), key=lambda x: (x["branch"], x["screen_slot"]))

    for out, fields, rows in [
        (args.out_matrix, ["branch", "file", "screen_slot", "module_label", "function_addr", "handler_role_candidate", "attribution_confidence", "evidence_sources", "evidence_level", "reason", "unknowns", "next_validation"], matrix),
        (args.out_unresolved, ["branch", "file", "screen_slot", "module_label", "reason_unresolved", "candidate_functions", "next_static_step", "next_bench_step", "notes"], unresolved),
    ]:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    md = f"""# DKS module handler attribution (v1)\n\nGenerated: {stamp}\n\n## Main interpretation\n- `0x497A` is treated as **shared dispatcher/runtime bridge**, not an exclusive MDS/MUP/PVK handler.\n- `0x613C` is treated as **state updater/latch bridge**, not a module-private entrypoint.\n- Stronger module-specific candidates remain around `0x673C`, `0x758B`, `0x53E6`, `0xAB62` depending on branch/slot context.\n\n## Why not exclusive assignment for `0x497A`\n`0x497A` appears in shared chain adjacency, multiple slot contexts, and high fan-out call graph patterns; current evidence supports common dispatch behavior.\n\n## Why `0x613C` is updater/bridge\nManual downstream and module decompile artifacts place `0x613C` in state-latch progression between shared runtime and downstream gating, with no slot-exclusive signature.\n\n## Remaining unresolved areas\nSee `docs/dks_module_unresolved_handlers.csv` for slot-level unknowns and next static/bench actions.\n"""
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    print(f"Wrote {args.out_matrix.relative_to(ROOT)} ({len(matrix)} rows)")
    print(f"Wrote {args.out_unresolved.relative_to(ROOT)} ({len(unresolved)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
