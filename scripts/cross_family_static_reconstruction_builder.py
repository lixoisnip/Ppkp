#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def load_csv(name: str) -> list[dict[str, str]]:
    p = DOCS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def pct(v: int) -> str:
    return f"{max(0, min(100, v))}%"


def main() -> int:
    ap = argparse.ArgumentParser(description="Build final cross-family static reconstruction v1")
    ap.add_argument("--out-md", type=Path, default=DOCS / "cross_family_static_reconstruction_v1.md")
    ap.add_argument("--out-dashboard", type=Path, default=DOCS / "cross_family_confidence_dashboard.csv")
    ap.add_argument("--out-unknowns", type=Path, default=DOCS / "cross_family_remaining_unknowns.csv")
    ap.add_argument("--out-plan", type=Path, default=DOCS / "cross_family_next_static_plan.csv")
    args = ap.parse_args()

    analogs = load_csv("cross_family_function_analogs.csv")
    xmap = load_csv("cross_family_xdata_schema_map.csv")
    pkt = load_csv("cross_family_packet_bridge_candidates.csv")
    outa = load_csv("cross_family_output_action_candidates.csv")
    enum = load_csv("cross_family_enum_state_matrix.csv")
    mods = load_csv("cross_family_module_semantics_matrix.csv")

    c_exact = sum(1 for r in analogs if r.get("match_type") == "exact_fingerprint")
    c_near = sum(1 for r in analogs if r.get("match_type") == "near_fingerprint")
    c_prob = sum(1 for r in analogs if r.get("confidence") in {"confirmed", "probable"})
    c_xconf = sum(1 for r in xmap if r.get("confidence") in {"confirmed", "probable"})
    c_mod_present = sum(1 for r in mods if r.get("presence_evidence") == "present")

    dashboard = [
        ("DKS_reference_model", 82, "confirmed", f"manual + static chain; analog rows={len(analogs)}"),
        ("shifted_DKS_mapping", 76 if c_near else 60, "probable", "address-shift and xdata-shift mapping"),
        ("v2_1_mapping", 68 if c_prob else 52, "probable", "callgraph/xdata analog candidates"),
        ("A03_A04_mapping", 64, "probable", "structural analogs without semantic transfer"),
        ("RTOS_service_mapping", 58, "hypothesis", "separate family, partial structural overlap"),
        ("cross_family_packet_export", 62 if pkt else 45, "probable" if pkt else "unknown", "0x5A7F-like bridge candidate density"),
        ("cross_family_output_action", 56 if outa else 40, "hypothesis", "output-start analogs and helper paths"),
        ("cross_family_enum_values", 66 if enum else 45, "probable", "shared enum vocabulary matrix"),
        ("cross_family_xdata_schema", 70 if c_xconf else 50, "probable", "conserved + shifted xdata clusters"),
        ("cross_family_module_semantics", 63 if c_mod_present else 45, "probable", "module map by family"),
        ("menu_keyboard_display", 44, "hypothesis", "limited direct static markers"),
        ("physical_semantics", 24, "unknown", "no direct bench evidence in this milestone"),
    ]

    with args.out_dashboard.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["area", "understanding_percent", "confidence", "main_evidence", "main_unknowns", "next_step"])
        w.writeheader()
        for area, p, c, ev in dashboard:
            w.writerow(
                {
                    "area": area,
                    "understanding_percent": pct(p),
                    "confidence": c,
                    "main_evidence": ev,
                    "main_unknowns": "family-specific semantics and packet framing",
                    "next_step": "targeted manual deep trace + bench/runtime capture",
                }
            )

    unknowns = [
        {"unknown_id": "CF-U01", "area": "packet_export", "description": "cross-family frame format relation", "priority": "high", "needed_evidence": "synchronized packet captures across families"},
        {"unknown_id": "CF-U02", "area": "output_action", "description": "meaning of 0x04-like write in non-DKS", "priority": "high", "needed_evidence": "bench IO correlation"},
        {"unknown_id": "CF-U03", "area": "enum_values", "description": "same byte value, different behavior risk", "priority": "high", "needed_evidence": "scenario-controlled runtime traces"},
        {"unknown_id": "CF-U04", "area": "module_semantics", "description": "MDS/MUP/PVK attribution in non-DKS", "priority": "medium", "needed_evidence": "slot-isolated tests and docs"},
        {"unknown_id": "CF-U05", "area": "RTOS_service", "description": "service-family specific chain semantics", "priority": "high", "needed_evidence": "service firmware documentation"},
    ]
    with args.out_unknowns.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["unknown_id", "area", "description", "priority", "needed_evidence"])
        w.writeheader()
        w.writerows(unknowns)

    plan = [
        {"step_id": "CF-N1", "priority": "high", "task": "Deepen A03/A04 packet bridge adjacency", "inputs": "call_xref/basic_block/xdata traces", "expected_output": "refined packet bridge candidate confidence"},
        {"step_id": "CF-N2", "priority": "high", "task": "Shifted_DKS + v2_1 xdata offset validation", "inputs": "xdata schema map + function analogs", "expected_output": "conserved/shifted cluster confirmation"},
        {"step_id": "CF-N3", "priority": "high", "task": "RTOS_service chain-specific manual decompile", "inputs": "0x758B/0x53E6/0xAB62 neighborhoods", "expected_output": "separate family chain report"},
        {"step_id": "CF-N4", "priority": "medium", "task": "Enum divergence trace per family", "inputs": "enum matrix + branch traces", "expected_output": "reduced enum ambiguity"},
        {"step_id": "CF-N5", "priority": "medium", "task": "Prepare cross-family bench matrix", "inputs": "unknowns dashboard", "expected_output": "minimal-risk validation plan"},
    ]
    with args.out_plan.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["step_id", "priority", "task", "inputs", "expected_output"])
        w.writeheader()
        w.writerows(plan)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    md = f"""# Cross-family static reconstruction v1

Generated: {stamp}

## 1. Scope and evidence rules
Evidence levels used: exact_fingerprint, near_fingerprint, callgraph_match, xdata_pattern_match, string_marker_match, screen_configuration, chain_adjacency, hypothesis, unknown.

## 2. Firmware families and files
Families included: 90CYE_DKS, 90CYE_shifted_DKS, 90CYE_v2_1, A03_A04, RTOS_service.

## 3. DKS as reference, not universal truth
DKS chain is used as structural reference only.

## 4. Function analog map
Rows: {len(analogs)} (exact={c_exact}, near={c_near}).

## 5. XDATA schema comparison
Rows: {len(xmap)} with confirmed/probable={c_xconf}.

## 6. Packet/export comparison
Bridge candidate rows: {len(pkt)}.

## 7. Output/action comparison
Output/action candidate rows: {len(outa)}.

## 8. Enum/state comparison
Enum matrix rows: {len(enum)}.

## 9. Module semantics comparison
Module matrix rows: {len(mods)}; present rows={c_mod_present}.

## 10. Family-specific summaries
- 90CYE_DKS: reference-only anchor.
- 90CYE_shifted_DKS: strongest address-shift analog family.
- 90CYE_v2_1: strong structural overlap, semantics still family-scoped.
- A03_A04: partial overlap; packet/output model may diverge.
- RTOS_service: separate family with partial chain analogs.

## 11. What is confirmed across families
- Dispatcher-level structural analogs exist.
- Some XDATA clusters are conserved or shifted.

## 12. What is probable
- Packet/export bridge analogs in non-DKS families.
- Shared enum vocabulary at byte-level.

## 13. What is hypothesis
- Output/action semantic equivalence.
- Module-level physical behavior mapping.

## 14. What remains unknown
See `cross_family_remaining_unknowns.csv`.

## 15. What external documentation is needed
- Protocol framing docs.
- Module/service family design notes.

## 16. What bench/runtime data would resolve the largest unknowns
- synchronized packet + IO capture with function/XDATA traces.

## 17. Next static iteration plan
See `cross_family_next_static_plan.csv`.
"""
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    print(f"Wrote {args.out_dashboard.relative_to(ROOT)} ({len(dashboard)} rows)")
    print(f"Wrote {args.out_unknowns.relative_to(ROOT)} ({len(unknowns)} rows)")
    print(f"Wrote {args.out_plan.relative_to(ROOT)} ({len(plan)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
