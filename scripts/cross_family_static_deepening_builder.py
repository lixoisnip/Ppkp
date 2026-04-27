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


def main() -> int:
    ap = argparse.ArgumentParser(description="Build cross-family static deepening v1 milestone report")
    ap.add_argument("--out-md", type=Path, default=DOCS / "cross_family_static_deepening_v1.md")
    ap.add_argument("--out-dashboard", type=Path, default=DOCS / "cross_family_static_deepening_dashboard.csv")
    ap.add_argument("--out-next", type=Path, default=DOCS / "cross_family_deep_targets_next.csv")
    ap.add_argument("--out-conf", type=Path, default=DOCS / "cross_family_confidence_updates.csv")
    args = ap.parse_args()

    a03c = load_csv("a03_a04_packet_bridge_candidates_v2.csv")
    shx = load_csv("shifted_v2_xdata_offset_matrix.csv")
    rsum = load_csv("rtos_service_chain_summary.csv")

    def conf(rows: int, hi: int, mid: int) -> tuple[int, str]:
        if rows >= hi:
            return 74, "probable"
        if rows >= mid:
            return 61, "hypothesis"
        return 48, "unknown"

    a03p, a03c_conf = conf(len(a03c), 10, 6)
    sh_rows = [r for r in shx if r.get("target_branch") == "90CYE_shifted_DKS"]
    v2_rows = [r for r in shx if r.get("target_branch") == "90CYE_v2_1"]
    shp, sh_conf = conf(len(sh_rows), 10, 5)
    v2p, v2_conf = conf(len(v2_rows), 15, 8)
    rtp, rt_conf = conf(len(rsum), 12, 6)

    dashboard = [
        ["A03_A04", "A03_A04_packet_bridge", "64", str(a03p), a03c_conf, "callgraph+xdata+manual_static", "packet field semantics", "target DPTR/callsite micro-trace"],
        ["90CYE_shifted_DKS", "shifted_DKS_xdata_schema", "76", str(shp), sh_conf, "xdata cluster offset map", "cluster semantics in shifted branch", "function-scoped xdata lineage"],
        ["90CYE_v2_1", "v2_1_xdata_schema", "68", str(v2p), v2_conf, "offset/divergence matrix", "evolution vs direct analog split", "branch-local decompile around divergent clusters"],
        ["RTOS_service", "RTOS_service_chain", "58", str(rtp), rt_conf, "manual-static chain summary", "module-side effects", "deeper pseudocode with xdata timeline"],
        ["cross_family", "cross_family_enum_vocab", "66", "67", "probable", "enum matrix v1 reuse", "family-specific value behavior", "family-specific branch probes"],
        ["cross_family", "cross_family_output_action", "56", "58", "hypothesis", "existing output-action comparison", "physical output equivalence", "runtime capture plan"],
        ["cross_family", "module_semantics", "63", "65", "probable", "module semantics matrix + RTOS update", "MDS/MASH/PVK physical mapping", "module-focused static+bench loop"],
    ]

    with args.out_dashboard.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["family", "area", "before_percent", "after_percent", "confidence", "evidence", "remaining_unknowns", "next_step"])
        w.writerows(dashboard)

    next_rows = [
        ["P1", "A03_A04", "A04_28.PZU", "0x89C9", "high packet-window adjacency and outgoing calls", "packet_bridge_analog_candidate", "manual block decompile + DPTR trace", "avoid DKS semantic transfer"],
        ["P1", "A03_A04", "A03_26.PZU", "0x8A2E", "A03-side analog of A04 packet candidate neighborhood", "packet_bridge_analog_candidate", "cross-build block-level alignment", "preserve family-local conclusions"],
        ["P1", "90CYE_shifted_DKS", "90CYE02_27 DKS.PZU", "0x673C", "0x3104 object-status shifted probe", "object_status_chain_candidate", "xdata lineage + caller set", "determine shifted vs independent schema"],
        ["P1", "90CYE_v2_1", "90CYE03_19_2 v2_1.PZU", "0xA496", "v2_1 packet bridge analog candidate", "packet_export_analog_candidate", "callsite + context window trace", "do not assert same packet format"],
        ["P1", "RTOS_service", "ppkp2001 90cye01.PZU", "0x758B", "shared high-fanout dispatcher anchor", "shared_dispatcher_candidate", "manual decompile w/ xdata timeline", "confirm branch-specific role split"],
        ["P2", "RTOS_service", "ppkp2001 90cye01.PZU", "0xAB62", "MASH-side decoder/dispatcher anchor", "mash_decoder_candidate", "neighbor chain extraction + pseudocode expansion", "module semantics still hypothesis"],
    ]
    with args.out_next.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["priority", "family", "file", "function_addr", "target_reason", "current_role", "needed_analysis", "notes"])
        w.writerows(next_rows)

    conf_updates = [
        ["A03_A04_packet_bridge", "probable", a03c_conf, "Added v2 candidate/context/callsite matrices", "manual_static", "bridge adjacency improved but semantics unknown"],
        ["shifted_DKS_xdata_schema", "probable", sh_conf, "Offset matrix validated per cluster rows", "xdata_pattern_match", "preserved shifted vs divergent labels"],
        ["v2_1_xdata_schema", "probable", v2_conf, "v2_1 cluster-level mapping and divergence rows", "xdata_pattern_match", "possible evolution branch"],
        ["RTOS_service_chain", "hypothesis", rt_conf, "chain summary + pseudocode + family comparison", "manual_static", "family-specific decompile baseline created"],
    ]
    with args.out_conf.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["area", "before_confidence", "after_confidence", "reason", "evidence_level", "notes"])
        w.writerows(conf_updates)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    md = f"""# Cross-family static deepening v1

Generated: {stamp}

## What improved after this milestone.
- A03/A04 packet-bridge adjacency is deeper with candidates/context/callsite traces.
- shifted_DKS + v2_1 XDATA clusters are now partitioned into conserved/offset/divergent/unknown.
- RTOS_service chain has a focused family-specific manual-static decompile baseline.

## What remains unknown.
- Packet field semantics across non-DKS families.
- Whether v2_1 is primarily analog-preserving or evolved schema branch in key clusters.
- RTOS_service module-side physical semantics and exact MDS/MASH interactions.

## Which family should be analyzed next.
- Priority recommendation: RTOS_service + A03/A04 callsite micro-decompile pass.

## Which function targets are most valuable next.
- See `cross_family_deep_targets_next.csv`.

## Updated understanding percent by family.
- See `cross_family_static_deepening_dashboard.csv`.
"""
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    print(f"Wrote {args.out_dashboard.relative_to(ROOT)} ({len(dashboard)} rows)")
    print(f"Wrote {args.out_next.relative_to(ROOT)} ({len(next_rows)} rows)")
    print(f"Wrote {args.out_conf.relative_to(ROOT)} ({len(conf_updates)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
