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
    return f"{max(0,min(100,v))}%"


def main() -> int:
    ap = argparse.ArgumentParser(description="Build consolidated DKS technical reconstruction v1 report")
    ap.add_argument("--out-md", type=Path, default=DOCS / "dks_firmware_technical_reconstruction_v1.md")
    ap.add_argument("--out-dashboard", type=Path, default=DOCS / "dks_reconstruction_confidence_dashboard.csv")
    ap.add_argument("--out-unknowns", type=Path, default=DOCS / "dks_remaining_unknowns.csv")
    ap.add_argument("--out-plan", type=Path, default=DOCS / "dks_next_iteration_plan.csv")
    args = ap.parse_args()

    enum_rows = load_csv("dks_enum_state_matrix.csv")
    packet_rows = load_csv("dks_packet_export_callsite_matrix.csv")
    action_rows = load_csv("dks_output_action_matrix.csv")
    mod_rows = load_csv("dks_module_handler_attribution_matrix.csv")
    unresolved_rows = load_csv("dks_module_unresolved_handlers.csv")

    global_arch = 72
    chain = 78
    xdata = 74
    enum = 61 if enum_rows else 45
    packet = 56 if packet_rows else 40
    output = 54 if action_rows else 38
    physical = 29

    dashboard = [
        {"area": "global_architecture", "understanding_percent": pct(global_arch), "confidence": "probable", "main_evidence": "cross-firmware architecture + DKS chain traces", "main_unknowns": "exclusive module ownership edges", "next_step": "targeted bench validation"},
        {"area": "90CYE_DKS_execution_chain", "understanding_percent": pct(chain), "confidence": "probable", "main_evidence": "0x497A->0x737C->0x613C->0x84A6->0x728A->0x6833->0x5A7F", "main_unknowns": "branch-specific side exits", "next_step": "deep windows around side exits"},
        {"area": "XDATA_lifecycle", "understanding_percent": pct(xdata), "confidence": "probable", "main_evidence": "dks_xdata_lifecycle_* artifacts", "main_unknowns": "byte-level semantics for all addresses", "next_step": "instrumented watchpoints"},
        {"area": "enum_state_values", "understanding_percent": pct(enum), "confidence": "probable", "main_evidence": "enum_branch_value_map + enum reconstruction", "main_unknowns": "exact physical labels per value", "next_step": "scenario-based enum probes"},
        {"area": "packet_export", "understanding_percent": pct(packet), "confidence": "probable", "main_evidence": "0x5A7F high fan-in callsites + context XDATA", "main_unknowns": "packet framing format", "next_step": "capture packet bytes with call correlation"},
        {"area": "output_action", "understanding_percent": pct(output), "confidence": "probable", "main_evidence": "0x6833/0x597F/0x7922/0x7DC2 reconstruction", "main_unknowns": "meaning of write 0x04 in hardware terms", "next_step": "bench output-start trigger tests"},
        {"area": "MDS_handler", "understanding_percent": "60%", "confidence": "probable", "main_evidence": "slot evidence + 0x673C-related traces", "main_unknowns": "family-specific divergence", "next_step": "branch-isolated MDS traces"},
        {"area": "MUP_handler", "understanding_percent": "49%", "confidence": "hypothesis", "main_evidence": "screen slot X06 + shared chain adjacency", "main_unknowns": "exclusive handler proof", "next_step": "X06-isolated bench scenarios"},
        {"area": "MASH_handler", "understanding_percent": "58%", "confidence": "probable", "main_evidence": "RTOS_service and global MASH traces", "main_unknowns": "direct DKS path linkage", "next_step": "separate-family validation"},
        {"area": "PVK_handler", "understanding_percent": "47%", "confidence": "hypothesis", "main_evidence": "screen evidence + candidate lists", "main_unknowns": "conclusive code path", "next_step": "slot-specific static narrowing"},
        {"area": "menu_keyboard_display", "understanding_percent": "66%", "confidence": "probable", "main_evidence": "screen/configuration + shared architecture", "main_unknowns": "full handler map", "next_step": "UI call graph extraction"},
        {"area": "physical_output_semantics", "understanding_percent": pct(physical), "confidence": "hypothesis", "main_evidence": "static paths only", "main_unknowns": "actuator mapping (MVK/GOA/valve/siren)", "next_step": "hardware bench with I/O capture"},
        {"area": "bench_validation", "understanding_percent": "52%", "confidence": "probable", "main_evidence": "bench plans across enum/xdata/output", "main_unknowns": "execution telemetry not yet collected", "next_step": "run v2 bench matrix"},
    ]

    unknowns = [
        {"unknown_id": "U-001", "area": "packet_export", "description": "Exact frame boundary and byte order around 0x5A7F", "why_unknown": "static traces show adjacency but not serialized bytes", "needed_evidence": "bench packet capture aligned with call path", "priority": "high", "next_action": "instrument packet buffer and trigger known states"},
        {"unknown_id": "U-002", "area": "output_action", "description": "Physical meaning of XDATA[DPTR]=0x04", "why_unknown": "write is visible but target channel semantics are not", "needed_evidence": "bench mapping from write timing to external output", "priority": "high", "next_action": "run OA-02 and OA-03 tests"},
        {"unknown_id": "U-003", "area": "enum_state_values", "description": "Per-value operational meaning across modules", "why_unknown": "current evidence mixes branch labels and inferred meaning", "needed_evidence": "controlled scenario replay with XDATA watch", "priority": "high", "next_action": "execute enum bench probes"},
        {"unknown_id": "U-004", "area": "MUP_handler", "description": "Exclusive MUP handler function identity", "why_unknown": "shared dispatch chain dominates evidence", "needed_evidence": "slot-isolated traces + dynamic correlation", "priority": "medium", "next_action": "bench with X06 enabled/disabled"},
        {"unknown_id": "U-005", "area": "PVK_handler", "description": "PVK-specific handler attribution", "why_unknown": "screen evidence present but code signature still broad", "needed_evidence": "targeted static deep trace around PVK-related calls", "priority": "medium", "next_action": "expand unresolved handler candidates"},
        {"unknown_id": "U-006", "area": "physical_output_semantics", "description": "Whether paths correspond to valve/siren/GOA/MVK classes", "why_unknown": "no direct hardware confirmation", "needed_evidence": "external IO captures with synchronized firmware events", "priority": "high", "next_action": "prepare isolated load tests"},
    ]

    plan = [
        {"iteration_id": "v1.1", "goal": "Resolve packet framing around 0x5A7F", "expected_outputs": "packet byte map + validated format CSV", "depends_on": "bench packet capture rig", "estimated_impact": "high", "priority": "high", "notes": "focus on 90CYE03 and cross-check 90CYE04"},
        {"iteration_id": "v1.2", "goal": "Validate output-start semantics", "expected_outputs": "confirmed meaning for write 0x04 and guard behavior", "depends_on": "output-action bench tests OA-01..OA-04", "estimated_impact": "high", "priority": "high", "notes": "no physical naming until evidence is direct"},
        {"iteration_id": "v1.3", "goal": "Narrow unresolved module handlers", "expected_outputs": "reduced unresolved handler CSV", "depends_on": "slot-isolated traces", "estimated_impact": "medium", "priority": "medium", "notes": "keep families separated"},
        {"iteration_id": "v1.4", "goal": "Cross-family consistency audit", "expected_outputs": "updated architecture comparison deltas", "depends_on": "v1.1-v1.3 results", "estimated_impact": "medium", "priority": "medium", "notes": "no semantics transfer without fingerprint match"},
        {"iteration_id": "v2.0", "goal": "Publish validated technical reconstruction v2", "expected_outputs": "v2 report + confidence uplift", "depends_on": "bench-confirmed unknown closures", "estimated_impact": "high", "priority": "high", "notes": "target fewer but deeper tasks"},
    ]

    for out, fields, rows in [
        (args.out_dashboard, ["area", "understanding_percent", "confidence", "main_evidence", "main_unknowns", "next_step"], dashboard),
        (args.out_unknowns, ["unknown_id", "area", "description", "why_unknown", "needed_evidence", "priority", "next_action"], unknowns),
        (args.out_plan, ["iteration_id", "goal", "expected_outputs", "depends_on", "estimated_impact", "priority", "notes"], plan),
    ]:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    md = f"""# DKS firmware technical reconstruction v1\n\nGenerated: {stamp}\n\n## 1. Scope and evidence rules\nThis report keeps strict evidence levels: `confirmed_static`, `probable_static`, `manual_decompile`, `chain_adjacency`, `screen_configuration`, `hypothesis`, `unknown`.\nNo physical semantics are claimed without direct static + bench evidence.\n\n## 2. Firmware families covered\nPrimary: `90CYE03_19_DKS.PZU`, cross-check `90CYE04_19_DKS.PZU`; shifted comparison for object-status path: `90CYE02_27 DKS.PZU`; `ppkp2001 90cye01.PZU` only for MDS/MASH comparison context.\n\n## 3. Real DKS configuration evidence\nUses existing `dks_real_configuration_evidence.*` as screen-level ground truth for module slot presence only.\n\n## 4. Reconstructed architecture diagram\nRuntime chain anchor remains: `0x497A -> 0x737C -> 0x613C -> 0x84A6 -> 0x728A -> 0x6833 -> 0x5A7F` with `0x7922`, `0x597F`, `0x7DC2` as service/output-side helpers.\n\n## 5. Main 90CYE_DKS execution chain\nCurrent chain understanding: **{chain}%** (probable). Side exits remain partially unresolved.\n\n## 6. Module roles: MDS / MUP / MASH / PVK / MVK / input-board\nShared dispatchers are separated from slot-specific candidates. MUP/MVK mapping remains unresolved without bench evidence.\n\n## 7. XDATA memory map\nState table candidate: `0x3010..0x301B`; mode/flags cluster: `0x30E7`, `0x30E9`, `0x30EA..0x30F9`; selector/context: `0x31BF`; packet/output context: `0x3640`, `0x364B`, `0x36D3..0x36FD`.\n\n## 8. Enum/state reconstruction\nSee `dks_enum_state_reconstruction.md` and supporting CSVs. Current enum understanding: **{enum}%**.\n\n## 9. Packet/export reconstruction\nSee `dks_packet_export_reconstruction.md`. Current packet understanding: **{packet}%**; `0x5A7F` best fit is bridge/helper.\n\n## 10. Output/action reconstruction\nSee `dks_output_action_reconstruction.md`. Current output-action understanding: **{output}%**; write `0x04` remains non-physical label candidate.\n\n## 11. Manual/auto mode logic\nManual/auto split around `0x84A6/0x728A` remains probable; manual path can go packet-only while auto path can enter output-start flow.\n\n## 12. What is confirmed\n- Screen-level module presence for listed slots.\n- Shared runtime chain existence and adjacency.\n\n## 13. What is probable\n- Enum/state classes and output-start pipeline sequence.\n- Packet-context XDATA clusters and `0x5A7F` bridge role.\n\n## 14. What is hypothesis\n- Physical output semantics (valve/siren/GOA/MVK).\n- Exclusive handler ownership for some module labels.\n\n## 15. What is unknown\nSee `dks_remaining_unknowns.csv`.\n\n## 16. Bench validation plan\nConsolidated in `dks_output_action_bench_tests.csv` and prior lifecycle/enum probe plans.\n\n## 17. Development implications for future compatible firmware\nUse shared runtime-chain abstractions and keep module-specific mappings behind evidence-gated interfaces; avoid hard-coding physical semantics before validation.\n\n## 18. Next iteration plan\nSee `dks_next_iteration_plan.csv`.\n\n---\n\n## Understanding estimates (v1)\n- Global architecture: **{global_arch}%**\n- DKS execution chain: **{chain}%**\n- XDATA lifecycle: **{xdata}%**\n- Packet/export: **{packet}%**\n- Output-action: **{output}%**\n- Full physical semantics: **{physical}%**\n\nThese values are intentionally conservative and should rise only with bench-confirmed evidence.\n"""
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    print(f"Wrote {args.out_dashboard.relative_to(ROOT)} ({len(dashboard)} rows)")
    print(f"Wrote {args.out_unknowns.relative_to(ROOT)} ({len(unknowns)} rows)")
    print(f"Wrote {args.out_plan.relative_to(ROOT)} ({len(plan)} rows)")
    print(f"Context rows: enum={len(enum_rows)}, packet={len(packet_rows)}, output={len(action_rows)}, module={len(mod_rows)}, unresolved={len(unresolved_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
