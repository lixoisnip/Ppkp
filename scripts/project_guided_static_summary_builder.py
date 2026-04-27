#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    rs = load_csv(DOCS / "project_guided_rs485_candidates.csv")
    crc = load_csv(DOCS / "project_guided_crc_checksum_candidates.csv")
    en = load_csv(DOCS / "project_guided_enum_mapping_candidates.csv")
    dl = load_csv(DOCS / "project_guided_delay_candidates.csv")
    md = load_csv(DOCS / "project_guided_mds_input_candidates.csv")
    vlv = load_csv(DOCS / "project_guided_valve_feedback_candidates.csv")
    out = load_csv(DOCS / "project_guided_aerosol_output_candidates.csv")
    prev_unknowns = load_csv(DOCS / "extracted" / "project_unknowns.csv")

    confidence_rows = [
        {
            "area": "RS-485_transfer_path",
            "previous_status": "high_unknown",
            "project_evidence": "90CYE01->90CYE02/03/04 fire transfer confirmed",
            "static_search_result": f"{len(rs)} candidates; strongest bridge 0x5A7F",
            "new_status": "partial_static_narrowing",
            "confidence": "medium",
            "evidence_level": "project_documentation+static_code",
            "notes": "Frame format/address/baud/CRC still unresolved.",
        },
        {
            "area": "enum_delay_interlock",
            "previous_status": "medium_unknown",
            "project_evidence": "30s delay + door interlock + AO semantics confirmed",
            "static_search_result": f"{len(en)} enum links and {len(dl)} delay candidates",
            "new_status": "improved_static_alignment",
            "confidence": "medium",
            "evidence_level": "project_documentation+static_code+manual_decompile",
            "notes": "Numeric enum semantics remain confidence-capped.",
        },
        {
            "area": "MDS_MVK_valve_output",
            "previous_status": "medium_unknown",
            "project_evidence": "MDS CP/CF/CH + MVK + damper + aerosol outputs confirmed",
            "static_search_result": f"{len(md)} MDS, {len(vlv)} valve, {len(out)} aerosol candidates",
            "new_status": "partial_narrowing",
            "confidence": "low_to_medium",
            "evidence_level": "project_documentation+static_code",
            "notes": "Terminal/object maps and pulse parameters unresolved.",
        },
    ]

    next_rows = [
        {"priority":"P1","area":"RS-485","branch":"90CYE_DKS","file":"90CYE03_19_DKS.PZU","function_addr":"0x5A7F","target_reason":"disambiguate bridge vs builder responsibilities","expected_gain":"PU-001/PU-004 narrowing","notes":"Extract immediate-byte loops and table accesses around all direct callers."},
        {"priority":"P1","area":"RS-485","branch":"RTOS_service","file":"ppkp2001 90cye01.PZU","function_addr":"0x920C","target_reason":"search address/baud constants and parser windows","expected_gain":"PU-002/PU-003 narrowing","notes":"Compare with UART init signatures and code-table candidates."},
        {"priority":"P1","area":"Delay/Interlock","branch":"90CYE_DKS","file":"90CYE03_19_DKS.PZU","function_addr":"0x6833","target_reason":"extract timer arithmetic proving 30s base","expected_gain":"PU-006 and delay confidence uplift","notes":"Need block-level immediate extraction around countdown updates."},
        {"priority":"P2","area":"Valve feedback","branch":"90CYE_shifted_DKS","file":"90CYE02_27 DKS.PZU","function_addr":"0x673C","target_reason":"separate open/closed/fault bit pathways","expected_gain":"PU-010 narrowing","notes":"Link object table writes to limit-switch read sequence."},
        {"priority":"P2","area":"Aerosol outputs","branch":"90CYE_DKS","file":"90CYE03_19_DKS.PZU","function_addr":"0x7DC2","target_reason":"separate GOA launch pulse from AN/AU warnings","expected_gain":"PU-009/PU-011 narrowing","notes":"Track writes immediately after delay-complete branch."},
    ]

    unresolved = {u["unknown_id"]: u for u in prev_unknowns}
    updates = {
        "PU-001": ("partial_static_narrowing", "manual_decompile + richer packet byte extraction", "inspect 0x5A7F callers"),
        "PU-002": ("unresolved", "explicit address constants or decoded frames", "scan RTOS_service and DKS dispatch tables"),
        "PU-003": ("unresolved", "UART divider constant evidence", "search init blocks for baud divisors"),
        "PU-004": ("unresolved", "checksum loop or CRC table linkage", "trace arithmetic loops in packet chain"),
        "PU-005": ("low_confidence_candidate", "timer state-machine proof", "deep trace around retry-like counters"),
        "PU-006": ("partial_static_narrowing", "branch-byte extraction + runtime correlation", "enum immediate compare mining"),
        "PU-007": ("unresolved", "electrical supervision docs/bench", "search for open/short branching near launch chain"),
        "PU-008": ("unresolved", "line supervision logic proofs", "trace CP/CF/CH fault branches"),
        "PU-009": ("unresolved", "pulse-width constants", "timer constant extraction around 0x6833/0x7DC2"),
        "PU-010": ("partial_static_narrowing", "terminal/object join tables", "expand 90CYE02 object map correlation"),
        "PU-011": ("partial_static_narrowing", "GOA terminal table and object index", "separate warning vs pulse writes"),
        "PU-012": ("split_preserved", "additional project sheets for MUP", "keep split in CSV evidence ledger"),
        "PU-013": ("split_preserved", "additional project sheets for PVK", "keep split in CSV evidence ledger"),
    }

    remaining_rows = []
    for uid, row in unresolved.items():
        status, needed, next_static = updates.get(uid, ("unresolved", row.get("needed_evidence", ""), row.get("next_static_step", "")))
        remaining_rows.append(
            {
                "unknown_id": uid,
                "area": row.get("area", ""),
                "description": row.get("description", ""),
                "status_after_project_guided_search": status,
                "needed_evidence": needed,
                "next_static_step": next_static,
                "next_doc_step": row.get("next_doc_step", ""),
                "next_bench_step": row.get("next_bench_step", ""),
            }
        )

    write_csv(
        DOCS / "project_guided_confidence_updates.csv",
        ["area","previous_status","project_evidence","static_search_result","new_status","confidence","evidence_level","notes"],
        confidence_rows,
    )
    write_csv(
        DOCS / "project_guided_next_static_targets.csv",
        ["priority","area","branch","file","function_addr","target_reason","expected_gain","notes"],
        next_rows,
    )
    write_csv(
        DOCS / "project_guided_remaining_unknowns_v2.csv",
        ["unknown_id","area","description","status_after_project_guided_search","needed_evidence","next_static_step","next_doc_step","next_bench_step"],
        remaining_rows,
    )

    md_txt = f"""# Project-guided static analysis summary

## 1. Scope and evidence separation
Project documentation was used as search constraints. Code claims remain separated into `static_code`, `manual_decompile`, `cross_family_pattern`, `hypothesis`, and `unknown` levels.

## 2. What project docs confirmed
- Device roles: 90CYE01 fire source, 90CYE02 damper controller, 90CYE03/04 aerosol start controllers.
- Project-level confirmation for RS-485 fire transfer, 30-second delay, door interlock, MDS CP/CF/CH, MVK output and warning/launch stages.

## 3. What static code search now supports
- RS-485 chain narrowed to high-fan-in bridge neighborhoods.
- Mode/timer/interlock chain narrowed around 0x84A6/0x728A/0x6833/0x7DC2.
- MDS/MVK/valve/output candidates grouped by device role with confidence caps.

## 4. RS-485 findings
- Strongest bridge remains 0x5A7F; no decisive frame-builder replacement identified.
- CRC/address/baud details remain unresolved.

## 5. Enum/delay/interlock findings
- Static support for 30-second delay path is present but timer-base details unresolved.
- Door-open to auto-disabled behavior is most strongly represented in 0x728A/0x84A6 candidate gates.

## 6. MDS/MVK/valve/aerosol output findings
- CP/CF/CH lines constrained by project docs; channel-bit mapping still unresolved.
- 90CYE02 valve feedback narrowed to 0x673C-centered candidates.
- AN/AU/AO/GOA separated into candidate output classes without terminal certainty.

## 7. MUP/PVK evidence split
MUP/PVK split is preserved explicitly: present in screen evidence, absent in current project-page subset, unresolved handler ownership.

## 8. What confidence improved
See `docs/project_guided_confidence_updates.csv`.

## 9. What remains unknown
See `docs/project_guided_remaining_unknowns_v2.csv`; PU-001..PU-013 remain open with narrowed static targets.

## 10. Next static targets
See `docs/project_guided_next_static_targets.csv`.

## 11. What additional project sheets would help most
- Protocol appendix (RS-485 frame/address/CRC/baud/timeout).
- Full terminal/object cross-reference for 90CYE02/03/04 outputs.
- MUP/PVK-specific project pages to reduce split-evidence ambiguity.
"""
    (DOCS / "project_guided_static_analysis_summary.md").write_text(md_txt, encoding="utf-8")

    print("Wrote docs/project_guided_static_analysis_summary.md")
    print("Wrote docs/project_guided_confidence_updates.csv")
    print("Wrote docs/project_guided_next_static_targets.csv")
    print("Wrote docs/project_guided_remaining_unknowns_v2.csv")
    print(f"Summary rows: rs485={len(rs)} crc={len(crc)} enum={len(en)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
