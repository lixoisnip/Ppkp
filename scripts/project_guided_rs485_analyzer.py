#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import defaultdict
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
    function_rows = load_csv(DOCS / "function_map.csv")
    call_rows = load_csv(DOCS / "call_xref.csv")
    xdata_rows = load_csv(DOCS / "xdata_confirmed_access.csv")
    dks_callsites = load_csv(DOCS / "dks_packet_export_callsite_matrix.csv")
    a03_bridge = load_csv(DOCS / "a03_a04_packet_bridge_candidates_v2.csv")
    linkage_rows = load_csv(DOCS / "extracted" / "project_to_firmware_linkage.csv")

    callers_by_target: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    callees_by_caller: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for r in call_rows:
        k_t = (r.get("branch", ""), r.get("file", ""), r.get("target_addr", ""))
        k_c = (r.get("branch", ""), r.get("file", ""), r.get("code_addr", ""))
        callers_by_target[k_t].add(r.get("code_addr", ""))
        callees_by_caller[k_c].add(r.get("target_addr", ""))

    xdata_by_func: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for r in xdata_rows:
        xdata_by_func[(r.get("branch", ""), r.get("file", ""), r.get("code_addr", ""))].add(r.get("dptr_addr", ""))

    anchor_roles = {
        "0x5A7F": ("packet_export_bridge", "high", "static_code", "PU-001|PU-004"),
        "0x737C": ("rs485_tx_builder", "medium", "static_code", "PU-001|PU-005"),
        "0x497A": ("fire_event_sender", "medium", "static_code", "PU-001|PU-005"),
        "0x84A6": ("address_dispatcher", "medium", "static_code", "PU-002|PU-005"),
        "0x613C": ("fire_event_receiver", "medium", "static_code", "PU-001|PU-005"),
        "0x4358": ("fire_event_sender", "low", "cross_family_pattern", "PU-001|PU-005"),
        "0x920C": ("rs485_rx_parser", "low", "cross_family_pattern", "PU-001|PU-004"),
        "0x53E6": ("timeout_retry_handler", "low", "cross_family_pattern", "PU-005"),
    }

    candidates: list[dict[str, str]] = []
    for row in function_rows:
        addr = row.get("function_addr", "")
        key_addr = addr.upper()
        if key_addr not in anchor_roles:
            continue
        branch, file_name = row.get("branch", ""), row.get("file", "")
        role, confidence, level, unknowns = anchor_roles[key_addr]
        key = (branch, file_name, addr)
        callers = sorted(callers_by_target.get(key, set()))
        callees = sorted(callees_by_caller.get(key, set()))
        xrefs = sorted(xdata_by_func.get(key, set()))
        score = min(100, 35 + int(row.get("call_count", "0") or 0) * 2 + int(row.get("incoming_lcalls", "0") or 0))
        notes = ""
        if addr == "0x5A7F":
            notes = "High fan-in packet bridge helper remains strongest RS-485 transfer anchor; builder/parser split still unresolved statically."
        elif addr in {"0x4358", "0x920C", "0x53E6"}:
            notes = "RTOS_service side-chain candidate; retain family separation and treat as cross-family pattern only."
        candidates.append(
            {
                "branch": branch,
                "file": file_name,
                "function_addr": addr,
                "candidate_role": role,
                "score": str(score),
                "confidence": confidence,
                "evidence_level": level,
                "callers": "|".join(callers),
                "callees": "|".join(callees),
                "xdata_refs": "|".join(xrefs),
                "string_refs": "",
                "constants": "",
                "related_project_unknowns": unknowns,
                "notes": notes,
            }
        )

    for r in a03_bridge:
        candidates.append(
            {
                "branch": r.get("branch", ""),
                "file": r.get("file", ""),
                "function_addr": r.get("function_addr", ""),
                "candidate_role": "packet_export_bridge",
                "score": r.get("score", "0"),
                "confidence": r.get("confidence", "low"),
                "evidence_level": "cross_family_pattern",
                "callers": r.get("callers", ""),
                "callees": r.get("callees", ""),
                "xdata_refs": r.get("xdata_refs", ""),
                "string_refs": r.get("string_refs", ""),
                "constants": "",
                "related_project_unknowns": "PU-001|PU-002|PU-004",
                "notes": "A03/A04 bridge analog imported for cross-check only; no direct RS-485 semantic transfer.",
            }
        )

    crc_rows = [
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x5A7F",
            "checksum_pattern": "bridge_without_explicit_crc_loop",
            "constants": "none_static",
            "loop_signature": "single-block fan-in bridge",
            "callers": "|".join(sorted({r.get('caller_addr','') for r in dks_callsites if r.get('called_addr') == '0x5A7F'})),
            "callees": "",
            "confidence": "low",
            "evidence_level": "static_code",
            "notes": "No direct XOR/add/CRC table loop confirmed in this function; likely helper/bridge scope only.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x737C",
            "checksum_pattern": "additive_or_selector_prep_hypothesis",
            "constants": "0x31BF|0x364B",
            "loop_signature": "multi-branch context transformer",
            "callers": "",
            "callees": "0x84A6|0x5A7F",
            "confidence": "low",
            "evidence_level": "hypothesis",
            "notes": "Candidate packet-context staging only; checksum algorithm unresolved (PU-004).",
        },
    ]

    addr_timeout_rows = [
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x84A6",
            "candidate_type": "address_dispatch",
            "constants": "0x31BF",
            "xdata_refs": "0x31BF|0x364B",
            "related_device": "90CYE03/04",
            "confidence": "low",
            "evidence_level": "static_code",
            "notes": "Likely dispatch/state selector, but explicit 90CYE01/02/03/04 numeric map not yet found (PU-002).",
        },
        {
            "branch": "RTOS_service",
            "file": "ppkp2001 90cye01.PZU",
            "function_addr": "0x53E6",
            "candidate_type": "timeout_counter",
            "constants": "unknown",
            "xdata_refs": "",
            "related_device": "90CYE01",
            "confidence": "low",
            "evidence_level": "cross_family_pattern",
            "notes": "Imported from RTOS_service chain summary as retry/timeout pattern candidate (PU-005).",
        },
        {
            "branch": "all",
            "file": "all",
            "function_addr": "unknown",
            "candidate_type": "uart_baud_config",
            "constants": "unresolved",
            "xdata_refs": "",
            "related_device": "90CYE01/02/03/04",
            "confidence": "unknown",
            "evidence_level": "unknown",
            "notes": "No reliable baud divisor constant isolated from current static inputs (PU-003).",
        },
    ]

    write_csv(
        DOCS / "project_guided_rs485_candidates.csv",
        [
            "branch","file","function_addr","candidate_role","score","confidence","evidence_level","callers","callees","xdata_refs","string_refs","constants","related_project_unknowns","notes",
        ],
        candidates,
    )
    write_csv(
        DOCS / "project_guided_crc_checksum_candidates.csv",
        ["branch","file","function_addr","checksum_pattern","constants","loop_signature","callers","callees","confidence","evidence_level","notes"],
        crc_rows,
    )
    write_csv(
        DOCS / "project_guided_address_timeout_candidates.csv",
        ["branch","file","function_addr","candidate_type","constants","xdata_refs","related_device","confidence","evidence_level","notes"],
        addr_timeout_rows,
    )

    linked = len(linkage_rows)
    report = f"""# Project-guided RS-485 static analysis

Evidence policy: project documentation constrains search, but all findings below are static-code/cross-family hypotheses unless explicitly marked unknown.

## Inputs used
- Project linkage rows: {linked}
- function/call/xdata matrices from docs baseline
- DKS packet callsite matrices and A03/A04 bridge candidates

## Strongest TX/RX/parser/builder candidates
- `0x5A7F` (90CYE_DKS): strongest **packet_export_bridge** by fan-in call topology (static_code).
- `0x737C` / `0x497A` (90CYE_DKS): strongest **event/context-to-export path** neighbors for transmit-side staging.
- `0x84A6` and `0x613C` remain dispatcher/gate candidates that can participate in sender/receiver split but do not prove frame format.

## 0x5A7F role question
Static evidence still supports `0x5A7F` primarily as bridge/helper. A stronger dedicated packet builder has not been isolated with current artifacts.

## Checksum / CRC candidates
No high-confidence CRC table or explicit polynomial loop was isolated in currently linked function windows. PU-004 stays unresolved.

## Address constants / timeout counters
- Candidate selector bytes around `0x31BF/0x364B` remain plausible dispatcher context only.
- RTOS_service chain includes retry/timeout-like topology candidate (`0x53E6`) but with cross-family confidence cap.
- Numeric address map and baud constants remain unresolved.

## Unknown closure status
- PU-001 frame format: **partial static narrowing**, unresolved.
- PU-002 address map: **unresolved**.
- PU-003 baudrate: **unresolved**.
- PU-004 CRC/checksum: **unresolved**.
- PU-005 timeout/retry: **low-confidence candidate only**, unresolved.
"""
    (DOCS / "project_guided_rs485_analysis.md").write_text(report, encoding="utf-8")

    print("Wrote docs/project_guided_rs485_analysis.md")
    print("Wrote docs/project_guided_rs485_candidates.csv")
    print("Wrote docs/project_guided_crc_checksum_candidates.csv")
    print("Wrote docs/project_guided_address_timeout_candidates.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
