#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def load_confidence_map() -> dict[str, str]:
    path = DOCS / "dks_reconstruction_confidence_dashboard.csv"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8", newline="") as f:
        return {r["area"]: r["understanding_percent"] for r in csv.DictReader(f)}


def runtime_matrix_rows() -> list[dict[str, str]]:
    return [
        {
            "test_id": "PKT-01",
            "area": "packet_export",
            "scenario": "manual event packet",
            "firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS",
            "trigger": "Manual fire/event command without auto output start",
            "expected_function_path": "0x497A->0x737C->0x84A6->0x728A->0x5A7F",
            "watch_xdata": "0x31BF;0x364B;0x36D3..0x36FD",
            "watch_functions": "0x497A;0x737C;0x84A6;0x728A;0x5A7F",
            "expected_packet": "Single event/export frame with manual-state context bytes",
            "expected_io_or_screen": "Event shown on screen; no output-start IO transition",
            "pass_criteria": "Packet appears with stable byte ordering across 3 repeats",
            "falsifies": "No packet near call path or unstable byte order by scenario",
            "priority": "high",
            "notes": "Targets U-001",
        },
        {
            "test_id": "PKT-02",
            "area": "packet_export",
            "scenario": "auto event + output-start packet",
            "firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS",
            "trigger": "Auto fire condition that enters 0x6833",
            "expected_function_path": "0x497A->0x737C->0x613C->0x84A6->0x728A->0x6833->0x5A7F",
            "watch_xdata": "0x30E7;0x30E9;0x315B;0x3181;0x3640;0x364B",
            "watch_functions": "0x613C;0x84A6;0x728A;0x6833;0x5A7F",
            "expected_packet": "Event/export frame containing output-start context",
            "expected_io_or_screen": "Output-start related screen status and IO transition candidate",
            "pass_criteria": "Packet delta correlates with output-start transition timestamp",
            "falsifies": "0x6833 path with no packet change compared to PKT-01",
            "priority": "high",
            "notes": "Targets U-001/U-002",
        },
        {
            "test_id": "PKT-03","area": "packet_export","scenario": "fault packet","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Inject controllable fault condition","expected_function_path": "0x497A->0x737C->0x84A6->0x5A7F","watch_xdata": "0x3010..0x301B;0x31BF;0x36D3..0x36FD","watch_functions": "0x497A;0x737C;0x84A6;0x5A7F","expected_packet": "Fault-class export packet","expected_io_or_screen": "Fault text/icon on HMI","pass_criteria": "Fault packet class reproducible and distinct from fire/manual","falsifies": "Fault scenario reuses fire packet without discriminators","priority": "high","notes": "Targets U-001/U-003"},
        {"test_id": "PKT-04","area": "packet_export","scenario": "service/disabled packet","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Put object/zone into service/disabled mode","expected_function_path": "0x497A->0x737C->0x84A6->0x5A7F","watch_xdata": "0x3010..0x301B;0x30EA..0x30F9;0x31BF","watch_functions": "0x497A;0x737C;0x84A6;0x5A7F","expected_packet": "Service/disabled-coded export","expected_io_or_screen": "Service/disabled status on screen","pass_criteria": "Distinct packet fields for service vs disabled if states differ","falsifies": "No packet difference between normal and service/disabled","priority": "medium","notes": "Targets U-001/U-003"},
        {"test_id": "PKT-05","area": "packet_export","scenario": "absent/not-detected/address-conflict packet","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Create absent/ND/address-conflict scenario","expected_function_path": "0x497A->0x737C->0x84A6->0x5A7F","watch_xdata": "0x3010..0x301B;0x31BF;0x36D3..0x36FD","watch_functions": "0x737C;0x84A6;0x5A7F","expected_packet": "Export packet with absent/conflict discriminators","expected_io_or_screen": "Screen shows absent/not-detected/conflict status","pass_criteria": "Values 0x08/0x7E/0xFF correlate with packet deltas","falsifies": "Packet fields do not change despite state transitions","priority": "high","notes": "Targets U-001/U-003"},
        {"test_id": "PKT-06","area": "packet_export","scenario": "repeated event debounce/duplicate packet","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Repeat identical event rapidly","expected_function_path": "0x497A->0x737C->0x84A6->0x5A7F","watch_xdata": "0x315B;0x3181;0x31BF","watch_functions": "0x84A6;0x5A7F","expected_packet": "Either deduplicated or sequence-marked repeated packet","expected_io_or_screen": "Stable HMI event count behavior","pass_criteria": "Duplicate policy is consistent in all repeats","falsifies": "Random duplicate behavior without state/timing relation","priority": "medium","notes": "Targets U-001"},
        {"test_id": "PKT-07","area": "packet_export","scenario": "90CYE03 vs 90CYE04 packet comparison","firmware_scope": "Cross-compare 90CYE03_19_DKS and 90CYE04_19_DKS","trigger": "Replay PKT-01..PKT-03 on both firmwares","expected_function_path": "Same chain anchors with variant side paths","watch_xdata": "0x31BF;0x364B;0x36D3..0x36FD","watch_functions": "0x497A;0x737C;0x5A7F","expected_packet": "Equivalent framing or documented deterministic variant deltas","expected_io_or_screen": "Equivalent scenario labels on screen","pass_criteria": "Family-separated comparison yields stable mapping rules","falsifies": "Unexplained random packet structure divergence","priority": "high","notes": "Targets U-001 and family separation"},
        {"test_id": "OA-01","area": "output_action","scenario": "precondition only, no output start","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Enter state preconditions but block auto start","expected_function_path": "0x613C->0x84A6->0x728A (no 0x6833)","watch_xdata": "0x30E7;0x30E9;0x315B","watch_functions": "0x613C;0x84A6;0x728A;0x597F","expected_packet": "Event packet possible without output-start marker","expected_io_or_screen": "No external output transition","pass_criteria": "No 0x04-like write correlation with IO","falsifies": "Output transition occurs without 0x6833/output path","priority": "high","notes": "Targets U-002"},
        {"test_id": "OA-02","area": "output_action","scenario": "auto fire output-start path","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Auto fire condition","expected_function_path": "0x613C->0x84A6->0x728A->0x6833->0x7922->0x7DC2","watch_xdata": "0x315B;0x3181;0x3640;0x364B","watch_functions": "0x6833;0x7922;0x7DC2","expected_packet": "Output-start-correlated packet delta","expected_io_or_screen": "Output-related IO transition + start status","pass_criteria": "Function/xdata/IO/packet timelines align","falsifies": "No IO transition when path executes","priority": "high","notes": "Targets U-002/U-006"},
        {"test_id": "OA-03","area": "output_action","scenario": "manual fire event-only path","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Manual fire in mode expected to suppress output start","expected_function_path": "0x613C->0x84A6->0x728A->0x5A7F (skip 0x6833)","watch_xdata": "0x30E7;0x30E9;0x315B","watch_functions": "0x728A;0x6833;0x5A7F","expected_packet": "Fire/event packet without output-start marker","expected_io_or_screen": "Fire/event visible, no output activation","pass_criteria": "Manual path diverges consistently from OA-02","falsifies": "Manual path always triggers same IO as OA-02","priority": "high","notes": "Targets U-002"},
        {"test_id": "OA-04","area": "output_action","scenario": "fault inhibits output-start","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Add fault gate then fire trigger","expected_function_path": "0x84A6->0x728A with guard/abort around 0x597F","watch_xdata": "0x3010..0x301B;0x315B","watch_functions": "0x597F;0x728A;0x6833","expected_packet": "Fault/event packet, no output-start packet signature","expected_io_or_screen": "Fault indicator and output inhibit behavior","pass_criteria": "Fault condition prevents output-start IO transitions","falsifies": "Output starts despite fault inhibit condition","priority": "high","notes": "Targets U-002/U-006"},
        {"test_id": "OA-05","area": "output_action","scenario": "reset/return from output-start state","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Execute reset after OA-02","expected_function_path": "0x7DC2 finalization + return to upstream state paths","watch_xdata": "0x315B;0x3181;0x3640","watch_functions": "0x7DC2;0x7922;0x597F","expected_packet": "Reset/status packet if implemented","expected_io_or_screen": "Output returns to normal/off state","pass_criteria": "State and IO return deterministically within timeout","falsifies": "Stuck output state without matching xdata transitions","priority": "medium","notes": "Targets U-002/U-006"},
        {"test_id": "OA-06","area": "physical_output_semantics","scenario": "XDATA[dptr]=0x04 correlation with external IO","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Capture write-to-target around 0x6833 while probing IO","expected_function_path": "0x6833->0x7922/0x7DC2","watch_xdata": "0x3640;0x364B;DPTR target under test","watch_functions": "0x6833;0x7922;0x7DC2","expected_packet": "Optional output-start packet annotation","expected_io_or_screen": "IO channel transition aligned to write timing","pass_criteria": "Repeatable write-to-IO timing correlation demonstrated","falsifies": "No correlation between 0x04 writes and external IO","priority": "high","notes": "Targets U-002/U-006; no physical class naming without capture"},
        {"test_id": "OA-07","area": "output_action","scenario": "0x597F guard behavior","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Toggle guard preconditions near output start","expected_function_path": "0x597F gate before downstream start/finalization","watch_xdata": "0x30E7;0x315B;0x3181","watch_functions": "0x597F;0x6833;0x7DC2","expected_packet": "Guard-dependent packet differences","expected_io_or_screen": "Guard blocks/allows start indication","pass_criteria": "Guard state predicts downstream execution","falsifies": "0x597F status unrelated to downstream behavior","priority": "medium","notes": "Targets U-002"},
        {"test_id": "OA-08","area": "output_action","scenario": "0x7DC2 downstream finalization","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Run complete start->finalize cycle","expected_function_path": "0x6833->0x7922->0x7DC2","watch_xdata": "0x315B;0x3181;0x36D3..0x36FD","watch_functions": "0x7922;0x7DC2;0x5A7F","expected_packet": "Finalization-related export if present","expected_io_or_screen": "End-of-cycle status on HMI","pass_criteria": "Finalization point reproducible and timestamped","falsifies": "No distinct finalization phase observable","priority": "medium","notes": "Targets U-002/U-006"},
    ] + [
        {"test_id": "ENUM-01","area": "enum_state_values","scenario": "normal","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Known normal/idle baseline","expected_function_path": "0x497A->0x737C->0x84A6","watch_xdata": "0x3010..0x301B;0x31BF","watch_functions": "0x497A;0x737C;0x84A6","expected_packet": "Normal/status packet baseline","expected_io_or_screen": "Normal state label","pass_criteria": "Baseline value stable","falsifies": "Baseline value unstable without stimulus","priority": "medium","notes": "State baseline"},
        {"test_id": "ENUM-02","area": "enum_state_values","scenario": "fire primary candidate 0x01","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Primary fire stimulus","expected_function_path": "0x497A->0x737C->0x84A6->0x728A","watch_xdata": "0x3010..0x301B;0x31BF","watch_functions": "0x737C;0x84A6;0x728A","expected_packet": "Fire packet candidate for 0x01","expected_io_or_screen": "Fire primary display","pass_criteria": "0x01 repeatedly maps to same fire behavior","falsifies": "0x01 appears in non-fire scenarios","priority": "high","notes": "U-003"},
        {"test_id": "ENUM-03","area": "enum_state_values","scenario": "fire secondary candidate 0x02","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Secondary fire-like stimulus","expected_function_path": "0x497A->0x737C->0x84A6","watch_xdata": "0x3010..0x301B;0x31BF","watch_functions": "0x737C;0x84A6","expected_packet": "Fire-secondary packet candidate","expected_io_or_screen": "Alternative fire status","pass_criteria": "0x02 consistently separated from 0x01 context","falsifies": "0x01/0x02 indistinguishable across all evidence","priority": "high","notes": "U-003"},
        {"test_id": "ENUM-04","area": "enum_state_values","scenario": "attention/alarm-fault candidate 0x03","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Attention or mixed alarm-fault stimulus","expected_function_path": "0x497A->0x737C->0x84A6","watch_xdata": "0x3010..0x301B","watch_functions": "0x737C;0x84A6","expected_packet": "Attention/fault-coded packet","expected_io_or_screen": "Attention/fault screen indicator","pass_criteria": "0x03 maps to specific non-fire state","falsifies": "0x03 random across unrelated states","priority": "medium","notes": "U-003"},
        {"test_id": "ENUM-05","area": "enum_state_values","scenario": "fault candidate 0x04","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Controlled fault scenario","expected_function_path": "0x497A->0x737C->0x84A6","watch_xdata": "0x3010..0x301B;0x31BF","watch_functions": "0x737C;0x84A6;0x5A7F","expected_packet": "Fault packet with 0x04 candidate","expected_io_or_screen": "Fault status text/icon","pass_criteria": "0x04 aligns with fault scenario across repeats","falsifies": "0x04 appears in normal scenario","priority": "high","notes": "U-003"},
        {"test_id": "ENUM-06","area": "enum_state_values","scenario": "disabled candidate 0x05","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Disable target object/zone","expected_function_path": "0x497A->0x737C->0x84A6","watch_xdata": "0x3010..0x301B;0x30EA..0x30F9","watch_functions": "0x737C;0x84A6","expected_packet": "Disabled/state packet candidate","expected_io_or_screen": "Disabled indicator","pass_criteria": "0x05 follows disable/enable toggles","falsifies": "0x05 unaffected by disable action","priority": "medium","notes": "U-003"},
        {"test_id": "ENUM-07","area": "enum_state_values","scenario": "service candidate 0x07","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Service mode enable","expected_function_path": "0x497A->0x737C->0x84A6","watch_xdata": "0x3010..0x301B;0x30EA..0x30F9","watch_functions": "0x737C;0x84A6","expected_packet": "Service/status packet candidate","expected_io_or_screen": "Service label on HMI","pass_criteria": "0x07 appears only in service state","falsifies": "0x07 appears outside service scenarios","priority": "medium","notes": "U-003"},
        {"test_id": "ENUM-08","area": "enum_state_values","scenario": "not-detected candidate 0x08","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Not-detected condition","expected_function_path": "0x497A->0x737C->0x84A6","watch_xdata": "0x3010..0x301B;0x31BF","watch_functions": "0x737C;0x84A6;0x5A7F","expected_packet": "Not-detected packet variant","expected_io_or_screen": "Not detected indicator","pass_criteria": "0x08 aligns with ND screen and packet","falsifies": "0x08 never observed under ND stimulus","priority": "high","notes": "U-003"},
        {"test_id": "ENUM-09","area": "enum_state_values","scenario": "address conflict candidate 0x7E","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Address conflict setup","expected_function_path": "0x497A->0x737C->0x84A6","watch_xdata": "0x3010..0x301B;0x31BF","watch_functions": "0x737C;0x84A6;0x5A7F","expected_packet": "Address-conflict packet variant","expected_io_or_screen": "Address conflict status","pass_criteria": "0x7E appears in conflict scenario","falsifies": "No 0x7E despite repeated conflict stimulus","priority": "high","notes": "U-003"},
        {"test_id": "ENUM-10","area": "enum_state_values","scenario": "absent/invalid candidate 0xFF","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Absent/invalid object scenario","expected_function_path": "0x497A->0x737C->0x84A6","watch_xdata": "0x3010..0x301B;0x31BF","watch_functions": "0x737C;0x84A6;0x5A7F","expected_packet": "Absent/invalid packet variant","expected_io_or_screen": "Absent object status","pass_criteria": "0xFF correlates with absent scenario","falsifies": "0xFF appears in healthy baseline","priority": "high","notes": "U-003"},
        {"test_id": "MOD-01","area": "MUP_handler","scenario": "X06 MUP isolated command/control scenario","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Only X06 MUP enabled; issue command","expected_function_path": "0x497A->0x613C->candidate MUP handlers","watch_xdata": "0x30EA..0x30F9;0x31BF;0x3640","watch_functions": "0x497A;0x613C;0x728A;0x6833","expected_packet": "MUP-related status/control packet","expected_io_or_screen": "X06-specific status/IO effect","pass_criteria": "Exclusive candidate path evidence for MUP slot","falsifies": "Same behavior when X06 disabled","priority": "high","notes": "U-004"},
        {"test_id": "MOD-02","area": "MUP_handler","scenario": "X06 MUP fault/feedback scenario","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Inject MUP feedback/fault with only X06 active","expected_function_path": "0x497A->0x737C->candidate MUP fault path","watch_xdata": "0x3010..0x301B;0x31BF;0x36D3..0x36FD","watch_functions": "0x497A;0x737C;0x84A6","expected_packet": "MUP fault packet","expected_io_or_screen": "X06 fault feedback on HMI","pass_criteria": "Fault path maps to MUP-only slot","falsifies": "Fault path unchanged with X06 removed","priority": "high","notes": "U-004"},
        {"test_id": "MOD-03","area": "PVK_handler","scenario": "X07 PVK normal/status scenario","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Only X07 PVK enabled and polled","expected_function_path": "0x497A->0x613C->candidate PVK handlers","watch_xdata": "0x30EA..0x30F9;0x31BF;0x3640","watch_functions": "0x497A;0x613C;0x728A","expected_packet": "PVK status packet","expected_io_or_screen": "X07 normal/status entry","pass_criteria": "Candidate functions become exclusive with X07 only","falsifies": "No slot isolation signal for PVK scenario","priority": "high","notes": "U-005"},
        {"test_id": "MOD-04","area": "PVK_handler","scenario": "X07 PVK fault/status scenario","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Inject PVK fault/feedback condition","expected_function_path": "0x497A->0x737C->candidate PVK fault path","watch_xdata": "0x3010..0x301B;0x31BF;0x36D3..0x36FD","watch_functions": "0x737C;0x84A6;0x5A7F","expected_packet": "PVK fault/status packet","expected_io_or_screen": "X07 fault/status indication","pass_criteria": "Fault updates tied to PVK-only configuration","falsifies": "Identical path when PVK slot absent","priority": "high","notes": "U-005"},
        {"test_id": "MOD-05","area": "MUP_handler","scenario": "disable/enable slot comparison","firmware_scope": "90CYE03_19_DKS + 90CYE04_19_DKS","trigger": "Toggle X06/X07 enable states","expected_function_path": "Shared dispatch with slot-conditioned branches","watch_xdata": "0x30EA..0x30F9;0x31BF","watch_functions": "0x497A;0x613C;0x737C","expected_packet": "Module presence/status delta packets","expected_io_or_screen": "Screen slot availability changes","pass_criteria": "Branching changes match slot toggles","falsifies": "No branch deltas under slot toggles","priority": "medium","notes": "U-004/U-005"},
        {"test_id": "MOD-06","area": "PVK_handler","scenario": "compare 90CYE03 and 90CYE04 same module behavior","firmware_scope": "Cross-compare 90CYE03_19_DKS and 90CYE04_19_DKS","trigger": "Replay MOD-01..MOD-04 on both images","expected_function_path": "Equivalent family-specific candidate sets","watch_xdata": "0x31BF;0x36D3..0x36FD","watch_functions": "0x497A;0x613C;0x737C;0x84A6","expected_packet": "Comparable module signatures by firmware","expected_io_or_screen": "Comparable slot behavior","pass_criteria": "Stable mapping table for both firmwares","falsifies": "Inconsistent non-repeatable module fingerprints","priority": "medium","notes": "U-004/U-005 + family separation"},
        {"test_id": "OBJ-01","area": "object_status","scenario": "90SAE object normal/status change","firmware_scope": "90CYE02_27 DKS object-status layer","trigger": "Object status change to normal","expected_function_path": "0x673C object-status handling","watch_xdata": "0x3104;0x3010..0x301B","watch_functions": "0x673C;0x5A7F","expected_packet": "Object status export baseline","expected_io_or_screen": "90SAE object screen normal","pass_criteria": "0x3104 updates correlate with 0x673C calls","falsifies": "No 0x3104 change under object updates","priority": "medium","notes": "Secondary scope"},
        {"test_id": "OBJ-02","area": "object_status","scenario": "90SAE object fault/status change","firmware_scope": "90CYE02_27 DKS object-status layer","trigger": "Inject object-level fault","expected_function_path": "0x673C fault/status branch","watch_xdata": "0x3104;0x3010..0x301B","watch_functions": "0x673C;0x5A7F","expected_packet": "Object fault/status packet","expected_io_or_screen": "90SAE object fault status","pass_criteria": "Fault mapping at 0x3104 repeatable","falsifies": "Fault scenario lacks 0x3104/0x673C linkage","priority": "medium","notes": "Secondary scope"},
        {"test_id": "OBJ-03","area": "object_status","scenario": "0x3104 watchpoint correlation with 0x673C","firmware_scope": "90CYE02_27 DKS object-status layer","trigger": "Replay OBJ-01/OBJ-02 with watchpoints","expected_function_path": "0x673C call-context around object status updates","watch_xdata": "0x3104","watch_functions": "0x673C","expected_packet": "Optional packet correlation","expected_io_or_screen": "Screen status changes tracked","pass_criteria": "Timestamped 0x3104 changes align to 0x673C entry","falsifies": "No temporal relation observed","priority": "high","notes": "U-003 support in secondary scope"},
        {"test_id": "OBJ-04","area": "object_status","scenario": "packet/screen correlation","firmware_scope": "90CYE02_27 DKS object-status layer","trigger": "Repeat known object status transitions","expected_function_path": "0x673C->packet/export downstream","watch_xdata": "0x3104;0x31BF","watch_functions": "0x673C;0x5A7F","expected_packet": "Screen-correlated status packet","expected_io_or_screen": "Screen labels and packet timestamps match","pass_criteria": "Packet/event timestamps consistent with HMI updates","falsifies": "Screens change with no packet-level reflection","priority": "medium","notes": "Secondary scope + U-001/U-003 linkage"},
    ]


def build_plan_md(stamp: str) -> str:
    return f"""# DKS runtime validation plan v1\n\nGenerated: {stamp}\n\n## Scope and safety\n- This document is a **validation plan** and does not contain bench-confirmed runtime evidence.\n- Static reconstruction evidence and future runtime evidence must be kept separate in stored artifacts.\n- No physical semantics hypothesis (valve/siren/GOA/MVK/etc.) is promoted to confirmed status before direct IO capture.\n- External outputs must be tested with safe dummy loads/indicators, never with real extinguishing actuators.\n- All procedures must explicitly avoid unintended fire-extinguishing activation.\n\n## Validation objectives\n- U-001 packet_export: exact frame boundary and byte order around `0x5A7F`.\n- U-002 output_action: physical meaning/correlation of `XDATA[DPTR] = 0x04`.\n- U-003 enum_state_values: per-value operational meaning under controlled scenarios.\n- U-004 MUP_handler: exclusive MUP handler attribution under slot isolation.\n- U-005 PVK_handler: PVK-specific handler attribution under slot isolation.\n- U-006 physical_output_semantics: whether output paths map to specific physical classes.\n\n## Required instrumentation\n- Serial/packet capture (if available).\n- Logic analyzer and/or IO capture for output lines.\n- XDATA watch/log mechanism (if available).\n- Synchronized timestamping across all capture channels.\n- Scenario trigger log with exact operator action timestamps.\n- Screen/HMI status photo/video log.\n- Power/reset state notes for each run.\n- Module configuration notes (slot mapping before each scenario).\n\n## XDATA watch list\n- `0x3010..0x301B`\n- `0x30E7`\n- `0x30E9`\n- `0x30EA..0x30F9`\n- `0x315B`\n- `0x3181`\n- `0x31BF`\n- `0x3640`\n- `0x364B`\n- `0x36D3..0x36FD`\n- `0x3104` (for `90CYE02_27 DKS` object-status tests only)\n\n## Function/path watch list\n- `0x497A`, `0x737C`, `0x613C`, `0x84A6`, `0x728A`, `0x6833`, `0x5A7F`, `0x7922`, `0x597F`, `0x7DC2`\n- `0x673C` (for `90CYE02_27 DKS` object-status tests)\n\n## Packet/export validation tests\nSee `docs/dks_runtime_validation_matrix.csv` rows `PKT-01..PKT-07`.\nFor each test the matrix captures:\n- trigger scenario\n- expected function path\n- XDATA watch list\n- expected packet observation\n- what would confirm `0x5A7F` role\n- what would falsify the current packet hypothesis\n\n## Output-action validation tests\nSee `docs/dks_runtime_validation_matrix.csv` rows `OA-01..OA-08`.\nFor each test the matrix captures:\n- trigger scenario\n- expected function path\n- expected XDATA change\n- external IO observation\n- packet observation\n- pass/fail criteria\n\n## Enum/state validation tests\nSee `docs/dks_runtime_validation_matrix.csv` rows `ENUM-01..ENUM-10`.\nFor each test the matrix captures:\n- required stimulus\n- expected XDATA state byte\n- expected downstream path\n- expected screen/HMI status\n- expected packet/export behavior\n- confidence if confirmed\n\n## MUP/PVK handler attribution tests\nSee `docs/dks_runtime_validation_matrix.csv` rows `MOD-01..MOD-06`.\nFor each test the matrix captures:\n- screen slot\n- module label\n- expected candidate functions\n- XDATA watch list\n- expected external IO or status effect\n- pass/fail criteria\n\n## 90CYE02 object-status tests\nSee `docs/dks_runtime_validation_matrix.csv` rows `OBJ-01..OBJ-04`.\n\n## Data collection procedure\n1. Record firmware file and device screen before test.\n2. Record module slots and enabled/disabled state.\n3. Reset device to known normal state.\n4. Start packet capture.\n5. Start IO capture.\n6. Start XDATA/function trace (if available).\n7. Trigger one scenario.\n8. Save captured data artifacts.\n9. Annotate exact trigger time.\n10. Return device to normal.\n11. Repeat each test three times.\n\n## Data import workflow\n- Raw captures should be normalized into:\n  - `docs/dks_packet_capture_schema.csv`\n  - `docs/dks_io_capture_schema.csv`\n- Summarized test outcomes should be appended using:\n  - `docs/dks_bench_result_import_template.csv`\n- Import commits must keep static evidence and bench evidence in separate sections/commits when practical.\n\n## Confidence uplift model\nIf required tests succeed with synchronized evidence, projected uplift targets are:\n- `packet_export`: `56% -> 75–85%`\n- `output_action`: `54% -> 75–85%`\n- `enum_state_values`: `61% -> 80–90%`\n- `MUP_handler`: `49% -> 65–80%`\n- `PVK_handler`: `47% -> 60–75%`\n- `physical_output_semantics`: `29% -> 55–75%`\n"""


def build_roadmap_md(stamp: str, conf: dict[str, str]) -> str:
    return f"""# DKS v1 -> v2 validation roadmap\n\nGenerated: {stamp}\n\n## What v1 knows\n- Global architecture and runtime chain are reconstructed at conservative confidence levels.\n- Current estimates: global architecture {conf.get('global_architecture', '72%')}, execution chain {conf.get('90CYE_DKS_execution_chain', '78%')}, XDATA lifecycle {conf.get('XDATA_lifecycle', '74%')}.\n- Packet/export, output-action, enum/state values and module-attribution edges remain validation-limited.\n\n## Why bench/runtime validation is needed\nStatic analysis established plausible paths and candidate semantics, but unresolved unknowns U-001..U-006 require synchronized packet/IO/XDATA/function evidence to move from hypothesis/probable to validated.\n\n## What to test first\nPrioritize tests that collapse multiple unknowns at once and produce reusable data schemas:\n1. packet framing (`PKT-01`, `PKT-02`)\n2. output-start split and 0x04 correlation (`OA-02`, `OA-03`, `OA-06`)\n3. enum anchors (`ENUM-02`, `ENUM-05`)\n4. module slot isolation (`MOD-01`, `MOD-03`)\n\n## Expected impact\nSuccessful completion of the minimal set should significantly reduce ambiguity in packet framing, output-action meaning, enum values and MUP/PVK attribution.\n\n## Minimal test set for fastest confidence uplift\n- PKT-01\n- PKT-02\n- OA-02\n- OA-03\n- OA-06\n- ENUM-02\n- ENUM-05\n- MOD-01\n- MOD-03\n\n## Full test set for v2.0 report\n- Packet/export: `PKT-01..PKT-07`\n- Output-action: `OA-01..OA-08`\n- Enum/state: `ENUM-01..ENUM-10`\n- Module attribution: `MOD-01..MOD-06`\n- Object-status layer: `OBJ-01..OBJ-04`\n\n## v2.0 readiness gate\nv2.0 validated reconstruction should be published only after import-ready bench evidence exists in standardized packet/IO/result schema files and unknowns U-001..U-006 have explicit pass/fail outcomes linked to test IDs.\n"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Build DKS runtime validation plan package (v1.1-v1.3 prep)")
    args = parser.parse_args()
    _ = args

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    conf = load_confidence_map()

    matrix_rows = runtime_matrix_rows()
    write_csv(
        DOCS / "dks_runtime_validation_matrix.csv",
        [
            "test_id","area","scenario","firmware_scope","trigger","expected_function_path","watch_xdata","watch_functions",
            "expected_packet","expected_io_or_screen","pass_criteria","falsifies","priority","notes",
        ],
        matrix_rows,
    )

    write_csv(
        DOCS / "dks_xdata_watchlist_v2.csv",
        ["xdata_addr","cluster","watch_reason","related_functions","related_tests","expected_change","confidence","notes"],
        [
            {"xdata_addr":"0x3010..0x301B","cluster":"state_table","watch_reason":"Enum/state byte candidates","related_functions":"0x497A;0x737C;0x84A6","related_tests":"ENUM-01..ENUM-10;PKT-03..PKT-05","expected_change":"State byte varies by scenario","confidence":"probable","notes":"Primary enum/value cluster"},
            {"xdata_addr":"0x30E7","cluster":"mode_flags","watch_reason":"Manual/auto gate context","related_functions":"0x728A;0x597F","related_tests":"OA-01..OA-04","expected_change":"Mode-dependent branch gate changes","confidence":"probable","notes":"Mode flag candidate"},
            {"xdata_addr":"0x30E9","cluster":"mode_flags","watch_reason":"Manual/auto companion flag","related_functions":"0x728A;0x597F","related_tests":"OA-01..OA-04","expected_change":"Correlates with event-only vs output-start split","confidence":"probable","notes":"Mode gate companion"},
            {"xdata_addr":"0x30EA..0x30F9","cluster":"module_config","watch_reason":"Slot/module configuration state","related_functions":"0x497A;0x613C","related_tests":"MOD-01..MOD-06;PKT-04","expected_change":"Enable/disable slot transitions","confidence":"hypothesis","notes":"Module slot condition candidates"},
            {"xdata_addr":"0x315B","cluster":"output_state","watch_reason":"Output-start lifecycle context","related_functions":"0x6833;0x7922;0x7DC2","related_tests":"OA-02..OA-08","expected_change":"Changes on output-start/finalization","confidence":"probable","notes":"Output status candidate"},
            {"xdata_addr":"0x3181","cluster":"output_state","watch_reason":"Output cycle companion byte","related_functions":"0x6833;0x7922;0x7DC2","related_tests":"OA-02..OA-08","expected_change":"Transitions during start/reset","confidence":"hypothesis","notes":"Needs runtime correlation"},
            {"xdata_addr":"0x31BF","cluster":"selector_context","watch_reason":"Packet/context selector candidate","related_functions":"0x497A;0x737C;0x5A7F","related_tests":"PKT-01..PKT-07;ENUM-01..ENUM-10","expected_change":"Selector changes by event/object","confidence":"probable","notes":"Packet-context anchor"},
            {"xdata_addr":"0x3640","cluster":"packet_output_context","watch_reason":"Output/packet adjacent context","related_functions":"0x6833;0x5A7F","related_tests":"PKT-02;OA-02;OA-06","expected_change":"Changes near output-start export","confidence":"hypothesis","notes":"Needs synchronized trace"},
            {"xdata_addr":"0x364B","cluster":"packet_output_context","watch_reason":"Packet window anchor candidate","related_functions":"0x737C;0x6833;0x5A7F","related_tests":"PKT-01..PKT-07;OA-02","expected_change":"Frame-context dependent bytes","confidence":"probable","notes":"Likely packet-context byte"},
            {"xdata_addr":"0x36D3..0x36FD","cluster":"packet_payload_cluster","watch_reason":"Packet payload/state cluster hypothesis","related_functions":"0x737C;0x84A6;0x5A7F","related_tests":"PKT-01..PKT-07;ENUM-02..ENUM-10","expected_change":"Payload byte deltas by scenario","confidence":"hypothesis","notes":"Byte order unknown (U-001)"},
            {"xdata_addr":"0x3104","cluster":"object_status","watch_reason":"90CYE02 object-status watchpoint","related_functions":"0x673C","related_tests":"OBJ-01..OBJ-04","expected_change":"Object status update correlation","confidence":"probable","notes":"Secondary scope only"},
        ],
    )

    write_csv(
        DOCS / "dks_function_watchlist_v2.csv",
        ["function_addr","current_role","watch_reason","related_tests","expected_call_context","confidence","notes"],
        [
            {"function_addr":"0x497A","current_role":"upstream dispatcher","watch_reason":"Entry for event/object flow","related_tests":"PKT-01..PKT-07;ENUM-*;MOD-*","expected_call_context":"Scenario trigger dispatch","confidence":"probable","notes":"Chain anchor"},
            {"function_addr":"0x737C","current_role":"state/context transformer","watch_reason":"Prepares downstream state for packet/output","related_tests":"PKT-*;ENUM-*;MOD-*","expected_call_context":"After dispatcher with state bytes","confidence":"probable","notes":"Chain anchor"},
            {"function_addr":"0x613C","current_role":"mid-chain branch hub","watch_reason":"Module/output branch split candidate","related_tests":"OA-*;MOD-*","expected_call_context":"Before mode gate/output branch","confidence":"probable","notes":"Shared dispatcher region"},
            {"function_addr":"0x84A6","current_role":"mode/state gate","watch_reason":"Separates event-only vs output-start paths","related_tests":"PKT-*;OA-*;ENUM-*","expected_call_context":"Before 0x728A/0x5A7F handoff","confidence":"probable","notes":"Gate candidate"},
            {"function_addr":"0x728A","current_role":"manual/auto branch gate","watch_reason":"Critical split for OA-02 vs OA-03","related_tests":"PKT-02;OA-01..OA-04","expected_call_context":"Pre-0x6833 decision point","confidence":"probable","notes":"Manual decompile support exists"},
            {"function_addr":"0x6833","current_role":"output-start entry candidate","watch_reason":"Contains 0x04 write hypothesis","related_tests":"PKT-02;OA-02..OA-08","expected_call_context":"Auto/output-start branch","confidence":"probable","notes":"No physical semantics without IO capture"},
            {"function_addr":"0x5A7F","current_role":"packet/export bridge helper candidate","watch_reason":"U-001 frame boundary target","related_tests":"PKT-*;ENUM-*;OBJ-*","expected_call_context":"High fan-in downstream packet context","confidence":"probable","notes":"Exact frame role unresolved"},
            {"function_addr":"0x7922","current_role":"downstream output helper","watch_reason":"Output-start continuation path","related_tests":"OA-02;OA-05;OA-08","expected_call_context":"After 0x6833","confidence":"hypothesis","notes":"Finalize/start sequencing unknown"},
            {"function_addr":"0x597F","current_role":"guard/check helper","watch_reason":"Guard behavior in OA-07","related_tests":"OA-01;OA-04;OA-07","expected_call_context":"Before or around output-start gating","confidence":"hypothesis","notes":"Guard semantics to validate"},
            {"function_addr":"0x7DC2","current_role":"finalization candidate","watch_reason":"End-of-cycle behavior in OA-08","related_tests":"OA-02;OA-05;OA-08","expected_call_context":"Downstream after start path","confidence":"hypothesis","notes":"Needs timing evidence"},
            {"function_addr":"0x673C","current_role":"90CYE02 object-status handler candidate","watch_reason":"OBJ tests + 0x3104 correlation","related_tests":"OBJ-01..OBJ-04","expected_call_context":"Object status update path","confidence":"probable","notes":"Secondary scope"},
        ],
    )

    write_csv(
        DOCS / "dks_packet_capture_schema.csv",
        ["capture_field","description","required","example","notes"],
        [
            {"capture_field":"capture_id","description":"Unique capture record id","required":"yes","example":"PKT02-20260427-001","notes":"Stable key for joins"},
            {"capture_field":"firmware_file","description":"Firmware under test","required":"yes","example":"90CYE03_19_DKS.PZU","notes":"Family separation required"},
            {"capture_field":"device_name","description":"Bench device identifier","required":"yes","example":"DKS-bench-A","notes":"Physical unit traceability"},
            {"capture_field":"timestamp_start","description":"Capture start timestamp","required":"yes","example":"2026-04-27T10:15:30Z","notes":"UTC recommended"},
            {"capture_field":"timestamp_trigger","description":"Scenario trigger timestamp","required":"yes","example":"2026-04-27T10:15:42.120Z","notes":"Must align with IO/XDATA logs"},
            {"capture_field":"test_id","description":"Validation matrix test id","required":"yes","example":"PKT-02","notes":"Must match runtime matrix"},
            {"capture_field":"scenario","description":"Human-readable scenario label","required":"yes","example":"auto event + output-start packet","notes":"Use matrix wording"},
            {"capture_field":"packet_raw_hex","description":"Raw packet payload/frame hex","required":"yes","example":"AA55...","notes":"No reinterpretation in raw field"},
            {"capture_field":"packet_direction","description":"Direction of packet","required":"yes","example":"tx","notes":"tx/rx/bidirectional"},
            {"capture_field":"suspected_function_path","description":"Observed/suspected function path","required":"no","example":"0x497A->0x737C->0x6833->0x5A7F","notes":"From trace if available"},
            {"capture_field":"xdata_snapshot_before","description":"Relevant XDATA state before trigger","required":"no","example":"31BF=01;315B=00","notes":"Subset allowed"},
            {"capture_field":"xdata_snapshot_after","description":"Relevant XDATA state after trigger","required":"no","example":"31BF=02;315B=04","notes":"Subset allowed"},
            {"capture_field":"screen_status","description":"HMI/screen state text or code","required":"yes","example":"FIRE AUTO START","notes":"Can reference photo/video id"},
            {"capture_field":"operator_notes","description":"Operator notes","required":"no","example":"Repeat 2/3 with same framing","notes":"Include anomalies"},
        ],
    )

    write_csv(
        DOCS / "dks_io_capture_schema.csv",
        ["capture_field","description","required","example","notes"],
        [
            {"capture_field":"capture_id","description":"Unique capture record id","required":"yes","example":"OA06-20260427-001","notes":"Join key"},
            {"capture_field":"firmware_file","description":"Firmware under test","required":"yes","example":"90CYE04_19_DKS.PZU","notes":"Family separated"},
            {"capture_field":"test_id","description":"Validation matrix test id","required":"yes","example":"OA-06","notes":"Must match matrix"},
            {"capture_field":"timestamp_trigger","description":"Trigger timestamp","required":"yes","example":"2026-04-27T11:20:01.005Z","notes":"Synchronize with packet/XDATA"},
            {"capture_field":"io_channel","description":"Measured IO channel id","required":"yes","example":"CH3","notes":"Analyzer channel"},
            {"capture_field":"io_label_if_known","description":"Known label for channel","required":"no","example":"Output relay candidate","notes":"Do not assert semantics without proof"},
            {"capture_field":"voltage_before","description":"Voltage/state before trigger","required":"yes","example":"0.0V","notes":"Or logical low/high"},
            {"capture_field":"voltage_after","description":"Voltage/state after trigger","required":"yes","example":"24.0V","notes":"Or logical low/high"},
            {"capture_field":"transition_time_ms","description":"Time from trigger to transition","required":"no","example":"48","notes":"ms resolution preferred"},
            {"capture_field":"related_xdata","description":"Correlated XDATA change","required":"no","example":"315B:00->04","notes":"Watchlist subset"},
            {"capture_field":"related_function","description":"Correlated function entry","required":"no","example":"0x6833","notes":"From trace if available"},
            {"capture_field":"screen_status","description":"HMI status during IO capture","required":"yes","example":"AUTO START ACTIVE","notes":"Photo/video cross-ref allowed"},
            {"capture_field":"notes","description":"Capture notes","required":"no","example":"Transition repeated all 3 runs","notes":"Record anomalies"},
        ],
    )

    write_csv(
        DOCS / "dks_bench_result_import_template.csv",
        ["capture_id","test_id","firmware_file","scenario","observed_function_path","observed_xdata_changes","observed_packet_raw_hex","observed_io_changes","screen_result","pass_fail","confidence_delta","notes"],
        [
            {
                "capture_id":"template-001","test_id":"PKT-01","firmware_file":"90CYE03_19_DKS.PZU","scenario":"manual event packet","observed_function_path":"","observed_xdata_changes":"","observed_packet_raw_hex":"","observed_io_changes":"","screen_result":"","pass_fail":"pending","confidence_delta":"0","notes":"Fill after bench capture import"
            }
        ],
    )

    write_csv(
        DOCS / "dks_validation_confidence_uplift.csv",
        ["area","current_percent","target_percent_if_validated","required_tests","reason","notes"],
        [
            {"area":"packet_export","current_percent":conf.get("packet_export", "56%"),"target_percent_if_validated":"75-85%","required_tests":"PKT-01..PKT-07","reason":"Frame boundary/byte order and call-path correlation","notes":"U-001 closure candidate"},
            {"area":"output_action","current_percent":conf.get("output_action", "54%"),"target_percent_if_validated":"75-85%","required_tests":"OA-01..OA-08","reason":"Output-start path and 0x04 write correlation","notes":"U-002 core"},
            {"area":"enum_state_values","current_percent":conf.get("enum_state_values", "61%"),"target_percent_if_validated":"80-90%","required_tests":"ENUM-01..ENUM-10","reason":"Per-value operational mapping with scenario controls","notes":"U-003 core"},
            {"area":"MUP_handler","current_percent":conf.get("MUP_handler", "49%"),"target_percent_if_validated":"65-80%","required_tests":"MOD-01;MOD-02;MOD-05;MOD-06","reason":"Slot-isolated evidence for exclusive handler attribution","notes":"U-004"},
            {"area":"PVK_handler","current_percent":conf.get("PVK_handler", "47%"),"target_percent_if_validated":"60-75%","required_tests":"MOD-03;MOD-04;MOD-05;MOD-06","reason":"PVK-specific slot attribution and cross-firmware consistency","notes":"U-005"},
            {"area":"physical_output_semantics","current_percent":conf.get("physical_output_semantics", "29%"),"target_percent_if_validated":"55-75%","required_tests":"OA-06 + synchronized IO captures","reason":"Direct IO evidence needed before naming physical classes","notes":"U-006"},
        ],
    )

    (DOCS / "dks_runtime_validation_plan_v1.md").write_text(build_plan_md(stamp), encoding="utf-8")
    (DOCS / "dks_v1_to_v2_validation_roadmap.md").write_text(build_roadmap_md(stamp, conf), encoding="utf-8")

    print("Wrote docs/dks_runtime_validation_plan_v1.md")
    print("Wrote docs/dks_runtime_validation_matrix.csv")
    print("Wrote docs/dks_xdata_watchlist_v2.csv")
    print("Wrote docs/dks_function_watchlist_v2.csv")
    print("Wrote docs/dks_packet_capture_schema.csv")
    print("Wrote docs/dks_io_capture_schema.csv")
    print("Wrote docs/dks_bench_result_import_template.csv")
    print("Wrote docs/dks_validation_confidence_uplift.csv")
    print("Wrote docs/dks_v1_to_v2_validation_roadmap.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
