#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


TARGETS = [
    {
        "priority": "P2",
        "area": "Delay/Output-start",
        "branch": "90CYE_DKS",
        "file": "90CYE03_19_DKS.PZU",
        "function_addr": "0x597F",
        "target_reason": "compact helper around 0x6833 start path",
        "unknowns": "PU-006|PU-009",
    },
    {
        "priority": "P2",
        "area": "Delay/Output-start",
        "branch": "90CYE_DKS",
        "file": "90CYE03_19_DKS.PZU",
        "function_addr": "0x7922",
        "target_reason": "two-byte helper in 0x6833/0x728A path",
        "unknowns": "PU-006|PU-009",
    },
    {
        "priority": "P2",
        "area": "RS-485 / runtime bridge",
        "branch": "90CYE_DKS",
        "file": "90CYE03_19_DKS.PZU",
        "function_addr": "0x497A",
        "target_reason": "byte-loop expansion around 0x5A7F caller windows",
        "unknowns": "PU-001|PU-004",
    },
    {
        "priority": "P2",
        "area": "Zone/object",
        "branch": "90CYE_DKS",
        "file": "90CYE03_19_DKS.PZU",
        "function_addr": "0x737C",
        "target_reason": "zone/object event/state path feeding 0x84A6 and 0x5A7F",
        "unknowns": "PU-010|PU-011",
    },
    {
        "priority": "P3",
        "area": "Mode/event bridge",
        "branch": "90CYE_DKS",
        "file": "90CYE03_19_DKS.PZU",
        "function_addr": "0x84A6",
        "target_reason": "mode/context bridge to 0x728A and packet bridge",
        "unknowns": "PU-009|PU-011",
    },
    {
        "priority": "P2",
        "area": "RTOS_service",
        "branch": "RTOS_service",
        "file": "ppkp2001 90cye01.PZU",
        "function_addr": "0x4374",
        "target_reason": "caller/router around 0x920C",
        "unknowns": "PU-002|PU-003|PU-004",
    },
    {
        "priority": "P2",
        "area": "RTOS_service",
        "branch": "RTOS_service",
        "file": "ppkp2001 90cye01.PZU",
        "function_addr": "0x9255",
        "target_reason": "post-0x920C helper continuation",
        "unknowns": "PU-002|PU-003|PU-004",
    },
    {
        "priority": "P2",
        "area": "RTOS_service",
        "branch": "RTOS_service",
        "file": "ppkp2001 90cye01.PZU",
        "function_addr": "0x758B",
        "target_reason": "high-fanout RTOS dispatcher XDATA timeline",
        "unknowns": "PU-002|PU-003|PU-006",
    },
    {
        "priority": "P2",
        "area": "Shifted status bridge",
        "branch": "90CYE_shifted_DKS",
        "file": "90CYE02_27 DKS.PZU",
        "function_addr": "0x613C",
        "target_reason": "shifted_DKS follow-up for status/valve path",
        "unknowns": "PU-010",
    },
]

REQUIRED_INPUTS = [
    "project_guided_next_static_targets.csv",
    "function_map.csv",
    "basic_block_map.csv",
    "disassembly_index.csv",
    "call_xref.csv",
    "xdata_confirmed_access.csv",
    "xdata_xref.csv",
    "xdata_branch_trace_map.csv",
    "enum_branch_value_map.csv",
    "code_table_candidates.csv",
    "string_index.csv",
    "output_transition_map.csv",
    "output_control_candidates.csv",
    "manual_dks_downstream_decompile_summary.csv",
    "manual_dks_downstream_pseudocode.csv",
    "manual_dks_module_decompile_summary.csv",
    "dks_xdata_lifecycle_matrix.csv",
    "dks_packet_export_callsite_matrix.csv",
    "project_guided_micro_decompile_summary.csv",
    "project_guided_micro_xdata_flow.csv",
    "project_guided_micro_constants.csv",
    "project_guided_micro_unknowns_update.csv",
    "rtos_service_chain_summary.csv",
    "rtos_service_pseudocode.csv",
    "shifted_v2_xdata_offset_matrix.csv",
    "shifted_v2_function_anchor_map.csv",
    "project_to_firmware_linkage.csv",
]


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return [{str(k): v for k, v in row.items() if k is not None} for row in csv.DictReader(f)]


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def parse_hex(v: str) -> int | None:
    try:
        return int(v.strip(), 16)
    except Exception:
        return None


def uniq(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for x in values:
        y = (x or "").strip()
        if y and y not in seen:
            seen.add(y)
            out.append(y)
    return out


def function_window(disasm_rows: list[dict[str, str]], start_hex: str, size_estimate: int) -> list[dict[str, str]]:
    start = parse_hex(start_hex) or 0
    limit = start + max(8, min(size_estimate, 0x500))
    return [r for r in disasm_rows if (parse_hex(r.get("code_addr", "")) or -1) in range(start, limit)]


def top_consts(rows: list[dict[str, str]], limit: int = 12) -> list[str]:
    c = Counter()
    for r in rows:
        ops = (r.get("operands") or "").replace(",", " ").replace(";", " ").split()
        for t in ops:
            if t.startswith("#0x"):
                c[t[1:]] += 1
            elif t.startswith("0x") and len(t) >= 4:
                c[t] += 1
    return [k for k, _ in c.most_common(limit)]


def main() -> int:
    datasets: dict[str, list[dict[str, str]]] = {}
    missing: list[str] = []
    for name in REQUIRED_INPUTS:
        p = DOCS / name
        if not p.exists() and name == "project_to_firmware_linkage.csv":
            p = DOCS / "extracted" / "project_to_firmware_linkage.csv"
        rows = load_csv(p)
        if not rows and not p.exists():
            missing.append(str(p.relative_to(ROOT)))
        datasets[name] = rows

    disasm = datasets["disassembly_index.csv"]
    fx = datasets["function_map.csv"]
    call_xref = datasets["call_xref.csv"]
    xacc = datasets["xdata_confirmed_access.csv"]
    xbranch = datasets["xdata_branch_trace_map.csv"]
    enum_map = datasets["enum_branch_value_map.csv"]
    out_map = datasets["output_transition_map.csv"]
    packet_calls = datasets["dks_packet_export_callsite_matrix.csv"]
    manual_down_sum = datasets["manual_dks_downstream_decompile_summary.csv"]
    manual_down_ps = datasets["manual_dks_downstream_pseudocode.csv"]
    rtos_chain = datasets["rtos_service_chain_summary.csv"]
    shifted_anchor = datasets["shifted_v2_function_anchor_map.csv"]

    disasm_by_file: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in disasm:
        disasm_by_file[r.get("file", "")].append(r)
    for rows in disasm_by_file.values():
        rows.sort(key=lambda r: parse_hex(r.get("code_addr", "")) or -1)

    fsize: dict[tuple[str, str], int] = {}
    for r in fx:
        try:
            fsize[(r.get("file", ""), r.get("function_addr", ""))] = int(r.get("size_estimate", "0"))
        except Exception:
            pass

    manual_summary = {(r.get("file", ""), r.get("function_addr", "")): r for r in manual_down_sum}
    manual_ps = {(r.get("file", ""), r.get("function_addr", "")): r for r in manual_down_ps}

    summary_rows: list[dict[str, str]] = []
    pseudocode_rows: list[dict[str, str]] = []
    constants_rows: list[dict[str, str]] = []
    xflow_rows: list[dict[str, str]] = []
    callsite_rows: list[dict[str, str]] = []
    section: dict[str, str] = {}

    for t in TARGETS:
        file = t["file"]
        addr = t["function_addr"]
        branch = t["branch"]
        start = parse_hex(addr) or 0
        frows = function_window(disasm_by_file.get(file, []), addr, fsize.get((file, addr), 0x120))
        callers = [r for r in call_xref if r.get("file") == file and r.get("target_addr") == addr]
        caller_list = uniq(r.get("code_addr", "") for r in callers)
        callees = [r for r in call_xref if r.get("file") == file and (parse_hex(r.get("code_addr", "")) or -1) in range(start, start + max(8, min(fsize.get((file, addr), 0x120), 0x500)))]
        callee_list = uniq(r.get("target_addr", "") for r in callees)

        local_x = [
            r for r in xacc
            if r.get("file") == file and abs((parse_hex(r.get("code_addr", "")) or 0) - start) <= 0x280
        ]
        local_branch_x = [r for r in xbranch if r.get("file") == file and r.get("function_addr") == addr]
        local_enum = [r for r in enum_map if r.get("file") == file and r.get("function_addr") == addr]
        local_out = [r for r in out_map if r.get("file") == file and r.get("function_addr") == addr]
        local_packets = [r for r in packet_calls if r.get("file") == file and (r.get("caller_addr") == addr or r.get("called_addr") == addr)]
        consts = top_consts(frows)

        micro_role = "unknown"
        conf = "low"
        level = "unknown"
        unknown_reduced = t["unknowns"]
        notes = ""
        if addr == "0x597F":
            micro_role = "bitmask_guard_helper (returns A & 0x07)"
            conf = "probable"
            level = "manual_decompile+static_code"
            notes = "No XDATA access in helper body; caller-side meaning (permission/mode/fault) remains unresolved."
        elif addr == "0x7922":
            micro_role = "two_byte_xdata_pair_reader (R0/R1)"
            conf = "probable"
            level = "manual_decompile+static_code"
            notes = "Confirmed MOVX->R0, INC DPTR, MOVX->R1 pattern; table semantic remains context-dependent."
        elif addr == "0x497A":
            micro_role = "shared_runtime_dispatcher_with_packet_bridge_adjacency"
            conf = "medium"
            level = "manual_decompile+static_code+project_documentation"
            notes = "Many callsites into 0x5A7F exist; caller-side loops/state fanout dominate over in-body serializer proof."
        elif addr == "0x737C":
            micro_role = "zone_object_state_update_plus_event_bridge_adjacency"
            conf = "medium"
            level = "manual_decompile+static_code"
            notes = "Touches 0x3010..0x301B and reads 0x31BF/0x36xx cluster before calling 0x84A6 and 0x5A7F."
        elif addr == "0x84A6":
            micro_role = "mode_context_bridge_to_0x728A_and_0x5A7F"
            conf = "low_to_medium"
            level = "manual_decompile+static_code+hypothesis"
            notes = "Mode/event bridge plausible from XDATA cluster 0x315B/0x3181/0x3640/0x36D3/0x36D9 but physical mapping stays hypothesis."
        elif addr == "0x4374":
            micro_role = "service_router_init_window_calling_0x920C"
            conf = "medium"
            level = "static_code+manual_decompile"
            notes = "Contains looped MOVX writes and immediate table initialization after 0x920C/0x916D."
        elif addr == "0x9255":
            micro_role = "rtos_service_helper_continuation (snapshot/copy from 0x763A.. into regs)"
            conf = "medium"
            level = "static_code+manual_decompile"
            notes = "Calls 0x53E6 then copies multi-byte XDATA sequence into R6..R1; checksum/baud role not proven."
        elif addr == "0x758B":
            micro_role = "rtos_service_dispatcher_with_state_xdata_timeline"
            conf = "medium"
            level = "static_code+manual_decompile"
            notes = "Writes 0x3011/0x3014 markers, checks 0x66EA mask, updates 0x3010, mirrors 0x6406(+1)."
        elif addr == "0x613C":
            micro_role = "shifted_status_bridge_candidate (not assumed equal to DKS 0x613C)"
            conf = "low_to_medium"
            level = "static_code+cross_family_pattern"
            notes = "Reads 0x32B2 and writes around 0x3108/0x31DD windows; suggests status-bridge logic with shifted mapping."

        summary_rows.append(
            {
                "priority": t["priority"],
                "area": t["area"],
                "branch": branch,
                "file": file,
                "function_addr": addr,
                "micro_role_after": micro_role,
                "confidence": conf,
                "evidence_level": level,
                "project_evidence": "targeted follow-up from project_guided_next_static_targets.csv",
                "static_evidence": f"callers={len(caller_list)};callees={len(callee_list)};xdata={len(local_x)};enum={len(local_enum)}",
                "unknowns_reduced": unknown_reduced,
                "remaining_gaps": notes,
                "next_step": "deepen callsite windows / helper context extraction",
                "notes": f"constants={','.join(consts[:8]) or '-'}",
            }
        )

        pseudocode = (manual_ps.get((file, addr), {}) or {}).get("pseudocode_block") or (
            f"void fn_{addr[2:]}(...) {{ /* branch helper / state transition / call fanout */ }}"
        )
        pseudocode_rows.append(
            {
                "branch": branch,
                "file": file,
                "function_addr": addr,
                "pseudocode_block": pseudocode,
                "known_operations": (manual_ps.get((file, addr), {}) or {}).get("known_operations", "call/context/xdata evidence from static window"),
                "unknown_operations": (manual_ps.get((file, addr), {}) or {}).get("unknown_operations", "exact physical semantics unresolved"),
                "confidence": conf,
                "notes": notes,
            }
        )

        for c in consts[:10]:
            constants_rows.append(
                {
                    "branch": branch,
                    "file": file,
                    "function_addr": addr,
                    "constant": c,
                    "constant_format": "hex_immediate",
                    "nearby_operation": "disassembly_local_window",
                    "possible_meaning": "mask/table/xdata selector",
                    "confidence": "low_to_medium",
                    "evidence_level": "static_code",
                    "notes": "pass2 constant extraction",
                }
            )

        for xr in local_x[:16]:
            xflow_rows.append(
                {
                    "branch": branch,
                    "file": file,
                    "function_addr": addr,
                    "xdata_addr": xr.get("dptr_addr", ""),
                    "access_type": xr.get("access_type", ""),
                    "access_context": "near_function_window",
                    "predecessor_function": caller_list[0] if caller_list else "",
                    "successor_function": callee_list[0] if callee_list else "",
                    "possible_role": "state/context/packet/service",
                    "confidence": xr.get("confidence", "low"),
                    "evidence_level": "static_code",
                    "notes": f"code_addr={xr.get('code_addr','')}",
                }
            )

        for xb in local_branch_x:
            xflow_rows.append(
                {
                    "branch": branch,
                    "file": file,
                    "function_addr": addr,
                    "xdata_addr": xb.get("xdata_addr", ""),
                    "access_type": xb.get("access_type", ""),
                    "access_context": xb.get("path_class", ""),
                    "predecessor_function": "",
                    "successor_function": xb.get("downstream_function", ""),
                    "possible_role": xb.get("downstream_role", "") or "state branch",
                    "confidence": xb.get("confidence", "low"),
                    "evidence_level": "static_code",
                    "notes": xb.get("notes", ""),
                }
            )

        for cr in callers[:16]:
            callsite_rows.append(
                {
                    "branch": branch,
                    "file": file,
                    "function_addr": addr,
                    "caller_addr": cr.get("code_addr", ""),
                    "callee_addr": addr,
                    "call_context": "direct_call_xref",
                    "pre_call_setup": "context-dependent",
                    "post_call_behavior": "returns_to_caller",
                    "confidence": cr.get("confidence", "high"),
                    "evidence_level": "static_code",
                    "notes": "from call_xref.csv",
                }
            )
        for cr in callees[:16]:
            callsite_rows.append(
                {
                    "branch": branch,
                    "file": file,
                    "function_addr": addr,
                    "caller_addr": addr,
                    "callee_addr": cr.get("target_addr", ""),
                    "call_context": "callee_within_function_window",
                    "pre_call_setup": "local-register/xdata context",
                    "post_call_behavior": "continues_local_flow",
                    "confidence": cr.get("confidence", "medium"),
                    "evidence_level": "static_code",
                    "notes": f"code_addr={cr.get('code_addr','')}",
                }
            )

        enum_vals = uniq(r.get("candidate_value", "") for r in local_enum)
        section[addr] = (
            f"- Direct callers: {', '.join(caller_list[:12]) or 'none listed'}.\n"
            f"- Callee targets in local function window: {', '.join(callee_list[:12]) or 'none in bounded window'}.\n"
            f"- Local constants: {', '.join(consts[:12]) or 'none extracted'}.\n"
            f"- XDATA refs (near-window/branch-map): {len(local_x)}/{len(local_branch_x)}.\n"
            f"- Enum compare values in map: {', '.join(enum_vals) if enum_vals else 'none mapped for this function'}.\n"
            f"- Output-transition adjacency rows: {len(local_out)}; packet-callsite adjacency rows: {len(local_packets)}.\n"
            f"- Micro role after pass2: {micro_role} ({conf}; {level}).\n"
            f"- Conservative caveat: {notes}"
        )

    # explicit constants required by questions
    constants_rows.extend(
        [
            {
                "branch": "90CYE_DKS",
                "file": "90CYE03_19_DKS.PZU",
                "function_addr": "0x597F",
                "constant": "0x07",
                "constant_format": "bitmask",
                "nearby_operation": "ANL A,#0x07",
                "possible_meaning": "guard/normalizer mask",
                "confidence": "probable",
                "evidence_level": "static_code+manual_decompile",
                "notes": "exact semantic label unresolved",
            },
            {
                "branch": "RTOS_service",
                "file": "ppkp2001 90cye01.PZU",
                "function_addr": "0x4374",
                "constant": "0x646E",
                "constant_format": "xdata_addr",
                "nearby_operation": "MOV DPTR,#0x646E ; MOVX @DPTR,#0xFF",
                "possible_meaning": "service init flag/cache",
                "confidence": "medium",
                "evidence_level": "static_code",
                "notes": "from direct disassembly window",
            },
        ]
    )

    write_csv(
        DOCS / "project_guided_micro_pass2_summary.csv",
        [
            "priority", "area", "branch", "file", "function_addr", "micro_role_after", "confidence", "evidence_level",
            "project_evidence", "static_evidence", "unknowns_reduced", "remaining_gaps", "next_step", "notes",
        ],
        summary_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_pass2_pseudocode.csv",
        ["branch", "file", "function_addr", "pseudocode_block", "known_operations", "unknown_operations", "confidence", "notes"],
        pseudocode_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_pass2_constants.csv",
        ["branch", "file", "function_addr", "constant", "constant_format", "nearby_operation", "possible_meaning", "confidence", "evidence_level", "notes"],
        constants_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_pass2_xdata_flow.csv",
        ["branch", "file", "function_addr", "xdata_addr", "access_type", "access_context", "predecessor_function", "successor_function", "possible_role", "confidence", "evidence_level", "notes"],
        xflow_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_pass2_callsite_matrix.csv",
        ["branch", "file", "function_addr", "caller_addr", "callee_addr", "call_context", "pre_call_setup", "post_call_behavior", "confidence", "evidence_level", "notes"],
        callsite_rows,
    )

    unknown_rows = [
        {
            "unknown_id": "PU-001", "area": "RS-485_format", "old_status": "micro_narrowed_bridge_vs_builder", "new_status": "pass2_narrowed_dispatch_vs_packet_prep",
            "static_evidence_added": "0x497A/0x737C callsite and transition windows refined near 0x5A7F",
            "remaining_gap": "No explicit serialized frame byte sequence proven in-function", "next_static_step": "expand 0x497A caller blocks around repeated 0x5A7F calls",
            "next_doc_step": "look for protocol field ordering notes", "next_bench_step": "capture frame bytes with state transitions",
        },
        {
            "unknown_id": "PU-002", "area": "RS-485_address_map", "old_status": "partial_static_narrowing", "new_status": "pass2_partial_static_narrowing",
            "static_evidence_added": "RTOS_service 0x4374/0x9255/0x758B windows mapped; no explicit per-device address table confirmed",
            "remaining_gap": "Address map constants still ambiguous", "next_static_step": "trace 0x920C+0x9255 table origins upstream",
            "next_doc_step": "search project docs for RTOS_service address descriptors", "next_bench_step": "isolate bus traffic by module address",
        },
        {
            "unknown_id": "PU-003", "area": "RS-485_baudrate", "old_status": "partial_static_narrowing", "new_status": "pass2_no_baud_proof",
            "static_evidence_added": "No divisor-like arithmetic confirmed in 0x4374/0x9255/0x758B target windows",
            "remaining_gap": "baud/framing constants unresolved", "next_static_step": "scan UART init routines beyond 0x920C chain",
            "next_doc_step": "find commissioning/serial setup pages", "next_bench_step": "measure line timing",
        },
        {
            "unknown_id": "PU-004", "area": "CRC_checksum", "old_status": "partial_static_narrowing", "new_status": "pass2_still_unresolved",
            "static_evidence_added": "0x9255 appears copy/helper, not explicit checksum loop", "remaining_gap": "checksum math/table unresolved",
            "next_static_step": "target arithmetic loops with rotate/xor accumulation", "next_doc_step": "collect checksum hints from protocol docs", "next_bench_step": "inject invalid checksum frames",
        },
        {
            "unknown_id": "PU-006", "area": "numeric_enum_delay", "old_status": "micro_narrowed", "new_status": "pass2_narrowed_helper_roles",
            "static_evidence_added": "0x597F mask helper and 0x7922 pair-reader confirmed; enum meanings still open", "remaining_gap": "enum semantic mapping incomplete",
            "next_static_step": "extend compare-immediate extraction around 0x6833/0x737C", "next_doc_step": "map labels in project tables conservatively", "next_bench_step": "capture state transition timing",
        },
        {
            "unknown_id": "PU-009", "area": "launch_pulse", "old_status": "partial_static_narrowing", "new_status": "pass2_mode_bridge_refined",
            "static_evidence_added": "0x84A6 context bridge to 0x728A/0x5A7F refined without pulse-width proof", "remaining_gap": "launch pulse duration constants unresolved",
            "next_static_step": "search timer blocks downstream of 0x728A/0x7DC2", "next_doc_step": "collect pulse timing references", "next_bench_step": "measure GOA pulse",
        },
        {
            "unknown_id": "PU-010", "area": "damper_terminal_object_map", "old_status": "micro_narrowed", "new_status": "pass2_shifted_bridge_narrowed",
            "static_evidence_added": "0x613C (shifted_DKS) analyzed separately; 0x32B2/0x3108 pathways suggest status bridge", "remaining_gap": "open/closed/fault bit mapping unproven",
            "next_static_step": "trace 0x613C branch exits to output handlers", "next_doc_step": "align object-status labels with shifted addresses", "next_bench_step": "probe valve feedback channels",
        },
        {
            "unknown_id": "PU-011", "area": "GOA_output_map", "old_status": "micro_narrowed", "new_status": "pass2_output_class_split_refined",
            "static_evidence_added": "0x737C state/event table touches separated from 0x84A6 mode bridge context", "remaining_gap": "terminal-level GOA/AN/AU/AO mapping unresolved",
            "next_static_step": "separate write-target classes after 0x5A7F bridge handoff", "next_doc_step": "review output naming conventions", "next_bench_step": "channel mapping on hardware",
        },
    ]
    write_csv(
        DOCS / "project_guided_micro_pass2_unknowns_update.csv",
        ["unknown_id", "area", "old_status", "new_status", "static_evidence_added", "remaining_gap", "next_static_step", "next_doc_step", "next_bench_step"],
        unknown_rows,
    )

    # markdown report
    warn = "\n".join(f"- WARNING: optional input missing: `{w}`" for w in missing) if missing else "- No optional input warnings."
    md = [
        "# Project-guided micro-decompile pass #2",
        "",
        "## Scope",
        "- Static micro-decompile pass #2.",
        "- Project evidence used as constraint only.",
        "- No bench confirmation.",
        "- Families kept separate (DKS / shifted_DKS / RTOS_service).",
        "- DKS semantics were not blindly transferred to RTOS_service.",
        "",
        warn,
        "",
        "## Target summary",
        "",
        "| priority | area | branch | file | function_addr | target_reason | micro_role_after | confidence | evidence_level | unknowns_reduced | next_step |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for t, r in zip(TARGETS, summary_rows):
        md.append(
            f"| {t['priority']} | {t['area']} | {t['branch']} | {t['file']} | {t['function_addr']} | {t['target_reason']} | {r['micro_role_after']} | {r['confidence']} | {r['evidence_level']} | {t['unknowns']} | {r['next_step']} |"
        )

    md.extend(
        [
            "",
            "## 0x597F guard/helper analysis",
            section["0x597F"],
            "- Is it really `A & 0x07`? **Yes, in the direct body window (ANL A,#0x07), with conservative `probable` confidence.**",
            "- What consumes return value? **Caller paths near 0x6833/0x737C via callsites (e.g., 0x5935, 0x7194, 0x73BA) consume masked accumulator context.**",
            "- Output-start/project launch gate relation: **hypothesis only; no direct physical gate claim.**",
            "",
            "## 0x7922 state/table reader analysis",
            section["0x7922"],
            "- Confirmed pseudocode: `MOVX A,@DPTR -> R0; INC DPTR; MOVX A,@DPTR -> R1; RET`.",
            "- DPTR source remains caller-provided; static evidence supports generic pair/table reads in 0x6833/0x728A-adjacent paths.",
            "",
            "## 0x497A byte-loop / packet-prep analysis",
            section["0x497A"],
            "- Caller-side repeated calls into 0x5A7F are visible in transition map/callsite matrices.",
            "- MOVX writes are present in broader function windows, but strict in-body byte-serialization proof remains incomplete.",
            "- Classified as mixed dispatcher + packet bridge adjacency, not hard-labeled packet builder.",
            "",
            "## 0x737C zone/object event-record analysis",
            section["0x737C"],
            "- Evidence supports both state-table updates (`0x3010..0x301B`) and bridge adjacency to packet path (0x5A7F).",
            "- Enum-like compares/masks include `0x03`, `0x07`, and CJNE branches (still hypothesis-level semantics).",
            "",
            "## 0x84A6 mode/event bridge analysis",
            section["0x84A6"],
            "- Exact mode/context XDATA references include `0x315B`, `0x3181`, `0x3640`, `0x36D3`, `0x36D9` (plus broader adjacent context).",
            "- Can feed 0x728A gate inputs and selected packet-bridge context, but door-open/auto-disabled physical semantics remain hypothesis.",
            "",
            "## 0x4374 RTOS_service caller/router analysis",
            section["0x4374"],
            "- Calls 0x920C then executes service-init style loops (MOVX writes around 0x646E/0x67EA/0x785F/0x6FE8 windows).",
            "- Treated as RTOS_service-local router/init path; no DKS semantic transfer.",
            "",
            "## 0x9255 RTOS_service helper analysis",
            section["0x9255"],
            "- Classified as parser/service continuation helper candidate (calls 0x53E6, copies data block from 0x763A..).",
            "- Address/baud/checksum signatures are not proven from this window alone.",
            "",
            "## 0x758B RTOS_service XDATA timeline",
            section["0x758B"],
            "- Timeline shows writes to 0x3011/0x3014, masked check on 0x66EA, conditionally updates 0x3010 and mirrors around 0x6406.",
            "- Fits mixed shared dispatcher/service-role in RTOS_service context.",
            "",
            "## 0x613C shifted_DKS status bridge analysis",
            section["0x613C"],
            "- In 90CYE02 shifted_DKS, 0x613C appears relevant to object/status bridge behavior but is not assumed identical to DKS 0x613C semantics.",
            "- Branch/mask and old/new-state style behavior is plausible; open/closed/fault mapping still unresolved.",
            "",
            "## Unknowns update",
            "- Updated: PU-001, PU-002, PU-003, PU-004, PU-006, PU-009, PU-010, PU-011 in `docs/project_guided_micro_pass2_unknowns_update.csv`.",
            "",
            "## Next targets",
            "- P1: `0x728A` (DKS gate context deepening), `0x920C` (RTOS parser/init boundary confirmation).",
            "- P2: `0x9275` (RTOS_service helper after 0x4374 loop), `0x7773` (shifted_DKS analog table/context).",
            "- P3: `0x73FD` (0x737C caller window refinement).",
            "- blocked_until_docs: project-level protocol/commissioning pages for address/baud framing semantics.",
            "- blocked_until_bench: physical terminal mapping and pulse timing confirmation.",
            "",
        ]
    )
    (DOCS / "project_guided_micro_decompile_pass2.md").write_text("\n".join(md), encoding="utf-8")

    # update static summary doc
    summary_md = DOCS / "project_guided_static_analysis_summary.md"
    pass2_section = (
        "\n## Micro-decompile pass #2\n"
        "\nGenerated artifacts:\n"
        "- docs/project_guided_micro_decompile_pass2.md\n"
        "- docs/project_guided_micro_pass2_summary.csv\n"
        "- docs/project_guided_micro_pass2_pseudocode.csv\n"
        "- docs/project_guided_micro_pass2_constants.csv\n"
        "- docs/project_guided_micro_pass2_xdata_flow.csv\n"
        "- docs/project_guided_micro_pass2_callsite_matrix.csv\n"
        "- docs/project_guided_micro_pass2_unknowns_update.csv\n"
    )
    if summary_md.exists():
        txt = summary_md.read_text(encoding="utf-8")
        if "## Micro-decompile pass #2" not in txt:
            summary_md.write_text(txt.rstrip() + "\n" + pass2_section, encoding="utf-8")

    # update next targets
    nxt_path = DOCS / "project_guided_next_static_targets.csv"
    nxt = load_csv(nxt_path)
    done = {t["function_addr"] for t in TARGETS}
    for r in nxt:
        if r.get("function_addr") in done:
            r["micro_pass_status"] = "completed_pass2_2026-04-27"
            r["micro_output"] = "docs/project_guided_micro_decompile_pass2.md"
    existing = {(r.get("branch", ""), r.get("function_addr", "")) for r in nxt}
    for item in [
        ("P2", "RTOS_service", "RTOS_service", "ppkp2001 90cye01.PZU", "0x9275", "post-0x4374 helper window"),
        ("P2", "Shifted status bridge", "90CYE_shifted_DKS", "90CYE02_27 DKS.PZU", "0x7773", "shifted context branch around 0x32B3"),
        ("P3", "Zone/object", "90CYE_DKS", "90CYE03_19_DKS.PZU", "0x73FD", "caller envelope around 0x737C"),
    ]:
        pr, area, branch, file, addr, reason = item
        if (branch, addr) not in existing:
            nxt.append(
                {
                    "priority": pr,
                    "area": area,
                    "branch": branch,
                    "file": file,
                    "function_addr": addr,
                    "target_reason": reason,
                    "expected_gain": "pass2 follow-up",
                    "notes": "added by project_guided_micro_decompiler_pass2.py",
                    "micro_pass_status": "pending",
                    "micro_output": "",
                }
            )
    write_csv(nxt_path, list(nxt[0].keys()), nxt)

    # update remaining unknowns v2
    rem_path = DOCS / "project_guided_remaining_unknowns_v2.csv"
    rem = load_csv(rem_path)
    by_id = {r["unknown_id"]: r for r in unknown_rows}
    if rem:
        for r in rem:
            u = by_id.get(r.get("unknown_id", ""))
            if u:
                r["status_after_micro_decompile"] = u["new_status"]
                r["micro_static_evidence"] = u["static_evidence_added"]
        write_csv(rem_path, list(rem[0].keys()), rem)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
