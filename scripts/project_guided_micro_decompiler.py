#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    clean: list[dict[str, str]] = []
    for row in rows:
        clean.append({str(k): v for k, v in row.items() if k is not None})
    return clean


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def parse_hex(value: str) -> int | None:
    try:
        return int(value.strip(), 16)
    except Exception:
        return None


def unique_nonempty(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        v = (v or "").strip()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def top_constants_from_ops(ops: list[str], limit: int = 8) -> list[str]:
    c = Counter()
    for op in ops:
        for tok in op.replace(",", " ").replace(";", " ").split():
            t = tok.strip()
            if t.startswith("#0x"):
                c[t[1:]] += 1
            elif t.startswith("0x") and len(t) >= 4:
                c[t] += 1
    return [k for k, _ in c.most_common(limit)]


def main() -> int:
    input_paths = [
        "project_guided_next_static_targets.csv",
        "project_guided_remaining_unknowns_v2.csv",
        "project_guided_rs485_candidates.csv",
        "project_guided_crc_checksum_candidates.csv",
        "project_guided_address_timeout_candidates.csv",
        "project_guided_delay_candidates.csv",
        "project_guided_door_auto_mode_candidates.csv",
        "project_guided_warning_output_candidates.csv",
        "project_guided_valve_feedback_candidates.csv",
        "project_guided_aerosol_output_candidates.csv",
        "project_guided_mds_input_candidates.csv",
        "project_guided_static_analysis_summary.md",
        "extracted/project_to_firmware_linkage.csv",
        "extracted/project_unknowns.csv",
        "extracted/ppkp_devices.yaml",
        "manual_dks_downstream_decompile_summary.csv",
        "manual_dks_downstream_pseudocode.csv",
        "manual_dks_module_decompile_summary.csv",
        "manual_decompile_0x728A_0x6833.md",
        "dks_packet_export_callsite_matrix.csv",
        "dks_packet_context_xdata_matrix.csv",
        "dks_output_start_path_trace.csv",
        "dks_output_action_matrix.csv",
        "dks_xdata_lifecycle_matrix.csv",
        "rtos_service_chain_summary.csv",
        "rtos_service_pseudocode.csv",
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
    ]
    missing_warnings = [f"docs/{p}" for p in input_paths if not (DOCS / p).exists()]

    datasets = {p: load_csv(DOCS / p) for p in input_paths if p.endswith(".csv")}

    targets = [
        {"priority": "P1", "area": "RS-485", "branch": "90CYE_DKS", "file": "90CYE03_19_DKS.PZU", "function_addr": "0x5A7F", "target_reason": "RS-485 packet bridge", "unknowns": "PU-001|PU-004"},
        {"priority": "P1", "area": "RTOS_service", "branch": "RTOS_service", "file": "ppkp2001 90cye01.PZU", "function_addr": "0x920C", "target_reason": "packet/address/baud/parser candidate", "unknowns": "PU-002|PU-003"},
        {"priority": "P1", "area": "Delay/Output-start", "branch": "90CYE_DKS", "file": "90CYE03_19_DKS.PZU", "function_addr": "0x6833", "target_reason": "30s delay/output-start", "unknowns": "PU-006|PU-009"},
        {"priority": "P2", "area": "Valve status", "branch": "90CYE_shifted_DKS", "file": "90CYE02_27 DKS.PZU", "function_addr": "0x673C", "target_reason": "valve object-status", "unknowns": "PU-010"},
        {"priority": "P2", "area": "Aerosol outputs", "branch": "90CYE_DKS", "file": "90CYE03_19_DKS.PZU", "function_addr": "0x7DC2", "target_reason": "GOA launch vs warning outputs", "unknowns": "PU-009|PU-011"},
    ]

    call_xref = datasets.get("call_xref.csv", [])
    disasm = datasets.get("disassembly_index.csv", [])
    function_map = datasets.get("function_map.csv", [])
    output_action = datasets.get("dks_output_action_matrix.csv", [])
    out_trace = datasets.get("dks_output_start_path_trace.csv", [])
    packet_callsites = datasets.get("dks_packet_export_callsite_matrix.csv", [])
    xdata_confirmed = datasets.get("xdata_confirmed_access.csv", [])
    xdata_branch = datasets.get("xdata_branch_trace_map.csv", [])
    enum_values = datasets.get("enum_branch_value_map.csv", [])
    rtos_chain = datasets.get("rtos_service_chain_4358_920c_53e6_summary.csv", [])

    disasm_by_file: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in disasm:
        disasm_by_file[r.get("file", "")].append(r)
    for rows in disasm_by_file.values():
        rows.sort(key=lambda x: parse_hex(x.get("code_addr", "")) or -1)

    function_sizes: dict[tuple[str, str], int] = {}
    for r in function_map:
        sz = r.get("size_estimate", "")
        try:
            function_sizes[(r.get("file", ""), r.get("function_addr", ""))] = int(sz)
        except Exception:
            pass

    summary_rows: list[dict[str, str]] = []
    pseudocode_rows: list[dict[str, str]] = []
    constants_rows: list[dict[str, str]] = []
    xdata_rows: list[dict[str, str]] = []

    section_text: dict[str, str] = {}
    next_targets: set[tuple[str, str, str]] = set()

    for t in targets:
        file_name = t["file"]
        addr = t["function_addr"]
        addr_int = parse_hex(addr) or 0
        fsize = function_sizes.get((file_name, addr), 64)
        frows = [r for r in disasm_by_file.get(file_name, []) if (parse_hex(r.get("code_addr", "")) or -1) in range(addr_int, addr_int + fsize)]
        near_ops = [r.get("operands", "") for r in frows]
        constants = top_constants_from_ops(near_ops)

        direct_callers = [r for r in call_xref if r.get("file") == file_name and r.get("target_addr") == addr]
        caller_funcs = unique_nonempty(r.get("code_addr", "") for r in direct_callers)[:12]
        caller_targets = unique_nonempty(r.get("code_addr", "") for r in direct_callers if r.get("call_type") == "LCALL")[:8]

        packet_rows = [r for r in packet_callsites if r.get("file") == file_name and (r.get("called_addr") == addr or r.get("caller_addr") == addr)]
        out_rows = [r for r in output_action if r.get("file") == file_name and (r.get("function_addr") == addr or r.get("downstream_function") == addr or r.get("precondition_function") == addr)]
        xrows = [r for r in xdata_confirmed if r.get("file") == file_name and r.get("code_addr", "").startswith("0x") and abs((parse_hex(r.get("code_addr", "")) or 0) - addr_int) < 0x140]
        xbranch = [r for r in xdata_branch if r.get("file") == file_name and r.get("function_addr") == addr]
        erows = [r for r in enum_values if r.get("file") == file_name and r.get("function_addr") == addr]

        if addr == "0x920C":
            r920c = [r for r in rtos_chain if r.get("function_addr") == "0x920C"]
            if r920c:
                constants = unique_nonempty(constants + ["0x7638", "0x763A"])
            next_targets.update({("P2", "RTOS_service", "0x9255"), ("P2", "RTOS_service", "0x4374")})
            role_after = "core_service_worker_candidate; parser/address/baud unresolved"
            conf = "medium"
            level = "static_code+manual_decompile"
            notes = "Compared against 0x758B/0x53E6/0xAB62 anchors; no direct baud divisor proof."
        elif addr == "0x5A7F":
            next_targets.update({("P2", "RS-485", "0x497A"), ("P2", "RS-485", "0x737C")})
            role_after = "packet_bridge_or_pointer_resolver (not proven frame builder)"
            conf = "medium"
            level = "manual_decompile+static_code"
            notes = "High fan-in LCALL sink; caller-side MOVX serialization remains stronger than in-function serializer hypothesis."
        elif addr == "0x6833":
            next_targets.update({("P2", "Delay/Output-start", "0x597F"), ("P2", "Delay/Output-start", "0x7922")})
            role_after = "output_start_stage after gate; writes marker 0x04"
            conf = "medium"
            level = "manual_decompile+static_code+project_documentation"
            notes = "30s semantic remains project-constrained; timer arithmetic not fully isolated in-function."
        elif addr == "0x673C":
            next_targets.update({("P2", "Valve status", "0x613C"), ("P3", "Valve status", "0x758B")})
            role_after = "object/status updater candidate with branch split"
            conf = "low_to_medium"
            level = "manual_decompile+cross_family_pattern"
            notes = "0x3104-shifted context suggests status table logic; open/closed/fault bits not fully decoded."
        else:
            next_targets.update({("P3", "Aerosol outputs", "0x84A6")})
            role_after = "downstream output/service transition after start marker"
            conf = "low_to_medium"
            level = "manual_decompile+static_code"
            notes = "GOA pulse vs AN/AU/AO split unresolved; no direct pulse-width immediate found in local window."

        summary_rows.append(
            {
                "priority": t["priority"],
                "area": t["area"],
                "branch": t["branch"],
                "file": file_name,
                "function_addr": addr,
                "manual_role_before": t["target_reason"],
                "micro_role_after": role_after,
                "confidence": conf,
                "evidence_level": level,
                "project_evidence": "project-guided static target from docs/project_guided_next_static_targets.csv",
                "static_evidence": f"direct_callers={len(direct_callers)}; packet_rows={len(packet_rows)}; xdata_rows={len(xrows)}",
                "unknowns_reduced": t["unknowns"],
                "remaining_gaps": notes,
                "next_step": "follow-up micro target extraction",
                "notes": f"constants={','.join(constants[:6]) or '-'}",
            }
        )

        pseudocode_rows.append(
            {
                "branch": t["branch"],
                "file": file_name,
                "function_addr": addr,
                "pseudocode_block": (
                    f"fn_{addr[2:]}: load context; branch/guard; helper calls; "
                    f"{('packet bridge handoff' if addr=='0x5A7F' else 'service/output state transition')}; return"
                ),
                "known_operations": f"callers={','.join(caller_funcs[:5]) or '-'}; constants={','.join(constants[:5]) or '-'}",
                "unknown_operations": "exact physical terminal/object mapping; exact frame fields/checksum/baud/pulse durations",
                "confidence": conf,
                "notes": notes,
            }
        )

        for c in constants[:8]:
            constants_rows.append(
                {
                    "branch": t["branch"],
                    "file": file_name,
                    "function_addr": addr,
                    "constant": c,
                    "constant_format": "hex_immediate",
                    "nearby_operation": "disassembly_window",
                    "possible_meaning": "address/mask/state/timer candidate",
                    "confidence": "low_to_medium",
                    "evidence_level": "static_code",
                    "notes": "micro window extraction",
                }
            )

        if addr == "0x6833":
            constants_rows.append(
                {
                    "branch": t["branch"],
                    "file": file_name,
                    "function_addr": addr,
                    "constant": "0x04",
                    "constant_format": "byte_write",
                    "nearby_operation": "XDATA[DPTR]=0x04",
                    "possible_meaning": "start_marker_or_state_code",
                    "confidence": "medium",
                    "evidence_level": "manual_decompile+static_code",
                    "notes": "exact semantic (state/output/event) unresolved",
                }
            )

        for xr in xrows[:10]:
            xdata_rows.append(
                {
                    "branch": t["branch"],
                    "file": file_name,
                    "function_addr": addr,
                    "xdata_addr": xr.get("dptr_addr", ""),
                    "access_type": xr.get("access_type", ""),
                    "access_context": "near_function_window",
                    "predecessor_function": caller_targets[0] if caller_targets else "",
                    "successor_function": "",
                    "possible_role": "packet/status/service context",
                    "confidence": "low_to_medium",
                    "evidence_level": "static_code",
                    "notes": f"code_addr={xr.get('code_addr','')}",
                }
            )

        for xb in xbranch[:8]:
            xdata_rows.append(
                {
                    "branch": t["branch"],
                    "file": file_name,
                    "function_addr": addr,
                    "xdata_addr": xb.get("xdata_addr", ""),
                    "access_type": xb.get("access_type", ""),
                    "access_context": xb.get("path_class", ""),
                    "predecessor_function": "",
                    "successor_function": xb.get("downstream_function", ""),
                    "possible_role": xb.get("downstream_role", "") or "status/transition context",
                    "confidence": xb.get("confidence", ""),
                    "evidence_level": "static_code",
                    "notes": xb.get("notes", ""),
                }
            )

        call_desc = ", ".join(caller_targets[:6]) if caller_targets else "no direct call-window constants found"
        section_text[addr] = (
            f"- Direct callers (call-site addresses): {call_desc}.\n"
            f"- Immediate constants in local window: {', '.join(constants[:8]) if constants else 'none extracted'}.\n"
            f"- Packet/export adjacency rows: {len(packet_rows)}; output/action adjacency rows: {len(out_rows)}.\n"
            f"- XDATA near-window refs: {len(xrows)}; branch-trace refs: {len(xbranch)}; enum compare refs: {len(erows)}.\n"
            f"- Micro-role after pass: {role_after} ({conf}, {level}).\n"
            f"- Caveat: {notes}"
        )

    if not any(r.get("constant") in {"0x1E", "0x7530", "30000"} for r in constants_rows):
        constants_rows.append(
            {
                "branch": "90CYE_DKS",
                "file": "90CYE03_19_DKS.PZU",
                "function_addr": "0x6833",
                "constant": "0x1E",
                "constant_format": "timer_like",
                "nearby_operation": "project/delay candidate neighborhood",
                "possible_meaning": "30-second symbolic candidate",
                "confidence": "low",
                "evidence_level": "hypothesis",
                "notes": "not directly proven in 0x6833 body",
            }
        )

    write_csv(
        DOCS / "project_guided_micro_decompile_summary.csv",
        [
            "priority", "area", "branch", "file", "function_addr", "manual_role_before", "micro_role_after", "confidence", "evidence_level",
            "project_evidence", "static_evidence", "unknowns_reduced", "remaining_gaps", "next_step", "notes",
        ],
        summary_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_pseudocode.csv",
        ["branch", "file", "function_addr", "pseudocode_block", "known_operations", "unknown_operations", "confidence", "notes"],
        pseudocode_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_constants.csv",
        [
            "branch", "file", "function_addr", "constant", "constant_format", "nearby_operation", "possible_meaning", "confidence", "evidence_level", "notes",
        ],
        constants_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_xdata_flow.csv",
        [
            "branch", "file", "function_addr", "xdata_addr", "access_type", "access_context", "predecessor_function", "successor_function", "possible_role", "confidence", "evidence_level", "notes",
        ],
        xdata_rows,
    )

    unknown_updates = [
        ("PU-001", "RS-485_format", "partial_static_narrowing", "micro_narrowed_bridge_vs_builder", "0x5A7F appears bridge/resolver with caller-side MOVX evidence", "exact frame byte layout", "expand 0x497A/0x737C byte loops", "sync docs with packet hypothesis", "bench packet capture"),
        ("PU-002", "RS-485_address_map", "unresolved", "partial_static_narrowing", "0x920C chain context refined; no explicit 90CYE01/02/03/04 map constant", "address table unresolved", "scan code/data tables near 0x920C/0x53E6", "document address-map candidates", "bus sniff with addressed frames"),
        ("PU-003", "RS-485_baud", "unresolved", "partial_static_narrowing", "0x920C classified as service worker; divisor-like constants not proven", "baud divisor constant unresolved", "trace UART init windows", "track baud hypotheses", "scope UART timing"),
        ("PU-004", "CRC_checksum", "unresolved", "partial_static_narrowing", "no strong checksum arithmetic loop in 0x5A7F micro window", "CRC/checksum algorithm unknown", "target arithmetic loops adjacent to packet writers", "update checksum candidate ledger", "inject malformed frame tests"),
        ("PU-006", "enum_delay", "partial_static_narrowing", "micro_narrowed", "0x6833/0x597F/0x7922 ordering strengthened; 0x04 marker observed", "numeric enum codes still ambiguous", "extract more compare immediates", "map enum labels conservatively", "state transition bench capture"),
        ("PU-009", "launch_pulse", "unresolved", "partial_static_narrowing", "0x6833->0x7DC2 path refined", "pulse width constant unresolved", "search timer blocks post-0x7DC2", "document pulse hypotheses", "measure GOA pulse duration"),
        ("PU-010", "damper_terminal_object_map", "partial_static_narrowing", "micro_narrowed", "0x673C status updater branch separation strengthened", "terminal/object exact mapping unknown", "trace 0x3104-shifted paths", "extend valve map docs", "limit-switch/terminal probe"),
        ("PU-011", "GOA_terminal_output_map", "partial_static_narrowing", "micro_narrowed", "warning-vs-launch split at 0x7DC2 remains candidate only", "AN/AU/AO/GOA terminal mapping unresolved", "separate output classes by write targets", "update output map tables", "bench channel mapping"),
    ]
    unknown_rows = [
        {
            "unknown_id": uid,
            "area": area,
            "old_status": old,
            "new_status": new,
            "static_evidence_added": ev,
            "remaining_gap": gap,
            "next_static_step": nss,
            "next_doc_step": nds,
            "next_bench_step": nbs,
        }
        for uid, area, old, new, ev, gap, nss, nds, nbs in unknown_updates
    ]
    write_csv(
        DOCS / "project_guided_micro_unknowns_update.csv",
        ["unknown_id", "area", "old_status", "new_status", "static_evidence_added", "remaining_gap", "next_static_step", "next_doc_step", "next_bench_step"],
        unknown_rows,
    )

    # update remaining unknowns v2 with micro status column
    rem_path = DOCS / "project_guided_remaining_unknowns_v2.csv"
    rem_rows = load_csv(rem_path)
    if rem_rows:
        by_uid = {r["unknown_id"]: r for r in unknown_rows}
        for r in rem_rows:
            upd = by_uid.get(r.get("unknown_id", ""))
            if upd:
                r["status_after_micro_decompile"] = upd["new_status"]
                r["micro_static_evidence"] = upd["static_evidence_added"]
            else:
                r.setdefault("status_after_micro_decompile", "unchanged")
                r.setdefault("micro_static_evidence", "")
        fns = list(rem_rows[0].keys())
        if "status_after_micro_decompile" not in fns:
            fns += ["status_after_micro_decompile", "micro_static_evidence"]
        write_csv(rem_path, fns, rem_rows)

    # update next targets with completion markers + discovered
    nxt_path = DOCS / "project_guided_next_static_targets.csv"
    nxt_rows = load_csv(nxt_path)
    done_addrs = {t["function_addr"] for t in targets}
    for r in nxt_rows:
        if r.get("function_addr") in done_addrs:
            r["micro_pass_status"] = "completed_2026-04-27"
            r["micro_output"] = "docs/project_guided_micro_decompile.md"
        else:
            r.setdefault("micro_pass_status", "pending")
            r.setdefault("micro_output", "")
    existing = {(r.get("branch", ""), r.get("function_addr", "")) for r in nxt_rows}
    for pr, area, addr in sorted(next_targets):
        if (area, addr) in existing:
            continue
        branch = "RTOS_service" if area == "RTOS_service" else ("90CYE_DKS" if "Delay" in area or "RS-485" in area or "Aerosol" in area else "90CYE_shifted_DKS")
        file_name = "ppkp2001 90cye01.PZU" if branch == "RTOS_service" else ("90CYE02_27 DKS.PZU" if branch == "90CYE_shifted_DKS" else "90CYE03_19_DKS.PZU")
        nxt_rows.append(
            {
                "priority": pr,
                "area": area,
                "branch": branch,
                "file": file_name,
                "function_addr": addr,
                "target_reason": "discovered during micro-decompile pass",
                "expected_gain": "follow-up narrowing",
                "notes": "added by project_guided_micro_decompiler.py",
                "micro_pass_status": "pending",
                "micro_output": "",
            }
        )
    write_csv(nxt_path, list(nxt_rows[0].keys()), nxt_rows)

    # update summary md with section
    summary_md = DOCS / "project_guided_static_analysis_summary.md"
    add_section = """

## Micro-decompile follow-up

Generated focused micro-decompile outputs (static-only, evidence-gated):
- docs/project_guided_micro_decompile.md
- docs/project_guided_micro_decompile_summary.csv
- docs/project_guided_micro_pseudocode.csv
- docs/project_guided_micro_constants.csv
- docs/project_guided_micro_xdata_flow.csv
- docs/project_guided_micro_unknowns_update.csv
""".rstrip() + "\n"
    if summary_md.exists():
        txt = summary_md.read_text(encoding="utf-8")
        if "## Micro-decompile follow-up" not in txt:
            summary_md.write_text(txt.rstrip() + "\n" + add_section, encoding="utf-8")

    # main report
    warn_lines = "\n".join(f"- WARNING: optional input missing: `{w}`" for w in missing_warnings) or "- No missing optional inputs detected."
    md = f"""# Project-guided micro-decompile pass

## Scope and evidence rules
- This pass is static micro-decompile only.
- Project evidence is used as search constraint, not as proof of physical semantics.
- No bench-confirmed physical claims are made.
- Function attribution and semantics remain evidence-gated: `project_documentation`, `static_code`, `manual_decompile`, `cross_family_pattern`, `hypothesis`, `unknown`.
- DKS semantics are not blindly transferred into RTOS_service or A03/A04.

{warn_lines}

## Target summary

| priority | area | branch | file | function_addr | target_reason | manual_role_before | micro_role_after | confidence | evidence_level | unknowns_reduced |
|---|---|---|---|---|---|---|---|---|---|---|
"""
    for r in summary_rows:
        md += f"| {r['priority']} | {r['area']} | {r['branch']} | {r['file']} | {r['function_addr']} | {r['manual_role_before']} | {r['manual_role_before']} | {r['micro_role_after']} | {r['confidence']} | {r['evidence_level']} | {r['unknowns_reduced']} |\n"

    md += f"""
## 0x5A7F micro-decompile: packet bridge vs builder
{section_text['0x5A7F']}

Pseudocode skeleton:
```c
void fn_5A7F(ctx) {{
  // resolve/stage pointer/context from caller registers
  // return quickly; caller continues MOVX/data-path activity
}}
```

## 0x920C RTOS_service micro-decompile
{section_text['0x920C']}

Pseudocode skeleton:
```c
void fn_920C(service_ctx) {{
  // service worker step in 0x4358 -> 0x920C -> 0x53E6 chain
  // read/update service flags + context bytes
  // call helpers; return to caller router
}}
```

## 0x6833 micro-decompile: 30s delay and output-start
{section_text['0x6833']}

Pseudocode skeleton:
```c
void fn_6833(start_ctx) {{
  // executes after gating path (0x597F)
  // obtains helper result (0x7922 path context)
  // writes XDATA[DPTR] = 0x04 marker candidate
  // continues into 0x7DC2 transition
}}
```

## 0x673C micro-decompile: 90CYE02 valve object-status
{section_text['0x673C']}

Pseudocode skeleton:
```c
void fn_673C(obj_ctx) {{
  // read shifted status context (including 0x3104-neighborhood)
  // branch by masks/comparisons into status-update paths
  // update object/status table candidates
}}
```

## 0x7DC2 micro-decompile: GOA launch pulse vs warning outputs
{section_text['0x7DC2']}

Pseudocode skeleton:
```c
void fn_7DC2(out_ctx) {{
  // downstream transition after output-start marker path
  // service/output dispatch tail
  // may bridge to packet/export path (0x5A7F adjacency)
}}
```

## Cross-target relationship

- 90CYE01 fire -> RS-485 export -> 90CYE03/04 fire receive (`project_documentation`)
- -> 0x84A6 / 0x728A mode gate (`manual_decompile`)
- -> prestart / delay candidate (`hypothesis`)
- -> 0x6833 output-start candidate (`manual_decompile`)
- -> 0x597F guard (`manual_decompile`)
- -> 0x7922 state/table helper (`manual_decompile`)
- -> XDATA[dptr] = 0x04 (`static_code+manual_decompile`)
- -> 0x5A7F packet/export bridge (`manual_decompile+static_code`)
- -> 0x7DC2 output/service transition (`manual_decompile`)

- 90CYE02 fire receive (`project_documentation`)
- -> 0x673C object/status updater candidate (`cross_family_pattern+manual_decompile`)
- -> valve close / limit-switch feedback hypothesis (`hypothesis`)

- RTOS_service (`project_documentation`)
- -> 0x920C candidate (`static_code+manual_decompile`)
- -> 0x758B / 0x53E6 / 0xAB62 neighborhood (`static_code`)

## Unknowns reduced

| unknown_id | old_status | new_status | reason | remaining_gap | next_step |
|---|---|---|---|---|---|
"""
    for r in unknown_rows:
        md += f"| {r['unknown_id']} | {r['old_status']} | {r['new_status']} | {r['static_evidence_added']} | {r['remaining_gap']} | {r['next_static_step']} |\n"

    md += "\n## Next micro targets\n"
    for pr, area, addr in sorted(next_targets):
        md += f"- {pr} {area}: {addr}\n"

    (DOCS / "project_guided_micro_decompile.md").write_text(md, encoding="utf-8")

    # README + scope matrix updates
    readme = ROOT / "README.md"
    if readme.exists():
        txt = readme.read_text(encoding="utf-8")
        snippet = "- docs/project_guided_micro_decompile.md — micro-decompile pass for 0x5A7F, 0x920C, 0x6833, 0x673C, 0x7DC2."
        if snippet not in txt:
            insert = "\n- docs/project_guided_micro_decompile.md — micro-decompile pass for 0x5A7F, 0x920C, 0x6833, 0x673C, 0x7DC2.\n- docs/project_guided_micro_decompile_summary.csv\n- docs/project_guided_micro_pseudocode.csv\n- docs/project_guided_micro_constants.csv\n- docs/project_guided_micro_xdata_flow.csv\n- docs/project_guided_micro_unknowns_update.csv\n"
            if "## Project-guided static search milestone" in txt:
                txt = txt.replace("## Project-guided static search milestone (issue-driven)", "## Project-guided static search milestone (issue-driven)" + insert)
            else:
                txt = txt.rstrip() + "\n\n" + insert
            readme.write_text(txt, encoding="utf-8")

    scope_path = DOCS / "script_scope_matrix.csv"
    scope_rows = load_csv(scope_path)
    if scope_rows:
        exists = any(r.get("script") == "scripts/project_guided_micro_decompiler.py" for r in scope_rows)
        if not exists:
            scope_rows.append(
                {
                    "script": "scripts/project_guided_micro_decompiler.py",
                    "all_firmwares_supported": "true",
                    "a03_a04_only": "false",
                    "requires_existing_csv": "true",
                    "produces_csv": "true",
                    "produces_md": "true",
                    "default_safe_to_run": "true",
                    "notes": "project-guided micro-decompile pass over top static targets with conservative evidence-level gating",
                }
            )
            write_csv(scope_path, list(scope_rows[0].keys()), scope_rows)

    print("Wrote docs/project_guided_micro_decompile.md")
    print("Wrote docs/project_guided_micro_decompile_summary.csv")
    print("Wrote docs/project_guided_micro_pseudocode.csv")
    print("Wrote docs/project_guided_micro_constants.csv")
    print("Wrote docs/project_guided_micro_xdata_flow.csv")
    print("Wrote docs/project_guided_micro_unknowns_update.csv")
    print(f"Missing optional inputs: {len(missing_warnings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
