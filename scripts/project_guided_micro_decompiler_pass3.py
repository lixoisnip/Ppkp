#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

TARGETS = [
    ("RTOS_service", "ppkp2001 90cye01.PZU", "0x9275", "P2", "RTOS_service"),
    ("90CYE_shifted_DKS", "90CYE02_27 DKS.PZU", "0x7773", "P2", "Shifted status bridge"),
    ("90CYE_DKS", "90CYE03_19_DKS.PZU", "0x73FD", "P3", "Zone/object"),
]

REQUIRED_INPUTS = [
    "project_guided_next_static_targets.csv",
    "project_guided_micro_pass2_unknowns_update.csv",
    "project_guided_micro_decompile_pass2.md",
    "project_guided_micro_pass2_summary.csv",
    "project_guided_micro_pass2_callsite_matrix.csv",
    "project_guided_micro_pass2_xdata_flow.csv",
    "project_guided_micro_pass2_constants.csv",
    "project_guided_micro_decompile_summary.csv",
    "project_guided_micro_xdata_flow.csv",
    "project_guided_micro_constants.csv",
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
    "dks_packet_export_callsite_matrix.csv",
    "dks_output_start_path_trace.csv",
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
        return int((v or "").strip(), 16)
    except Exception:
        return None


def uniq(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in values:
        y = (x or "").strip()
        if y and y not in seen:
            seen.add(y)
            out.append(y)
    return out


def top_consts(dis_rows: list[dict[str, str]], limit: int = 10) -> list[str]:
    c = Counter()
    for r in dis_rows:
        ops = (r.get("operands") or "").replace(",", " ").replace(";", " ").split()
        for t in ops:
            if t.startswith("#0x"):
                c[t[1:]] += 1
            elif t.startswith("0x"):
                c[t] += 1
    return [x for x, _ in c.most_common(limit)]


def function_window(disasm: list[dict[str, str]], start_hex: str, size: int) -> list[dict[str, str]]:
    s = parse_hex(start_hex) or 0
    hi = s + max(0x20, min(size, 0x600))
    return [r for r in disasm if s <= (parse_hex(r.get("code_addr", "")) or -1) < hi]


def replace_or_append_section(md_path: Path, title: str, body_lines: list[str]) -> None:
    text = md_path.read_text(encoding="utf-8") if md_path.exists() else ""
    marker = f"## {title}\n"
    new_block = marker + "\n".join(body_lines).rstrip() + "\n"
    if marker in text:
        start = text.index(marker)
        next_idx = text.find("\n## ", start + len(marker))
        if next_idx == -1:
            text = text[:start] + new_block
        else:
            text = text[:start] + new_block + text[next_idx + 1 :]
    else:
        if text and not text.endswith("\n"):
            text += "\n"
        text += "\n" + new_block
    md_path.write_text(text, encoding="utf-8")


def main() -> int:
    datasets: dict[str, list[dict[str, str]]] = {}
    missing_optional: list[str] = []
    for n in REQUIRED_INPUTS:
        p = DOCS / n
        if not p.exists() and n == "project_to_firmware_linkage.csv":
            p = DOCS / "extracted" / "project_to_firmware_linkage.csv"
        rows = load_csv(p)
        datasets[n] = rows
        if not p.exists():
            missing_optional.append(str(p.relative_to(ROOT)))

    disasm = datasets["disassembly_index.csv"]
    call_xref = datasets["call_xref.csv"]
    f_map = datasets["function_map.csv"]
    xacc = datasets["xdata_confirmed_access.csv"]
    xbranch = datasets["xdata_branch_trace_map.csv"]
    enum_map = datasets["enum_branch_value_map.csv"]
    packet_calls = datasets["dks_packet_export_callsite_matrix.csv"]
    out_path = datasets["dks_output_start_path_trace.csv"]

    disasm_by_file: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in disasm:
        disasm_by_file[r.get("file", "")].append(r)
    for rows in disasm_by_file.values():
        rows.sort(key=lambda r: parse_hex(r.get("code_addr", "")) or -1)

    fsize: dict[tuple[str, str], int] = {}
    for r in f_map:
        try:
            fsize[(r.get("file", ""), r.get("function_addr", ""))] = int(r.get("size_estimate", "0"))
        except Exception:
            pass

    summary_rows: list[dict[str, str]] = []
    pseudo_rows: list[dict[str, str]] = []
    const_rows: list[dict[str, str]] = []
    xflow_rows: list[dict[str, str]] = []
    callsite_rows: list[dict[str, str]] = []

    pending_table: list[list[str]] = []
    target_notes: dict[str, str] = {}

    for branch, file, addr, priority, area in TARGETS:
        s = parse_hex(addr) or 0
        w = function_window(disasm_by_file.get(file, []), addr, fsize.get((file, addr), 0x180))
        callers = [r for r in call_xref if r.get("file") == file and r.get("target_addr") == addr]
        callees = [r for r in call_xref if r.get("file") == file and s <= (parse_hex(r.get("code_addr", "")) or -1) < s + max(0x20, min(fsize.get((file, addr), 0x180), 0x600))]
        x_local = [r for r in xacc if r.get("file") == file and abs((parse_hex(r.get("code_addr", "")) or 0) - s) <= 0x300]
        xb_local = [r for r in xbranch if r.get("file") == file and r.get("function_addr") == addr]
        e_local = [r for r in enum_map if r.get("file") == file and r.get("function_addr") == addr]
        cvals = top_consts(w)

        if addr == "0x9275":
            role = "rtos_service_generic_helper_with_table_copy_adjacency"
            conf = "medium"
            ev = "static_code+manual_decompile"
            note = "Called from 0x4374 init/service window; callee set overlaps 0x9255/0x920C neighborhood."
        elif addr == "0x7773":
            role = "shifted_status_branch_helper_candidate"
            conf = "low_to_medium"
            ev = "static_code+cross_family_pattern"
            note = "In shifted_DKS branch neighborhood around 0x32B3/0x3104/0x31DD; status-bit semantics remain unproven."
        else:
            role = "caller_envelope_prep_for_0x737C_0x84A6"
            conf = "medium"
            ev = "static_code+manual_decompile+hypothesis"
            note = "Direct caller envelope for 0x737C/0x84A6 context staging without physical output mapping claims."

        pending_table.append([priority, area, branch, file, addr, role, conf, ev])
        target_notes[addr] = (
            f"callers={','.join(uniq(r.get('code_addr','') for r in callers)) or '-'}; "
            f"callees={','.join(uniq(r.get('target_addr','') for r in callees)[:10]) or '-'}; "
            f"xdata_refs={len(x_local)}/{len(xb_local)}; enum_values={','.join(uniq(r.get('candidate_value','') for r in e_local)) or '-'}"
        )

        summary_rows.append(
            {
                "priority": priority,
                "area": area,
                "branch": branch,
                "file": file,
                "function_addr": addr,
                "micro_role_after": role,
                "confidence": conf,
                "evidence_level": ev,
                "static_evidence": target_notes[addr],
                "unknowns_reduced": "PU-002|PU-003|PU-004" if addr == "0x9275" else ("PU-010" if addr == "0x7773" else "PU-006|PU-009|PU-011"),
                "remaining_gaps": "conservative-only; no bench-confirmed protocol/terminal mapping",
                "next_step": "expand caller blocks and downstream write classes",
                "notes": note,
            }
        )

        pseudo_rows.append(
            {
                "branch": branch,
                "file": file,
                "function_addr": addr,
                "pseudocode_block": "windowed micro-decompile skeleton extracted from disassembly/call/xdata neighborhoods",
                "known_operations": f"constants={','.join(cvals[:8]) or '-'}; calls={','.join(uniq(r.get('target_addr','') for r in callees)[:8]) or '-'}",
                "unknown_operations": "semantic labels, external protocol framing, physical terminal assignment",
                "confidence": conf,
                "notes": note,
            }
        )

        for c in cvals[:8]:
            const_rows.append(
                {
                    "branch": branch,
                    "file": file,
                    "function_addr": addr,
                    "constant": c,
                    "constant_format": "hex_immediate_or_addr",
                    "nearby_operation": "window-immediate",
                    "possible_meaning": "status_mask_or_table_ptr_or_dispatch_literal",
                    "confidence": "low_to_medium",
                    "evidence_level": "static_code",
                    "notes": "pass3 window extraction; meaning remains conservative",
                }
            )

        for xr in x_local[:18]:
            xflow_rows.append(
                {
                    "branch": branch,
                    "file": file,
                    "function_addr": addr,
                    "xdata_addr": xr.get("dptr_addr", ""),
                    "access_type": xr.get("access_type", ""),
                    "access_context": f"near_{addr}",
                    "predecessor_function": ",".join(uniq(r.get("code_addr", "") for r in callers)[:4]),
                    "successor_function": ",".join(uniq(r.get("target_addr", "") for r in callees)[:4]),
                    "possible_role": "status_table_or_service_context",
                    "confidence": "low_to_medium",
                    "evidence_level": "static_code",
                    "notes": "proximity-based extraction",
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
                    "call_context": "direct caller envelope",
                    "pre_call_setup": "see disassembly window near caller",
                    "post_call_behavior": "context-dependent branch/write",
                    "confidence": "medium" if addr != "0x7773" else "low_to_medium",
                    "evidence_level": "static_code",
                    "notes": note,
                }
            )
        for cr in callees[:20]:
            callsite_rows.append(
                {
                    "branch": branch,
                    "file": file,
                    "function_addr": addr,
                    "caller_addr": addr,
                    "callee_addr": cr.get("target_addr", ""),
                    "call_context": "in-function callee",
                    "pre_call_setup": "register/xdata staging in bounded window",
                    "post_call_behavior": "branch/write continuation",
                    "confidence": "low_to_medium",
                    "evidence_level": "static_code",
                    "notes": note,
                }
            )

    uart_candidates: list[dict[str, str]] = []
    checksum_candidates: list[dict[str, str]] = []
    timer_candidates: list[dict[str, str]] = []
    calls_5a7f: list[dict[str, str]] = []

    # UART/baud scan: look for SCON/TMOD/TH1/TL1/PCON strings and probable timer constants in RTOS neighborhood.
    uart_hint_tokens = ["SCON", "TMOD", "TH1", "TL1", "PCON", "0xFD", "0xFA", "0xE8"]
    for r in disasm:
        ops = (r.get("operands") or "")
        mnem = (r.get("mnemonic") or "")
        text = f"{mnem} {ops}"
        if any(tok in text for tok in uart_hint_tokens):
            uart_candidates.append(
                {
                    "branch": r.get("branch", ""),
                    "file": r.get("file", ""),
                    "function_addr": r.get("code_addr", ""),
                    "candidate_role": "uart_init_candidate",
                    "constants": ",".join([t for t in uart_hint_tokens if t in text]),
                    "register_or_timer_hint": text,
                    "callers": "-",
                    "callees": "-",
                    "confidence": "low",
                    "evidence_level": "static_code",
                    "notes": "token hit only; not enough to prove configured baud/framing",
                }
            )

    # checksum candidates: xor/add loops near requested neighborhoods.
    wanted = {"0x497A", "0x737C", "0x5A7F", "0x4374", "0x920C", "0x9255", "0x9275", "0x758B"}
    for r in disasm:
        m = (r.get("mnemonic") or "").upper()
        if m in {"XRL", "ANL", "ADD", "ADDC", "RL", "RLC", "RR", "RRC", "DJNZ"}:
            ops = (r.get("operands") or "")
            if any(w in ops for w in wanted) or any(abs((parse_hex(r.get("code_addr", "")) or 0) - (parse_hex(w) or 0)) < 0x180 for w in wanted):
                checksum_candidates.append(
                    {
                        "branch": r.get("branch", ""),
                        "file": r.get("file", ""),
                        "function_addr": r.get("code_addr", ""),
                        "candidate_pattern": "xor_add_rotate_accumulation_candidate",
                        "operations": m,
                        "constants": ops,
                        "loop_signature": "single-op hit in neighborhood",
                        "packet_context": "near packet/service candidate window",
                        "confidence": "low",
                        "evidence_level": "static_code",
                        "notes": "needs explicit buffer loop/table linkage for checksum proof",
                    }
                )

    # 0x5A7F caller block expansion from packet callsite matrix
    wanted_callers = ["0x55AD", "0x55C0", "0x55C9", "0x55E6", "0x55F9", "0x5602"]
    for ca in wanted_callers:
        rows = [r for r in packet_calls if r.get("caller_addr") == ca and r.get("called_addr") == "0x5A7F"]
        if rows:
            for r in rows:
                calls_5a7f.append(
                    {
                        "branch": r.get("branch", ""),
                        "file": r.get("file", ""),
                        "caller_addr": ca,
                        "callee_addr": "0x5A7F",
                        "pre_call_setup": r.get("pre_call_dptr", "") or r.get("pre_call_acc_or_reg", ""),
                        "post_call_movx_or_write": r.get("post_call_operation", ""),
                        "possible_field_role": r.get("probable_packet_role", "packet_field_or_pointer_staging"),
                        "xdata_context": r.get("xdata_context", ""),
                        "confidence": r.get("confidence", "low_to_medium"),
                        "evidence_level": "static_code+manual_decompile",
                        "notes": r.get("notes", ""),
                    }
                )
        else:
            calls_5a7f.append(
                {
                    "branch": "90CYE_DKS",
                    "file": "90CYE03_19_DKS.PZU",
                    "caller_addr": ca,
                    "callee_addr": "0x5A7F",
                    "pre_call_setup": "not explicitly present in packet_callsite_matrix",
                    "post_call_movx_or_write": "unknown",
                    "possible_field_role": "packet_field_or_pointer_staging (hypothesis)",
                    "xdata_context": "unknown",
                    "confidence": "low",
                    "evidence_level": "unknown",
                    "notes": "required row retained with conservative unknown fields",
                }
            )

    # timer/output downstream candidates from dks_output_start_path_trace + windows near target anchors.
    downstream_addrs = ["0x728A", "0x6833", "0x7DC2", "0x84A6"]
    for r in out_path:
        if r.get("function_addr") in downstream_addrs or r.get("next_function") in downstream_addrs:
            timer_candidates.append(
                {
                    "branch": "90CYE_DKS",
                    "file": "90CYE03_19_DKS.PZU",
                    "function_addr": r.get("function_addr", ""),
                    "candidate_type": "timer_or_output_downstream",
                    "constant_or_xdata": (r.get("value", "") or r.get("xdata_addr", "")),
                    "timer_or_output_context": r.get("operation", ""),
                    "related_path": f"{r.get('function_addr','')}->{r.get('next_function','')}",
                    "confidence": "low_to_medium",
                    "evidence_level": r.get("evidence_level", "static_code"),
                    "notes": r.get("notes", ""),
                }
            )

    unknown_rows = [
        {
            "unknown_id": "PU-001",
            "area": "RS-485_format",
            "old_status": "pass2_narrowed_dispatch_vs_packet_prep",
            "new_status": "pass3_still_unresolved",
            "static_evidence_added": "expanded 0x5A7F caller block rows including fixed caller set",
            "remaining_gap": "no explicit serialized byte sequence proved",
            "next_static_step": "extend packet-callsite pre/post write tracing around 0x55AD..0x5602",
            "next_doc_step": "seek protocol field-order appendix",
            "next_bench_step": "capture frame bytes vs event transitions",
        },
        {
            "unknown_id": "PU-002",
            "area": "RS-485_address_map",
            "old_status": "pass2_partial_static_narrowing",
            "new_status": "pass3_partial_table_origin_narrowing",
            "static_evidence_added": "0x9275 caller envelope tied to 0x4374/0x920C/0x9255 neighborhood",
            "remaining_gap": "address constants/table origin not explicit",
            "next_static_step": "trace table roots around 0x920C/0x9255 with pointer provenance",
            "next_doc_step": "collect address map pages",
            "next_bench_step": "device-isolated bus address capture",
        },
        {
            "unknown_id": "PU-003",
            "area": "RS-485_baudrate",
            "old_status": "pass2_no_baud_proof",
            "new_status": "pass3_no_baud_proof",
            "static_evidence_added": "global UART token scan executed; low-confidence hits only",
            "remaining_gap": "no strong UART init divisor/framing proof",
            "next_static_step": "continue serial init scan beyond 0x920C chain",
            "next_doc_step": "commissioning serial settings",
            "next_bench_step": "measure line timing",
        },
        {
            "unknown_id": "PU-004",
            "area": "CRC_checksum",
            "old_status": "pass2_still_unresolved",
            "new_status": "pass3_candidate_loops_only",
            "static_evidence_added": "xor/add/rotate op scan near packet/service neighborhoods",
            "remaining_gap": "no verified checksum loop/table",
            "next_static_step": "tie arithmetic loops to bounded packet buffer",
            "next_doc_step": "protocol checksum notes",
            "next_bench_step": "invalid-checksum behavior test",
        },
        {
            "unknown_id": "PU-006",
            "area": "numeric_enum_delay",
            "old_status": "pass2_narrowed_helper_roles",
            "new_status": "pass3_partial_compare_extension",
            "static_evidence_added": "0x73FD caller-envelope constants and enum map proximity extracted",
            "remaining_gap": "semantic labels for enum values",
            "next_static_step": "expand compare-immediate mining near 0x6833/0x737C/0x73FD",
            "next_doc_step": "project enum/state tables",
            "next_bench_step": "runtime correlation capture",
        },
        {
            "unknown_id": "PU-009",
            "area": "launch_pulse",
            "old_status": "pass2_mode_bridge_refined",
            "new_status": "pass3_timer_downstream_candidates_added",
            "static_evidence_added": "downstream candidates from 0x728A/0x7DC2/0x84A6 path trace",
            "remaining_gap": "exact pulse duration unresolved",
            "next_static_step": "narrow constants tied to countdown decrement endpoint",
            "next_doc_step": "launch timing requirements",
            "next_bench_step": "scope pulse width",
        },
        {
            "unknown_id": "PU-010",
            "area": "damper_terminal_object_map",
            "old_status": "pass2_shifted_bridge_narrowed",
            "new_status": "pass3_shifted_status_branch_extended",
            "static_evidence_added": "0x7773 focused branch envelope with 0x32B3 neighborhood extraction",
            "remaining_gap": "open/closed/fault bit mapping unproven",
            "next_static_step": "trace 0x613C/0x673C exits to status writes",
            "next_doc_step": "terminal/object cross-table",
            "next_bench_step": "limit-switch channel probes",
        },
        {
            "unknown_id": "PU-011",
            "area": "GOA_output_map",
            "old_status": "pass2_output_class_split_refined",
            "new_status": "pass3_write_target_class_expanded",
            "static_evidence_added": "0x73FD + 0x5A7F caller-block expansion captured",
            "remaining_gap": "terminal-level GOA/AN/AU/AO mapping unresolved",
            "next_static_step": "classify post-0x5A7F write targets",
            "next_doc_step": "output naming/terminal docs",
            "next_bench_step": "terminal-level output tracing",
        },
    ]

    write_csv(
        DOCS / "project_guided_micro_pass3_summary.csv",
        [
            "priority",
            "area",
            "branch",
            "file",
            "function_addr",
            "micro_role_after",
            "confidence",
            "evidence_level",
            "static_evidence",
            "unknowns_reduced",
            "remaining_gaps",
            "next_step",
            "notes",
        ],
        summary_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_pass3_pseudocode.csv",
        ["branch", "file", "function_addr", "pseudocode_block", "known_operations", "unknown_operations", "confidence", "notes"],
        pseudo_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_pass3_constants.csv",
        [
            "branch",
            "file",
            "function_addr",
            "constant",
            "constant_format",
            "nearby_operation",
            "possible_meaning",
            "confidence",
            "evidence_level",
            "notes",
        ],
        const_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_pass3_xdata_flow.csv",
        [
            "branch",
            "file",
            "function_addr",
            "xdata_addr",
            "access_type",
            "access_context",
            "predecessor_function",
            "successor_function",
            "possible_role",
            "confidence",
            "evidence_level",
            "notes",
        ],
        xflow_rows,
    )
    write_csv(
        DOCS / "project_guided_micro_pass3_callsite_matrix.csv",
        [
            "branch",
            "file",
            "function_addr",
            "caller_addr",
            "callee_addr",
            "call_context",
            "pre_call_setup",
            "post_call_behavior",
            "confidence",
            "evidence_level",
            "notes",
        ],
        callsite_rows,
    )
    write_csv(
        DOCS / "project_guided_uart_baud_candidates.csv",
        [
            "branch",
            "file",
            "function_addr",
            "candidate_role",
            "constants",
            "register_or_timer_hint",
            "callers",
            "callees",
            "confidence",
            "evidence_level",
            "notes",
        ],
        uart_candidates,
    )
    write_csv(
        DOCS / "project_guided_checksum_candidates_v2.csv",
        [
            "branch",
            "file",
            "function_addr",
            "candidate_pattern",
            "operations",
            "constants",
            "loop_signature",
            "packet_context",
            "confidence",
            "evidence_level",
            "notes",
        ],
        checksum_candidates,
    )
    write_csv(
        DOCS / "project_guided_5a7f_caller_block_expansion.csv",
        [
            "branch",
            "file",
            "caller_addr",
            "callee_addr",
            "pre_call_setup",
            "post_call_movx_or_write",
            "possible_field_role",
            "xdata_context",
            "confidence",
            "evidence_level",
            "notes",
        ],
        calls_5a7f,
    )
    write_csv(
        DOCS / "project_guided_timer_output_downstream_candidates.csv",
        [
            "branch",
            "file",
            "function_addr",
            "candidate_type",
            "constant_or_xdata",
            "timer_or_output_context",
            "related_path",
            "confidence",
            "evidence_level",
            "notes",
        ],
        timer_candidates,
    )
    write_csv(
        DOCS / "project_guided_micro_pass3_unknowns_update.csv",
        [
            "unknown_id",
            "area",
            "old_status",
            "new_status",
            "static_evidence_added",
            "remaining_gap",
            "next_static_step",
            "next_doc_step",
            "next_bench_step",
        ],
        unknown_rows,
    )

    md = []
    md.append("# Project-guided micro-decompile pass #3\n")
    md.append("## Scope")
    md.append("- Static pass #3 only.")
    md.append("- Project evidence used as constraints.")
    md.append("- No bench claims.")
    md.append("- Family separation preserved (90CYE_DKS / 90CYE_shifted_DKS / RTOS_service).")
    if missing_optional:
        md.append("- Optional input warnings:")
        for m in missing_optional:
            md.append(f"  - missing: {m}")
    else:
        md.append("- No optional input warnings.")

    md.append("\n## Pending target summary")
    md.append("| priority | area | branch | file | function_addr | micro_role_after | confidence | evidence_level |")
    md.append("|---|---|---|---|---|---|---|---|")
    for r in pending_table:
        md.append("| " + " | ".join(r) + " |")

    md.append("\n## 0x9275 RTOS_service table/helper analysis")
    md.append(f"- What calls 0x9275? {target_notes['0x9275']}")
    md.append("- Classification: generic service/helper with table-copy adjacency; not enough proof for baud/checksum helper.")
    md.append("- Relation to 0x920C/0x9255/0x4374/0x758B: same RTOS_service envelope; 0x4374 appears as caller-router window and 0x9255 as nearby helper continuation.")

    md.append("\n## 0x7773 shifted_DKS status branch analysis")
    md.append(f"- Function-window summary: {target_notes['0x7773']}")
    md.append("- XDATA around 0x3104/0x3108/0x31DD/0x32B2/0x32B3 was searched via xdata proximity and branch map context.")
    md.append("- Relation to 0x613C/0x673C: strengthened as shifted status branch helper candidate only; open/closed/fault bit mapping remains unproven.")

    md.append("\n## 0x73FD DKS caller-envelope analysis")
    md.append(f"- Function-window summary: {target_notes['0x73FD']}")
    md.append("- 0x73FD is retained as caller-envelope prep around 0x737C/0x84A6 context staging and bridge adjacency.")
    md.append("- Enum compare extraction remains incomplete; immediate values extracted conservatively in constants CSV.")

    md.append("\n## UART/baud candidate search")
    md.append(f"- Candidate rows: {len(uart_candidates)} (token-hits only, generally low confidence).")
    md.append("- PU-003 status: unchanged unresolved/no_baud_proof unless stronger register-divisor linkage appears.")

    md.append("\n## CRC/checksum candidate search")
    md.append(f"- Candidate rows: {len(checksum_candidates)} (xor/add/rotate op proximity hits).")
    md.append("- PU-004 status: still unresolved; no bounded packet-buffer checksum loop/table proved.")

    md.append("\n## 0x5A7F caller block expansion")
    md.append("- Caller rows added for: 0x55AD, 0x55C0, 0x55C9, 0x55E6, 0x55F9, 0x5602.")
    md.append("- Each row records pre-call setup, post-call write behavior (if present), and conservative field-role hypothesis.")

    md.append("\n## Timer/output downstream search")
    md.append(f"- Candidate rows: {len(timer_candidates)} from 0x728A/0x6833/0x7DC2/0x84A6 downstream trace neighborhoods.")
    md.append("- Pulse-width constants remain unresolved; outputs classified as candidate classes only.")

    md.append("\n## Unknowns update")
    md.append("- Updated PU-001, PU-002, PU-003, PU-004, PU-006, PU-009, PU-010, PU-011 in pass3 unknowns CSV.")

    md.append("\n## Next targets")
    md.append("- next_static: 0x920C table-origin root, 0x5A7F post-call write-class separators, 0x613C/0x673C exit-to-status handlers.")
    md.append("- blocked_until_docs: protocol baud/framing/checksum details; terminal/object tables.")
    md.append("- blocked_until_bench: physical terminal mapping and pulse-duration confirmation.")
    md.append("- low_priority: broad cross-family cosmetic enum labels without new static anchors.")

    (DOCS / "project_guided_micro_decompile_pass3.md").write_text("\n".join(md).strip() + "\n", encoding="utf-8")

    replace_or_append_section(
        DOCS / "project_guided_static_analysis_summary.md",
        "Micro-decompile pass #3",
        [
            "Generated artifacts:",
            "- docs/project_guided_micro_decompile_pass3.md",
            "- docs/project_guided_micro_pass3_summary.csv",
            "- docs/project_guided_micro_pass3_pseudocode.csv",
            "- docs/project_guided_micro_pass3_constants.csv",
            "- docs/project_guided_micro_pass3_xdata_flow.csv",
            "- docs/project_guided_micro_pass3_callsite_matrix.csv",
            "- docs/project_guided_uart_baud_candidates.csv",
            "- docs/project_guided_checksum_candidates_v2.csv",
            "- docs/project_guided_5a7f_caller_block_expansion.csv",
            "- docs/project_guided_timer_output_downstream_candidates.csv",
            "- docs/project_guided_micro_pass3_unknowns_update.csv",
        ],
    )

    # update next static targets
    next_targets_path = DOCS / "project_guided_next_static_targets.csv"
    next_rows = load_csv(next_targets_path)
    for row in next_rows:
        if row.get("function_addr") in {"0x9275", "0x7773", "0x73FD"}:
            row["micro_pass_status"] = "completed_pass3_2026-04-27"
            row["micro_output"] = "docs/project_guided_micro_decompile_pass3.md"
    for extra in [
        ("P1", "RTOS_service", "RTOS_service", "ppkp2001 90cye01.PZU", "0x920C", "table-origin root for address/baud unresolveds"),
        ("P2", "RS-485", "90CYE_DKS", "90CYE03_19_DKS.PZU", "0x5A7F", "post-call write-target class separation after caller expansion"),
        ("P2", "Shifted status bridge", "90CYE_shifted_DKS", "90CYE02_27 DKS.PZU", "0x673C", "status branch exits to object/status handlers"),
        ("P2", "RS-485", "90CYE_DKS", "90CYE03_19_DKS.PZU", "0x55AD", "0x5A7F caller block pre/post write staging from pass3 expansion"),
        ("P2", "RS-485", "90CYE_DKS", "90CYE03_19_DKS.PZU", "0x5602", "tail 0x5A7F caller block staging from pass3 expansion"),
    ]:
        if not any(r.get("function_addr") == extra[4] and r.get("file") == extra[3] for r in next_rows):
            next_rows.append(
                {
                    "priority": extra[0],
                    "area": extra[1],
                    "branch": extra[2],
                    "file": extra[3],
                    "function_addr": extra[4],
                    "target_reason": extra[5],
                    "expected_gain": "pass3 follow-up",
                    "notes": "added by project_guided_micro_decompiler_pass3.py",
                    "micro_pass_status": "pending",
                    "micro_output": "",
                }
            )
    write_csv(next_targets_path, list(next_rows[0].keys()) if next_rows else ["priority", "area", "branch", "file", "function_addr", "target_reason", "expected_gain", "notes", "micro_pass_status", "micro_output"], next_rows)

    # update remaining unknowns v2
    rem_path = DOCS / "project_guided_remaining_unknowns_v2.csv"
    rem_rows = load_csv(rem_path)
    by_id = {r.get("unknown_id", ""): r for r in rem_rows}
    for ur in unknown_rows:
        rid = ur["unknown_id"]
        if rid in by_id:
            by_id[rid]["status_after_micro_decompile"] = ur["new_status"]
            by_id[rid]["micro_static_evidence"] = ur["static_evidence_added"]
            by_id[rid]["next_static_step"] = ur["next_static_step"]
            by_id[rid]["next_doc_step"] = ur["next_doc_step"]
            by_id[rid]["next_bench_step"] = ur["next_bench_step"]
    write_csv(rem_path, list(rem_rows[0].keys()) if rem_rows else ["unknown_id", "area", "description", "status_after_project_guided_search", "needed_evidence", "next_static_step", "next_doc_step", "next_bench_step", "status_after_micro_decompile", "micro_static_evidence"], list(by_id.values()) if by_id else rem_rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
