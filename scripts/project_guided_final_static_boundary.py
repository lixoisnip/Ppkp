#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

INPUTS = [
    "project_guided_next_static_targets.csv",
    "project_guided_micro_pass3_unknowns_update.csv",
    "project_guided_micro_decompile_pass3.md",
    "project_guided_micro_pass3_summary.csv",
    "project_guided_micro_pass3_callsite_matrix.csv",
    "project_guided_5a7f_caller_block_expansion.csv",
    "project_guided_micro_pass3_constants.csv",
    "project_guided_micro_pass3_xdata_flow.csv",
    "project_guided_uart_baud_candidates.csv",
    "project_guided_checksum_candidates_v2.csv",
    "project_guided_timer_output_downstream_candidates.csv",
    "project_guided_micro_decompile.md",
    "project_guided_micro_decompile_pass2.md",
    "project_guided_micro_pass2_unknowns_update.csv",
    "project_guided_micro_unknowns_update.csv",
    "project_guided_static_analysis_summary.md",
    "project_guided_remaining_unknowns_v2.csv",
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
    "dks_packet_export_callsite_matrix.csv",
    "dks_packet_context_xdata_matrix.csv",
    "dks_xdata_lifecycle_matrix.csv",
    "extracted/project_to_firmware_linkage.csv",
    "extracted/project_unknowns.csv",
]

CALLERS = ["0x55AD", "0x55C0", "0x55C9", "0x55E6", "0x55F9", "0x5602"]
DKS_FILE = "90CYE03_19_DKS.PZU"
DKS_BRANCH = "90CYE_DKS"


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
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        t = (v or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


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


def summarize_callsite(dis_rows: list[dict[str, str]], addr: str) -> dict[str, str]:
    call = parse_hex(addr) or 0
    rows = [r for r in dis_rows if r.get("file") == DKS_FILE]
    rows.sort(key=lambda r: parse_hex(r.get("code_addr", "")) or -1)
    idx = next((i for i, r in enumerate(rows) if r.get("code_addr") == addr), -1)
    if idx < 0:
        return {
            "pre_call_setup": "unknown",
            "post_call_behavior": "unknown",
            "movx_before": "unknown",
            "movx_after": "unknown",
            "xdata_context": "unknown",
            "checksum_like": "no bounded loop in callsite window",
            "possible_role": "unknown",
            "confidence": "low",
            "evidence_level": "unknown",
        }

    prev = rows[max(0, idx - 6) : idx]
    nxt = rows[idx + 1 : idx + 7]
    prev_txt = "; ".join(f"{r.get('code_addr')} {r.get('mnemonic')} {r.get('operands')}" for r in prev)
    nxt_txt = "; ".join(f"{r.get('code_addr')} {r.get('mnemonic')} {r.get('operands')}" for r in nxt)

    movx_before = "yes" if any((r.get("mnemonic") or "").upper() == "MOVX" for r in prev) else "no"
    movx_after = "yes" if any((r.get("mnemonic") or "").upper() == "MOVX" for r in nxt) else "no"
    xdata = uniq(
        t.replace("#", "")
        for r in prev + nxt
        for t in (r.get("operands") or "").replace(",", " ").split()
        if t.startswith("#0x3") or t.startswith("#0x7")
    )

    checksum_hits = [
        r
        for r in rows[max(0, idx - 16) : idx + 16]
        if (r.get("mnemonic") or "").upper() in {"ADD", "ADDC", "XRL", "RLC", "RRC", "DJNZ"}
    ]

    if addr == "0x55AD":
        role = "pointer_or_index_staging_then_bridge_readback"
        post = "post-call MOVX read + compare loop branch context"
    elif addr == "0x5602":
        role = "pointer_or_index_staging_then_bridge_writeback"
        post = "post-call MOV A,R1 then MOVX @DPTR,A write path"
    else:
        role = "repeated pointer/index staging in caller block"
        post = "mixed read/write loop stage around 0x5A7F"

    return {
        "pre_call_setup": prev_txt or "none_in_window",
        "post_call_behavior": post + (f"; window={nxt_txt}" if nxt_txt else ""),
        "movx_before": movx_before,
        "movx_after": movx_after,
        "xdata_context": "|".join(xdata) if xdata else "not_explicit_in_window",
        "checksum_like": "candidate ops nearby only" if checksum_hits else "none in bounded callsite window",
        "possible_role": role,
        "confidence": "medium" if addr in {"0x55AD", "0x5602"} else "low_to_medium",
        "evidence_level": "static_code",
    }


def main() -> int:
    datasets: dict[str, list[dict[str, str]]] = {}
    missing: list[str] = []
    for name in INPUTS:
        p = DOCS / name
        rows = load_csv(p)
        datasets[name] = rows
        if not p.exists():
            missing.append(name)

    disasm = datasets["disassembly_index.csv"]
    next_targets = datasets["project_guided_next_static_targets.csv"]
    remaining_unknowns = datasets["project_guided_remaining_unknowns_v2.csv"]
    packet_calls = datasets["dks_packet_export_callsite_matrix.csv"]

    callsite = {addr: summarize_callsite(disasm, addr) for addr in CALLERS}

    synth_rows: list[dict[str, str]] = []
    for addr in CALLERS:
        s = callsite[addr]
        synth_rows.append(
            {
                "caller_addr": addr,
                "callee_addr": "0x5A7F",
                "pre_call_setup": s["pre_call_setup"],
                "post_call_behavior": s["post_call_behavior"],
                "xdata_context": s["xdata_context"],
                "possible_role": s["possible_role"],
                "confidence": s["confidence"],
                "evidence_level": s["evidence_level"],
                "notes": "final_static_boundary_pass; no frame-format/CRC overclaim",
            }
        )

    write_csv(
        DOCS / "project_guided_5a7f_caller_synthesis.csv",
        [
            "caller_addr",
            "callee_addr",
            "pre_call_setup",
            "post_call_behavior",
            "xdata_context",
            "possible_role",
            "confidence",
            "evidence_level",
            "notes",
        ],
        synth_rows,
    )

    dashboard_rows = [
        {
            "area": "RS-485 frame",
            "current_status": "narrowed_bridge_not_serialized",
            "static_confidence": "medium",
            "blocked_by": "blocked_until_docs+blocked_until_bench",
            "next_best_evidence": "protocol frame sheet + bus capture with event tags",
            "do_not_repeat_until": "new protocol-doc pages or captured bytes are available",
            "notes": "0x5A7F caller synthesis confirms repeated staging, not full frame bytes",
        },
        {
            "area": "RS-485 address map",
            "current_status": "partial_context_only",
            "static_confidence": "low_to_medium",
            "blocked_by": "blocked_until_docs+blocked_until_bench",
            "next_best_evidence": "address table docs + per-device isolated capture",
            "do_not_repeat_until": "address map docs or address-tagged captures arrive",
            "notes": "table origin narrowed in pass3, still not decoded",
        },
        {
            "area": "RS-485 baudrate",
            "current_status": "token_hits_only",
            "static_confidence": "low",
            "blocked_by": "blocked_until_docs+blocked_until_bench",
            "next_best_evidence": "commissioning UART settings or line timing scope",
            "do_not_repeat_until": "new UART init constants with register proof are found",
            "notes": "PU-003 unresolved",
        },
        {
            "area": "CRC/checksum",
            "current_status": "candidate_loops_not_buffer_bounded",
            "static_confidence": "low",
            "blocked_by": "blocked_until_docs+blocked_until_bench",
            "next_best_evidence": "checksum appendix + invalid-checksum runtime behavior",
            "do_not_repeat_until": "bounded packet-buffer loop linked to packet window is proven",
            "notes": "PU-004 unresolved",
        },
        {
            "area": "enum numeric codes",
            "current_status": "partially_narrowed",
            "static_confidence": "medium",
            "blocked_by": "blocked_until_docs",
            "next_best_evidence": "project enum/state table pages",
            "do_not_repeat_until": "new enum table docs or branch/value anchors emerge",
            "notes": "no exact semantic lock without docs",
        },
        {
            "area": "30s delay / start chain",
            "current_status": "chain_supported",
            "static_confidence": "medium",
            "blocked_by": "blocked_until_bench",
            "next_best_evidence": "runtime timing capture on delay->start transition",
            "do_not_repeat_until": "bench timing traces are available",
            "notes": "0x6833 marker and 0x7DC2 transition remain conservative",
        },
        {
            "area": "launch pulse width",
            "current_status": "unresolved",
            "static_confidence": "low",
            "blocked_by": "blocked_until_docs+blocked_until_bench",
            "next_best_evidence": "launch timing requirements + oscilloscope pulse width",
            "do_not_repeat_until": "timing spec or pulse waveform evidence exists",
            "notes": "PU-009 unresolved",
        },
        {
            "area": "damper open/closed/fault",
            "current_status": "partially_narrowed",
            "static_confidence": "medium",
            "blocked_by": "blocked_until_docs+blocked_until_bench",
            "next_best_evidence": "terminal/object cross-table + limit-switch probe",
            "do_not_repeat_until": "terminal docs or labeled bench mapping is available",
            "notes": "0x673C/0x613C/0x7773 chain static-only",
        },
        {
            "area": "GOA/AN/AU/AO output map",
            "current_status": "output_class_only",
            "static_confidence": "low_to_medium",
            "blocked_by": "blocked_until_docs+blocked_until_bench",
            "next_best_evidence": "terminal mapping docs + output line tracing",
            "do_not_repeat_until": "terminal/object docs or captured output toggles exist",
            "notes": "PU-011 unresolved",
        },
        {
            "area": "MDS CP/CF/CH bit map",
            "current_status": "class_narrowing_only",
            "static_confidence": "low_to_medium",
            "blocked_by": "blocked_until_docs+blocked_until_bench",
            "next_best_evidence": "electrical supervision tables + controlled fault bench",
            "do_not_repeat_until": "CP/CF/CH documentation pages are provided",
            "notes": "no full bit-to-terminal mapping",
        },
        {
            "area": "MUP/PVK handler split",
            "current_status": "split_preserved",
            "static_confidence": "medium",
            "blocked_by": "blocked_until_docs+blocked_until_bench",
            "next_best_evidence": "missing project pages + slot-isolated runtime traces",
            "do_not_repeat_until": "new MUP/PVK project pages or isolated traces exist",
            "notes": "PU-012/PU-013 unchanged split",
        },
    ]
    write_csv(
        DOCS / "project_guided_final_static_boundary_dashboard.csv",
        [
            "area",
            "current_status",
            "static_confidence",
            "blocked_by",
            "next_best_evidence",
            "do_not_repeat_until",
            "notes",
        ],
        dashboard_rows,
    )

    pending_rows: list[dict[str, str]] = []
    for r in next_targets:
        addr = (r.get("function_addr") or "").strip()
        status = (r.get("micro_pass_status") or "").strip()
        final_status = "completed"
        if addr in {"0x55AD", "0x5602"}:
            status = "completed_final_boundary_2026-04-27"
        final_role = callsite.get(addr, {}).get("possible_role", "historical_completed_target")
        confidence = callsite.get(addr, {}).get("confidence", "medium")
        evidence = callsite.get(addr, {}).get("evidence_level", "static_code")
        pending_rows.append(
            {
                "priority": r.get("priority", "P3"),
                "area": r.get("area", "unknown"),
                "branch": r.get("branch", ""),
                "file": r.get("file", ""),
                "function_addr": addr,
                "status": final_status if status.startswith("completed") else status,
                "final_role": final_role,
                "confidence": confidence,
                "evidence_level": evidence,
                "remaining_gap": "no bench/protocol-doc closure" if "RS-485" in (r.get("area") or "") else "semantic mapping may require docs/bench",
                "next_step": "wait for docs/bench evidence or targeted static anchor",
                "notes": "final boundary inventory row",
            }
        )

    write_csv(
        DOCS / "project_guided_final_pending_targets.csv",
        [
            "priority",
            "area",
            "branch",
            "file",
            "function_addr",
            "status",
            "final_role",
            "confidence",
            "evidence_level",
            "remaining_gap",
            "next_step",
            "notes",
        ],
        pending_rows,
    )

    unknown_rows: list[dict[str, str]] = []
    for i in range(1, 14):
        uid = f"PU-{i:03d}"
        src = next((r for r in remaining_unknowns if (r.get("unknown_id") or "") == uid), {})
        blocked = "blocked_until_docs+blocked_until_bench"
        if uid in {"PU-006", "PU-012", "PU-013"}:
            blocked = "blocked_until_docs"
        unknown_rows.append(
            {
                "unknown_id": uid,
                "area": src.get("area", "unknown"),
                "latest_status": src.get("status_after_micro_decompile", src.get("status_after_project_guided_search", "unknown")),
                "static_boundary": "narrowed_without_claiming_runtime_confirmation",
                "blocked_by": blocked,
                "next_doc_step": src.get("next_doc_step", "collect missing protocol/terminal pages"),
                "next_bench_step": src.get("next_bench_step", "capture runtime waveform/serial traces"),
                "next_static_step": "only rerun with new anchored evidence",
                "notes": src.get("micro_static_evidence", "final boundary pass preserved conservative confidence caps"),
            }
        )

    write_csv(
        DOCS / "project_guided_final_unknowns_status.csv",
        [
            "unknown_id",
            "area",
            "latest_status",
            "static_boundary",
            "blocked_by",
            "next_doc_step",
            "next_bench_step",
            "next_static_step",
            "notes",
        ],
        unknown_rows,
    )

    do_not_repeat = [
        ("RS-485 frame format", "no serialized byte sequence proven", "protocol frame appendix or serial capture", "only parse new anchored protocol bytes", "avoid speculative frame byte synthesis"),
        ("CRC/checksum", "no bounded packet-buffer checksum loop", "checksum docs or invalid-checksum capture", "resume only when bounded loop evidence appears", "candidate arithmetic scans are exhausted"),
        ("baudrate", "only low-confidence token hits", "commissioning UART settings or scope timing", "resume with register-level UART init proof", "repeat token scans are low value"),
        ("GOA terminal map", "class-level only without terminal table", "terminal/object cross-reference docs or IO capture", "resume once terminal IDs are documented/captured", "no direct GOA/AN/AU/AO mapping claim"),
        ("damper terminal map", "status chain narrowed but terminals unmapped", "damper terminal table + limit-switch bench", "resume when table/probe labels exist", "avoid re-labeling 0x673C without docs"),
        ("MUP/PVK handler ownership", "evidence split unresolved", "MUP/PVK project pages + isolated slot traces", "resume with new pages or slot-isolated traces", "keep split explicitly"),
        ("exact enum semantic mapping", "numeric values lack authoritative labels", "state enum docs or labeled runtime traces", "resume when labels can be cross-checked", "avoid forced semantic naming"),
        ("launch pulse duration", "no pulse-width constants tied to output line", "timing requirements + scope waveform", "resume with timing spec or waveform", "chain evidence does not equal duration proof"),
    ]
    write_csv(
        DOCS / "project_guided_do_not_repeat_until.csv",
        ["topic", "reason_currently_blocked", "required_new_evidence", "next_allowed_action", "notes"],
        [
            {
                "topic": t,
                "reason_currently_blocked": r,
                "required_new_evidence": e,
                "next_allowed_action": n,
                "notes": no,
            }
            for t, r, e, n, no in do_not_repeat
        ],
    )

    # update next targets with final completion notes
    updated_next = []
    for r in next_targets:
        rr = dict(r)
        if rr.get("function_addr") in {"0x55AD", "0x5602"}:
            rr["micro_pass_status"] = "completed_final_boundary_2026-04-27"
            rr["micro_output"] = "docs/project_guided_final_static_boundary.md"
            rr["notes"] = (rr.get("notes") or "") + " final static boundary completed"
        updated_next.append(rr)
    if not any((r.get("function_addr") or "") == "final_boundary_note" for r in updated_next):
        updated_next.append(
            {
                "priority": "P3",
                "area": "Meta",
                "branch": "all",
                "file": "-",
                "function_addr": "final_boundary_note",
                "target_reason": "no new strong static targets",
                "expected_gain": "focus future work by new docs/bench evidence",
                "notes": "future static work should be driven by protocol sheets or bench captures",
                "micro_pass_status": "deferred_until_new_evidence",
                "micro_output": "docs/project_guided_final_static_boundary.md",
            }
        )
    write_csv(
        DOCS / "project_guided_next_static_targets.csv",
        [
            "priority",
            "area",
            "branch",
            "file",
            "function_addr",
            "target_reason",
            "expected_gain",
            "notes",
            "micro_pass_status",
            "micro_output",
        ],
        updated_next,
    )

    # update remaining unknowns with explicit blocked states
    rem_updated = []
    for r in remaining_unknowns:
        rr = dict(r)
        uid = rr.get("unknown_id", "")
        if uid in {"PU-001", "PU-003", "PU-004", "PU-009", "PU-010", "PU-011"}:
            rr["status_after_micro_decompile"] = "final_boundary_blocked_docs_bench"
        elif uid in {"PU-006", "PU-012", "PU-013"}:
            rr["status_after_micro_decompile"] = "final_boundary_blocked_docs"
        rr["micro_static_evidence"] = (rr.get("micro_static_evidence") or "") + " | final boundary: no overclaim"
        rem_updated.append(rr)
    write_csv(
        DOCS / "project_guided_remaining_unknowns_v2.csv",
        list(remaining_unknowns[0].keys()) if remaining_unknowns else [
            "unknown_id",
            "area",
            "description",
            "status_after_project_guided_search",
            "needed_evidence",
            "next_static_step",
            "next_doc_step",
            "next_bench_step",
            "status_after_micro_decompile",
            "micro_static_evidence",
        ],
        rem_updated,
    )

    # markdown report
    md = []
    md += ["# Project-guided final static boundary pass", "", "## Scope", "- This pass is the final static boundary pass for the current evidence set.", "- It does not close protocol-doc or bench-blocked unknowns.", "- Project evidence, static code evidence, and bench/runtime evidence remain separated."]
    if missing:
        md += ["", "### Input warnings", *[f"- Missing optional input: `{m}`" for m in missing]]

    c55, c56 = callsite["0x55AD"], callsite["0x5602"]
    md += [
        "",
        "## Remaining pending target analysis",
        "",
        "### 0x55AD caller-block analysis",
        f"- DPTR/ACC/register setup before `0x5A7F`: {c55['pre_call_setup']}",
        f"- MOVX writes before/after call: before={c55['movx_before']}, after={c55['movx_after']} (post-call is read-first pattern).",
        f"- Staging interpretation: {c55['possible_role']} (conservative).",
        f"- XDATA context in bounded window: {c55['xdata_context']}.",
        f"- Checksum-like arithmetic: {c55['checksum_like']}.",
        "- PU narrowing: narrows caller-side staging behavior for PU-001/PU-004/PU-011 but does not prove frame/CRC/terminal mapping.",
        "",
        "### 0x5602 caller-block analysis",
        f"- DPTR/ACC/register setup before `0x5A7F`: {c56['pre_call_setup']}",
        f"- MOVX writes before/after call: before={c56['movx_before']}, after={c56['movx_after']} (post-call shows writeback).",
        f"- Staging interpretation: {c56['possible_role']} (conservative).",
        f"- XDATA context in bounded window: {c56['xdata_context']}.",
        f"- Checksum-like arithmetic: {c56['checksum_like']}.",
        "- PU narrowing: strengthens post-call write-target class hypothesis for PU-011, without terminal-level proof.",
        "",
        "## 0x5A7F caller-block synthesis",
        "- Compared callers: 0x55AD, 0x55C0, 0x55C9, 0x55E6, 0x55F9, 0x5602.",
        "- Synthesis: repeated looped caller-envelope staging around `R0/R1/DPTR` is statically visible.",
        "- Likely role: pointer/index staging + bridge invocation + post-call read/write handling class.",
        "- Not supported: full serialized frame format, address map, definitive packet-vs-event schema.",
        "",
        "## RS-485 boundary conclusion",
        "- Static evidence supports `0x5A7F` as a high-fan-in packet/event bridge neighborhood with repeated caller staging.",
        "- Static evidence does not support explicit byte-level frame layout or full address map decode.",
        "- PU-001 remains blocked (docs + bench).",
        "- PU-004 remains blocked (docs + bench).",
        "- Needed new evidence: protocol frame/address/checksum appendix and serial capture tied to known events.",
        "",
        "## UART/baud boundary conclusion",
        "- Pass3 UART candidates remain low-confidence token hits only; no strong register-level UART init proof.",
        "- PU-003 remains unresolved.",
        "- Commissioning docs or line timing measurement are required.",
        "",
        "## CRC/checksum boundary conclusion",
        "- Candidate loops exist, but none is tied to a bounded packet-buffer checksum loop.",
        "- PU-004 remains unresolved.",
        "- Confirmation requires explicit bounded buffer traversal and checksum field linkage (or bench invalid-checksum behavior).",
        "",
        "## Timer/output/pulse boundary conclusion",
        "- Static chain support remains: `0x6833` output-start marker `0x04`, `0x7DC2` downstream transition, pass3 timer candidates.",
        "- Exact launch pulse width remains blocked without protocol timing docs or scope capture.",
        "",
        "## Valve/status boundary conclusion",
        "- Static support exists around `0x673C`, `0x613C`, `0x7773`, and status neighborhoods (`0x3104/0x3108/0x31DD/0x32B2/0x32B3`).",
        "- Open/closed/fault terminal mapping is still unresolved without terminal docs or bench-labeled probes.",
        "",
        "## Evidence boundary dashboard",
        "See `docs/project_guided_final_static_boundary_dashboard.csv`.",
        "",
        "## Final static next steps",
        "### 1. worthwhile_next_static",
        "- Ingest new protocol/terminal documents when available and anchor static scans to new concrete constants/tables.",
        "- Tooling-only improvement: parse protocol sheets into searchable field/address dictionaries.",
        "",
        "### 2. blocked_until_docs",
        "- RS-485 protocol frame/address/baud/CRC docs.",
        "- 90CYE02/03/04 terminal-object tables and GOA/AN/AU/AO mapping sheets.",
        "- MUP/PVK project pages and launch timing requirements.",
        "",
        "### 3. blocked_until_bench",
        "- Serial capture with event labels.",
        "- IO capture for GOA/AN/AU/AO and damper statuses.",
        "- Launch pulse width waveform capture.",
        "",
        "### 4. low_value_reanalysis",
        "- Repeating broad scans on `0x5A7F`, `0x6833`, `0x737C`, UART tokens, and checksum token loops without new evidence.",
    ]
    (DOCS / "project_guided_final_static_boundary.md").write_text("\n".join(md).rstrip() + "\n", encoding="utf-8")

    # static summary section
    replace_or_append_section(
        DOCS / "project_guided_static_analysis_summary.md",
        "Final static boundary pass",
        [
            "Generated artifacts:",
            "- docs/project_guided_final_static_boundary.md",
            "- docs/project_guided_final_static_boundary_dashboard.csv",
            "- docs/project_guided_final_pending_targets.csv",
            "- docs/project_guided_final_unknowns_status.csv",
            "- docs/project_guided_5a7f_caller_synthesis.csv",
            "- docs/project_guided_do_not_repeat_until.csv",
        ],
    )

    # README: append links if absent
    readme = ROOT / "README.md"
    txt = readme.read_text(encoding="utf-8")
    marker = "- docs/project_guided_micro_pass3_unknowns_update.csv\n"
    if "docs/project_guided_final_static_boundary.md" not in txt and marker in txt:
        inject = (
            "- docs/project_guided_final_static_boundary.md — final static boundary pass and stop conditions for reanalysis.\n"
            "- docs/project_guided_final_static_boundary_dashboard.csv\n"
            "- docs/project_guided_final_pending_targets.csv\n"
            "- docs/project_guided_final_unknowns_status.csv\n"
            "- docs/project_guided_5a7f_caller_synthesis.csv\n"
            "- docs/project_guided_do_not_repeat_until.csv\n"
        )
        txt = txt.replace(marker, marker + inject)
        readme.write_text(txt, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
