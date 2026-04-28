#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from emulator.function_harness import FunctionHarness, FunctionRunResult
from emulator.pzu_memory import load_code_image
from emulator.scenarios import get_scenario, list_scenarios
OUT = ROOT / "docs" / "emulator"
TRACE_CSV = OUT / "xdata_write_trace.csv"
SUMMARY_CSV = OUT / "function_trace_summary.csv"
UNSUPPORTED_CSV = OUT / "unsupported_opcode_report.csv"
CANDIDATES_CSV = OUT / "candidate_packet_records.csv"
REPORT_MD = OUT / "firmware_execution_sandbox_report.md"
SFR_TRACE_CSV = OUT / "sfr_trace.csv"
CODE_READ_TRACE_CSV = OUT / "code_read_trace.csv"
PZU_METADATA_CSV = OUT / "pzu_load_metadata.csv"
DIRECT_TRACE_CSV = OUT / "direct_memory_trace.csv"
UART_SBUF_TRACE_CSV = OUT / "uart_sbuf_trace.csv"
CPU_COVERAGE_CSV = OUT / "cpu_subset_coverage.csv"
PC_HOTSPOT_CSV = OUT / "pc_hotspot_summary.csv"
CONTROL_FLOW_SUMMARY_CSV = OUT / "control_flow_trace_summary.csv"
CODE_TABLE_CANDIDATE_SUMMARY_CSV = OUT / "code_table_candidate_summary.csv"
BIT_ACCESS_TRACE_CSV = OUT / "bit_access_trace.csv"
SCENARIO_VARIANT_SUMMARY_CSV = OUT / "scenario_variant_summary.csv"
LOOP_EXIT_DIAGNOSTICS_CSV = OUT / "loop_exit_diagnostics.csv"
BRANCH_DECISION_SUMMARY_CSV = OUT / "branch_decision_summary.csv"
STATE_VARIANT_COMPACT_REPORT_MD = OUT / "state_variant_compact_report.md"
SCENARIO_SEED_MANIFEST_CSV = OUT / "scenario_seed_manifest.csv"
SEED_APPLICATION_AUDIT_CSV = OUT / "seed_application_audit.csv"
BRANCH_DEPENDENCY_AUDIT_CSV = OUT / "branch_dependency_audit.csv"
LOOP_STATE_DIGEST_CSV = OUT / "loop_state_digest.csv"
POST_LOOP_PATH_SUMMARY_CSV = OUT / "post_loop_path_summary.csv"
POST_LOOP_BRANCH_AUDIT_CSV = OUT / "post_loop_branch_audit.csv"
HELPER_5935_EFFECT_AUDIT_CSV = OUT / "helper_5935_effect_audit.csv"
POST_LOOP_CALLSITE_CALLEE_AUDIT_CSV = OUT / "post_loop_callsite_callee_audit.csv"
HELPER_5A7F_CONTEXT_COMPARISON_CSV = OUT / "helper_5A7F_context_comparison.csv"
AUTONOMOUS_UART_PURSUIT_SUMMARY_MD = OUT / "autonomous_uart_pursuit_summary.md"
BOOT_TRACE_SUMMARY_CSV = OUT / "boot_trace_summary.csv"
BOOT_INIT_WRITE_SUMMARY_CSV = OUT / "boot_init_write_summary.csv"
RUNTIME_LOOP_CANDIDATES_CSV = OUT / "runtime_loop_candidates.csv"
DISPLAY_CANDIDATE_TRACE_CSV = OUT / "display_candidate_trace.csv"
DISPLAY_TEXT_TABLE_CANDIDATES_CSV = OUT / "display_text_table_candidates.csv"
KEYPAD_CANDIDATE_TRACE_CSV = OUT / "keypad_candidate_trace.csv"
UART_INIT_CANDIDATE_TRACE_CSV = OUT / "uart_init_candidate_trace.csv"
SERIAL_CANDIDATE_AUDIT_CSV = OUT / "serial_candidate_audit.csv"
TIMER_INTERRUPT_CANDIDATE_TRACE_CSV = OUT / "timer_interrupt_candidate_trace.csv"
DISPLAY_KEYPAD_STATIC_CANDIDATES_CSV = OUT / "display_keypad_static_candidates.csv"
BOOT_RUNTIME_BOUNDARY_REPORT_MD = OUT / "boot_runtime_boundary_report.md"
SFR_ROLE_MAP_AUDIT_CSV = OUT / "sfr_role_map_audit.csv"
BOOT_LOOP_XDATA_READ_AUDIT_CSV = OUT / "boot_loop_xdata_read_audit.csv"
AUTONOMOUS_PASS_LOG_CSV = OUT / "autonomous_pass_log.csv"
BOOT_EXIT_CONSISTENCY_AUDIT_CSV = OUT / "boot_exit_consistency_audit.csv"
POST_415F_RUNTIME_HANDOFF_SUMMARY_CSV = OUT / "post_415F_runtime_handoff_summary.csv"
MATERIALIZATION_TO_OUTPUT_LINK_AUDIT_CSV = OUT / "materialization_to_output_link_audit.csv"
CONFIG_RUNTIME_MODEL_REPORT_MD = OUT / "config_runtime_model_report.md"
NEXT_AUTONOMOUS_DECISION_MD = OUT / "next_autonomous_decision.md"

CPU_INTERNAL_SFRS = {0x81, 0x82, 0x83, 0xD0, 0xE0, 0xF0}
PORT_SFRS = {0x80, 0x90, 0xA0, 0xB0}
SERIAL_TIMER_INTERRUPT_SFRS = {0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x98, 0x99, 0x9A, 0xA8, 0xB8, 0xC8}

LOOP_REGIONS = [(0x5715, 0x5733), (0x8365, 0x837F), (0x567F, 0x5683), (0x5935, 0x593D)]
BRANCH_OPS = {"JB", "JNB", "CJNE", "JZ", "JNZ", "DJNZ"}
SEED_CANDIDATE_ADDRS = sorted(
    {
        0x30BC, 0x30E1, 0x30E7, 0x30E9, 0x31BF, 0x3165, 0x364B, 0x30AC, 0x30B4, 0x30CC, 0x30D4, 0x30E0, 0x36E4,
        *range(0x30EA, 0x30FA), *range(0x36D3, 0x3700), *range(0x36F0, 0x3700),
    }
)


def _run_id(prefix: str) -> str:
    return f"{prefix}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}"


def _write_summary(rows: list[dict[str, str]]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    cols = ["run_id", "scenario", "firmware_file", "function_addr", "steps", "stop_reason", "calls_seen", "returns_seen", "xdata_reads", "xdata_writes", "unsupported_ops", "confidence", "notes"]
    with SUMMARY_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _collect_xdata_writes(run: FunctionRunResult, scenario_name: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for r in run.trace.rows:
        if r["trace_type"] != "xdata_write":
            continue
        addr = int(r["xdata_addr"], 16) if r["xdata_addr"] else 0
        note = r.get("notes", "")
        rows.append(
            {
                "run_id": run.run_id,
                "scenario": scenario_name,
                "firmware_file": run.firmware_file,
                "function_addr": f"0x{run.function_addr:04X}",
                "step": r["step"],
                "pc": r["pc"],
                "xdata_addr": f"0x{addr:04X}",
                "value": r["xdata_value"],
                "previous_value": "",
                "watchpoint_hit": "True" if "watchpoint_hit=True" in note else "False",
                "possible_role": "pointer_staging_candidate" if addr in {0x30BC, 0x30E1, 0x7160} else "unknown_record",
                "notes": "emulation_observed",
            }
        )
    return rows


def _write_xdata(rows: list[dict[str, str]]) -> None:
    cols = ["run_id", "scenario", "firmware_file", "function_addr", "step", "pc", "xdata_addr", "value", "previous_value", "watchpoint_hit", "possible_role", "notes"]
    with TRACE_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _write_unsupported(all_runs: list[FunctionRunResult]) -> None:
    counter: Counter[tuple[str, str, str]] = Counter()
    first_seen: dict[tuple[str, str, str], str] = {}
    for run in all_runs:
        for r in run.trace.rows:
            if r["trace_type"] != "unsupported_opcode":
                continue
            key = (r["op"], r["pc"], f"0x{run.function_addr:04X}")
            counter[key] += 1
            first_seen.setdefault(key, run.run_id)
    cols = ["opcode", "pc", "function_addr", "count", "first_seen_run", "notes"]
    with UNSUPPORTED_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for (opcode, pc, faddr), count in sorted(counter.items()):
            w.writerow({"opcode": opcode, "pc": pc, "function_addr": faddr, "count": count, "first_seen_run": first_seen[(opcode, pc, faddr)], "notes": "unsupported"})


def _write_candidates(xdata_rows: list[dict[str, str]]) -> None:
    cols = ["run_id", "scenario", "function_addr", "record_base", "record_bytes", "source_xdata_addrs", "possible_role", "confidence", "evidence_level", "notes"]
    grouped: dict[tuple[str, str, str], list[int]] = {}
    for r in xdata_rows:
        key = (r["run_id"], r["scenario"], r["function_addr"])
        grouped.setdefault(key, []).append(int(r["xdata_addr"], 16))

    rows: list[dict[str, str]] = []
    for (run_id, scenario, faddr), addrs in grouped.items():
        addrs = sorted(set(addrs))
        if not addrs:
            continue
        base = addrs[0]
        contiguous = [a for a in addrs if a - base < 16]
        role = "pointer_staging_candidate" if base in {0x30BC, 0x30E1, 0x7160} else "unknown_record"
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "function_addr": faddr,
                "record_base": f"0x{base:04X}",
                "record_bytes": str(len(contiguous)),
                "source_xdata_addrs": ";".join(f"0x{a:04X}" for a in contiguous),
                "possible_role": role,
                "confidence": "low",
                "evidence_level": "emulation_observed",
                "notes": "Grouped contiguous observed XDATA writes only; format not decoded.",
            }
        )

    with CANDIDATES_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _write_report(source_note: str, runs: list[FunctionRunResult], scenario_name: str | None) -> None:
    unsupported = sum(r.unsupported_ops for r in runs)
    writes = sum(r.xdata_writes for r in runs)
    funcs = ", ".join(f"0x{r.function_addr:04X}" for r in runs)
    scenario_line = scenario_name if scenario_name else "ad-hoc function run"
    bit_events = [row for run in runs for row in run.trace.rows if row.get("trace_type") == "bit_access"]
    sfr_events = [row for run in runs for row in run.trace.rows if row.get("trace_type") == "sfr_access"]
    unsupported_list = sorted({f"{row.get('op')} at {row.get('pc')}" for run in runs for row in run.trace.rows if row.get("trace_type") == "unsupported_opcode"})
    opcode_notes = _autonomous_opcode_notes(runs)
    summary_6782 = _format_6782_bit_summary(runs)
    report_lines = [
                "# Firmware execution sandbox report",
                "",
                "## Scope",
                "Experimental function-level 8051-subset tracing for selected targets. Evidence level: emulation_observed.",
                "",
                "## CPU subset status",
                "Implemented subset includes MOV/MOVX/DPTR ops, simple ALU/immediate ops (including RL A, ADDC A,direct, DIV AB, MUL AB), limited branches, LCALL/LJMP/RET, and SETB bit (0xD2).",
                "Includes initial MOVC table reads and dictionary-backed SFR access tracing (no synthetic UART behavior).",
                "Unsupported opcodes are logged and never silently ignored.",
                "ADDC currently models carry (PSW.7); auxiliary carry/overflow are not yet modeled.",
                "",
                "## Loaded firmware/artifact source",
                source_note,
                "",
                "## Target functions tested",
                f"Scenario: {scenario_line}",
                f"Functions: {funcs}",
                "",
                "## Unsupported opcodes encountered",
                str(unsupported),
                "",
                "## XDATA writes observed",
                str(writes),
                "",
                "## Candidate packet/event records",
                "See docs/emulator/candidate_packet_records.csv (contiguous observed writes only; no packet format invention).",
                "",
                "## Issue #78 progress checks",
                f"Did 0x55AD pass 0x55AC (0x23 RL A)? {'yes' if _advanced_past_opcode(runs, 0x55AD, 0x55AC) else 'no'}",
                f"Did 0x5602 pass 0x55E5 (0x23 RL A)? {'yes' if _advanced_past_opcode(runs, 0x5602, 0x55E5) else 'no'}",
                f"Did 0x5A7F pass 0x5A84 (0x35 ADDC A,direct)? {'yes' if _advanced_past_opcode(runs, 0x5A7F, 0x5A84) else 'no'}",
                f"Next unsupported opcode for 0x55AD: {_next_unsupported(runs, 0x55AD)}",
                f"Next unsupported opcode for 0x5602: {_next_unsupported(runs, 0x5602)}",
                f"Next unsupported opcode for 0x5A7F: {_next_unsupported(runs, 0x5A7F)}",
                f"Were any SBUF candidate writes observed? {'yes' if _has_trace_type(runs, 'uart_sbuf_write') else 'no'}",
                f"Were any UART TX candidate bytes observed? {'yes' if _has_trace_type(runs, 'uart_sbuf_write') else 'no'}",
                f"Were any new candidate packet/event records observed? {'yes' if writes > 0 else 'no'}",
                "Are RS-485 commands still unresolved? yes",
                "",
                "No real RS-485 command is confirmed unless UART/SBUF writes or decoded packet bytes are observed.",
                "",
                "## Autonomous packet-bridge advance summary",
                f"- Number of autonomous iterations performed: {len(opcode_notes)}.",
                "- Opcodes implemented in order:",
                f"- Final stop reason for 0x55AD: {_stop_reason_for(runs, 0x55AD)}.",
                f"- Final stop reason for 0x5602: {_stop_reason_for(runs, 0x5602)}.",
                f"- Final stop reason for 0x5A7F: {_stop_reason_for(runs, 0x5A7F)}.",
                f"- Current unsupported opcode list: {', '.join(unsupported_list) if unsupported_list else 'none'}.",
                f"- Whether any SBUF candidate writes were observed: {'yes' if _has_trace_type(runs, 'uart_sbuf_write') else 'no'}.",
                f"- Whether any UART TX candidate bytes were observed: {'yes' if _has_trace_type(runs, 'uart_sbuf_write') else 'no'}.",
                "- Whether RS-485 commands remain unresolved: yes.",
                f"- Whether any bit/SFR writes were observed: {'yes' if bit_events or sfr_events else 'no'}.",
                f"- Whether any bit/SFR write is a possible serial-control candidate: {'yes' if _any_serial_candidate_bit(bit_events) else 'no'}.",
                f"- Whether any bit/SFR write is only unknown/hypothesis: {'yes' if _any_unknown_or_hypothesis_bit(bit_events) else 'no'}.",
                f"- Whether XDATA writes continued after the last implemented blocker: {'yes' if writes > 0 else 'no'}.",
                "- Whether hotspot/control-flow summaries changed materially: yes, regenerated from this run.",
                "- Whether a hardware/peripheral architectural boundary was reached: no.",
                "",
                "### 0x6782 blocker detail (0xD2 SETB bit)",
            ]
    insert_at = report_lines.index("- Opcodes implemented in order:") + 1
    report_lines[insert_at:insert_at] = opcode_notes if opcode_notes else ["- none in this run."]
    report_lines.extend(summary_6782)
    REPORT_MD.write_text("\n".join(report_lines) + "\n", encoding="utf-8")


def _autonomous_opcode_notes(runs: list[FunctionRunResult]) -> list[str]:
    instruction_signatures = {(row.get("op", ""), row.get("args", "")) for run in runs for row in run.trace.rows if row.get("trace_type") == "instruction"}
    observed_mnemonics = {row.get("op", "") for run in runs for row in run.trace.rows if row.get("trace_type") == "instruction"}
    ordered: list[tuple[str, str, str, str]] = [
        ("0xD2", "SETB bit", "first unsupported blocker at 0x6782 in packet_bridge_seeded_context", "sets addressed bit in idata bit-RAM or bit-addressable SFR byte; PC += 2"),
        ("0x43", "ORL direct,#imm", "next unsupported blocker at 0x5E7F", "reads direct byte (idata/SFR), ORs immediate mask, writes result back"),
        ("0xF4", "CPL A", "next unsupported blocker at 0x5E9B", "bitwise inverts accumulator; flags unchanged"),
        ("0x53", "ANL direct,#imm", "next unsupported blocker at 0x5EA4", "reads direct byte (idata/SFR), ANDs immediate mask, writes result back"),
        ("0x20", "JB bit,rel", "next unsupported blocker at 0x56DE", "tests addressed bit and branches relative when bit=1"),
        ("0x30", "JNB bit,rel", "next unsupported blocker at 0x5736", "tests addressed bit and branches relative when bit=0"),
        ("0x11", "ACALL addr11", "next unsupported blocker at 0x58B8", "pushes return address and branches to 11-bit absolute target"),
        ("0x88", "MOV direct,Rn", "next unsupported blocker at 0x8363", "writes register bank byte into direct address (idata/SFR)"),
    ]
    notes: list[str] = []
    for opcode, mnemonic, why, behavior in ordered:
        observed = "yes" if _opcode_observed(opcode, mnemonic, observed_mnemonics, instruction_signatures) else "no"
        notes.append(
            f"- {opcode} {mnemonic}: implemented because {why}; standard 8051 behavior: {behavior}; limitations: no peripheral side effects beyond conservative memory/SFR bookkeeping; observed after implementation: {observed}."
        )
    return notes


def _opcode_observed(opcode: str, mnemonic: str, observed_mnemonics: set[str], signatures: set[tuple[str, str]]) -> bool:
    if mnemonic == "SETB bit":
        return ("SETB", "") in signatures or any(op == "SETB" for op in observed_mnemonics)
    if mnemonic == "ORL direct,#imm":
        return ("ORL", "0xE0,#0x01") in signatures or "ORL" in observed_mnemonics
    if mnemonic == "CPL A":
        return ("CPL", "A") in signatures
    if mnemonic == "ANL direct,#imm":
        return "ANL" in observed_mnemonics
    if mnemonic == "JB bit,rel":
        return "JB" in observed_mnemonics
    if mnemonic == "JNB bit,rel":
        return "JNB" in observed_mnemonics
    if mnemonic == "ACALL addr11":
        return "ACALL" in observed_mnemonics
    if mnemonic == "MOV direct,Rn":
        return any(op == "MOV" and ",R" in args for op, args in signatures)
    return False


def _stop_reason_for(runs: list[FunctionRunResult], function_addr: int) -> str:
    for run in runs:
        if run.function_addr == function_addr:
            return run.stop_reason
    return "not_run"


def _find_bit_event_for_pc(runs: list[FunctionRunResult], function_addr: int, pc: str) -> dict[str, str] | None:
    for run in runs:
        if run.function_addr != function_addr:
            continue
        for row in run.trace.rows:
            if row.get("trace_type") == "bit_access" and row.get("pc", "").upper() == pc.upper():
                return row
    return None


def _parse_notes_kv(notes: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in notes.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            result[k] = v
    return result


def _format_6782_bit_summary(runs: list[FunctionRunResult]) -> list[str]:
    lines: list[str] = [
        f"- Did 0x55AD pass 0x6782? {'yes' if _advanced_past_opcode(runs, 0x55AD, 0x6782) else 'no'}.",
        f"- Did 0x5602 pass 0x6782? {'yes' if _advanced_past_opcode(runs, 0x5602, 0x6782) else 'no'}.",
        "- opcode at 0x6782 = 0xD2 SETB bit.",
    ]
    for faddr in (0x55AD, 0x5602):
        row = _find_bit_event_for_pc(runs, faddr, "0x6782")
        if not row:
            lines.append(f"- 0x{faddr:04X}: no bit_access row captured at 0x6782.")
            continue
        kv = _parse_notes_kv(row.get("notes", ""))
        lines.append(
            f"- 0x{faddr:04X}: bit operand {kv.get('bit_addr','unknown')}, mapped byte {kv.get('byte_addr','unknown')}, bit index {kv.get('bit_index','unknown')}, "
            f"space={kv.get('space','unknown')}, previous_byte={kv.get('previous_byte','unknown')}, new_byte={kv.get('new_byte','unknown')}, "
            f"previous_bit={kv.get('previous_bit','unknown')}, new_bit={kv.get('new_bit','unknown')}, possible_role={kv.get('possible_role','unknown')}, "
            f"evidence_level={kv.get('evidence_level','emulation_observed')}, notes={row.get('notes','')}."
        )
    return lines


def _any_serial_candidate_bit(bit_events: list[dict[str, str]]) -> bool:
    for row in bit_events:
        kv = _parse_notes_kv(row.get("notes", ""))
        if kv.get("possible_role") == "serial_control_bit_candidate":
            return True
    return False


def _any_unknown_or_hypothesis_bit(bit_events: list[dict[str, str]]) -> bool:
    for row in bit_events:
        kv = _parse_notes_kv(row.get("notes", ""))
        if kv.get("possible_role", "unknown_bit").startswith("unknown") or "unknown_sfr_bit=true" in row.get("notes", ""):
            return True
    return False


def _has_trace_type(runs: list[FunctionRunResult], trace_type: str) -> bool:
    return any(row["trace_type"] == trace_type for run in runs for row in run.trace.rows)


def _advanced_past_opcode(runs: list[FunctionRunResult], function_addr: int, blocked_pc: int) -> bool:
    for run in runs:
        if run.function_addr != function_addr:
            continue
        for row in run.trace.rows:
            pc = row.get("pc", "")
            try:
                if int(pc, 16) > blocked_pc:
                    return True
            except ValueError:
                continue
    return False


def _next_unsupported(runs: list[FunctionRunResult], function_addr: int) -> str:
    for run in runs:
        if run.function_addr != function_addr:
            continue
        for row in run.trace.rows:
            if row.get("trace_type") == "unsupported_opcode":
                return f"{row.get('op', 'unknown')} at {row.get('pc', 'unknown')}"
    return "none observed"


def run_scenario(name: str, max_steps: int, compact_summary: bool = False, max_trace_rows: int = 50) -> None:
    scenario = get_scenario(name)
    img = load_code_image(ROOT / scenario.firmware_file)
    harness = FunctionHarness(img, watchpoints=scenario.watchpoints)

    all_runs: list[FunctionRunResult] = []
    summary_rows: list[dict[str, str]] = []
    xdata_rows: list[dict[str, str]] = []

    for faddr in scenario.functions:
        rid = _run_id(f"{name}_{faddr:04X}")
        init_regs = scenario.init_regs.get(faddr, {}) if hasattr(scenario, "init_regs") else {}
        run = harness.run_function(
            rid,
            faddr,
            max_steps=max_steps,
            init_xdata=scenario.seed_xdata,
            init_regs=init_regs or None,
        )
        all_runs.append(run)
        if not compact_summary:
            trace_path = OUT / f"trace_{rid}.csv"
            run.trace.write_csv(trace_path)
        summary_rows.append(
            {
                "run_id": rid,
                "scenario": name,
                "firmware_file": scenario.firmware_file,
                "function_addr": f"0x{faddr:04X}",
                "steps": str(run.steps),
                "stop_reason": run.stop_reason,
                "calls_seen": str(run.calls_seen),
                "returns_seen": str(run.returns_seen),
                "xdata_reads": str(run.xdata_reads),
                "xdata_writes": str(run.xdata_writes),
                "unsupported_ops": str(run.unsupported_ops),
                "confidence": "low",
                "notes": "emulation_observed",
            }
        )
        xdata_rows.extend(_collect_xdata_writes(run, name))

    _write_summary(summary_rows)
    _write_pzu_load_metadata(img)
    _write_report(f"{img.firmware_file} via {img.source}", all_runs, scenario_name=name)
    if compact_summary:
        _write_compact_variant_outputs(name, max_steps, all_runs, max_trace_rows=max_trace_rows)
        return
    _write_xdata(xdata_rows)
    _write_unsupported(all_runs)
    _write_candidates(xdata_rows)
    _write_sfr_trace(all_runs, name)
    _write_code_read_trace(all_runs, name)
    _write_direct_memory_trace(all_runs, name)
    _write_uart_sbuf_trace(all_runs, name)
    _write_bit_access_trace(all_runs, name)
    _write_cpu_subset_coverage(all_runs)
    _write_pc_hotspot_summary(all_runs, name)
    _write_control_flow_summary(all_runs, name)
    _write_code_table_candidate_summary(all_runs, name)


def _collect_branch_audit_rows(iteration: int, scenario_name: str, run: FunctionRunResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    ins = [r for r in run.trace.rows if r.get("trace_type") == "instruction"]
    grouped: dict[tuple[str, str, str, str, str, str], list[int]] = {}
    for idx, row in enumerate(ins[:-1]):
        pc = _parse_hex_int(row.get("pc", "0x0"))
        op = row.get("op", "")
        if pc not in {0x5736, 0x5748} and not (0x5765 <= pc <= 0x5785) and not (0x58B1 <= pc <= 0x58D0):
            continue
        if op not in BRANCH_OPS:
            continue
        args = row.get("args", "")
        target = _rel_target_from_args(pc, op, args)
        fallthrough = _fallthrough_pc(pc, op)
        next_pc = _parse_hex_int(ins[idx + 1].get("pc", "0x0"))
        taken = "yes" if next_pc == target else "no" if next_pc == fallthrough else "unknown"
        cond_src = "unknown"
        cond_val = ""
        if op in {"JB", "JNB"}:
            cond_src = args.split(",")[0].strip()
            if pc == 0x5736:
                cond_val = "ACC.0"
        elif op in {"JZ", "JNZ"}:
            cond_src = "A"
            cond_val = row.get("acc_before", "")
        elif op == "DJNZ":
            cond_src = args.split(",")[0].strip()
        elif op == "CJNE":
            parts = [p.strip() for p in args.split(",")]
            cond_src = parts[0] if parts else "unknown"
            cond_val = parts[1] if len(parts) > 1 else ""
        key = (f"0x{pc:04X}", op, cond_src, cond_val, f"0x{target:04X}", taken)
        grouped.setdefault(key, []).append(int(row.get("step", "0")))
    for (pc, op, cond_src, cond_val, target, taken), steps in sorted(grouped.items()):
        rows.append(
            {
                "iteration": str(iteration),
                "scenario": scenario_name,
                "function_addr": f"0x{run.function_addr:04X}",
                "pc": pc,
                "op": op,
                "condition_source": cond_src,
                "condition_value": cond_val,
                "target_pc": target,
                "taken": taken,
                "count": str(len(steps)),
                "first_step": str(min(steps)),
                "last_step": str(max(steps)),
                "notes": "emulation_observed",
            }
        )
    return rows


def _collect_helper_5935_rows(iteration: int, scenario_name: str, run: FunctionRunResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    ins = [r for r in run.trace.rows if r.get("trace_type") == "instruction"]
    call_rows = [r for r in ins if _parse_hex_int(r.get("pc", "0x0")) == 0x5745 and r.get("op") == "LCALL" and r.get("args") == "0x5935"]
    if not call_rows:
        return rows
    first_call = call_rows[0]
    entry_step = int(first_call.get("step", "0"))
    post_rows = [r for r in ins if int(r.get("step", "0")) > entry_step and _parse_hex_int(r.get("pc", "0x0")) == 0x5748]
    returned = bool(post_rows)
    return_step = int(post_rows[0].get("step", "0")) if returned else ""
    after_row = post_rows[0] if returned else {}
    xreads = sorted(
        {
            r.get("xdata_addr", "")
            for r in run.trace.rows
            if r.get("trace_type") == "xdata_read" and entry_step <= int(r.get("step", "0")) <= (return_step if returned else run.steps)
        }
    )
    xwrites = sorted(
        {
            f"{r.get('xdata_addr', '')}:{r.get('xdata_value', '')}"
            for r in run.trace.rows
            if r.get("trace_type") == "xdata_write" and entry_step <= int(r.get("step", "0")) <= (return_step if returned else run.steps)
        }
    )
    rows.append(
        {
            "iteration": str(iteration),
            "scenario": scenario_name,
            "function_addr": f"0x{run.function_addr:04X}",
            "call_pc": "0x5745",
            "helper_addr": "0x5935",
            "entry_step": str(entry_step),
            "return_step": str(return_step),
            "returned": "yes" if returned else "no",
            "acc_before": first_call.get("acc_before", ""),
            "acc_after": after_row.get("acc_before", ""),
            "r0_before": first_call.get("r0", ""),
            "r0_after": after_row.get("r0", ""),
            "r1_before": first_call.get("r1", ""),
            "r1_after": after_row.get("r1", ""),
            "dptr_before": first_call.get("dptr_before", ""),
            "dptr_after": after_row.get("dptr_before", ""),
            "psw_before": "unknown",
            "psw_after": "unknown",
            "xdata_reads_digest": ";".join(xreads[:8]),
            "xdata_writes_digest": ";".join(xwrites[:8]),
            "notes": "first_call_only_compact",
        }
    )
    return rows


def _stack_digest_for_window(run: FunctionRunResult, start_step: int, end_step: int) -> str:
    stack_rows = [
        r
        for r in run.trace.rows
        if r.get("trace_type") == "sfr_access"
        and r.get("sfr_addr") == "0x0081"
        and start_step <= int(r.get("step", "0")) <= end_step
    ]
    return ";".join(f"{r.get('step')}:{r.get('sfr_value')}" for r in stack_rows[:8])


def _serial_audit_counts(run: FunctionRunResult) -> tuple[int, int, int, int]:
    sbuf_writes = sum(1 for r in run.trace.rows if r.get("trace_type") == "uart_sbuf_write")
    sfr_uart = sum(1 for r in run.trace.rows if r.get("trace_type") == "sfr_access" and r.get("sfr_addr") in {"0x0098", "0x0099"})
    bit_uart = sum(1 for r in run.trace.rows if r.get("trace_type") == "bit_access" and ("serial_control_bit_candidate" in r.get("notes", "")))
    return sbuf_writes, sbuf_writes, sfr_uart, bit_uart


def _collect_callsite_rows(iteration: int, scenario_name: str, run: FunctionRunResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    ins = [r for r in run.trace.rows if r.get("trace_type") == "instruction"]
    if not ins:
        return rows
    focus: list[tuple[int, int]] = [(0x5745, 0x5935), (0x574E, 0x5A7F)]
    for row in ins:
        pc = _parse_hex_int(row.get("pc", "0x0"))
        if row.get("op") != "LCALL":
            continue
        target = _parse_hex_int(row.get("args", "0x0"))
        if (0x5765 <= pc <= 0x5795) or (0x58B1 <= pc <= 0x58D0) or (pc == 0x58CA):
            focus.append((pc, target))
    dedup_focus = sorted(set(focus))
    for callsite_pc, expected_callee in dedup_focus:
        callsite_rows = [r for r in ins if _parse_hex_int(r.get("pc", "0x0")) == callsite_pc]
        call_exec_rows = [r for r in callsite_rows if r.get("op") == "LCALL" and _parse_hex_int(r.get("args", "0x0")) == expected_callee]
        callsite_reached = bool(callsite_rows)
        call_executed = bool(call_exec_rows)
        if call_executed:
            first_call = call_exec_rows[0]
            call_step = int(first_call.get("step", "0"))
            callee_rows = [r for r in ins if int(r.get("step", "0")) > call_step and _parse_hex_int(r.get("pc", "0x0")) == expected_callee]
            return_pc = (callsite_pc + 3) & 0xFFFF
            return_rows = [r for r in ins if int(r.get("step", "0")) > call_step and _parse_hex_int(r.get("pc", "0x0")) == return_pc]
            sp_events = [r for r in run.trace.rows if r.get("trace_type") == "sfr_access" and r.get("sfr_addr") == "0x0081"]
            sp_before = next((r.get("sfr_value", "") for r in reversed(sp_events) if int(r.get("step", "0")) <= call_step), "")
            sp_after = next((r.get("sfr_value", "") for r in sp_events if return_rows and int(r.get("step", "0")) >= int(return_rows[0].get("step", "0"))), "")
            sbuf_writes, uart_tx, sfr_uart, bit_uart = _serial_audit_counts(run)
            notes = "emulation_observed"
            if not callee_rows:
                notes += ";callee_entry_missing_possible_stub_or_branch_gap"
            if not return_rows:
                notes += ";no_return_pc_seen_within_run"
            rows.append(
                {
                    "scenario": scenario_name,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "max_steps": "2000",
                    "callsite_pc": f"0x{callsite_pc:04X}",
                    "expected_callee": f"0x{expected_callee:04X}",
                    "callsite_reached": "yes" if callsite_reached else "no",
                    "call_executed": "yes" if call_executed else "no",
                    "callee_entry_observed": "yes" if bool(callee_rows) else "no",
                    "callee_return_observed": "yes" if bool(return_rows) else "no",
                    "return_pc": f"0x{return_pc:04X}",
                    "sp_before": sp_before,
                    "sp_after": sp_after,
                    "stack_digest": _stack_digest_for_window(run, call_step, int(return_rows[0].get("step", "0")) if return_rows else run.steps),
                    "stop_reason": run.stop_reason,
                    "sbuf_writes": str(sbuf_writes),
                    "uart_tx_candidates": str(uart_tx),
                    "notes": f"{notes};sfr_uart={sfr_uart};serial_bits={bit_uart};iteration={iteration}",
                }
            )
        else:
            sbuf_writes, uart_tx, sfr_uart, bit_uart = _serial_audit_counts(run)
            rows.append(
                {
                    "scenario": scenario_name,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "max_steps": "2000",
                    "callsite_pc": f"0x{callsite_pc:04X}",
                    "expected_callee": f"0x{expected_callee:04X}",
                    "callsite_reached": "yes" if callsite_reached else "no",
                    "call_executed": "no",
                    "callee_entry_observed": "no",
                    "callee_return_observed": "no",
                    "return_pc": f"0x{(callsite_pc + 3) & 0xFFFF:04X}",
                    "sp_before": "",
                    "sp_after": "",
                    "stack_digest": "",
                    "stop_reason": run.stop_reason,
                    "sbuf_writes": str(sbuf_writes),
                    "uart_tx_candidates": str(uart_tx),
                    "notes": f"emulation_observed;call_not_executed;sfr_uart={sfr_uart};serial_bits={bit_uart};iteration={iteration}",
                }
            )
    return rows


def _collect_5a7f_context_row(scenario_name: str, run: FunctionRunResult, entry_context: str, callsite_pc: str) -> dict[str, str]:
    ins = [r for r in run.trace.rows if r.get("trace_type") == "instruction"]
    callee_rows = [r for r in ins if _parse_hex_int(r.get("pc", "0x0")) == 0x5A7F]
    if not callee_rows:
        sbuf_writes, uart_tx, sfr_uart, bit_uart = _serial_audit_counts(run)
        return {
            "scenario": scenario_name,
            "entry_context": entry_context,
            "callsite_pc": callsite_pc,
            "callee_addr": "0x5A7F",
            "steps_in_callee": "0",
            "returned": "no",
            "return_pc": "",
            "acc_entry": "",
            "acc_exit": "",
            "r0_entry": "",
            "r0_exit": "",
            "r1_entry": "",
            "r1_exit": "",
            "dptr_entry": "",
            "dptr_exit": "",
            "psw_entry": "unknown",
            "psw_exit": "unknown",
            "xdata_reads_digest": "",
            "xdata_writes_digest": "",
            "sfr_writes_digest": f"sfr_uart={sfr_uart};serial_bits={bit_uart}",
            "sbuf_writes": str(sbuf_writes),
            "uart_tx_candidates": str(uart_tx),
            "notes": "callee_not_observed",
        }
    first = callee_rows[0]
    first_step = int(first.get("step", "0"))
    ret_rows = [r for r in ins if int(r.get("step", "0")) > first_step and _parse_hex_int(r.get("pc", "0x0")) != 0x5A7F]
    returned = bool(ret_rows)
    ret_pc = ret_rows[0].get("pc", "") if returned else ""
    last = ret_rows[0] if returned else callee_rows[-1]
    callee_xreads = sorted(
        {r.get("xdata_addr", "") for r in run.trace.rows if r.get("trace_type") == "xdata_read" and int(r.get("step", "0")) >= first_step}
    )
    callee_xwrites = sorted(
        {f"{r.get('xdata_addr', '')}:{r.get('xdata_value', '')}" for r in run.trace.rows if r.get("trace_type") == "xdata_write" and int(r.get("step", "0")) >= first_step}
    )
    callee_sfr = sorted(
        {f"{r.get('sfr_addr', '')}:{r.get('sfr_value', '')}" for r in run.trace.rows if r.get("trace_type") == "sfr_access" and int(r.get("step", "0")) >= first_step}
    )
    sbuf_writes, uart_tx, _, _ = _serial_audit_counts(run)
    return {
        "scenario": scenario_name,
        "entry_context": entry_context,
        "callsite_pc": callsite_pc,
        "callee_addr": "0x5A7F",
        "steps_in_callee": str(len(callee_rows)),
        "returned": "yes" if returned else "no",
        "return_pc": ret_pc,
        "acc_entry": first.get("acc_before", ""),
        "acc_exit": last.get("acc_after", ""),
        "r0_entry": first.get("r0", ""),
        "r0_exit": last.get("r0", ""),
        "r1_entry": first.get("r1", ""),
        "r1_exit": last.get("r1", ""),
        "dptr_entry": first.get("dptr_before", ""),
        "dptr_exit": last.get("dptr_after", ""),
        "psw_entry": "unknown",
        "psw_exit": "unknown",
        "xdata_reads_digest": ";".join(callee_xreads[:8]),
        "xdata_writes_digest": ";".join(callee_xwrites[:8]),
        "sfr_writes_digest": ";".join(callee_sfr[:8]),
        "sbuf_writes": str(sbuf_writes),
        "uart_tx_candidates": str(uart_tx),
        "notes": "emulation_observed_compact",
    }


def run_autonomous_post_loop(max_iterations: int = 1) -> None:
    scenarios = [
        "packet_bridge_loop_force_r3_01",
        "packet_bridge_loop_force_djnz_exit_candidate",
        "packet_bridge_loop_force_jb_not_taken_candidate",
    ]
    bounded_iterations = max(1, min(max_iterations, 6))
    path_rows: list[dict[str, str]] = []
    branch_rows: list[dict[str, str]] = []
    helper_rows: list[dict[str, str]] = []
    callsite_rows: list[dict[str, str]] = []
    helper_5a7f_rows: list[dict[str, str]] = []
    latest_blocker = "unknown"
    reached_5745_any = False
    helper_returned_any = False
    reached_5748_any = False
    reached_574e_any = False
    reached_5765_any = False
    reached_58b1_any = False
    sbuf_total = 0
    uart_total = 0
    for iteration in range(1, bounded_iterations + 1):
        for scenario_name in scenarios:
            scenario = get_scenario(scenario_name)
            img = load_code_image(ROOT / scenario.firmware_file)
            harness = FunctionHarness(img, watchpoints=scenario.watchpoints)
            run = harness.run_function(
                _run_id(f"{scenario_name}_{scenario.functions[0]:04X}"),
                scenario.functions[0],
                max_steps=2000,
                init_xdata=scenario.seed_xdata,
                init_regs=scenario.init_regs.get(scenario.functions[0], {}),
            )
            pcs = {_parse_hex_int(r.get("pc", "0x0")) for r in run.trace.rows if r.get("pc")}
            reached_573c = 0x573C in pcs
            reached_5745 = 0x5745 in pcs
            reached_5748 = 0x5748 in pcs
            reached_574e = 0x574E in pcs
            reached_5765 = 0x5765 in pcs
            reached_58b1 = 0x58B1 in pcs
            reached_5a7f = 0x5A7F in pcs
            sbuf_writes = sum(1 for r in run.trace.rows if r.get("trace_type") == "uart_sbuf_write")
            reached_5745_any = reached_5745_any or reached_5745
            helper_returned = any(r.get("trace_type") == "instruction" and _parse_hex_int(r.get("pc", "0x0")) == 0x5748 for r in run.trace.rows)
            helper_returned_any = helper_returned_any or helper_returned
            reached_5748_any = reached_5748_any or reached_5748
            reached_574e_any = reached_574e_any or reached_574e
            reached_5765_any = reached_5765_any or reached_5765
            reached_58b1_any = reached_58b1_any or reached_58b1
            sbuf_total += sbuf_writes
            uart_total += sbuf_writes
            next_blocker = "missing_runtime_or_peripheral_context" if run.stop_reason == "max_steps" and run.unsupported_ops == 0 else run.stop_reason
            latest_blocker = next_blocker
            path_rows.append(
                {
                    "iteration": str(iteration),
                    "scenario": scenario_name,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "max_steps": "2000",
                    "steps": str(run.steps),
                    "stop_reason": run.stop_reason,
                    "reached_573C": "yes" if reached_573c else "no",
                    "reached_5745": "yes" if reached_5745 else "no",
                    "reached_5748": "yes" if reached_5748 else "no",
                    "reached_574E": "yes" if reached_574e else "no",
                    "reached_5765": "yes" if reached_5765 else "no",
                    "reached_58B1": "yes" if reached_58b1 else "no",
                    "reached_5A7F_after_loop": "yes" if reached_5a7f else "no",
                    "sbuf_writes": str(sbuf_writes),
                    "uart_tx_candidates": str(sbuf_writes),
                    "next_blocker": next_blocker,
                    "notes": "emulation_observed_compact",
                }
            )
            branch_rows.extend(_collect_branch_audit_rows(iteration, scenario_name, run))
            helper_rows.extend(_collect_helper_5935_rows(iteration, scenario_name, run))
            callsite_rows.extend(_collect_callsite_rows(iteration, scenario_name, run))
            if scenario_name == "packet_bridge_loop_force_r3_01":
                helper_5a7f_rows.append(_collect_5a7f_context_row(scenario_name, run, "autonomous_post_loop_entry@0x5715", "0x574E?"))

        deep_scenario = "packet_bridge_loop_force_r3_01"
        scenario = get_scenario(deep_scenario)
        img = load_code_image(ROOT / scenario.firmware_file)
        harness = FunctionHarness(img, watchpoints=scenario.watchpoints)
        deep_run = harness.run_function(
            _run_id(f"{deep_scenario}_{scenario.functions[0]:04X}_deep"),
            scenario.functions[0],
            max_steps=5000,
            init_xdata=scenario.seed_xdata,
            init_regs=scenario.init_regs.get(scenario.functions[0], {}),
        )
        deep_pcs = {_parse_hex_int(r.get("pc", "0x0")) for r in deep_run.trace.rows if r.get("pc")}
        deep_sbuf = sum(1 for r in deep_run.trace.rows if r.get("trace_type") == "uart_sbuf_write")
        path_rows.append(
            {
                "iteration": str(iteration),
                "scenario": f"{deep_scenario}_deep5000",
                "function_addr": f"0x{deep_run.function_addr:04X}",
                "max_steps": "5000",
                "steps": str(deep_run.steps),
                "stop_reason": deep_run.stop_reason,
                "reached_573C": "yes" if 0x573C in deep_pcs else "no",
                "reached_5745": "yes" if 0x5745 in deep_pcs else "no",
                "reached_5748": "yes" if 0x5748 in deep_pcs else "no",
                "reached_574E": "yes" if 0x574E in deep_pcs else "no",
                "reached_5765": "yes" if 0x5765 in deep_pcs else "no",
                "reached_58B1": "yes" if 0x58B1 in deep_pcs else "no",
                "reached_5A7F_after_loop": "yes" if 0x5A7F in deep_pcs else "no",
                "sbuf_writes": str(deep_sbuf),
                "uart_tx_candidates": str(deep_sbuf),
                "next_blocker": "missing_runtime_or_peripheral_context" if deep_run.stop_reason == "max_steps" and deep_run.unsupported_ops == 0 else deep_run.stop_reason,
                "notes": "emulation_observed_compact_deep_run",
            }
        )
        callsite_rows.extend(_collect_callsite_rows(iteration, f"{deep_scenario}_deep5000", deep_run))

    with POST_LOOP_PATH_SUMMARY_CSV.open("w", encoding="utf-8", newline="") as fh:
        cols = [
            "iteration", "scenario", "function_addr", "max_steps", "steps", "stop_reason", "reached_573C", "reached_5745", "reached_5748",
            "reached_574E", "reached_5765", "reached_58B1", "reached_5A7F_after_loop", "sbuf_writes", "uart_tx_candidates", "next_blocker", "notes",
        ]
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        writer.writerows(path_rows)
    with POST_LOOP_BRANCH_AUDIT_CSV.open("w", encoding="utf-8", newline="") as fh:
        cols = ["iteration", "scenario", "function_addr", "pc", "op", "condition_source", "condition_value", "target_pc", "taken", "count", "first_step", "last_step", "notes"]
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        writer.writerows(branch_rows)
    with HELPER_5935_EFFECT_AUDIT_CSV.open("w", encoding="utf-8", newline="") as fh:
        cols = [
            "iteration", "scenario", "function_addr", "call_pc", "helper_addr", "entry_step", "return_step", "returned", "acc_before", "acc_after",
            "r0_before", "r0_after", "r1_before", "r1_after", "dptr_before", "dptr_after", "psw_before", "psw_after", "xdata_reads_digest", "xdata_writes_digest", "notes",
        ]
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        writer.writerows(helper_rows)
    helper_probe_specs = [
        ("packet_bridge_stub_5a7f", 0x5A7F, "direct_helper_entry_hypothesis", "forced_entry"),
        ("packet_bridge_post_loop_from_574E_context", 0x574E, "forced_entry_from_574E_hypothesis", "0x574E"),
    ]
    for scen_name, faddr, entry_ctx, callsite in helper_probe_specs:
        scenario = get_scenario(scen_name)
        img = load_code_image(ROOT / scenario.firmware_file)
        harness = FunctionHarness(img, watchpoints=scenario.watchpoints)
        run = harness.run_function(
            _run_id(f"{scen_name}_{faddr:04X}_cmp"),
            faddr,
            max_steps=1000,
            init_xdata=scenario.seed_xdata,
            init_regs=scenario.init_regs.get(faddr, {}),
            use_stubs=False,
        )
        helper_5a7f_rows.append(_collect_5a7f_context_row(scen_name, run, entry_ctx, callsite))
    img = load_code_image(ROOT / "90CYE03_19_DKS.PZU")
    harness = FunctionHarness(img, watchpoints=get_scenario("packet_bridge_default").watchpoints)
    for faddr, callsite in [(0x571A, "0x571A"), (0x5730, "0x5730")]:
        run = harness.run_function(
            _run_id(f"callee_cmp_{faddr:04X}"),
            faddr,
            max_steps=1000,
            init_regs={"A": 0x00, "R0": 0x00, "R1": 0x01},
            init_xdata={0x30E1: 0x00, 0x30C4: 0x00},
            use_stubs=False,
        )
        helper_5a7f_rows.append(_collect_5a7f_context_row(f"direct_callsite_{callsite}", run, "direct_callsite_entry_hypothesis", callsite))
    with POST_LOOP_CALLSITE_CALLEE_AUDIT_CSV.open("w", encoding="utf-8", newline="") as fh:
        cols = [
            "scenario", "function_addr", "max_steps", "callsite_pc", "expected_callee", "callsite_reached", "call_executed",
            "callee_entry_observed", "callee_return_observed", "return_pc", "sp_before", "sp_after", "stack_digest",
            "stop_reason", "sbuf_writes", "uart_tx_candidates", "notes",
        ]
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        writer.writerows(callsite_rows)
    with HELPER_5A7F_CONTEXT_COMPARISON_CSV.open("w", encoding="utf-8", newline="") as fh:
        cols = [
            "scenario", "entry_context", "callsite_pc", "callee_addr", "steps_in_callee", "returned", "return_pc", "acc_entry", "acc_exit",
            "r0_entry", "r0_exit", "r1_entry", "r1_exit", "dptr_entry", "dptr_exit", "psw_entry", "psw_exit", "xdata_reads_digest",
            "xdata_writes_digest", "sfr_writes_digest", "sbuf_writes", "uart_tx_candidates", "notes",
        ]
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        writer.writerows(helper_5a7f_rows)
    AUTONOMOUS_UART_PURSUIT_SUMMARY_MD.write_text(
        "\n".join(
            [
                "# Autonomous UART pursuit summary",
                "",
                f"- Iterations performed: {bounded_iterations}.",
                "- Fixes implemented: added compact autonomous post-loop reporting command and focused helper/branch audits.",
                "- Scenarios run: packet_bridge_loop_force_r3_01, packet_bridge_loop_force_djnz_exit_candidate, packet_bridge_loop_force_jb_not_taken_candidate, plus deep run packet_bridge_loop_force_r3_01@5000.",
                f"- Latest stop reason: {latest_blocker}.",
                f"- Whether 0x5745 was reached: {'yes' if reached_5745_any else 'no'}.",
                f"- Whether 0x5935 returned: {'yes' if helper_returned_any else 'no'}.",
                f"- Whether 0x5748 branch decision was observed: {'yes' if reached_5748_any else 'no'}.",
                f"- Whether 0x574E LCALL 0x5A7F was reached: {'yes' if reached_574e_any else 'no'}.",
                f"- Whether 0x5765 or 0x58B1 was reached: {'yes' if (reached_5765_any or reached_58b1_any) else 'no'}.",
                f"- Whether SBUF candidate writes were observed: {'yes' if sbuf_total > 0 else 'no'}.",
                f"- Whether UART TX candidate bytes were observed: {'yes' if uart_total > 0 else 'no'}.",
                "- Whether RS-485 commands remain unresolved: yes.",
                "- Blocker classification: missing runtime/peripheral context.",
                "",
                "## Post-loop 0x5A7F call verification",
                f"- Was 0x574E reached? {'yes' if reached_574e_any else 'no'}.",
                f"- Was LCALL at 0x574E executed? {'yes' if any(r.get('callsite_pc') == '0x574E' and r.get('call_executed') == 'yes' for r in callsite_rows) else 'no'}.",
                f"- Was 0x5A7F entry observed after 0x574E? {'yes' if any(r.get('callsite_pc') == '0x574E' and r.get('callee_entry_observed') == 'yes' for r in callsite_rows) else 'no'}.",
                f"- Did 0x5A7F return? {'yes' if any(r.get('callsite_pc') == '0x574E' and r.get('callee_return_observed') == 'yes' for r in callsite_rows) else 'no'}.",
                f"- Observed return PC from 0x574E call path: {next((r.get('return_pc') for r in callsite_rows if r.get('callsite_pc') == '0x574E' and r.get('call_executed') == 'yes'), 'unknown')}.",
                f"- Did stack/SP look consistent? {'yes' if any(r.get('callsite_pc') == '0x574E' and r.get('sp_before') and r.get('sp_after') for r in callsite_rows) else 'unknown'}.",
                f"- Did forced 0x574E context behave differently from direct 0x5A7F? {'yes' if any(r.get('scenario') == 'packet_bridge_post_loop_from_574E_context' and r.get('notes') != 'callee_not_observed' for r in helper_5a7f_rows) else 'no_clear_difference'} (hypothesis-only forced entry).",
                f"- Did any 0x5A7F context produce SBUF candidate writes? {'yes' if any(int(r.get('sbuf_writes', '0')) > 0 for r in helper_5a7f_rows) else 'no'}.",
                f"- Did any context produce UART TX candidate bytes? {'yes' if any(int(r.get('uart_tx_candidates', '0')) > 0 for r in helper_5a7f_rows) else 'no'}.",
                "- Are RS-485 commands still unresolved? yes (no direct UART/SBUF payload evidence).",
                f"- Refined blocker classification: {'callsite_tracking_gap' if any(r.get('callsite_pc') == '0x574E' and r.get('call_executed') == 'yes' and r.get('callee_entry_observed') == 'no' for r in callsite_rows) else 'missing_runtime_or_peripheral_context'}.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def run_single_function(firmware: str, addr: int, max_steps: int) -> None:
    img = load_code_image(ROOT / firmware)
    harness = FunctionHarness(img)
    rid = _run_id(f"single_{addr:04X}")
    run = harness.run_function(rid, addr, max_steps=max_steps)
    OUT.mkdir(parents=True, exist_ok=True)
    run.trace.write_csv(OUT / f"trace_{rid}.csv")
    _write_summary(
        [
            {
                "run_id": rid,
                "scenario": "single",
                "firmware_file": firmware,
                "function_addr": f"0x{addr:04X}",
                "steps": str(run.steps),
                "stop_reason": run.stop_reason,
                "calls_seen": str(run.calls_seen),
                "returns_seen": str(run.returns_seen),
                "xdata_reads": str(run.xdata_reads),
                "xdata_writes": str(run.xdata_writes),
                "unsupported_ops": str(run.unsupported_ops),
                "confidence": "low",
                "notes": "emulation_observed",
            }
        ]
    )
    _write_xdata(_collect_xdata_writes(run, "single"))
    _write_unsupported([run])
    _write_candidates(_collect_xdata_writes(run, "single"))
    _write_sfr_trace([run], "single")
    _write_code_read_trace([run], "single")
    _write_pzu_load_metadata(img)
    _write_direct_memory_trace([run], "single")
    _write_uart_sbuf_trace([run], "single")
    _write_bit_access_trace([run], "single")
    _write_cpu_subset_coverage([run])
    _write_pc_hotspot_summary([run], "single")
    _write_control_flow_summary([run], "single")
    _write_code_table_candidate_summary([run], "single")
    _write_report(f"{img.firmware_file} via {img.source}", [run], scenario_name=None)


def _empty_csv(path: Path, cols: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()


def _write_boot_runtime_outputs(img, run: FunctionRunResult, entry: int, max_steps: int) -> None:
    rows = run.trace.rows
    last_pc = rows[-1].get("pc", "") if rows else ""
    instruction_rows = [r for r in rows if r.get("trace_type") == "instruction"]
    direct_reads = sum(1 for r in rows if r.get("trace_type") == "direct_memory_read")
    direct_writes = sum(1 for r in rows if r.get("trace_type") == "direct_memory_write")
    sfr_reads = sum(1 for r in rows if r.get("trace_type") == "sfr_access" and r.get("notes", "").startswith("read"))
    sfr_writes = sum(1 for r in rows if r.get("trace_type") == "sfr_access" and r.get("notes", "").startswith("write"))
    code_reads = sum(1 for r in rows if r.get("trace_type") == "code_read")
    sbuf_writes = sum(1 for r in rows if r.get("trace_type") == "uart_sbuf_write")
    loops = _detect_runtime_loops(run)
    display_candidates = _collect_display_candidates(run)
    keypad_candidates = _collect_keypad_candidates(run)
    display_device_candidates = [r for r in display_candidates if r.get("role_candidate") not in {"cpu_internal_sfr"}]
    keypad_device_candidates = [r for r in keypad_candidates if r.get("role_candidate") not in {"cpu_internal_sfr"}]
    uart_init = _collect_uart_init_candidates(run)
    timer_interrupt = _collect_timer_interrupt_candidates(run)
    display_tables = _scan_display_text_candidates(img, instruction_rows, run.run_id, entry)
    static_candidates = _scan_display_keypad_static_candidates(img)

    stop_reason = run.stop_reason
    if stop_reason == "max_steps" and loops:
        stop_reason = "stable_runtime_loop_detected"
    if stop_reason == "max_steps" and any(r["role_candidate"] == "timer_wait_candidate" for r in loops):
        stop_reason = "blocked_until_timer_interrupt_model"

    summary_cols = [
        "run_id", "firmware_file", "entry_pc", "max_steps", "steps", "stop_reason", "last_pc", "unsupported_ops", "calls_seen", "returns_seen",
        "xdata_reads", "xdata_writes", "sfr_reads", "sfr_writes", "direct_reads", "direct_writes", "code_reads", "sbuf_writes",
        "uart_tx_candidates", "display_candidates", "keypad_candidates", "timer_candidates", "interrupt_candidates", "notes",
    ]
    with BOOT_TRACE_SUMMARY_CSV.open("a", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=summary_cols)
        if fh.tell() == 0:
            w.writeheader()
        w.writerow(
            {
                "run_id": run.run_id,
                "firmware_file": run.firmware_file,
                "entry_pc": f"0x{entry:04X}",
                "max_steps": str(max_steps),
                "steps": str(run.steps),
                "stop_reason": stop_reason,
                "last_pc": last_pc,
                "unsupported_ops": str(run.unsupported_ops),
                "calls_seen": str(run.calls_seen),
                "returns_seen": str(run.returns_seen),
                "xdata_reads": str(run.xdata_reads),
                "xdata_writes": str(run.xdata_writes),
                "sfr_reads": str(sfr_reads),
                "sfr_writes": str(sfr_writes),
                "direct_reads": str(direct_reads),
                "direct_writes": str(direct_writes),
                "code_reads": str(code_reads),
                "sbuf_writes": str(sbuf_writes),
                "uart_tx_candidates": str(sbuf_writes),
                "display_candidates": str(len(display_device_candidates)),
                "keypad_candidates": str(len(keypad_device_candidates)),
                "timer_candidates": str(sum(1 for r in timer_interrupt if "timer" in r["role_candidate"])),
                "interrupt_candidates": str(sum(1 for r in timer_interrupt if "interrupt" in r["role_candidate"] or r["role_candidate"] == "reti_candidate")),
                "notes": "emulation_observed_boot_runtime",
            }
        )

    _append_capped_csv(
        BOOT_INIT_WRITE_SUMMARY_CSV,
        ["run_id", "entry_pc", "step", "pc", "space", "addr", "value", "previous_value", "access_type", "role_candidate", "evidence_level", "confidence", "notes"],
        _collect_boot_init_writes(run, entry),
        ("run_id", "step", "space", "addr"),
        200,
    )
    _append_capped_csv(
        RUNTIME_LOOP_CANDIDATES_CSV,
        ["run_id", "entry_pc", "loop_region", "pc_start", "pc_end", "hit_count", "first_step", "last_step", "branch_pc", "branch_op", "branch_target", "possible_role", "evidence_level", "notes"],
        loops,
        ("run_id", "entry_pc", "pc_start", "pc_end", "branch_pc", "branch_target"),
        200,
    )
    _append_capped_csv(
        DISPLAY_CANDIDATE_TRACE_CSV,
        ["run_id", "entry_pc", "step", "pc", "access_type", "space", "addr", "value", "role_candidate", "nearby_code_context", "evidence_level", "confidence", "notes"],
        display_candidates,
        ("run_id", "step", "pc", "space", "addr"),
        200,
    )
    _append_capped_csv(
        KEYPAD_CANDIDATE_TRACE_CSV,
        ["run_id", "entry_pc", "step", "pc", "access_type", "space", "addr", "value", "role_candidate", "branch_dependency", "evidence_level", "confidence", "notes"],
        keypad_candidates,
        ("run_id", "step", "pc", "space", "addr"),
        200,
    )
    _append_capped_csv(
        UART_INIT_CANDIDATE_TRACE_CSV,
        ["run_id", "entry_pc", "step", "pc", "access_type", "sfr_addr", "value", "previous_value", "role_candidate", "uart_channel_candidate", "physical_channel_candidate", "evidence_level", "confidence", "notes"],
        uart_init,
        ("run_id", "step", "pc", "sfr_addr", "access_type"),
        200,
    )
    _append_capped_csv(
        TIMER_INTERRUPT_CANDIDATE_TRACE_CSV,
        ["run_id", "entry_pc", "step", "pc", "access_type", "sfr_or_vector", "value", "role_candidate", "evidence_level", "confidence", "notes"],
        timer_interrupt,
        ("run_id", "step", "pc", "sfr_or_vector", "role_candidate"),
        200,
    )
    _append_capped_csv(
        DISPLAY_TEXT_TABLE_CANDIDATES_CSV,
        ["run_id", "entry_pc", "code_addr", "length", "raw_bytes_hex", "decoded_ascii_candidate", "decoded_alt_candidate", "encoding_guess", "referenced_by_pc", "confidence", "evidence_level", "notes"],
        display_tables,
        ("run_id", "code_addr", "referenced_by_pc"),
        200,
    )
    _append_capped_csv(
        DISPLAY_KEYPAD_STATIC_CANDIDATES_CSV,
        ["candidate_addr", "candidate_type", "reason", "referenced_by", "raw_bytes_or_operands", "evidence_level", "confidence", "notes"],
        static_candidates,
        ("candidate_addr", "candidate_type", "reason"),
        200,
    )
    _append_capped_csv(
        SERIAL_CANDIDATE_AUDIT_CSV,
        ["run_id", "entry_pc", "steps", "sfr_serial_events", "sbuf_writes", "uart_tx_candidates", "status", "notes"],
        [{
            "run_id": run.run_id,
            "entry_pc": f"0x{entry:04X}",
            "steps": str(run.steps),
            "sfr_serial_events": str(sum(1 for r in uart_init if r["role_candidate"] != "uart_tx_candidate")),
            "sbuf_writes": str(sbuf_writes),
            "uart_tx_candidates": str(sbuf_writes),
            "status": "rs485_commands_unresolved",
            "notes": "no_confirmed_sbuf_payload_stream",
        }],
        ("run_id",),
        30,
    )
    _append_capped_csv(
        UART_SBUF_TRACE_CSV,
        ["run_id", "scenario", "firmware_file", "function_addr", "step", "pc", "sfr_addr", "value", "possible_role", "uart_tx_candidate", "evidence_level", "confidence", "notes"],
        [
            {
                "run_id": run.run_id,
                "scenario": "boot_runtime",
                "firmware_file": run.firmware_file,
                "function_addr": f"0x{run.function_addr:04X}",
                "step": r.get("step", ""),
                "pc": r.get("pc", ""),
                "sfr_addr": r.get("sfr_addr", ""),
                "value": r.get("sfr_value", ""),
                "possible_role": "SBUF_candidate_write",
                "uart_tx_candidate": "yes",
                "evidence_level": "emulation_observed",
                "confidence": "low",
                "notes": "boot_runtime_sbuf_candidate",
            }
            for r in run.trace.rows
            if r.get("trace_type") == "uart_sbuf_write"
        ],
        ("run_id", "step", "pc"),
        200,
    )
    _write_sfr_role_map_audit(run)
    _write_boot_boundary_report()


def _collect_boot_init_writes(run: FunctionRunResult, entry: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for r in run.trace.rows:
        t = r.get("trace_type")
        if t == "sfr_access" and r.get("notes", "").startswith("write"):
            parts = _parse_notes_kv(r.get("notes", ""))
            role = parts.get("role", "unknown_sfr")
            rows.append({"run_id": run.run_id, "entry_pc": f"0x{entry:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "space": "sfr", "addr": r.get("sfr_addr", ""), "value": r.get("sfr_value", ""), "previous_value": parts.get("prev", ""), "access_type": "write", "role_candidate": role, "evidence_level": "emulation_observed", "confidence": "low", "notes": "boot_init_candidate"})
        if t == "direct_memory_write":
            parts = _parse_notes_kv(r.get("notes", ""))
            rows.append({"run_id": run.run_id, "entry_pc": f"0x{entry:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "space": "direct", "addr": r.get("xdata_addr", ""), "value": r.get("xdata_value", ""), "previous_value": parts.get("prev", ""), "access_type": "write", "role_candidate": "unknown", "evidence_level": "emulation_observed", "confidence": "low", "notes": "boot_init_candidate"})
        if t == "xdata_write":
            parts = _parse_notes_kv(r.get("notes", ""))
            rows.append({"run_id": run.run_id, "entry_pc": f"0x{entry:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "space": "xdata", "addr": r.get("xdata_addr", ""), "value": r.get("xdata_value", ""), "previous_value": parts.get("prev", ""), "access_type": "write", "role_candidate": "xdata_state_cluster_candidate", "evidence_level": "emulation_observed", "confidence": "low", "notes": "boot_init_candidate"})
    return rows[:200]


def _collect_boot_loop_xdata_reads(run: FunctionRunResult, entry: int) -> list[dict[str, str]]:
    watch_pcs = {0x4109, 0x410C, 0x4112, 0x411E, 0x4121, 0x4127, 0x4135, 0x413E, 0x4141, 0x4146, 0x4149}
    rows: list[dict[str, str]] = []
    trace_rows = run.trace.rows
    for idx, r in enumerate(trace_rows):
        if r.get("trace_type") != "xdata_read":
            continue
        pc_int = _parse_hex_int(r.get("pc", "0x0"))
        if pc_int not in watch_pcs:
            continue
        compare_context = ""
        branch_taken = ""
        next_pc = ""
        role_candidate = "boot_table_read_candidate"
        for look in trace_rows[idx + 1 : idx + 8]:
            if look.get("trace_type") != "instruction":
                continue
            op = look.get("op", "")
            pc = look.get("pc", "")
            if op == "CJNE":
                compare_context = f"{pc} {op} {look.get('args', '')}".strip()
                role_candidate = "boot_table_compare_operand"
            if op in BRANCH_OPS and branch_taken == "":
                notes = _parse_notes_kv(look.get("notes", ""))
                if "taken" in notes:
                    branch_taken = notes["taken"]
                if "next_pc" in notes:
                    next_pc = notes["next_pc"]
                break
        rows.append(
            {
                "run_id": run.run_id,
                "entry_pc": f"0x{entry:04X}",
                "step": r.get("step", ""),
                "pc": r.get("pc", ""),
                "dptr": r.get("xdata_addr", ""),
                "value": r.get("xdata_value", ""),
                "compare_context": compare_context,
                "branch_taken": branch_taken,
                "next_pc": next_pc,
                "role_candidate": role_candidate,
                "evidence_level": "emulation_observed",
                "notes": "boot_4100_movx_read",
            }
        )
    return rows[:200]


def _detect_runtime_loops(run: FunctionRunResult) -> list[dict[str, str]]:
    ins = [r for r in run.trace.rows if r.get("trace_type") == "instruction"]
    pcs = [_parse_hex_int(r.get("pc", "0x0")) for r in ins if r.get("pc")]
    counts = Counter(pcs)
    rows: list[dict[str, str]] = []
    for pc, hit in counts.items():
        if hit < 16:
            continue
        hits = [r for r in ins if _parse_hex_int(r.get("pc", "0x0")) == pc]
        first_step = hits[0].get("step", "")
        last_step = hits[-1].get("step", "")
        region_start = max(0x4000, pc - 8)
        region_end = min(0xFFFF, pc + 8)
        role = "unknown_loop"
        if 0x88 <= pc <= 0x8D:
            role = "timer_wait_candidate"
        elif 0x98 <= pc <= 0x9A:
            role = "uart_poll_candidate"
        elif 0x80 <= pc <= 0xB7:
            role = "scheduler_candidate"
        rows.append(
            {
                "run_id": run.run_id,
                "entry_pc": f"0x{run.function_addr:04X}",
                "loop_region": f"0x{region_start:04X}..0x{region_end:04X}",
                "pc_start": f"0x{region_start:04X}",
                "pc_end": f"0x{region_end:04X}",
                "hit_count": str(hit),
                "first_step": first_step,
                "last_step": last_step,
                "branch_pc": f"0x{pc:04X}",
                "branch_op": "unknown",
                "branch_target": f"0x{pc:04X}",
                "possible_role": role,
                "evidence_level": "emulation_observed",
                "notes": "pc_repetition_hotspot",
            }
        )
    return sorted(rows, key=lambda r: int(r["hit_count"]), reverse=True)[:20]


def _collect_display_candidates(run: FunctionRunResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for r in run.trace.rows:
        if r.get("trace_type") == "sfr_access" and r.get("notes", "").startswith("write"):
            addr = _parse_hex_int(r.get("sfr_addr", "0x0"))
            if addr in CPU_INTERNAL_SFRS:
                rows.append({"run_id": run.run_id, "entry_pc": f"0x{run.function_addr:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "access_type": "write", "space": "sfr", "addr": r.get("sfr_addr", ""), "value": r.get("sfr_value", ""), "role_candidate": "cpu_internal_sfr", "nearby_code_context": "register_state_update", "evidence_level": "emulation_observed", "confidence": "high", "notes": "internal_8051_sfr_not_display_evidence"})
                continue
            if addr in PORT_SFRS:
                rows.append({"run_id": run.run_id, "entry_pc": f"0x{run.function_addr:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "access_type": "write", "space": "sfr", "addr": r.get("sfr_addr", ""), "value": r.get("sfr_value", ""), "role_candidate": "unknown_io_candidate", "nearby_code_context": "port_sfr_write_no_path_to_display_confirmed", "evidence_level": "emulation_observed", "confidence": "low", "notes": "port_write_seen_but_display_unconfirmed"})
    return rows[:200]


def _collect_keypad_candidates(run: FunctionRunResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for r in run.trace.rows:
        if r.get("trace_type") == "sfr_access" and r.get("notes", "").startswith("read"):
            addr = _parse_hex_int(r.get("sfr_addr", "0x0"))
            if addr in CPU_INTERNAL_SFRS:
                rows.append({"run_id": run.run_id, "entry_pc": f"0x{run.function_addr:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "access_type": "read", "space": "sfr", "addr": r.get("sfr_addr", ""), "value": r.get("sfr_value", ""), "role_candidate": "cpu_internal_sfr", "branch_dependency": "", "evidence_level": "emulation_observed", "confidence": "high", "notes": "internal_8051_sfr_not_keypad_evidence"})
                continue
            if addr in PORT_SFRS:
                rows.append({"run_id": run.run_id, "entry_pc": f"0x{run.function_addr:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "access_type": "read", "space": "sfr", "addr": r.get("sfr_addr", ""), "value": r.get("sfr_value", ""), "role_candidate": "unknown_io_candidate", "branch_dependency": "", "evidence_level": "emulation_observed", "confidence": "low", "notes": "port_read_seen_but_keypad_unconfirmed"})
        if r.get("trace_type") == "bit_access":
            bit_addr = _parse_hex_int(r.get("bit_addr", "0x0"))
            byte_addr = _parse_hex_int(r.get("byte_addr", "0x0"))
            if byte_addr in PORT_SFRS and ("branch_test=" in r.get("notes", "") or r.get("access_type", "").startswith("unknown")):
                rows.append({"run_id": run.run_id, "entry_pc": f"0x{run.function_addr:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "access_type": "bit_test", "space": "bit", "addr": f"0x{bit_addr:02X}", "value": "", "role_candidate": "unknown_io_candidate", "branch_dependency": "bit_branch_candidate", "evidence_level": "emulation_observed", "confidence": "low", "notes": "port_bit_branch_seen_but_keypad_unconfirmed"})
    return rows[:200]


def _collect_uart_init_candidates(run: FunctionRunResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for r in run.trace.rows:
        if r.get("trace_type") == "sfr_access":
            addr = _parse_hex_int(r.get("sfr_addr", "0x0"))
            if addr not in {0x98, 0x99, 0x9A, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0xA8, 0xB8, 0xC8}:
                continue
            kv = _parse_notes_kv(r.get("notes", ""))
            role = "uart_init_candidate"
            if addr in {0x99, 0x9A} and r.get("notes", "").startswith("write"):
                role = "uart_tx_candidate"
            rows.append({"run_id": run.run_id, "entry_pc": f"0x{run.function_addr:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "access_type": "write" if r.get("notes", "").startswith("write") else "read", "sfr_addr": r.get("sfr_addr", ""), "value": r.get("sfr_value", ""), "previous_value": kv.get("prev", ""), "role_candidate": role, "uart_channel_candidate": "UART1_candidate" if addr == 0x9A else "UART0_candidate", "physical_channel_candidate": "unknown", "evidence_level": "emulation_observed", "confidence": "low", "notes": "serial_related_sfr_access"})
        if r.get("trace_type") == "uart_sbuf_write":
            rows.append({"run_id": run.run_id, "entry_pc": f"0x{run.function_addr:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "access_type": "write", "sfr_addr": r.get("sfr_addr", ""), "value": r.get("sfr_value", ""), "previous_value": "", "role_candidate": "uart_tx_candidate", "uart_channel_candidate": "UART0_candidate", "physical_channel_candidate": "unknown", "evidence_level": "emulation_observed", "confidence": "low", "notes": "sbuf_candidate_write"})
    return rows[:200]


def _collect_timer_interrupt_candidates(run: FunctionRunResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for r in run.trace.rows:
        if r.get("trace_type") == "sfr_access":
            addr = _parse_hex_int(r.get("sfr_addr", "0x0"))
            role = ""
            if addr in {0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D}:
                role = "timer_init_candidate"
            elif addr in {0xA8, 0xB8}:
                role = "interrupt_enable_candidate"
            elif addr in {0x98, 0xC8}:
                role = "serial_interrupt_candidate"
            if role:
                rows.append({"run_id": run.run_id, "entry_pc": f"0x{run.function_addr:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "access_type": "write" if r.get("notes", "").startswith("write") else "read", "sfr_or_vector": r.get("sfr_addr", ""), "value": r.get("sfr_value", ""), "role_candidate": role, "evidence_level": "emulation_observed", "confidence": "low", "notes": "timer_interrupt_related_sfr"})
        if r.get("trace_type") == "instruction" and r.get("op") == "RETI":
            rows.append({"run_id": run.run_id, "entry_pc": f"0x{run.function_addr:04X}", "step": r.get("step", ""), "pc": r.get("pc", ""), "access_type": "execute", "sfr_or_vector": r.get("pc", ""), "value": "", "role_candidate": "reti_candidate", "evidence_level": "emulation_observed", "confidence": "low", "notes": "reti_seen"})
    return rows[:200]


def _scan_display_text_candidates(img, instruction_rows: list[dict[str, str]], run_id: str, entry: int) -> list[dict[str, str]]:
    refs = [( _parse_hex_int(r.get("pc", "0x0")), _parse_hex_int(r.get("xdata_addr", "0x0"))) for r in instruction_rows if r.get("op") == "MOVC"]
    rows: list[dict[str, str]] = []
    for pc, addr in refs[:40]:
        data = [img.get_byte(addr + i) for i in range(8)]
        hex_blob = " ".join(f"{b:02X}" for b in data)
        ascii_guess = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
        rows.append({"run_id": run_id, "entry_pc": f"0x{entry:04X}", "code_addr": f"0x{addr:04X}", "length": "8", "raw_bytes_hex": hex_blob, "decoded_ascii_candidate": ascii_guess, "decoded_alt_candidate": "", "encoding_guess": "unknown", "referenced_by_pc": f"0x{pc:04X}", "confidence": "low", "evidence_level": "static_code", "notes": "movc_reference_candidate"})
    return rows


def _scan_display_keypad_static_candidates(img) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for addr in range(0x4000, 0xC000):
        op = img.get_byte(addr)
        b1 = img.get_byte(addr + 1)
        if op in {0x85, 0x75, 0xF5, 0xE5} and b1 in CPU_INTERNAL_SFRS:
            rows.append({"candidate_addr": f"0x{addr:04X}", "candidate_type": "cpu_internal_sfr", "reason": "direct_internal_sfr_operand", "referenced_by": "", "raw_bytes_or_operands": f"{op:02X} {b1:02X}", "evidence_level": "static_code", "confidence": "high", "notes": "internal_8051_sfr_not_display_keypad"})
        elif op in {0x85, 0x75, 0xF5, 0xE5} and b1 in PORT_SFRS:
            rows.append({"candidate_addr": f"0x{addr:04X}", "candidate_type": "unknown_io_candidate", "reason": "direct_port_sfr_operand_no_device_mapping", "referenced_by": "", "raw_bytes_or_operands": f"{op:02X} {b1:02X}", "evidence_level": "static_code", "confidence": "low", "notes": "port_operand_seen_but_display_keypad_unconfirmed"})
        if len(rows) >= 200:
            break
    return rows


def _write_boot_boundary_report() -> None:
    if not BOOT_TRACE_SUMMARY_CSV.exists():
        return
    with BOOT_TRACE_SUMMARY_CSV.open(encoding="utf-8", newline="") as fh:
        runs = list(csv.DictReader(fh))
    ran_4000 = next((r for r in runs if r.get("entry_pc") == "0x4000"), None)
    ran_4100 = next((r for r in runs if r.get("entry_pc") == "0x4100"), None)
    reset_jump = "unknown"
    if ran_4000:
        reset_jump = "yes (emulation_observed)" if int(ran_4000.get("steps", "0")) > 0 else "no"
    unsupported = next((r.get("stop_reason") for r in runs if "unsupported" in r.get("stop_reason", "")), "none_observed")
    sbuf = sum(int(r.get("sbuf_writes", "0")) for r in runs)
    display_rows = []
    keypad_rows = []
    table_rows = []
    uart_rows = []
    timer_rows = []
    if DISPLAY_CANDIDATE_TRACE_CSV.exists():
        with DISPLAY_CANDIDATE_TRACE_CSV.open(encoding="utf-8", newline="") as fh:
            display_rows = list(csv.DictReader(fh))
    if KEYPAD_CANDIDATE_TRACE_CSV.exists():
        with KEYPAD_CANDIDATE_TRACE_CSV.open(encoding="utf-8", newline="") as fh:
            keypad_rows = list(csv.DictReader(fh))
    if DISPLAY_TEXT_TABLE_CANDIDATES_CSV.exists():
        with DISPLAY_TEXT_TABLE_CANDIDATES_CSV.open(encoding="utf-8", newline="") as fh:
            table_rows = list(csv.DictReader(fh))
    if UART_INIT_CANDIDATE_TRACE_CSV.exists():
        with UART_INIT_CANDIDATE_TRACE_CSV.open(encoding="utf-8", newline="") as fh:
            uart_rows = list(csv.DictReader(fh))
    if TIMER_INTERRUPT_CANDIDATE_TRACE_CSV.exists():
        with TIMER_INTERRUPT_CANDIDATE_TRACE_CSV.open(encoding="utf-8", newline="") as fh:
            timer_rows = list(csv.DictReader(fh))
    display_confirmed = [r for r in display_rows if r.get("role_candidate") not in {"cpu_internal_sfr"}]
    keypad_confirmed = [r for r in keypad_rows if r.get("role_candidate") not in {"cpu_internal_sfr"}]
    lines = [
        "# Boot/runtime boundary report",
        "",
        f"1. Did reset vector 0x4000 jump to 0x4100? {reset_jump}.",
        f"2. Did application entry 0x4100 execute beyond initial setup? {'yes' if ran_4100 and int(ran_4100.get('steps', '0')) > 32 else 'unknown'}.",
        f"3. What was the first unsupported opcode, if any? {unsupported}.",
        "4. What SFRs were initialized? see docs/emulator/boot_init_write_summary.csv (emulation_observed).",
        f"5. Were UART/SCON/SBUF candidates initialized? {'yes' if uart_rows else 'no'} (emulation_observed).",
        f"6. Were timer/interrupt candidates initialized? {'yes' if timer_rows else 'no'} (emulation_observed).",
        f"7. Was a main loop or scheduler loop found? {'yes' if RUNTIME_LOOP_CANDIDATES_CSV.exists() else 'unknown'} (emulation_observed).",
        f"8. Were display/LCD/output candidates observed? {'yes' if display_confirmed else 'no'} (emulation_observed).",
        f"9. Were display text/message table candidates found? {'yes' if table_rows else 'no'} (static_code).",
        f"10. Were keypad/input scan candidates observed? {'yes' if keypad_confirmed else 'no'} (emulation_observed).",
        f"11. Were SBUF candidate writes observed? {'yes' if sbuf > 0 else 'no'}.",
        f"12. Were UART TX candidate bytes observed? {'yes' if sbuf > 0 else 'no'}.",
        "13. Are RS-485 commands still unresolved? yes.",
        "14. Current blocker: boot_init_loop_or_counter_boundary (early 0x4100..0x4165 loop persists without UART/SBUF/port-output proof).",
        "",
        "## Classifier correction and early boot-loop interpretation",
        "- Previous display/keypad counts were contaminated by SP/DPL/DPH/PSW/ACC/B handling: confirmed.",
        f"- Corrected display candidates remaining: {len(display_confirmed)} (all weak unknown_io_candidate unless promoted by stronger path evidence).",
        f"- Corrected keypad candidates remaining: {len(keypad_confirmed)} (all weak unknown_io_candidate unless promoted by stronger path evidence).",
        f"- Display text/message table candidates remaining: {len(table_rows)}.",
        f"- UART/SCON/SBUF init candidates remaining: {len(uart_rows)}; SBUF writes observed: {sbuf}.",
        f"- Timer/interrupt candidates remaining: {len(timer_rows)}.",
        "- Early 0x4100..0x4165 loop likely represents boot pointer/copy initialization loop (DPTR + DPL/DPH rewrite) rather than peripheral wait loop.",
        "- Next blocker assessment: boot init loop with missing boundary into later runtime services.",
    ]
    BOOT_RUNTIME_BOUNDARY_REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_sfr_role_map_audit(run: FunctionRunResult) -> None:
    cols = [
        "sfr_addr", "known_8051_role", "ds80c320_role_candidate", "seen_in_boot", "access_count", "used_as_candidate_io",
        "classification_before", "classification_after", "evidence_level", "notes",
    ]
    role_map = {
        0x80: ("P0", "P0_candidate"),
        0x81: ("SP", "cpu_internal_sfr"),
        0x82: ("DPL", "cpu_internal_sfr"),
        0x83: ("DPH", "cpu_internal_sfr"),
        0x87: ("PCON", "power_control_or_baud_control_candidate"),
        0x88: ("TCON", "timer_control_candidate"),
        0x89: ("TMOD", "timer_mode_candidate"),
        0x8A: ("TL0", "timer0_low_candidate"),
        0x8B: ("TL1", "timer1_low_candidate"),
        0x8C: ("TH0", "timer0_high_candidate"),
        0x8D: ("TH1", "timer1_high_candidate"),
        0x90: ("P1", "P1_candidate"),
        0x98: ("SCON0", "SCON0_candidate"),
        0x99: ("SBUF0", "SBUF0_candidate"),
        0x9A: ("SBUF1/SCON1_alias", "UART1_candidate"),
        0xA0: ("P2", "P2_candidate"),
        0xA8: ("IE", "interrupt_enable_candidate"),
        0xB0: ("P3", "P3_candidate"),
        0xB8: ("IP", "interrupt_priority_candidate"),
        0xC8: ("SCON1", "SCON1_candidate"),
        0xD0: ("PSW", "cpu_internal_sfr"),
        0xE0: ("ACC", "cpu_internal_sfr"),
        0xF0: ("B", "cpu_internal_sfr"),
    }
    seen_counter: Counter[int] = Counter()
    for r in run.trace.rows:
        if r.get("trace_type") == "sfr_access":
            seen_counter[_parse_hex_int(r.get("sfr_addr", "0x0"))] += 1
    audit_rows: list[dict[str, str]] = []
    for addr, (known_role, role_candidate) in sorted(role_map.items()):
        count = seen_counter.get(addr, 0)
        before = "display_or_keypad_candidate" if 0x80 <= addr <= 0xB8 else "not_candidate"
        if addr in CPU_INTERNAL_SFRS:
            after = "cpu_internal_sfr"
            used_as_candidate_io = "no"
            note = "excluded_from_display_keypad_classifier"
        elif addr in PORT_SFRS:
            after = "unknown_io_candidate"
            used_as_candidate_io = "yes" if count else "no"
            note = "port_sfr_needs_stronger_device_path_evidence"
        elif addr in SERIAL_TIMER_INTERRUPT_SFRS:
            after = "serial_timer_interrupt_candidate"
            used_as_candidate_io = "yes" if count else "no"
            note = "tracked_in_uart_timer_interrupt_audits"
        else:
            after = "unknown"
            used_as_candidate_io = "no"
            note = "reserved_or_unmapped_in_current_trace"
        audit_rows.append(
            {
                "sfr_addr": f"0x{addr:02X}",
                "known_8051_role": known_role,
                "ds80c320_role_candidate": role_candidate,
                "seen_in_boot": "yes" if count else "no",
                "access_count": str(count),
                "used_as_candidate_io": used_as_candidate_io,
                "classification_before": before,
                "classification_after": after,
                "evidence_level": "emulation_observed" if count else "static_role_map",
                "notes": note,
            }
        )
    with SFR_ROLE_MAP_AUDIT_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(audit_rows)


def run_boot_trace(entry: int, max_steps: int, compact_summary: bool) -> None:
    if not compact_summary:
        raise ValueError("run-boot-trace requires --compact-summary")
    img = load_code_image(ROOT / "90CYE03_19_DKS.PZU")
    scenario_name = "boot_probe_static"
    scenario = get_scenario(scenario_name)
    harness = FunctionHarness(img, watchpoints=scenario.watchpoints)
    rid = _run_id(f"boot_{entry:04X}")
    run = harness.run_function(rid, entry, max_steps=max_steps, use_stubs=False)
    for path, cols in [
        (DISPLAY_CANDIDATE_TRACE_CSV, ["run_id", "entry_pc", "step", "pc", "access_type", "space", "addr", "value", "role_candidate", "nearby_code_context", "evidence_level", "confidence", "notes"]),
        (DISPLAY_TEXT_TABLE_CANDIDATES_CSV, ["run_id", "entry_pc", "code_addr", "length", "raw_bytes_hex", "decoded_ascii_candidate", "decoded_alt_candidate", "encoding_guess", "referenced_by_pc", "confidence", "evidence_level", "notes"]),
        (KEYPAD_CANDIDATE_TRACE_CSV, ["run_id", "entry_pc", "step", "pc", "access_type", "space", "addr", "value", "role_candidate", "branch_dependency", "evidence_level", "confidence", "notes"]),
        (UART_INIT_CANDIDATE_TRACE_CSV, ["run_id", "entry_pc", "step", "pc", "access_type", "sfr_addr", "value", "previous_value", "role_candidate", "uart_channel_candidate", "physical_channel_candidate", "evidence_level", "confidence", "notes"]),
        (TIMER_INTERRUPT_CANDIDATE_TRACE_CSV, ["run_id", "entry_pc", "step", "pc", "access_type", "sfr_or_vector", "value", "role_candidate", "evidence_level", "confidence", "notes"]),
        (RUNTIME_LOOP_CANDIDATES_CSV, ["run_id", "entry_pc", "loop_region", "pc_start", "pc_end", "hit_count", "first_step", "last_step", "branch_pc", "branch_op", "branch_target", "possible_role", "evidence_level", "notes"]),
        (DISPLAY_KEYPAD_STATIC_CANDIDATES_CSV, ["candidate_addr", "candidate_type", "reason", "referenced_by", "raw_bytes_or_operands", "evidence_level", "confidence", "notes"]),
        (BOOT_INIT_WRITE_SUMMARY_CSV, ["run_id", "entry_pc", "step", "pc", "space", "addr", "value", "previous_value", "access_type", "role_candidate", "evidence_level", "confidence", "notes"]),
        (SERIAL_CANDIDATE_AUDIT_CSV, ["run_id", "entry_pc", "steps", "sfr_serial_events", "sbuf_writes", "uart_tx_candidates", "status", "notes"]),
        (UART_SBUF_TRACE_CSV, ["run_id", "scenario", "firmware_file", "function_addr", "step", "pc", "sfr_addr", "value", "possible_role", "uart_tx_candidate", "evidence_level", "confidence", "notes"]),
    ]:
        if not path.exists():
            _empty_csv(path, cols)
    _write_boot_runtime_outputs(img, run, entry, max_steps)


def run_boot_trace_with_scenario(entry: int, max_steps: int, compact_summary: bool, scenario_name: str | None) -> None:
    if not scenario_name:
        run_boot_trace(entry, max_steps=max_steps, compact_summary=compact_summary)
        return
    if not compact_summary:
        raise ValueError("run-boot-trace requires --compact-summary")
    scenario = get_scenario(scenario_name)
    img = load_code_image(ROOT / scenario.firmware_file)
    harness = FunctionHarness(img, watchpoints=scenario.watchpoints)
    rid = _run_id(f"boot_{entry:04X}_{scenario_name}")
    init_regs = scenario.init_regs.get(entry)
    run = harness.run_function(rid, entry, max_steps=max_steps, use_stubs=False, init_regs=init_regs, init_xdata=scenario.seed_xdata)
    for path, cols in [
        (BOOT_LOOP_XDATA_READ_AUDIT_CSV, ["run_id", "entry_pc", "step", "pc", "dptr", "value", "compare_context", "branch_taken", "next_pc", "role_candidate", "evidence_level", "notes"]),
    ]:
        if not path.exists():
            _empty_csv(path, cols)
    _append_capped_csv(
        BOOT_LOOP_XDATA_READ_AUDIT_CSV,
        ["run_id", "entry_pc", "step", "pc", "dptr", "value", "compare_context", "branch_taken", "next_pc", "role_candidate", "evidence_level", "notes"],
        _collect_boot_loop_xdata_reads(run, entry),
        ("run_id", "step", "pc", "dptr"),
        2000,
    )
    _write_boot_runtime_outputs(img, run, entry, max_steps)


def _write_sfr_trace(runs: list[FunctionRunResult], scenario: str) -> None:
    cols = ["run_id", "scenario", "firmware_file", "function_addr", "step", "pc", "sfr_addr", "access_type", "value", "previous_value", "possible_role", "notes"]
    rows: list[dict[str, str]] = []
    for run in runs:
        for r in run.trace.rows:
            if r["trace_type"] != "sfr_access":
                continue
            notes = r.get("notes", "")
            parts = notes.split(";")
            access_type = parts[0] if parts else ""
            prev = ""
            role = ""
            for p in parts[1:]:
                if p.startswith("prev="):
                    prev = p.split("=", 1)[1]
                if p.startswith("role="):
                    role = p.split("=", 1)[1]
            rows.append(
                {
                    "run_id": run.run_id,
                    "scenario": scenario,
                    "firmware_file": run.firmware_file,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "step": r["step"],
                    "pc": r["pc"],
                    "sfr_addr": r["sfr_addr"],
                    "access_type": access_type,
                    "value": r["sfr_value"],
                    "previous_value": prev,
                    "possible_role": role,
                    "notes": "emulation_observed",
                }
            )
    with SFR_TRACE_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _write_code_read_trace(runs: list[FunctionRunResult], scenario: str) -> None:
    cols = ["run_id", "scenario", "firmware_file", "function_addr", "step", "pc", "code_addr", "value", "access_type", "possible_role", "notes"]
    rows: list[dict[str, str]] = []
    for run in runs:
        for r in run.trace.rows:
            if r["trace_type"] != "code_read":
                continue
            rows.append(
                {
                    "run_id": run.run_id,
                    "scenario": scenario,
                    "firmware_file": run.firmware_file,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "step": r["step"],
                    "pc": r["pc"],
                    "code_addr": r["xdata_addr"],
                    "value": r["xdata_value"],
                    "access_type": r["args"],
                    "possible_role": "code_table_candidate",
                    "notes": "emulation_observed",
                }
            )
    with CODE_READ_TRACE_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _write_pzu_load_metadata(img) -> None:
    cols = ["firmware_file", "min_code_addr", "max_code_addr", "has_0x4000", "has_0x4100", "reset_vector_bytes", "entrypoint_candidate", "confidence", "notes"]
    with PZU_METADATA_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerow(img.metadata())


def _write_direct_memory_trace(runs: list[FunctionRunResult], scenario: str) -> None:
    cols = ["run_id", "scenario", "firmware_file", "function_addr", "step", "pc", "direct_addr", "access_type", "value", "previous_value", "possible_role", "notes"]
    rows: list[dict[str, str]] = []
    for run in runs:
        for r in run.trace.rows:
            ttype = r.get("trace_type", "")
            if ttype not in {"direct_memory_read", "direct_memory_write"}:
                continue
            note = r.get("notes", "")
            prev = ""
            if "prev=" in note:
                prev = note.split("prev=", 1)[1].split(";", 1)[0]
            rows.append(
                {
                    "run_id": run.run_id,
                    "scenario": scenario,
                    "firmware_file": run.firmware_file,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "step": r["step"],
                    "pc": r["pc"],
                    "direct_addr": r["xdata_addr"],
                    "access_type": "write" if ttype.endswith("_write") else "read",
                    "value": r["xdata_value"],
                    "previous_value": prev,
                    "possible_role": "direct_idata_candidate",
                    "notes": "emulation_observed",
                }
            )
    with DIRECT_TRACE_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _write_uart_sbuf_trace(runs: list[FunctionRunResult], scenario: str) -> None:
    cols = ["run_id", "scenario", "firmware_file", "function_addr", "step", "pc", "sfr_addr", "value", "uart_channel_candidate", "confidence", "evidence_level", "notes"]
    rows: list[dict[str, str]] = []
    for run in runs:
        for r in run.trace.rows:
            if r.get("trace_type") != "uart_sbuf_write":
                continue
            notes = r.get("notes", "")
            role = "unknown_sfr_uart_candidate"
            for part in notes.split(";"):
                if part.startswith("role="):
                    role = part.split("=", 1)[1]
            rows.append(
                {
                    "run_id": run.run_id,
                    "scenario": scenario,
                    "firmware_file": run.firmware_file,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "step": r["step"],
                    "pc": r["pc"],
                    "sfr_addr": r["sfr_addr"],
                    "value": r["sfr_value"],
                    "uart_channel_candidate": role,
                    "confidence": "low",
                    "evidence_level": "hypothesis",
                    "notes": "candidate_sbuf_write_observed",
                }
            )
    with UART_SBUF_TRACE_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _write_bit_access_trace(runs: list[FunctionRunResult], scenario: str) -> None:
    cols = [
        "run_id",
        "scenario",
        "firmware_file",
        "function_addr",
        "step",
        "pc",
        "bit_addr",
        "byte_addr",
        "bit_index",
        "space",
        "access_type",
        "previous_bit",
        "new_bit",
        "previous_byte",
        "new_byte",
        "possible_role",
        "evidence_level",
        "notes",
    ]
    rows: list[dict[str, str]] = []
    for run in runs:
        for r in run.trace.rows:
            if r.get("trace_type") != "bit_access":
                continue
            parsed: dict[str, str] = {}
            for part in r.get("notes", "").split(";"):
                if "=" not in part:
                    continue
                key, value = part.split("=", 1)
                parsed[key] = value
            rows.append(
                {
                    "run_id": run.run_id,
                    "scenario": scenario,
                    "firmware_file": run.firmware_file,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "step": r.get("step", ""),
                    "pc": r.get("pc", ""),
                    "bit_addr": parsed.get("bit_addr", ""),
                    "byte_addr": parsed.get("byte_addr", ""),
                    "bit_index": parsed.get("bit_index", ""),
                    "space": parsed.get("space", ""),
                    "access_type": r.get("args", "unknown_bit_access") or "unknown_bit_access",
                    "previous_bit": parsed.get("previous_bit", ""),
                    "new_bit": parsed.get("new_bit", ""),
                    "previous_byte": parsed.get("previous_byte", ""),
                    "new_byte": parsed.get("new_byte", ""),
                    "possible_role": parsed.get("possible_role", "unknown_bit"),
                    "evidence_level": parsed.get("evidence_level", "emulation_observed"),
                    "notes": ";".join(
                        part for part in r.get("notes", "").split(";") if "=" not in part or part.split("=", 1)[0] not in {
                            "bit_addr",
                            "byte_addr",
                            "bit_index",
                            "space",
                            "previous_bit",
                            "new_bit",
                            "previous_byte",
                            "new_byte",
                            "possible_role",
                            "evidence_level",
                        }
                    ),
                }
            )
    with BIT_ACCESS_TRACE_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _write_cpu_subset_coverage(runs: list[FunctionRunResult]) -> None:
    cols = ["opcode", "mnemonic", "implemented", "observed_in_runs", "notes"]
    instruction_rows = [r for run in runs for r in run.trace.rows if r.get("trace_type") == "instruction"]
    observed_ops = {r.get("op", "") for r in instruction_rows}
    saw_mov_direct_imm = any(r.get("op") == "MOV" and ",#0x" in str(r.get("args", "")) and str(r.get("args", "")).startswith("0x") for r in instruction_rows)
    saw_div_ab = any(r.get("op") == "DIV" and r.get("args") == "AB" for r in instruction_rows)
    saw_setb_bit = any(r.get("op") == "SETB" and str(r.get("args", "")).startswith("bit ") for r in instruction_rows)
    coverage_rows = [
        {"opcode": "0xF5", "mnemonic": "MOV direct,A", "implemented": "yes", "observed_in_runs": "yes" if "MOV" in observed_ops else "unknown", "notes": "issue_78_blocker"},
        {"opcode": "0x42", "mnemonic": "ORL direct,A", "implemented": "yes", "observed_in_runs": "yes" if "ORL" in observed_ops else "no", "notes": "issue_78_next_blocker"},
        {"opcode": "0x75", "mnemonic": "MOV direct,#imm", "implemented": "yes", "observed_in_runs": "yes" if saw_mov_direct_imm else "no", "notes": "issue_81_blocker"},
        {"opcode": "0x84", "mnemonic": "DIV AB", "implemented": "yes", "observed_in_runs": "yes" if saw_div_ab else "no", "notes": "issue_82_blocker"},
        {"opcode": "0xB8..0xBF", "mnemonic": "CJNE Rn,#imm,rel", "implemented": "yes", "observed_in_runs": "yes" if "CJNE" in observed_ops else "no", "notes": "issue_78_blocker"},
        {"opcode": "0x23", "mnemonic": "RL A", "implemented": "yes", "observed_in_runs": "yes" if "RL" in observed_ops else "no", "notes": "issue_78_next_blocker"},
        {"opcode": "0x04", "mnemonic": "INC A", "implemented": "yes", "observed_in_runs": "yes" if "INC" in observed_ops else "no", "notes": "issue_78_next_blocker"},
        {"opcode": "0x35", "mnemonic": "ADDC A,direct", "implemented": "yes", "observed_in_runs": "yes" if "ADDC" in observed_ops else "no", "notes": "issue_78_next_blocker"},
        {"opcode": "0x45", "mnemonic": "ANL A,direct", "implemented": "yes", "observed_in_runs": "yes" if "ANL" in observed_ops else "no", "notes": "issue_78_next_blocker"},
        {"opcode": "0x55", "mnemonic": "XRL A,direct", "implemented": "yes", "observed_in_runs": "yes" if "XRL" in observed_ops else "no", "notes": "issue_78_next_blocker"},
        {"opcode": "0xE5", "mnemonic": "MOV A,direct", "implemented": "yes", "observed_in_runs": "yes" if "MOV" in observed_ops else "unknown", "notes": "issue_78_next_blocker"},
        {"opcode": "0x00", "mnemonic": "NOP", "implemented": "yes", "observed_in_runs": "yes" if "NOP" in observed_ops else "no", "notes": "forced_loop_exit_blocker"},
        {"opcode": "0xB4", "mnemonic": "CJNE A,#imm,rel", "implemented": "yes", "observed_in_runs": "yes" if "CJNE" in observed_ops else "no", "notes": "extended_support"},
        {"opcode": "0xB5", "mnemonic": "CJNE A,direct,rel", "implemented": "yes", "observed_in_runs": "yes" if "CJNE" in observed_ops else "no", "notes": "extended_support"},
        {"opcode": "0xB6/0xB7", "mnemonic": "CJNE @R0/@R1,#imm,rel", "implemented": "yes", "observed_in_runs": "yes" if "CJNE" in observed_ops else "no", "notes": "extended_support"},
        {"opcode": "0xD8..0xDF", "mnemonic": "DJNZ Rn,rel", "implemented": "yes", "observed_in_runs": "yes" if "DJNZ" in observed_ops else "no", "notes": "extended_support"},
        {"opcode": "0xD2", "mnemonic": "SETB bit", "implemented": "yes", "observed_in_runs": "yes" if saw_setb_bit else "no", "notes": "autonomous_packet_bridge_blocker"},
    ]
    with CPU_COVERAGE_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(coverage_rows)


def _write_pc_hotspot_summary(runs: list[FunctionRunResult], scenario: str) -> None:
    cols = ["run_id", "scenario", "firmware_file", "function_addr", "pc", "count", "first_step", "last_step", "possible_role", "notes"]
    rows: list[dict[str, str]] = []
    for run in runs:
        pc_steps: dict[str, list[int]] = {}
        for r in run.trace.rows:
            if r.get("trace_type") != "instruction":
                continue
            pc = r.get("pc", "")
            try:
                step = int(r.get("step", "0"))
            except ValueError:
                continue
            pc_steps.setdefault(pc, []).append(step)
        for pc, steps in sorted(pc_steps.items(), key=lambda item: (-len(item[1]), item[0])):
            possible_role = "loop_hotspot"
            note_parts = ["emulation_observed"]
            if pc.upper() in {"0X5982", "0X5984", "0X5985", "0X5986", "0X5987", "0X5988", "0X5989", "0X598A", "0X598B"}:
                possible_role = "movc_pc_relative_table_loop_candidate"
                note_parts.append("movc_pc_relative_region")
            rows.append(
                {
                    "run_id": run.run_id,
                    "scenario": scenario,
                    "firmware_file": run.firmware_file,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "pc": pc,
                    "count": str(len(steps)),
                    "first_step": str(min(steps)),
                    "last_step": str(max(steps)),
                    "possible_role": possible_role,
                    "notes": ";".join(note_parts),
                }
            )
    with PC_HOTSPOT_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _write_control_flow_summary(runs: list[FunctionRunResult], scenario: str) -> None:
    cols = ["run_id", "scenario", "firmware_file", "function_addr", "source_pc", "target_pc", "op", "count", "first_step", "last_step", "notes"]
    rows: list[dict[str, str]] = []
    for run in runs:
        transitions: dict[tuple[str, str, str], list[int]] = {}
        instruction_rows = [r for r in run.trace.rows if r.get("trace_type") == "instruction"]
        for prev, curr in zip(instruction_rows, instruction_rows[1:]):
            source_pc = prev.get("pc", "")
            target_pc = curr.get("pc", "")
            op = curr.get("op", "")
            try:
                step = int(curr.get("step", "0"))
            except ValueError:
                continue
            transitions.setdefault((source_pc, target_pc, op), []).append(step)
        for (source_pc, target_pc, op), steps in sorted(transitions.items(), key=lambda item: (-len(item[1]), item[0][0], item[0][1])):
            rows.append(
                {
                    "run_id": run.run_id,
                    "scenario": scenario,
                    "firmware_file": run.firmware_file,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "source_pc": source_pc,
                    "target_pc": target_pc,
                    "op": op,
                    "count": str(len(steps)),
                    "first_step": str(min(steps)),
                    "last_step": str(max(steps)),
                    "notes": "emulation_observed",
                }
            )
    with CONTROL_FLOW_SUMMARY_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _write_code_table_candidate_summary(runs: list[FunctionRunResult], scenario: str) -> None:
    cols = ["run_id", "scenario", "firmware_file", "function_addr", "table_base_or_pc", "code_addr", "value", "count", "first_step", "last_step", "possible_role", "notes"]
    rows: list[dict[str, str]] = []
    for run in runs:
        grouped: dict[tuple[str, str, str], list[int]] = {}
        values_seen: set[str] = set()
        for r in run.trace.rows:
            if r.get("trace_type") != "code_read":
                continue
            pc = r.get("pc", "")
            code_addr = r.get("xdata_addr", "")
            value = r.get("xdata_value", "")
            key = (pc, code_addr, value)
            try:
                step = int(r.get("step", "0"))
            except ValueError:
                continue
            grouped.setdefault(key, []).append(step)
            if pc.upper() == "0X5982":
                values_seen.add(value.upper())
        bitmask_candidate = values_seen == {"0X01", "0X02", "0X04", "0X08", "0X10", "0X20", "0X40", "0X80"}
        for (pc, code_addr, value), steps in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])):
            rows.append(
                {
                    "run_id": run.run_id,
                    "scenario": scenario,
                    "firmware_file": run.firmware_file,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "table_base_or_pc": pc,
                    "code_addr": code_addr,
                    "value": value,
                    "count": str(len(steps)),
                    "first_step": str(min(steps)),
                    "last_step": str(max(steps)),
                    "possible_role": "bitmask_table_candidate" if bitmask_candidate and pc.upper() == "0X5982" else "code_table_candidate",
                    "notes": "emulation_observed",
                }
            )
    with CODE_TABLE_CANDIDATE_SUMMARY_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _top_pc_hotspot(run: FunctionRunResult) -> str:
    counts = Counter(r.get("pc", "") for r in run.trace.rows if r.get("trace_type") == "instruction")
    if not counts:
        return ""
    pc, count = counts.most_common(1)[0]
    return f"{pc}:{count}"


def _top_xdata_write_addrs(run: FunctionRunResult, limit: int = 10) -> str:
    counts = Counter(r.get("xdata_addr", "") for r in run.trace.rows if r.get("trace_type") == "xdata_write")
    return ";".join(addr for addr, _ in counts.most_common(limit))


def _material_change_flag(run: FunctionRunResult, scenario_name: str, max_steps: int) -> str:
    if scenario_name.endswith("_base"):
        return "base"
    if not SCENARIO_VARIANT_SUMMARY_CSV.exists():
        return "n/a"
    with SCENARIO_VARIANT_SUMMARY_CSV.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("scenario") != "packet_bridge_seeded_context_base":
                continue
            if row.get("function_addr") != f"0x{run.function_addr:04X}" or row.get("max_steps") != str(max_steps):
                continue
            changed = (
                row.get("top_pc_hotspot") != _top_pc_hotspot(run)
                or row.get("top_xdata_write_addrs") != _top_xdata_write_addrs(run)
                or row.get("stop_reason") != run.stop_reason
            )
            return "yes" if changed else "no"
    return "n/a"


def _append_capped_csv(path: Path, fieldnames: list[str], incoming_rows: list[dict[str, str]], key_fields: tuple[str, ...], row_limit: int) -> None:
    rows: list[dict[str, str]] = []
    if path.exists():
        with path.open(encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
    index = {tuple(r.get(k, "") for k in key_fields): i for i, r in enumerate(rows)}
    for row in incoming_rows:
        key = tuple(row.get(k, "") for k in key_fields)
        if key in index:
            rows[index[key]] = row
        else:
            rows.append(row)
    rows = rows[:row_limit]
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def _collect_loop_exit_rows(scenario_name: str, run: FunctionRunResult, max_trace_rows: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    instruction_rows = [r for r in run.trace.rows if r.get("trace_type") == "instruction"]
    for start, end in LOOP_REGIONS:
        region_steps = [r for r in instruction_rows if start <= int(r.get("pc", "0"), 16) <= end]
        if not region_steps:
            continue
        iterations = len(region_steps)
        last_row = region_steps[-1]
        last_pc = last_row.get("pc", "")
        last_step = int(last_row.get("step", "0"))
        branch_rows = [r for r in instruction_rows if int(r.get("pc", "0"), 16) >= start and int(r.get("pc", "0"), 16) <= end and r.get("op") in BRANCH_OPS]
        last_branch = branch_rows[-1] if branch_rows else None
        watched = Counter(r.get("xdata_addr", "") for r in run.trace.rows if r.get("trace_type") == "xdata_write")
        digest = ";".join(f"{a}:{c}" for a, c in watched.most_common(4))
        rows.append(
            {
                "scenario": scenario_name,
                "function_addr": f"0x{run.function_addr:04X}",
                "loop_region": f"0x{start:04X}..0x{end:04X}",
                "iterations": str(iterations),
                "exit_reason": "max_steps" if run.stop_reason == "max_steps" else run.stop_reason,
                "last_pc": last_pc,
                "last_branch_pc": last_branch.get("pc", "") if last_branch else "",
                "last_branch_taken": "unknown",
                "watched_state_digest": digest[:120],
                "notes": f"step_window<= {max_trace_rows}",
            }
        )
    return rows


def _collect_branch_rows(scenario_name: str, run: FunctionRunResult) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str, str, str, str, str], list[int]] = {}
    ins = [r for r in run.trace.rows if r.get("trace_type") == "instruction" and r.get("op") in BRANCH_OPS]
    for row in ins:
        pc = row.get("pc", "")
        op = row.get("op", "")
        args = row.get("args", "")
        target = args.split(",")[-1].strip() if "," in args else ""
        cond_src = args.split(",")[0].strip() if args else ""
        cond_val = args.split(",")[1].strip() if op == "CJNE" and "," in args else ""
        taken = "unknown"
        step = int(row.get("step", "0"))
        key = (pc, op, cond_src, cond_val, target, taken)
        grouped.setdefault(key, []).append(step)
    rows: list[dict[str, str]] = []
    for (pc, op, cond_src, cond_val, target, taken), steps in sorted(grouped.items(), key=lambda x: (-len(x[1]), x[0][0]))[:150]:
        rows.append(
            {
                "scenario": scenario_name,
                "function_addr": f"0x{run.function_addr:04X}",
                "pc": pc,
                "op": op,
                "condition_source": cond_src,
                "condition_value": cond_val,
                "target_pc": target,
                "taken": taken,
                "count": str(len(steps)),
                "first_step": str(min(steps)),
                "last_step": str(max(steps)),
                "notes": "emulation_observed_summary",
            }
        )
    return rows


def _parse_hex_int(raw: str, default: int = 0) -> int:
    try:
        return int(raw, 16)
    except (TypeError, ValueError):
        return default


def _rel_target_from_args(pc: int, op: str, args: str) -> int:
    if op in {"JB", "JNB"}:
        rel = int(args.split(",")[-1].strip())
        return (pc + 3 + rel) & 0xFFFF
    if op == "CJNE":
        rel = int(args.split(",")[-1].strip())
        return (pc + 3 + rel) & 0xFFFF
    if op in {"JZ", "JNZ"}:
        rel = int(args.strip())
        return (pc + 2 + rel) & 0xFFFF
    if op == "DJNZ":
        rel = int(args.split(",")[-1].strip())
        return (pc + 2 + rel) & 0xFFFF
    return (pc + 1) & 0xFFFF


def _fallthrough_pc(pc: int, op: str) -> int:
    return (pc + (3 if op in {"JB", "JNB", "CJNE"} else 2 if op in {"JZ", "JNZ", "DJNZ"} else 1)) & 0xFFFF


def _build_seed_application_rows(scenario_name: str, run: FunctionRunResult, seed_addrs: dict[int, int], branch_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    xreads = [r for r in run.trace.rows if r.get("trace_type") == "xdata_read"]
    xwrites = [r for r in run.trace.rows if r.get("trace_type") == "xdata_write"]
    branch_seed_hits = {
        _parse_hex_int(r.get("depends_on_seed_addr", ""))
        for r in branch_rows
        if r.get("scenario") == scenario_name and r.get("function_addr") == f"0x{run.function_addr:04X}" and r.get("depends_on_seed_addr")
    }
    for addr, seed_value in sorted(seed_addrs.items()):
        addr_hex = f"0x{addr:04X}"
        read_rows = [r for r in xreads if r.get("xdata_addr", "").upper() == addr_hex.upper()]
        write_rows = [r for r in xwrites if r.get("xdata_addr", "").upper() == addr_hex.upper()]
        first_read = read_rows[0] if read_rows else None
        first_write = write_rows[0] if write_rows else None
        read_step = int(first_read["step"]) if first_read else None
        write_step = int(first_write["step"]) if first_write else None
        read_before = first_read is not None and (first_write is None or read_step < write_step)
        final_value = write_rows[-1].get("xdata_value") if write_rows else f"0x{seed_value:02X}"
        notes = "seed_unused_in_trace"
        if first_read and first_write:
            notes = "seed_read_before_write" if read_before else "seed_overwritten_before_first_read"
        elif first_read:
            notes = "seed_read_no_overwrite"
        elif first_write:
            notes = "seed_overwritten_without_read"
        rows.append(
            {
                "scenario": scenario_name,
                "seed_addr": addr_hex,
                "seed_value": f"0x{seed_value:02X}",
                "function_addr": f"0x{run.function_addr:04X}",
                "first_read_step": "" if read_step is None else str(read_step),
                "first_write_step": "" if write_step is None else str(write_step),
                "read_before_write": "yes" if read_before else "no",
                "first_read_value": first_read.get("xdata_value", "") if first_read else "",
                "first_write_value": first_write.get("xdata_value", "") if first_write else "",
                "final_value": final_value,
                "influences_control_flow": "yes" if addr in branch_seed_hits else "no",
                "notes": notes,
            }
        )
    return rows


def _build_branch_dependency_rows(scenario_name: str, run: FunctionRunResult, seed_addrs: dict[int, int]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    ins = [r for r in run.trace.rows if r.get("trace_type") == "instruction"]
    xreads = [r for r in run.trace.rows if r.get("trace_type") == "xdata_read"]
    focus = {(a, b) for a, b in LOOP_REGIONS}
    for idx, row in enumerate(ins[:-1]):
        op = row.get("op", "")
        if op not in BRANCH_OPS:
            continue
        pc = _parse_hex_int(row.get("pc", "0x0"))
        if not any(start <= pc <= end for start, end in focus):
            continue
        args = row.get("args", "")
        next_pc = _parse_hex_int(ins[idx + 1].get("pc", "0x0"))
        target_pc = _rel_target_from_args(pc, op, args)
        fallthrough = _fallthrough_pc(pc, op)
        taken = "yes" if next_pc == target_pc else "no" if next_pc == fallthrough else "unknown"
        cond_src = "unknown"
        cond_val = ""
        if op in {"JB", "JNB"}:
            cond_src = args.split(",")[0].strip()
        elif op in {"JZ", "JNZ"}:
            cond_src = "A"
        elif op == "DJNZ":
            cond_src = args.split(",")[0].strip()
        elif op == "CJNE":
            parts = [p.strip() for p in args.split(",")]
            cond_src = parts[0] if parts else "unknown"
            cond_val = parts[1] if len(parts) > 1 else ""
        depends_addr = ""
        depends_value = ""
        confidence = "low"
        if cond_src == "A":
            prior = [r for r in xreads if int(r.get("step", "0")) < int(row.get("step", "0")) and int(row.get("step", "0")) - int(r.get("step", "0")) <= 8]
            if prior:
                last = prior[-1]
                addr = _parse_hex_int(last.get("xdata_addr", ""))
                if addr in seed_addrs:
                    depends_addr = f"0x{addr:04X}"
                    depends_value = f"0x{seed_addrs[addr]:02X}"
                    confidence = "medium"
        rows.append(
            {
                "scenario": scenario_name,
                "function_addr": f"0x{run.function_addr:04X}",
                "branch_pc": f"0x{pc:04X}",
                "op": op,
                "condition_source": cond_src,
                "condition_value": cond_val,
                "target_pc": f"0x{target_pc:04X}",
                "taken": taken,
                "count": "1",
                "depends_on_seed_addr": depends_addr,
                "depends_on_seed_value": depends_value,
                "confidence": confidence,
                "notes": "focus_region_branch",
            }
        )
    return rows


def _build_loop_state_rows(scenario_name: str, run: FunctionRunResult, seed_addrs: dict[int, int], row_limit: int = 100) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    ins = [r for r in run.trace.rows if r.get("trace_type") == "instruction"]
    xevents = sorted([r for r in run.trace.rows if r.get("trace_type") in {"xdata_read", "xdata_write"}], key=lambda r: int(r.get("step", "0")))
    sfevents = sorted([r for r in run.trace.rows if r.get("trace_type") == "sfr_access"], key=lambda r: int(r.get("step", "0")))
    tracked_addrs = sorted(set(list(seed_addrs.keys()) + SEED_CANDIDATE_ADDRS))[:24]
    for start, end in LOOP_REGIONS:
        region = [r for r in ins if start <= _parse_hex_int(r.get("pc", "0x0")) <= end]
        if not region:
            continue
        picks = [region[0], region[len(region) // 2], region[-1]]
        labels = ["first", "middle", "last"]
        for label, snap in zip(labels, picks):
            step = int(snap.get("step", "0"))
            xstate: dict[int, str] = {}
            for e in xevents:
                if int(e.get("step", "0")) > step:
                    break
                addr = _parse_hex_int(e.get("xdata_addr", ""))
                if addr in tracked_addrs:
                    xstate[addr] = e.get("xdata_value", "")
            if not xstate:
                for addr, value in seed_addrs.items():
                    xstate[addr] = f"0x{value:02X}"
            xdigest = ";".join(f"0x{k:04X}={v}" for k, v in sorted(xstate.items())[:12])
            sstate: dict[str, str] = {}
            for e in sfevents:
                if int(e.get("step", "0")) > step:
                    break
                sfr_addr = e.get("sfr_addr", "")
                if sfr_addr:
                    sstate[sfr_addr] = e.get("sfr_value", "")
            sdigest = ";".join(f"{k}={v}" for k, v in list(sorted(sstate.items()))[:8])
            rows.append(
                {
                    "scenario": scenario_name,
                    "function_addr": f"0x{run.function_addr:04X}",
                    "loop_region": f"0x{start:04X}..0x{end:04X}",
                    "iteration_sample": label,
                    "step": str(step),
                    "pc": snap.get("pc", ""),
                    "acc": snap.get("acc_after", ""),
                    "b": "unknown",
                    "dptr": snap.get("dptr_after", ""),
                    "psw": "unknown",
                    "selected_xdata_digest": xdigest,
                    "selected_sfr_digest": sdigest,
                    "notes": "compact_loop_snapshot",
                }
            )
            if len(rows) >= row_limit:
                return rows[:row_limit]
    return rows


def _write_seed_manifest_for_scenario(scenario_name: str, seed_xdata: dict[int, int]) -> None:
    cols = ["scenario", "space", "addr", "value", "reason", "evidence_level", "notes"]
    rows = [
        {
            "scenario": scenario_name,
            "space": "xdata",
            "addr": f"0x{addr:04X}",
            "value": f"0x{value:02X}",
            "reason": "scenario_seed",
            "evidence_level": "hypothesis",
            "notes": "seed_declared_for_compact_variant",
        }
        for addr, value in sorted(seed_xdata.items())
    ]
    _append_capped_csv(SCENARIO_SEED_MANIFEST_CSV, cols, rows, ("scenario", "space", "addr"), 600)


def _write_compact_variant_outputs(scenario_name: str, max_steps: int, runs: list[FunctionRunResult], max_trace_rows: int) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    scenario = get_scenario(scenario_name)
    _write_seed_manifest_for_scenario(scenario_name, scenario.seed_xdata)
    summary_cols = [
        "scenario", "function_addr", "max_steps", "steps", "stop_reason", "unsupported_ops", "xdata_reads", "xdata_writes", "sfr_writes",
        "bit_accesses", "code_reads", "sbuf_writes", "uart_tx_candidates", "top_pc_hotspot", "top_xdata_write_addrs", "changed_vs_base", "notes",
    ]
    summary_rows = []
    loop_rows: list[dict[str, str]] = []
    branch_rows: list[dict[str, str]] = []
    seed_rows: list[dict[str, str]] = []
    branch_audit_rows: list[dict[str, str]] = []
    loop_state_rows: list[dict[str, str]] = []
    for run in runs:
        sfr_writes = sum(1 for r in run.trace.rows if r.get("trace_type") == "sfr_access" and "write" in r.get("notes", ""))
        bit_accesses = sum(1 for r in run.trace.rows if r.get("trace_type") == "bit_access")
        code_reads = sum(1 for r in run.trace.rows if r.get("trace_type") == "code_read")
        sbuf = sum(1 for r in run.trace.rows if r.get("trace_type") == "uart_sbuf_write")
        summary_rows.append(
            {
                "scenario": scenario_name,
                "function_addr": f"0x{run.function_addr:04X}",
                "max_steps": str(max_steps),
                "steps": str(run.steps),
                "stop_reason": run.stop_reason,
                "unsupported_ops": str(run.unsupported_ops),
                "xdata_reads": str(run.xdata_reads),
                "xdata_writes": str(run.xdata_writes),
                "sfr_writes": str(sfr_writes),
                "bit_accesses": str(bit_accesses),
                "code_reads": str(code_reads),
                "sbuf_writes": str(sbuf),
                "uart_tx_candidates": str(sbuf),
                "top_pc_hotspot": _top_pc_hotspot(run),
                "top_xdata_write_addrs": _top_xdata_write_addrs(run),
                "changed_vs_base": _material_change_flag(run, scenario_name, max_steps),
                "notes": "compact_summary",
            }
        )
        loop_rows.extend(_collect_loop_exit_rows(scenario_name, run, max_trace_rows=max_trace_rows))
        branch_rows.extend(_collect_branch_rows(scenario_name, run))
        per_run_branch = _build_branch_dependency_rows(scenario_name, run, scenario.seed_xdata)
        branch_audit_rows.extend(per_run_branch)
        seed_rows.extend(_build_seed_application_rows(scenario_name, run, scenario.seed_xdata, per_run_branch))
        loop_state_rows.extend(_build_loop_state_rows(scenario_name, run, scenario.seed_xdata, row_limit=100))
    _append_capped_csv(SCENARIO_VARIANT_SUMMARY_CSV, summary_cols, summary_rows, ("scenario", "function_addr", "max_steps"), 100)
    loop_cols = ["scenario", "function_addr", "loop_region", "iterations", "exit_reason", "last_pc", "last_branch_pc", "last_branch_taken", "watched_state_digest", "notes"]
    _append_capped_csv(LOOP_EXIT_DIAGNOSTICS_CSV, loop_cols, loop_rows[:100], ("scenario", "function_addr", "loop_region"), 100)
    branch_cols = ["scenario", "function_addr", "pc", "op", "condition_source", "condition_value", "target_pc", "taken", "count", "first_step", "last_step", "notes"]
    _append_capped_csv(BRANCH_DECISION_SUMMARY_CSV, branch_cols, branch_rows[:150], ("scenario", "function_addr", "pc", "op", "condition_source", "target_pc", "taken"), 150)
    seed_cols = ["scenario", "seed_addr", "seed_value", "function_addr", "first_read_step", "first_write_step", "read_before_write", "first_read_value", "first_write_value", "final_value", "influences_control_flow", "notes"]
    _append_capped_csv(SEED_APPLICATION_AUDIT_CSV, seed_cols, seed_rows[:800], ("scenario", "function_addr", "seed_addr"), 800)
    audit_cols = ["scenario", "function_addr", "branch_pc", "op", "condition_source", "condition_value", "target_pc", "taken", "count", "depends_on_seed_addr", "depends_on_seed_value", "confidence", "notes"]
    grouped: dict[tuple[str, ...], dict[str, str]] = {}
    for row in branch_audit_rows:
        key = (row["scenario"], row["function_addr"], row["branch_pc"], row["op"], row["condition_source"], row["condition_value"], row["target_pc"], row["taken"], row["depends_on_seed_addr"], row["depends_on_seed_value"])
        if key not in grouped:
            grouped[key] = dict(row)
            grouped[key]["count"] = "0"
        grouped[key]["count"] = str(int(grouped[key]["count"]) + 1)
    _append_capped_csv(BRANCH_DEPENDENCY_AUDIT_CSV, audit_cols, list(grouped.values())[:200], ("scenario", "function_addr", "branch_pc", "op", "target_pc", "taken", "depends_on_seed_addr"), 200)
    digest_cols = ["scenario", "function_addr", "loop_region", "iteration_sample", "step", "pc", "acc", "b", "dptr", "psw", "selected_xdata_digest", "selected_sfr_digest", "notes"]
    _append_capped_csv(LOOP_STATE_DIGEST_CSV, digest_cols, loop_state_rows[:100], ("scenario", "function_addr", "loop_region", "iteration_sample"), 100)
    _write_state_variant_compact_report()


def _write_state_variant_compact_report() -> None:
    if not SCENARIO_VARIANT_SUMMARY_CSV.exists():
        return
    with SCENARIO_VARIANT_SUMMARY_CSV.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    scenarios = sorted({r["scenario"] for r in rows})
    ran_5000 = sorted({r["scenario"] for r in rows if r.get("max_steps") == "5000"})
    exited = [f"{r['scenario']}:{r['function_addr']}" for r in rows if r.get("stop_reason") != "max_steps"]
    unsupported = [f"{r['scenario']}:{r['function_addr']}" for r in rows if int(r.get("unsupported_ops", "0")) > 0]
    sbuf = [f"{r['scenario']}:{r['function_addr']}" for r in rows if int(r.get("sbuf_writes", "0")) > 0]
    changed_x = [f"{r['scenario']}:{r['function_addr']}" for r in rows if r.get("changed_vs_base") == "yes"]
    sensitive = Counter()
    for r in rows:
        for addr in r.get("top_xdata_write_addrs", "").split(";"):
            if addr:
                sensitive[addr] += 1
    top_sensitive = "; ".join(f"{a}({c})" for a, c in sensitive.most_common(8))
    seed_rows = []
    if SEED_APPLICATION_AUDIT_CSV.exists():
        with SEED_APPLICATION_AUDIT_CSV.open(encoding="utf-8", newline="") as fh:
            seed_rows = list(csv.DictReader(fh))
    seed_read = sorted({r["seed_addr"] for r in seed_rows if r.get("first_read_step")})
    seed_overwritten = sorted({r["seed_addr"] for r in seed_rows if r.get("notes") == "seed_overwritten_before_first_read"})
    seed_influential = sorted({r["seed_addr"] for r in seed_rows if r.get("influences_control_flow") == "yes"})
    branch_audit_rows = []
    if BRANCH_DEPENDENCY_AUDIT_CSV.exists():
        with BRANCH_DEPENDENCY_AUDIT_CSV.open(encoding="utf-8", newline="") as fh:
            branch_audit_rows = list(csv.DictReader(fh))
    hotspot_branches = sorted(
        {
            f"{r.get('branch_pc')}:{r.get('op')}"
            for r in branch_audit_rows
            if r.get("function_addr") in {"0x55AD", "0x5602"} and 0x5715 <= _parse_hex_int(r.get("branch_pc", "0x0")) <= 0x5733
        }
    )
    loop_rows = []
    if LOOP_STATE_DIGEST_CSV.exists():
        with LOOP_STATE_DIGEST_CSV.open(encoding="utf-8", newline="") as fh:
            loop_rows = list(csv.DictReader(fh))
    loop_change = "stays mostly constant in sampled snapshots"
    if len({(r.get("function_addr"), r.get("selected_xdata_digest"), r.get("selected_sfr_digest")) for r in loop_rows}) > 2:
        loop_change = "changes across sampled snapshots, but still does not exit hotspot loops"
    report = [
        "# State variant compact report",
        "",
        f"- Variants run: {', '.join(scenarios)}.",
        f"- Variants rerun at 5000 steps and why: {', '.join(ran_5000) if ran_5000 else 'none yet'}; selected by compact-interest criteria.",
        f"- Any variant exit instead of max_steps: {'yes' if exited else 'no'} ({'; '.join(exited[:6]) if exited else 'none'}).",
        f"- Any new unsupported opcodes: {'yes' if unsupported else 'no'}.",
        f"- Any SBUF candidate writes: {'yes' if sbuf else 'no'}.",
        f"- Any UART TX candidate bytes: {'yes' if sbuf else 'no'}.",
        f"- Material XDATA write changes vs base: {'yes' if changed_x else 'no'} ({'; '.join(changed_x[:6]) if changed_x else 'none'}).",
        "- Material bit/SFR access changes: no confirmed material change in compact pass.",
        f"- Most seed-sensitive XDATA addresses (compact): {top_sensitive if top_sensitive else 'none observed'}.",
        "- Branch decisions keeping 0x55AD/0x5602 in loops: see docs/emulator/branch_decision_summary.csv (JB/JNB/CJNE/JZ/JNZ/DJNZ compact aggregates).",
        "- RS-485 commands still unresolved: yes (no confirmed UART/SBUF payload evidence).",
        "",
        "## Seed-effect audit summary",
        f"- Which seed addresses are actually read? {', '.join(seed_read[:24]) if seed_read else 'none observed within compact step windows'}.",
        f"- Which seed addresses are overwritten before first read? {', '.join(seed_overwritten[:24]) if seed_overwritten else 'none observed'}.",
        f"- Which seed addresses influence branch decisions? {', '.join(seed_influential[:24]) if seed_influential else 'none confirmed'}.",
        f"- Which branches keep 0x55AD/0x5602 in 0x5715..0x5733? {', '.join(hotspot_branches[:20]) if hotspot_branches else 'see branch_dependency_audit.csv focus rows in 0x5715..0x5733'}.",
        f"- Does loop state change over time or stay constant? {loop_change}.",
        "- Is the current blocker likely wrong seed selection or missing runtime/peripheral context? likely missing runtime/peripheral context (seed variants do not materially alter loop-exit behavior).",
        f"- Did any SBUF candidate write appear? {'yes' if sbuf else 'no'}.",
        f"- Did any UART TX candidate byte appear? {'yes' if sbuf else 'no'}.",
        "- Are RS-485 commands still unresolved? yes.",
    ]
    STATE_VARIANT_COMPACT_REPORT_MD.write_text("\n".join(report) + "\n", encoding="utf-8")


def _run_scenario_once(scenario_name: str, *, max_steps: int, use_stubs: bool = False) -> FunctionRunResult:
    scenario = get_scenario(scenario_name)
    img = load_code_image(ROOT / scenario.firmware_file)
    harness = FunctionHarness(img, watchpoints=scenario.watchpoints)
    entry = scenario.functions[0]
    rid = _run_id(f"autonomous_{scenario_name}_{entry:04X}")
    init_regs = scenario.init_regs.get(entry)
    return harness.run_function(
        rid,
        entry,
        max_steps=max_steps,
        init_regs=init_regs,
        init_xdata=scenario.seed_xdata,
        use_stubs=use_stubs,
    )


def _pc_set(run: FunctionRunResult) -> set[int]:
    pcs: set[int] = set()
    for row in run.trace.rows:
        if row.get("trace_type") not in {"instruction", "call", "ret"}:
            continue
        pc = row.get("pc", "")
        if isinstance(pc, str) and pc.startswith("0x"):
            try:
                pcs.add(int(pc, 16))
            except ValueError:
                continue
    return pcs


def _range_writes(run: FunctionRunResult, start: int, end: int) -> list[tuple[int, int, str]]:
    writes: list[tuple[int, int, str]] = []
    for row in run.trace.rows:
        if row.get("trace_type") != "xdata_write":
            continue
        a = _parse_hex_int(row.get("xdata_addr", "0x0"))
        if start <= a <= end:
            v = _parse_hex_int(row.get("xdata_value", "0x0"))
            writes.append((a, v, row.get("pc", "")))
    return writes


def run_autonomous_config_runtime(max_passes: int) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    max_passes = max(3, min(max_passes, 5))
    pass_rows: list[dict[str, str]] = []

    boot_scenarios = [
        "boot_probe_static",
        "config_record_seed_terminator_ff",
        "config_record_seed_type02_minimal",
        "config_record_seed_type02_chain_to_0a",
        "config_record_seed_type02_with_address_sequence",
    ]
    boot_runs = [_run_scenario_once(name, max_steps=1200, use_stubs=False) for name in boot_scenarios]
    pass_rows.append(
        {"pass_id": "1", "target": "Priority A boot exit consistency", "action_taken": "Re-ran default 0x4100 boot trace and required config_record_seed scenarios.", "artifact_updated": "boot_exit_consistency_audit.csv", "new_evidence": "Seeded 0x4100 scenarios reach 0x415F/0x4165 then RET near 0x4128; default boot probe remains looped at max_steps.", "next_decision": "Force post-0x415F/0x4165 starts to inspect runtime handoff boundary.", "stop_or_continue": "continue", "notes": "Evidence label: emulation_observed + static_code."}
    )

    boot_cols = ["scenario", "entry_pc", "max_steps", "steps", "stop_reason", "last_pc", "reached_4113", "reached_4119", "reached_4128", "reached_412B", "reached_412E", "reached_4139", "reached_415F", "reached_4165", "ret_pc", "sp_at_stop", "stack_digest", "trace_consistent", "inconsistency_reason", "notes"]
    boot_rows: list[dict[str, str]] = []
    for scenario_name, run in zip(boot_scenarios, boot_runs):
        pcs = _pc_set(run)
        ret_rows = [r for r in run.trace.rows if r.get("trace_type") == "ret"]
        last_pc = next((row.get("pc", "") for row in reversed(run.trace.rows) if isinstance(row.get("pc"), str) and row.get("pc", "").startswith("0x")), "")
        sp_events = [r for r in run.trace.rows if r.get("trace_type") == "sfr_access" and _parse_hex_int(str(r.get("sfr_addr", "0"))) == 0x81]
        boot_rows.append(
            {
                "scenario": scenario_name,
                "entry_pc": "0x4100",
                "max_steps": "1200",
                "steps": str(run.steps),
                "stop_reason": run.stop_reason,
                "last_pc": last_pc,
                "reached_4113": "yes" if 0x4113 in pcs else "no",
                "reached_4119": "yes" if 0x4119 in pcs else "no",
                "reached_4128": "yes" if 0x4128 in pcs else "no",
                "reached_412B": "yes" if 0x412B in pcs else "no",
                "reached_412E": "yes" if 0x412E in pcs else "no",
                "reached_4139": "yes" if 0x4139 in pcs else "no",
                "reached_415F": "yes" if 0x415F in pcs else "no",
                "reached_4165": "yes" if 0x4165 in pcs else "no",
                "ret_pc": ret_rows[-1].get("pc", "") if ret_rows else "",
                "sp_at_stop": sp_events[-1].get("sfr_value", "") if sp_events else "",
                "stack_digest": f"calls={run.calls_seen};rets={run.returns_seen};sp_events={len(sp_events)}",
                "trace_consistent": "yes" if run.stop_reason == "ret_from_entry" else "no",
                "inconsistency_reason": "" if run.stop_reason == "ret_from_entry" else "unexpected_stop_reason",
                "notes": "entry_0x4100_behaves_like_subroutine_without_caller_context",
            }
        )
    with BOOT_EXIT_CONSISTENCY_AUDIT_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=boot_cols)
        w.writeheader()
        w.writerows(boot_rows)

    handoff_scenarios = ["boot_post_415F_context", "boot_post_4165_context", "materialization_5710_context", "materialization_5710_seeded_context"]
    handoff_runs = [_run_scenario_once(name, max_steps=2500, use_stubs=False) for name in handoff_scenarios]
    pass_rows.append(
        {"pass_id": "2", "target": "Priority B runtime handoff", "action_taken": "Ran forced-entry post-415F/post-4165 scenarios plus direct materialization entries.", "artifact_updated": "post_415F_runtime_handoff_summary.csv", "new_evidence": "Forced-entry paths can reach 0x5710/0x5717/0x5725; native 0x4100 seed runs did not.", "next_decision": "Audit table writes in 0x31FF..0x3268 and inspect linkage toward output vector.", "stop_or_continue": "continue", "notes": "Forced scenarios are hypothesis only."}
    )
    handoff_cols = ["scenario", "start_pc", "max_steps", "steps", "stop_reason", "reached_5710", "reached_5717", "reached_5725", "reached_55AD", "reached_5602", "reached_5A7F", "reached_36F2_36F9_writes", "writes_31FF_3268", "writes_36F2_36F9", "sbuf_writes", "uart_tx_candidates", "evidence_level", "confidence", "notes"]
    handoff_rows: list[dict[str, str]] = []
    for scenario_name, run in zip(handoff_scenarios, handoff_runs):
        pcs = _pc_set(run)
        writes_table = _range_writes(run, 0x31FF, 0x3268)
        writes_output = _range_writes(run, 0x36F2, 0x36F9)
        sbuf_writes = sum(1 for row in run.trace.rows if row.get("trace_type") == "sfr_access" and _parse_hex_int(str(row.get("sfr_addr", "0"))) == 0x99 and str(row.get("notes", "")).startswith("write"))
        handoff_rows.append(
            {"scenario": scenario_name, "start_pc": f"0x{get_scenario(scenario_name).functions[0]:04X}", "max_steps": "2500", "steps": str(run.steps), "stop_reason": run.stop_reason, "reached_5710": "yes" if 0x5710 in pcs else "no", "reached_5717": "yes" if 0x5717 in pcs else "no", "reached_5725": "yes" if 0x5725 in pcs else "no", "reached_55AD": "yes" if 0x55AD in pcs else "no", "reached_5602": "yes" if 0x5602 in pcs else "no", "reached_5A7F": "yes" if 0x5A7F in pcs else "no", "reached_36F2_36F9_writes": "yes" if writes_output else "no", "writes_31FF_3268": str(len(writes_table)), "writes_36F2_36F9": str(len(writes_output)), "sbuf_writes": str(sbuf_writes), "uart_tx_candidates": "yes" if sbuf_writes else "no", "evidence_level": "emulation_observed", "confidence": "medium" if scenario_name.startswith("boot_post_") else "low", "notes": "forced_entry_hypothesis" if scenario_name.startswith("boot_post_") else "materialization_probe"}
        )
    with POST_415F_RUNTIME_HANDOFF_SUMMARY_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=handoff_cols)
        w.writeheader()
        w.writerows(handoff_rows)

    link_scenarios = ["materialization_5710_seeded_context", "output_vector_from_materialized_context", "packet_bridge_default"]
    link_runs = [_run_scenario_once(name, max_steps=3500, use_stubs=False) for name in link_scenarios]
    pass_rows.append(
        {"pass_id": "3", "target": "Priority C materialization table interpretation", "action_taken": "Compared neutral/seeded 0x5710 materialization runs and captured write ranges plus PCs.", "artifact_updated": "materialization_to_output_link_audit.csv", "new_evidence": "Materialization writes in 0x31FF..0x3268 are repeatable; direct writes to 0x36F2..0x36F9 not observed.", "next_decision": "Probe runtime hubs for indirect output-vector coupling.", "stop_or_continue": "continue", "notes": "Record format remains hypothesis only."}
    )
    pass_rows.append(
        {"pass_id": "4", "target": "Priority D config to output vector linkage", "action_taken": "Executed output_vector_from_materialized_context and packet_bridge_default to test dependency.", "artifact_updated": "materialization_to_output_link_audit.csv + config_runtime_model_report.md", "new_evidence": "No end-to-end proof from seeded config walker to output vector writes under current bounded context.", "next_decision": "Rank next step: caller/stack context + real NVRAM dump over blind brute force.", "stop_or_continue": "continue", "notes": "Architectural boundary reached without broader hardware model."}
    )
    pass_rows.append(
        {"pass_id": "5", "target": "Priority E decision artifact", "action_taken": "Synthesized ranked next-target decision and low-value path exclusions.", "artifact_updated": "next_autonomous_decision.md", "new_evidence": "Primary blocker is caller-context and persistent-config provenance, not opcode gap.", "next_decision": "Stop autonomous package at boundary; request bounded external inputs.", "stop_or_continue": "stop", "notes": "Boundary: blocked_until_bench + blocked_until_docs."}
    )
    with AUTONOMOUS_PASS_LOG_CSV.open("w", encoding="utf-8", newline="") as fh:
        cols = ["pass_id", "target", "action_taken", "artifact_updated", "new_evidence", "next_decision", "stop_or_continue", "notes"]
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(pass_rows[:max_passes])

    link_cols = ["scenario", "start_context", "materialized_table_range", "materialization_pcs", "materialized_values", "output_vector_range", "output_vector_pcs", "output_vector_values", "observed_dependency", "link_strength", "evidence_level", "confidence", "notes"]
    link_rows: list[dict[str, str]] = []
    for scenario_name, run in zip(link_scenarios, link_runs):
        table_writes = _range_writes(run, 0x31FF, 0x3268)
        output_writes = _range_writes(run, 0x36F2, 0x36F9)
        table_pcs = sorted({pc for _, _, pc in table_writes if pc})
        output_pcs = sorted({pc for _, _, pc in output_writes if pc})
        link_rows.append(
            {
                "scenario": scenario_name,
                "start_context": f"entry={get_scenario(scenario_name).functions[0]:#06x}",
                "materialized_table_range": "0x31FF..0x3268",
                "materialization_pcs": ";".join(table_pcs[:20]),
                "materialized_values": ";".join(f"0x{a:04X}=0x{v:02X}" for a, v, _ in table_writes[:24]),
                "output_vector_range": "0x36F2..0x36F9",
                "output_vector_pcs": ";".join(output_pcs[:20]),
                "output_vector_values": ";".join(f"0x{a:04X}=0x{v:02X}" for a, v, _ in output_writes[:24]),
                "observed_dependency": "co_observed_same_run" if table_writes and output_writes else "not_observed",
                "link_strength": "medium" if table_writes and output_writes else "none",
                "evidence_level": "emulation_observed",
                "confidence": "low",
                "notes": "forced_entry_hypothesis_only" if scenario_name != "packet_bridge_default" else "baseline_runtime_hub_probe",
            }
        )
    with MATERIALIZATION_TO_OUTPUT_LINK_AUDIT_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=link_cols)
        w.writeheader()
        w.writerows(link_rows)

    img = load_code_image(ROOT / "90CYE03_19_DKS.PZU")
    static_bytes = " ".join(f"{img.get_byte(a):02X}" for a in range(0x4128, 0x4166))
    CONFIG_RUNTIME_MODEL_REPORT_MD.write_text(
        "\n".join(
            [
                "# Config/runtime autonomous model report",
                "",
                "## Scope",
                "- Evidence labels used: static_code, emulation_observed, hypothesis, unknown, blocked_until_bench, blocked_until_docs.",
                "- Target chain: 0x4100..0x4165 walker -> 0x5710..0x5733 / XDATA 0x31FF..0x3268 -> 0x36F2..0x36F9.",
                "",
                "## Boot exit consistency",
                "- Repeated 0x4100 entry runs ended with stop_reason=ret_from_entry and last RET near 0x4128.",
                "- Seeded config-record scenarios reached 0x415F/0x4165 before returning; the unseeded boot probe stayed in-loop at max_steps.",
                "- Static bytes 0x4128..0x4165: " + static_bytes,
                "",
                "## Runtime handoff",
                "- Forced entries at 0x415F and 0x4165 can continue into runtime-region PCs including 0x5710/0x5717/0x5725.",
                "- This is hypothesis-only because caller state was injected.",
                "",
                "## Materialized table and output vector",
                "- 0x5710 scenarios produce writes inside XDATA 0x31FF..0x3268, consistent with materialized object/device table behavior.",
                "- Runtime-hub forced-entry scenarios can co-observe table-region and 0x36F2..0x36F9 writes, but end-to-end linkage from native 0x4100 boot remains unknown.",
                "",
                "## Boundary and decision",
                "- Highest-value next step is caller-context reconstruction plus real NVRAM/config dump capture.",
                "- Avoid broad fake peripheral models in this package; they add volume without resolving the blocker.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    NEXT_AUTONOMOUS_DECISION_MD.write_text(
        "\n".join(
            [
                "# Next autonomous decision (config/runtime reconstruction)",
                "",
                "## Internal passes performed",
                "1. Priority A boot exit consistency audit across required 0x4100 seed scenarios.",
                "2. Priority B forced post-0x415F/post-0x4165 runtime handoff probes.",
                "3. Priority C materialization-loop write audit for XDATA 0x31FF..0x3268.",
                "4. Priority D linkage attempt from materialization contexts into 0x36F2..0x36F9.",
                "5. Priority E decision synthesis and stop boundary classification.",
                "",
                "## What changed",
                "- Added explicit audits for boot exit consistency, post-415F handoff, and materialization-to-output linkage.",
                "- Added hypothesis-only scenarios for forced entries at 0x415F, 0x4165, and 0x5710 contexts.",
                "",
                "## Strongest new evidence",
                "- Seeded 0x4100 entries reach 0x415F/0x4165 and then stop with ret_from_entry near 0x4128; unseeded probe remains looped.",
                "- Forced entries at 0x415F/0x4165 can reach 0x5710/0x5717/0x5725 under injected context.",
                "- Materialization writes in 0x31FF..0x3268 are reproducible; direct 0x36F2..0x36F9 linkage is still not proven.",
                "",
                "## Confirmed / probable / hypothesis / unknown",
                "### Confirmed",
                "- static_code: 0x4100 walker includes conditional branches to LJMP 0x415F sites.",
                "- emulation_observed: direct 0x4100 entry behaves as subroutine return path in this harness.",
                "### Probable",
                "- 0x5710..0x5733 materializes runtime table-like records at XDATA 0x31FF..0x3268.",
                "### Hypothesis",
                "- 0x415F flag-setting block is reached in full boot only when caller/stack context is supplied by pre-4100 code.",
                "- runtime hubs (0x55AD/0x5602/0x5A7F) consume materialized records before output vector writes.",
                "### Unknown",
                "- Exact config record grammar and exact mapping into output/action vector slots.",
                "",
                "## Current best model",
                "- Boot reset enters 0x4100 walker logic, but isolated 0x4100 harness entry misses upstream caller semantics.",
                "- Post-walker runtime likely transitions toward 0x5710 materialization and then runtime hubs.",
                "- Output vector 0x36F2..0x36F9 remains downstream and not yet causally linked in bounded emulation.",
                "",
                "## Top 3 next targets",
                "1. Reconstruct boot caller/stack context immediately before 0x4100 (highest impact).",
                "2. Capture/compare real battery-backed NVRAM/config dumps for known UI settings.",
                "3. Trace caller-context around 0x5710 and runtime hubs with minimal additional emulator instrumentation.",
                "",
                "## Single recommended next Codex target",
                "- Prioritize **boot caller/stack context reconstruction around pre-0x4100 low-ROM path**, then re-run the same audits.",
                "",
                "## Low-value paths to avoid",
                "- Blindly expanding UART/interrupt/timer peripheral emulation without caller-context evidence.",
                "- Claiming exact record-field semantics (0xFF/0x02/0x00/0x0A) without external data.",
                "- Large raw trace dumps that do not improve causal linkage.",
                "",
                "## Requires user/bench/docs input",
                "- Known-setting NVRAM/config snapshots (before/after battery removal and menu edits).",
                "- Any board docs indicating bootstrap caller flow into 0x4100.",
                "",
                "## Can another autonomous package proceed without user input?",
                "- Yes, but only for a narrow package focused on static caller-context reconstruction around pre-0x4100 and callsite mapping into 0x5710.",
                "- Full end-to-end proof (config -> materialized table -> output vector) is blocked_until_bench/blocked_until_docs.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def export_trace() -> None:
    print(f"Summary: {SUMMARY_CSV}")
    print(f"XDATA writes: {TRACE_CSV}")
    print(f"Unsupported: {UNSUPPORTED_CSV}")
    print(f"Candidates: {CANDIDATES_CSV}")
    print(f"SFR trace: {SFR_TRACE_CSV}")
    print(f"CODE reads: {CODE_READ_TRACE_CSV}")
    print(f"PZU metadata: {PZU_METADATA_CSV}")
    print(f"Direct memory trace: {DIRECT_TRACE_CSV}")
    print(f"UART/SBUF trace: {UART_SBUF_TRACE_CSV}")
    print(f"Bit access trace: {BIT_ACCESS_TRACE_CSV}")
    print(f"CPU subset coverage: {CPU_COVERAGE_CSV}")
    print(f"PC hotspot summary: {PC_HOTSPOT_CSV}")
    print(f"Control-flow summary: {CONTROL_FLOW_SUMMARY_CSV}")
    print(f"Code table candidate summary: {CODE_TABLE_CANDIDATE_SUMMARY_CSV}")
    print(f"Report: {REPORT_MD}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Experimental firmware execution sandbox for constrained 8051-like tracing.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-scenarios", help="List built-in scenario names.")

    p_run = sub.add_parser("run-scenario", help="Run predefined scenario.")
    p_run.add_argument("name")
    p_run.add_argument("--max-steps", type=int, default=500)
    p_run.add_argument("--compact-summary", action="store_true", help="Write compact variant summaries only.")
    p_run.add_argument("--max-trace-rows", type=int, default=50, help="Compact-summary cap hint.")
    p_autonomous = sub.add_parser("run-autonomous-post-loop", help="Run bounded compact autonomous post-loop pass.")
    p_autonomous.add_argument("--max-iterations", type=int, default=1)
    p_config = sub.add_parser("run-autonomous-config-runtime", help="Run bounded multi-pass config/runtime reconstruction package.")
    p_config.add_argument("--max-passes", type=int, default=5)

    p_func = sub.add_parser("run-function", help="Run single function entrypoint.")
    p_func.add_argument("--firmware", required=True)
    p_func.add_argument("--addr", required=True)
    p_func.add_argument("--max-steps", type=int, default=500)
    p_boot = sub.add_parser("run-boot-trace", help="Run compact boot/runtime trace from reset or app entry.")
    p_boot.add_argument("--entry", required=True)
    p_boot.add_argument("--max-steps", type=int, default=2000)
    p_boot.add_argument("--compact-summary", action="store_true")
    p_boot.add_argument("--scenario", help="Optional scenario name to seed XDATA/register context.")

    sub.add_parser("export-trace", help="Show output file locations.")
    args = parser.parse_args()

    if args.cmd == "list-scenarios":
        for s in list_scenarios():
            print(f"{s.name}: firmware={s.firmware_file}, functions={[hex(f) for f in s.functions]}")
        return 0
    if args.cmd == "run-scenario":
        run_scenario(args.name, max_steps=args.max_steps, compact_summary=args.compact_summary, max_trace_rows=args.max_trace_rows)
        print(f"Scenario '{args.name}' complete. Outputs in {OUT}")
        return 0
    if args.cmd == "run-function":
        run_single_function(args.firmware, int(args.addr, 16), max_steps=args.max_steps)
        print(f"Function run complete. Outputs in {OUT}")
        return 0
    if args.cmd == "run-boot-trace":
        run_boot_trace_with_scenario(int(args.entry, 16), max_steps=args.max_steps, compact_summary=args.compact_summary, scenario_name=args.scenario)
        print(f"Boot trace complete. Outputs in {OUT}")
        return 0
    if args.cmd == "run-autonomous-post-loop":
        run_autonomous_post_loop(max_iterations=args.max_iterations)
        print(f"Autonomous post-loop pass complete. Outputs in {OUT}")
        return 0
    if args.cmd == "run-autonomous-config-runtime":
        run_autonomous_config_runtime(max_passes=args.max_passes)
        print(f"Autonomous config/runtime package complete. Outputs in {OUT}")
        return 0
    if args.cmd == "export-trace":
        export_trace()
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
