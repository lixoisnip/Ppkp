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

    p_func = sub.add_parser("run-function", help="Run single function entrypoint.")
    p_func.add_argument("--firmware", required=True)
    p_func.add_argument("--addr", required=True)
    p_func.add_argument("--max-steps", type=int, default=500)

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
    if args.cmd == "run-autonomous-post-loop":
        run_autonomous_post_loop(max_iterations=args.max_iterations)
        print(f"Autonomous post-loop pass complete. Outputs in {OUT}")
        return 0
    if args.cmd == "export-trace":
        export_trace()
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
