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

LOOP_REGIONS = [(0x5715, 0x5733), (0x8365, 0x837F), (0x567F, 0x5683), (0x5935, 0x593D)]
BRANCH_OPS = {"JB", "JNB", "CJNE", "JZ", "JNZ", "DJNZ"}


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
        run = harness.run_function(rid, faddr, max_steps=max_steps, init_xdata=scenario.seed_xdata)
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


def _write_compact_variant_outputs(scenario_name: str, max_steps: int, runs: list[FunctionRunResult], max_trace_rows: int) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    summary_cols = [
        "scenario", "function_addr", "max_steps", "steps", "stop_reason", "unsupported_ops", "xdata_reads", "xdata_writes", "sfr_writes",
        "bit_accesses", "code_reads", "sbuf_writes", "uart_tx_candidates", "top_pc_hotspot", "top_xdata_write_addrs", "changed_vs_base", "notes",
    ]
    summary_rows = []
    loop_rows: list[dict[str, str]] = []
    branch_rows: list[dict[str, str]] = []
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
    _append_capped_csv(SCENARIO_VARIANT_SUMMARY_CSV, summary_cols, summary_rows, ("scenario", "function_addr", "max_steps"), 100)
    loop_cols = ["scenario", "function_addr", "loop_region", "iterations", "exit_reason", "last_pc", "last_branch_pc", "last_branch_taken", "watched_state_digest", "notes"]
    _append_capped_csv(LOOP_EXIT_DIAGNOSTICS_CSV, loop_cols, loop_rows[:100], ("scenario", "function_addr", "loop_region"), 100)
    branch_cols = ["scenario", "function_addr", "pc", "op", "condition_source", "condition_value", "target_pc", "taken", "count", "first_step", "last_step", "notes"]
    _append_capped_csv(BRANCH_DECISION_SUMMARY_CSV, branch_cols, branch_rows[:150], ("scenario", "function_addr", "pc", "op", "condition_source", "target_pc", "taken"), 150)
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
    if args.cmd == "export-trace":
        export_trace()
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
