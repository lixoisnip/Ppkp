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
    REPORT_MD.write_text(
        "\n".join(
            [
                "# Firmware execution sandbox report",
                "",
                "## Scope",
                "Experimental function-level 8051-subset tracing for selected targets. Evidence level: emulation_observed.",
                "",
                "## CPU subset status",
                "Implemented subset includes MOV/MOVX/DPTR ops, simple ALU immediates, limited branches, LCALL/LJMP/RET.",
                "Includes initial MOVC table reads and dictionary-backed SFR access tracing (no synthetic UART behavior).",
                "Unsupported opcodes are logged and never silently ignored.",
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
                f"Did 0x55AD advance past 0xB8? {'yes' if _advanced_past_opcode(runs, 0x55AD, 0x55D0) else 'no'}",
                f"Did 0x5602 advance past 0xB8? {'yes' if _advanced_past_opcode(runs, 0x5602, 0x5609) else 'no'}",
                f"Did 0x5A7F advance past 0xF5? {'yes' if _advanced_past_opcode(runs, 0x5A7F, 0x5A81) else 'no'}",
                f"Were any SBUF candidate writes observed? {'yes' if _has_trace_type(runs, 'uart_sbuf_write') else 'no'}",
                f"Were any UART TX candidate bytes observed? {'yes' if _has_trace_type(runs, 'uart_sbuf_write') else 'no'}",
                f"Were any new candidate packet/event records observed? {'yes' if writes > 0 else 'no'}",
                "Are RS-485 commands still unresolved? yes",
                "",
                "No real RS-485 command is confirmed unless UART/SBUF writes or decoded packet bytes are observed.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


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


def run_scenario(name: str, max_steps: int) -> None:
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
    _write_xdata(xdata_rows)
    _write_unsupported(all_runs)
    _write_candidates(xdata_rows)
    _write_sfr_trace(all_runs, name)
    _write_code_read_trace(all_runs, name)
    _write_pzu_load_metadata(img)
    _write_direct_memory_trace(all_runs, name)
    _write_uart_sbuf_trace(all_runs, name)
    _write_cpu_subset_coverage(all_runs)
    _write_report(f"{img.firmware_file} via {img.source}", all_runs, scenario_name=name)


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
    _write_cpu_subset_coverage([run])
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


def _write_cpu_subset_coverage(runs: list[FunctionRunResult]) -> None:
    cols = ["opcode", "mnemonic", "implemented", "observed_in_runs", "notes"]
    observed_ops = {r["op"] for run in runs for r in run.trace.rows if r.get("trace_type") == "instruction"}
    coverage_rows = [
        {"opcode": "0xF5", "mnemonic": "MOV direct,A", "implemented": "yes", "observed_in_runs": "yes" if "MOV" in observed_ops else "unknown", "notes": "issue_78_blocker"},
        {"opcode": "0xB8..0xBF", "mnemonic": "CJNE Rn,#imm,rel", "implemented": "yes", "observed_in_runs": "yes" if "CJNE" in observed_ops else "no", "notes": "issue_78_blocker"},
        {"opcode": "0xB4", "mnemonic": "CJNE A,#imm,rel", "implemented": "yes", "observed_in_runs": "yes" if "CJNE" in observed_ops else "no", "notes": "extended_support"},
        {"opcode": "0xB5", "mnemonic": "CJNE A,direct,rel", "implemented": "yes", "observed_in_runs": "yes" if "CJNE" in observed_ops else "no", "notes": "extended_support"},
        {"opcode": "0xB6/0xB7", "mnemonic": "CJNE @R0/@R1,#imm,rel", "implemented": "yes", "observed_in_runs": "yes" if "CJNE" in observed_ops else "no", "notes": "extended_support"},
    ]
    with CPU_COVERAGE_CSV.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(coverage_rows)


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
    print(f"CPU subset coverage: {CPU_COVERAGE_CSV}")
    print(f"Report: {REPORT_MD}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Experimental firmware execution sandbox for constrained 8051-like tracing.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-scenarios", help="List built-in scenario names.")

    p_run = sub.add_parser("run-scenario", help="Run predefined scenario.")
    p_run.add_argument("name")
    p_run.add_argument("--max-steps", type=int, default=500)

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
        run_scenario(args.name, max_steps=args.max_steps)
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
