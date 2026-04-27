#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


@dataclass(frozen=True)
class SmokeCommand:
    script: str
    scope: str
    command: list[str]
    output_files: list[str]
    notes: str


def run_command(cmd: list[str], cwd: Path) -> tuple[int, str]:
    completed = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    output = "\n".join(part for part in (completed.stdout.strip(), completed.stderr.strip()) if part).strip()
    return completed.returncode, output


def main() -> int:
    parser = argparse.ArgumentParser(description="Run smoke test for all analysis scripts and write CSV report.")
    parser.add_argument(
        "--results",
        type=Path,
        default=DOCS / "analysis_smoke_test_results.csv",
        help="Output CSV with smoke test statuses.",
    )
    args = parser.parse_args()

    commands: list[SmokeCommand] = [
        SmokeCommand(
            script="py_compile",
            scope="utility",
            command=[sys.executable, "-m", "py_compile", "scripts/*.py"],
            output_files=[],
            notes="syntax compile check for all scripts",
        ),
        SmokeCommand("validate_pzu.py", "all_firmwares", [sys.executable, "scripts/validate_pzu.py"], [], "validation only"),
        SmokeCommand(
            "firmware_manifest.py",
            "all_firmwares",
            [sys.executable, "scripts/firmware_manifest.py"],
            [
                "docs/firmware_manifest.json",
                "docs/firmware_inventory.csv",
                "docs/vector_entrypoints.csv",
            ],
            "global inventory artifacts",
        ),
        SmokeCommand(
            "family_matrix.py",
            "all_firmwares",
            [sys.executable, "scripts/family_matrix.py"],
            ["docs/firmware_family_matrix.csv"],
            "pairwise family similarity",
        ),
        SmokeCommand(
            "xdata_xref.py",
            "all_firmwares",
            [sys.executable, "scripts/xdata_xref.py"],
            [
                "docs/xdata_xref.csv",
                "docs/xdata_xref_detailed.csv",
                "docs/xdata_confirmed_access.csv",
                "docs/dptr_pointer_args.csv",
                "docs/code_table_candidates.csv",
            ],
            "xdata evidence baseline",
        ),
        SmokeCommand(
            "disasm_8051.py",
            "all_firmwares",
            [sys.executable, "scripts/disasm_8051.py"],
            ["docs/disassembly_index.csv"],
            "reachable disassembly index",
        ),
        SmokeCommand(
            "call_xref.py",
            "all_firmwares",
            [sys.executable, "scripts/call_xref.py"],
            ["docs/call_xref.csv", "docs/call_xref_legacy.csv", "docs/call_targets_summary.csv"],
            "call graph layers",
        ),
        SmokeCommand(
            "basic_block_map.py",
            "all_firmwares",
            [sys.executable, "scripts/basic_block_map.py"],
            ["docs/basic_block_map.csv"],
            "requires disassembly/call/function inputs",
        ),
        SmokeCommand(
            "function_map.py",
            "all_firmwares",
            [sys.executable, "scripts/function_map.py"],
            ["docs/function_map.csv"],
            "function-level synthesis",
        ),
        SmokeCommand(
            "string_index.py",
            "all_firmwares",
            [sys.executable, "scripts/string_index.py"],
            ["docs/string_index.csv"],
            "movc/string candidates",
        ),
        SmokeCommand(
            "branch_comparison_report.py",
            "all_firmwares",
            [sys.executable, "scripts/branch_comparison_report.py"],
            ["docs/branch_comparison_summary.csv", "docs/global_branch_comparison.md"],
            "global branch-level comparison report after smoke-test",
        ),
        SmokeCommand(
            "global_packet_pipeline_miner.py",
            "all_firmwares",
            [sys.executable, "scripts/global_packet_pipeline_miner.py"],
            [
                "docs/global_packet_pipeline_candidates.csv",
                "docs/global_packet_pipeline_chains.csv",
                "docs/global_packet_pipeline_mining.md",
            ],
            "global packet/runtime pipeline candidate mining across all branches",
        ),
        SmokeCommand(
            "rtos_service_pipeline_analysis.py",
            "rtos_service_only",
            [sys.executable, "scripts/rtos_service_pipeline_analysis.py"],
            [
                "docs/rtos_service_function_candidates.csv",
                "docs/rtos_service_pipeline_chains.csv",
                "docs/rtos_service_xdata_role_candidates.csv",
                "docs/rtos_service_pipeline_analysis.md",
                "docs/rtos_service_next_deep_dive_plan.md",
            ],
            "branch-focused RTOS_service runtime/service pipeline candidate analysis",
        ),
        SmokeCommand(
            "rtos_chain_deep_trace.py",
            "rtos_service_only",
            [sys.executable, "scripts/rtos_chain_deep_trace.py"],
            [
                "docs/rtos_service_chain_4358_920c_53e6_trace.csv",
                "docs/rtos_service_chain_4358_920c_53e6_summary.csv",
                "docs/rtos_service_chain_4358_920c_53e6_analysis.md",
            ],
            "branch-specific deep static trace for top RTOS_service valid chain 0x4358->0x920C->0x53E6",
        ),
        SmokeCommand(
            "a03_a04_packet_builder_candidates.py",
            "a03_a04_only",
            [sys.executable, "scripts/a03_a04_packet_builder_candidates.py"],
            ["docs/a03_a04_packet_builder_candidates.csv"],
            "specialized for A03_26/A04_28",
        ),
        SmokeCommand(
            "extract_function_trace.py",
            "a03_a04_only",
            [sys.executable, "scripts/extract_function_trace.py"],
            ["docs/a03_a04_top_packet_function_trace.csv"],
            "trace for default A03/A04 target functions",
        ),
        SmokeCommand(
            "extract_call_neighborhood.py",
            "a03_a04_only",
            [sys.executable, "scripts/extract_call_neighborhood.py"],
            ["docs/a03_a04_packet_call_neighborhood.csv"],
            "default depth=1",
        ),
        SmokeCommand(
            "extract_pipeline_chain_trace.py",
            "a03_a04_only",
            [sys.executable, "scripts/extract_pipeline_chain_trace.py"],
            ["docs/a03_a04_packet_pipeline_chain_trace.csv"],
            "static chain trace for default chains",
        ),
        SmokeCommand(
            "find_packet_window_writers.py",
            "a03_a04_only",
            [sys.executable, "scripts/find_packet_window_writers.py"],
            ["docs/a03_a04_packet_window_writers.csv"],
            "packet-window writers in A03/A04 branch",
        ),
        SmokeCommand(
            "find_a03_analogs_for_a04_writers.py",
            "a03_a04_only",
            [sys.executable, "scripts/find_a03_analogs_for_a04_writers.py"],
            ["docs/a03_analogs_for_a04_packet_writers.csv", "docs/a03_analogs_for_a04_packet_writers.md"],
            "A03 structural analogs for A04 references",
        ),
        SmokeCommand(
            "mash_sensor_evidence_report.py",
            "documentation_seed",
            [sys.executable, "scripts/mash_sensor_evidence_report.py"],
            ["docs/supported_sensor_evidence.csv", "docs/mash_address_loop_sensor_model.md"],
            "seed evidence for MASH/address-loop sensors from PDF (firmware linkage remains hypothesis)",
        ),
        SmokeCommand(
            "dks_configuration_evidence.py",
            "documentation_seed",
            [sys.executable, "scripts/dks_configuration_evidence.py"],
            ["docs/dks_real_configuration_evidence.csv", "docs/dks_real_configuration_evidence.md"],
            "manual real-device DKS screen evidence transcription (configuration-level evidence only)",
        ),
        SmokeCommand(
            "mash_code_evidence_analyzer.py",
            "global_mash_analysis",
            [sys.executable, "scripts/mash_code_evidence_analyzer.py"],
            [
                "docs/mash_code_evidence_candidates.csv",
                "docs/mash_candidate_chains.csv",
                "docs/mash_code_evidence_analysis.md",
            ],
            "global / MASH code evidence analysis",
        ),
        SmokeCommand(
            "mash_handler_deep_trace.py",
            "a03_a04_only",
            [sys.executable, "scripts/mash_handler_deep_trace.py"],
            [
                "docs/mash_handler_deep_trace.csv",
                "docs/mash_handler_deep_trace_summary.csv",
                "docs/mash_handler_deep_trace_analysis.md",
            ],
            "branch/module-specific MASH deep trace",
        ),
        SmokeCommand(
            "zone_output_deep_trace.py",
            "a03_a04_only",
            [sys.executable, "scripts/zone_output_deep_trace.py"],
            [
                "docs/zone_output_deep_trace.csv",
                "docs/zone_output_deep_trace_summary.csv",
                "docs/zone_output_deep_trace_analysis.md",
            ],
            "branch-specific zone/output deep trace",
        ),
        SmokeCommand(
            "state_mode_logic_analyzer.py",
            "a03_a04_only",
            [sys.executable, "scripts/state_mode_logic_analyzer.py"],
            [
                "docs/sensor_state_candidates.csv",
                "docs/zone_state_mode_candidates.csv",
                "docs/extinguishing_output_gating_chains.csv",
                "docs/state_mode_logic_analysis.md",
            ],
            "sensor/zone state-machine and auto/manual output gating analysis",
        ),
        SmokeCommand(
            "auto_manual_gating_deep_trace.py",
            "a03_a04_only",
            [sys.executable, "scripts/auto_manual_gating_deep_trace.py"],
            [
                "docs/auto_manual_gating_deep_trace.csv",
                "docs/auto_manual_gating_deep_trace_summary.csv",
                "docs/auto_manual_gating_deep_trace_analysis.md",
            ],
            "branch-specific deep trace for manual/auto gating chain 0x497A->0x737C->0x613C->0x84A6->0x728A->0x6833->0x5A7F",
        ),
        SmokeCommand(
            "zone_output_logic_analyzer.py",
            "all_firmwares",
            [sys.executable, "scripts/zone_output_logic_analyzer.py"],
            [
                "docs/zone_logic_candidates.csv",
                "docs/output_control_candidates.csv",
                "docs/zone_to_output_chains.csv",
                "docs/zone_output_logic_analysis.md",
            ],
            "module/zone/output-control semantic analysis",
        ),
        SmokeCommand(
            "runtime_state_machine_reconstructor.py",
            "a03_a04_only",
            [sys.executable, "scripts/runtime_state_machine_reconstructor.py"],
            [
                "docs/runtime_state_machine_nodes.csv",
                "docs/runtime_state_machine_edges.csv",
                "docs/xdata_state_mode_flag_map.csv",
                "docs/runtime_branch_comparison.csv",
                "docs/runtime_state_machine_reconstruction.md",
            ],
            "large runtime state-machine reconstruction / 90CYE_DKS",
        ),
        SmokeCommand(
            "state_enum_and_techdoc_reconstructor.py",
            "a03_a04_only",
            [sys.executable, "scripts/state_enum_and_techdoc_reconstructor.py"],
            [
                "docs/xdata_lifecycle_map.csv",
                "docs/state_enum_hypotheses.csv",
                "docs/auto_manual_mode_hypotheses.csv",
                "docs/output_action_map.csv",
                "docs/state_machine_branch_comparison.csv",
                "docs/bench_validation_matrix.csv",
                "docs/state_enum_and_techdoc_reconstruction.md",
            ],
            "large orchestrated reconstruction for state/mode enums and technical documentation",
        ),
        SmokeCommand(
            "xdata_enum_branch_resolver.py",
            "a03_a04_only",
            [sys.executable, "scripts/xdata_enum_branch_resolver.py"],
            [
                "docs/xdata_branch_trace_map.csv",
                "docs/enum_branch_value_map.csv",
                "docs/manual_auto_branch_map.csv",
                "docs/output_transition_map.csv",
                "docs/xdata_lifecycle_map.csv",
                "docs/state_enum_hypotheses.csv",
                "docs/auto_manual_mode_hypotheses.csv",
                "docs/output_action_map.csv",
                "docs/xdata_enum_branch_resolution.md",
            ],
            "deep follow-up resolver for XDATA lifecycle, enum values and manual/auto/output branch evidence",
        ),
        SmokeCommand(
            "firmware_module_architecture_analyzer.py",
            "all_firmwares",
            [sys.executable, "scripts/firmware_module_architecture_analyzer.py"],
            [
                "docs/firmware_architecture_matrix.csv",
                "docs/shared_core_function_map.csv",
                "docs/module_presence_matrix.csv",
                "docs/mvk_output_semantics.csv",
                "docs/aerosol_line_supervision_candidates.csv",
                "docs/input_board_presence_matrix.csv",
                "docs/cross_firmware_pattern_summary.csv",
                "docs/mds_mup_module_candidates.csv",
                "docs/firmware_module_architecture_comparison.md",
            ],
            "full cross-firmware module architecture analyzer and comparison report",
        ),
        SmokeCommand(
            "dks_module_deep_trace.py",
            "dks_module_followup",
            [sys.executable, "scripts/dks_module_deep_trace.py"],
            [
                "docs/dks_module_deep_trace_candidates.csv",
                "docs/dks_module_slot_summary.csv",
                "docs/dks_module_deep_trace_analysis.md",
            ],
            "deep-trace mapping of screen-confirmed DKS module slots to static code-level handler candidates",
        ),
        SmokeCommand(
            "manual_dks_module_decompiler.py",
            "dks_module_followup",
            [sys.executable, "scripts/manual_dks_module_decompiler.py"],
            [
                "docs/manual_dks_module_decompile.md",
                "docs/manual_dks_module_decompile_summary.csv",
                "docs/manual_dks_module_pseudocode.csv",
            ],
            "semi-manual DKS decompile follow-up report plus machine-readable summary and pseudocode CSVs",
        ),
    ]

    rows: list[dict[str, str]] = []
    for item in commands:
        cmd = item.command
        if item.script == "py_compile":
            rc, output = run_command(["bash", "-lc", f"{sys.executable} -m py_compile scripts/*.py"], ROOT)
            command_text = f"{sys.executable} -m py_compile scripts/*.py"
        else:
            rc, output = run_command(cmd, ROOT)
            command_text = " ".join(cmd)

        missing = [path for path in item.output_files if not (ROOT / path).exists()]
        status = "pass" if rc == 0 and not missing else "fail"
        notes = item.notes
        if missing:
            notes = f"{notes}; missing outputs: {', '.join(missing)}"
        if output:
            short = " ".join(output.splitlines()[-2:])
            notes = f"{notes}; output_tail={short[:220]}"

        rows.append(
            {
                "script": item.script,
                "scope": item.scope,
                "command": command_text,
                "status": status,
                "exit_code": str(rc),
                "output_files": ";".join(item.output_files),
                "notes": notes,
            }
        )

    args.results.parent.mkdir(parents=True, exist_ok=True)
    with args.results.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["script", "scope", "command", "status", "exit_code", "output_files", "notes"],
        )
        writer.writeheader()
        writer.writerows(rows)

    failed = sum(1 for row in rows if row["status"] != "pass")
    print(f"Wrote smoke test results: {args.results.relative_to(ROOT)}")
    print(f"Total commands: {len(rows)}; failed: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
