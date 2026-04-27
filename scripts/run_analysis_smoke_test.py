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
            "integrate_project_scan_extraction.py",
            "documentation_seed",
            [sys.executable, "scripts/integrate_project_scan_extraction.py"],
            [
                "docs/extracted/project_scan_report_v0_1.md",
                "docs/extracted/ppkp_90CYE01_logic.md",
                "docs/extracted/ppkp_90CYE01_mds_water_extinguishing.md",
                "docs/extracted/ppkp_90CYE02_valves.md",
                "docs/extracted/ppkp_90CYE03_90CYE04_aerosol.md",
                "docs/extracted/terminals_90CYE01_mds.md",
                "docs/extracted/states_enum_candidates.md",
                "docs/extracted/firmware_search_targets.md",
                "docs/extracted/spec_69_1ES_AFP_SA_001.md",
                "docs/extracted/spec_69_1ES_AFP_SA_002.md",
                "docs/extracted/ppkp_devices.yaml",
                "docs/extracted/project_to_firmware_linkage.csv",
                "docs/extracted/project_unknowns.csv",
                "docs/extracted/project_evidence_confidence_impact.csv",
            ],
            "project scan extraction integration layer generator using user-supplied structured report data",
        ),
        SmokeCommand(
            "project_guided_rs485_analyzer.py",
            "project_guided_static",
            [sys.executable, "scripts/project_guided_rs485_analyzer.py"],
            [
                "docs/project_guided_rs485_analysis.md",
                "docs/project_guided_rs485_candidates.csv",
                "docs/project_guided_crc_checksum_candidates.csv",
                "docs/project_guided_address_timeout_candidates.csv",
            ],
            "project-constrained RS-485 static analysis",
        ),
        SmokeCommand(
            "project_guided_enum_delay_interlock_analyzer.py",
            "project_guided_static",
            [sys.executable, "scripts/project_guided_enum_delay_interlock_analyzer.py"],
            [
                "docs/project_guided_enum_delay_interlock_analysis.md",
                "docs/project_guided_enum_mapping_candidates.csv",
                "docs/project_guided_delay_candidates.csv",
                "docs/project_guided_door_auto_mode_candidates.csv",
                "docs/project_guided_warning_output_candidates.csv",
            ],
            "project-guided enum/delay/interlock static analysis",
        ),
        SmokeCommand(
            "project_guided_mds_mvk_valve_output_analyzer.py",
            "project_guided_static",
            [sys.executable, "scripts/project_guided_mds_mvk_valve_output_analyzer.py"],
            [
                "docs/project_guided_mds_mvk_valve_output_analysis.md",
                "docs/project_guided_mds_input_candidates.csv",
                "docs/project_guided_mvk_output_candidates.csv",
                "docs/project_guided_valve_feedback_candidates.csv",
                "docs/project_guided_aerosol_output_candidates.csv",
                "docs/project_guided_mup_pvk_evidence_split.csv",
            ],
            "project-guided physical IO/static narrowing",
        ),
        SmokeCommand(
            "project_guided_static_summary_builder.py",
            "project_guided_static",
            [sys.executable, "scripts/project_guided_static_summary_builder.py"],
            [
                "docs/project_guided_static_analysis_summary.md",
                "docs/project_guided_confidence_updates.csv",
                "docs/project_guided_next_static_targets.csv",
                "docs/project_guided_remaining_unknowns_v2.csv",
            ],
            "project-guided consolidated summary",
        ),
        SmokeCommand(
            "project_guided_micro_decompiler.py",
            "project_guided_static",
            [sys.executable, "scripts/project_guided_micro_decompiler.py"],
            [
                "docs/project_guided_micro_decompile.md",
                "docs/project_guided_micro_decompile_summary.csv",
                "docs/project_guided_micro_pseudocode.csv",
                "docs/project_guided_micro_constants.csv",
                "docs/project_guided_micro_xdata_flow.csv",
                "docs/project_guided_micro_unknowns_update.csv",
            ],
            "project-guided focused micro-decompile pass over top static targets",
        ),
        SmokeCommand(
            "project_guided_micro_decompiler_pass2.py",
            "project_guided_static",
            [sys.executable, "scripts/project_guided_micro_decompiler_pass2.py"],
            [
                "docs/project_guided_micro_decompile_pass2.md",
                "docs/project_guided_micro_pass2_summary.csv",
                "docs/project_guided_micro_pass2_pseudocode.csv",
                "docs/project_guided_micro_pass2_constants.csv",
                "docs/project_guided_micro_pass2_xdata_flow.csv",
                "docs/project_guided_micro_pass2_callsite_matrix.csv",
                "docs/project_guided_micro_pass2_unknowns_update.csv",
            ],
            "project-guided micro-decompile pass #2 over follow-up target set",
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
        SmokeCommand(
            "manual_dks_downstream_decompiler.py",
            "dks_module_followup",
            [sys.executable, "scripts/manual_dks_downstream_decompiler.py"],
            [
                "docs/manual_dks_downstream_decompile.md",
                "docs/manual_dks_downstream_decompile_summary.csv",
                "docs/manual_dks_downstream_pseudocode.csv",
            ],
            "semi-manual downstream DKS decompile follow-up report plus machine-readable summary and pseudocode CSVs",
        ),
        SmokeCommand(
            "dks_xdata_lifecycle_reconstructor.py",
            "dks_module_followup",
            [sys.executable, "scripts/dks_xdata_lifecycle_reconstructor.py"],
            [
                "docs/dks_xdata_lifecycle_analysis.md",
                "docs/dks_xdata_lifecycle_matrix.csv",
                "docs/dks_xdata_function_roles.csv",
                "docs/dks_xdata_bench_probe_plan.csv",
            ],
            "focused DKS XDATA lifecycle reconstruction for zone/object state, mode flags and packet context",
        ),
        SmokeCommand(
            "dks_enum_state_reconstructor.py",
            "dks_module_followup",
            [sys.executable, "scripts/dks_enum_state_reconstructor.py"],
            [
                "docs/dks_enum_state_reconstruction.md",
                "docs/dks_enum_state_matrix.csv",
                "docs/dks_enum_state_transition_candidates.csv",
            ],
            "DKS enum/state value reconstruction and transition candidates",
        ),
        SmokeCommand(
            "dks_packet_export_reconstructor.py",
            "dks_module_followup",
            [sys.executable, "scripts/dks_packet_export_reconstructor.py"],
            [
                "docs/dks_packet_export_reconstruction.md",
                "docs/dks_packet_export_callsite_matrix.csv",
                "docs/dks_packet_context_xdata_matrix.csv",
                "docs/dks_packet_format_hypothesis.csv",
            ],
            "DKS packet/export path reconstruction around 0x5A7F and packet context XDATA",
        ),
        SmokeCommand(
            "dks_output_action_reconstructor.py",
            "dks_module_followup",
            [sys.executable, "scripts/dks_output_action_reconstructor.py"],
            [
                "docs/dks_output_action_reconstruction.md",
                "docs/dks_output_action_matrix.csv",
                "docs/dks_output_start_path_trace.csv",
                "docs/dks_output_action_bench_tests.csv",
            ],
            "DKS output/start action reconstruction for 0x6833/0x597F/0x7922/0x7DC2",
        ),
        SmokeCommand(
            "dks_module_handler_attribution.py",
            "dks_module_followup",
            [sys.executable, "scripts/dks_module_handler_attribution.py"],
            [
                "docs/dks_module_handler_attribution.md",
                "docs/dks_module_handler_attribution_matrix.csv",
                "docs/dks_module_unresolved_handlers.csv",
            ],
            "DKS slot-label to handler attribution refinement with unresolved matrix",
        ),
        SmokeCommand(
            "dks_final_techdoc_builder.py",
            "dks_module_followup",
            [sys.executable, "scripts/dks_final_techdoc_builder.py"],
            [
                "docs/dks_firmware_technical_reconstruction_v1.md",
                "docs/dks_reconstruction_confidence_dashboard.csv",
                "docs/dks_remaining_unknowns.csv",
                "docs/dks_next_iteration_plan.csv",
            ],
            "consolidated DKS technical reconstruction v1 report and confidence/unknown/plan dashboards",
        ),
        SmokeCommand(
            "dks_runtime_validation_planner.py",
            "dks_module_followup",
            [sys.executable, "scripts/dks_runtime_validation_planner.py"],
            [
                "docs/dks_runtime_validation_plan_v1.md",
                "docs/dks_runtime_validation_matrix.csv",
                "docs/dks_xdata_watchlist_v2.csv",
                "docs/dks_function_watchlist_v2.csv",
                "docs/dks_packet_capture_schema.csv",
                "docs/dks_io_capture_schema.csv",
                "docs/dks_bench_result_import_template.csv",
                "docs/dks_validation_confidence_uplift.csv",
                "docs/dks_v1_to_v2_validation_roadmap.md",
            ],
            "consolidated DKS runtime/bench validation planning package and schema templates",
        ),
        SmokeCommand(
            "cross_family_function_analog_mapper.py",
            "cross_family_static_v1",
            [sys.executable, "scripts/cross_family_function_analog_mapper.py"],
            [
                "docs/cross_family_function_analogs.md",
                "docs/cross_family_function_analogs.csv",
                "docs/cross_family_unmatched_dks_functions.csv",
            ],
            "cross-family mapping of DKS reference functions to structural analogs",
        ),
        SmokeCommand(
            "cross_family_xdata_schema_mapper.py",
            "cross_family_static_v1",
            [sys.executable, "scripts/cross_family_xdata_schema_mapper.py"],
            [
                "docs/cross_family_xdata_schema_map.md",
                "docs/cross_family_xdata_schema_map.csv",
                "docs/cross_family_xdata_unresolved.csv",
            ],
            "cross-family mapping of DKS XDATA clusters to conserved/shifted/family-specific candidates",
        ),
        SmokeCommand(
            "cross_family_packet_output_comparator.py",
            "cross_family_static_v1",
            [sys.executable, "scripts/cross_family_packet_output_comparator.py"],
            [
                "docs/cross_family_packet_output_comparison.md",
                "docs/cross_family_packet_bridge_candidates.csv",
                "docs/cross_family_output_action_candidates.csv",
                "docs/cross_family_packet_format_variants.csv",
            ],
            "cross-family packet/export and output-action structural comparison",
        ),
        SmokeCommand(
            "cross_family_enum_state_comparator.py",
            "cross_family_static_v1",
            [sys.executable, "scripts/cross_family_enum_state_comparator.py"],
            [
                "docs/cross_family_enum_state_comparison.md",
                "docs/cross_family_enum_state_matrix.csv",
                "docs/cross_family_enum_state_divergences.csv",
            ],
            "cross-family enum/state value vocabulary comparison",
        ),
        SmokeCommand(
            "cross_family_module_semantics_reporter.py",
            "cross_family_static_v1",
            [sys.executable, "scripts/cross_family_module_semantics_reporter.py"],
            [
                "docs/cross_family_module_semantics.md",
                "docs/cross_family_module_semantics_matrix.csv",
                "docs/cross_family_module_semantics_unknowns.csv",
            ],
            "cross-family consolidated module semantics map with confidence and unknowns",
        ),
        SmokeCommand(
            "cross_family_static_reconstruction_builder.py",
            "cross_family_static_v1",
            [sys.executable, "scripts/cross_family_static_reconstruction_builder.py"],
            [
                "docs/cross_family_static_reconstruction_v1.md",
                "docs/cross_family_confidence_dashboard.csv",
                "docs/cross_family_remaining_unknowns.csv",
                "docs/cross_family_next_static_plan.csv",
            ],
            "final cross-family static reconstruction v1 builder",
        ),
        SmokeCommand(
            "a03_a04_packet_bridge_deepener.py",
            "cross_family_static_v1_1",
            [sys.executable, "scripts/a03_a04_packet_bridge_deepener.py"],
            [
                "docs/a03_a04_packet_bridge_deepening.md",
                "docs/a03_a04_packet_bridge_candidates_v2.csv",
                "docs/a03_a04_packet_context_matrix.csv",
                "docs/a03_a04_packet_callsite_trace_v2.csv",
            ],
            "A03/A04 packet bridge adjacency deepening (family-local semantics only)",
        ),
        SmokeCommand(
            "shifted_v2_xdata_offset_validator.py",
            "cross_family_static_v1_1",
            [sys.executable, "scripts/shifted_v2_xdata_offset_validator.py"],
            [
                "docs/shifted_v2_xdata_offset_validation.md",
                "docs/shifted_v2_xdata_offset_matrix.csv",
                "docs/shifted_v2_function_anchor_map.csv",
                "docs/shifted_v2_schema_divergence.csv",
            ],
            "Shifted_DKS/v2_1 XDATA cluster offset/divergence validation",
        ),
        SmokeCommand(
            "rtos_service_chain_decompiler.py",
            "cross_family_static_v1_1",
            [sys.executable, "scripts/rtos_service_chain_decompiler.py"],
            [
                "docs/rtos_service_chain_decompile_v1.md",
                "docs/rtos_service_chain_summary.csv",
                "docs/rtos_service_pseudocode.csv",
                "docs/rtos_service_family_comparison.csv",
            ],
            "RTOS_service family-specific chain decompile summary",
        ),
        SmokeCommand(
            "cross_family_static_deepening_builder.py",
            "cross_family_static_v1_1",
            [sys.executable, "scripts/cross_family_static_deepening_builder.py"],
            [
                "docs/cross_family_static_deepening_v1.md",
                "docs/cross_family_static_deepening_dashboard.csv",
                "docs/cross_family_deep_targets_next.csv",
                "docs/cross_family_confidence_updates.csv",
            ],
            "Cross-family static deepening v1 milestone builder",
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
