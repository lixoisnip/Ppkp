#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

INPUT_FILES = [
    "runtime_state_machine_reconstruction.md",
    "runtime_state_machine_nodes.csv",
    "runtime_state_machine_edges.csv",
    "xdata_state_mode_flag_map.csv",
    "runtime_branch_comparison.csv",
    "auto_manual_gating_deep_trace.csv",
    "auto_manual_gating_deep_trace_summary.csv",
    "auto_manual_gating_deep_trace_analysis.md",
    "state_mode_logic_analysis.md",
    "sensor_state_candidates.csv",
    "zone_state_mode_candidates.csv",
    "extinguishing_output_gating_chains.csv",
    "zone_output_deep_trace.csv",
    "zone_output_deep_trace_summary.csv",
    "zone_output_deep_trace_analysis.md",
    "zone_logic_candidates.csv",
    "output_control_candidates.csv",
    "zone_to_output_chains.csv",
    "mash_handler_deep_trace.csv",
    "mash_handler_deep_trace_summary.csv",
    "mash_handler_deep_trace_analysis.md",
    "function_map.csv",
    "basic_block_map.csv",
    "disassembly_index.csv",
    "call_xref.csv",
    "xdata_confirmed_access.csv",
    "code_table_candidates.csv",
    "string_index.csv",
    "xdata_map_by_branch.csv",
]

MANDATORY_XDATA = ["0x30EA..0x30F9", "0x315B", "0x3165", "0x31BF", "0x364B"]
PRIMARY_CHAIN = ["0x497A", "0x737C", "0x613C", "0x84A6", "0x728A", "0x6833", "0x5A7F"]
PRIMARY_BRANCH = "90CYE_DKS"
PRIMARY_FILE = "90CYE03_19_DKS.PZU"
PRIMARY_BRANCH_FILES = {"90CYE03_19_DKS.PZU", "90CYE04_19_DKS.PZU"}
COMPARE_FILES = [
    "90CYE03_19_DKS.PZU",
    "90CYE04_19_DKS.PZU",
    "90CYE02_27 DKS.PZU",
    "A03_26.PZU",
    "A04_28.PZU",
    "ppkp2001 90cye01.PZU",
]


def load_csv(path: Path, warnings: list[str]) -> list[dict[str, str]]:
    if not path.exists():
        warnings.append(f"missing file: {path.relative_to(ROOT)}")
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_text(path: Path, warnings: list[str]) -> str:
    if not path.exists():
        warnings.append(f"missing file: {path.relative_to(ROOT)}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def uniq(xs: list[str]) -> str:
    return "; ".join(sorted({x for x in xs if x})) or "-"


def classify_confidence(score: float) -> str:
    if score >= 0.75:
        return "probable"
    if score >= 0.45:
        return "low"
    return "hypothesis"


def xdata_match(target: str, addr: str) -> bool:
    if not addr:
        return False
    if ".." not in target:
        return addr.upper() == target.upper()
    lo, hi = target.split("..", 1)
    try:
        value = int(addr, 16)
        return int(lo, 16) <= value <= int(hi, 16)
    except ValueError:
        return False


def main() -> int:
    p = argparse.ArgumentParser(description="Reconstruct state/mode enum hypotheses and technical model")
    p.add_argument("--out-xdata", type=Path, default=DOCS / "xdata_lifecycle_map.csv")
    p.add_argument("--out-enum", type=Path, default=DOCS / "state_enum_hypotheses.csv")
    p.add_argument("--out-mode", type=Path, default=DOCS / "auto_manual_mode_hypotheses.csv")
    p.add_argument("--out-output", type=Path, default=DOCS / "output_action_map.csv")
    p.add_argument("--out-branch", type=Path, default=DOCS / "state_machine_branch_comparison.csv")
    p.add_argument("--out-bench", type=Path, default=DOCS / "bench_validation_matrix.csv")
    p.add_argument("--out-md", type=Path, default=DOCS / "state_enum_and_techdoc_reconstruction.md")
    args = p.parse_args()

    warnings: list[str] = []
    for fn in INPUT_FILES:
        fp = DOCS / fn
        if fn.endswith(".md"):
            load_text(fp, warnings)
        else:
            load_csv(fp, warnings)

    function_map = load_csv(DOCS / "function_map.csv", warnings)
    call_xref = load_csv(DOCS / "call_xref.csv", warnings)
    xacc = load_csv(DOCS / "xdata_confirmed_access.csv", warnings)
    xmap = load_csv(DOCS / "xdata_state_mode_flag_map.csv", warnings)
    sensor = load_csv(DOCS / "sensor_state_candidates.csv", warnings)
    zone = load_csv(DOCS / "zone_state_mode_candidates.csv", warnings)
    outc = load_csv(DOCS / "output_control_candidates.csv", warnings)
    zchains = load_csv(DOCS / "zone_to_output_chains.csv", warnings)
    deep = load_csv(DOCS / "auto_manual_gating_deep_trace.csv", warnings)
    bcmp = load_csv(DOCS / "runtime_branch_comparison.csv", warnings)

    # XDATA lifecycle map
    xdata_rows: list[dict[str, str]] = []
    roles = defaultdict(list)
    for r in xmap:
        addr = r.get("xdata_addr", "")
        roles[(r.get("branch", ""), r.get("file", ""), addr)].append(r.get("role_candidate", ""))

    for target in MANDATORY_XDATA:
        src = [
            r
            for r in xacc
            if r.get("branch", "") == PRIMARY_BRANCH
            and r.get("file", "") in PRIMARY_BRANCH_FILES
            and xdata_match(target, r.get("xdata_addr", ""))
        ]
        by_bf: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        for r in src:
            by_bf[(r.get("branch", ""), r.get("file", ""))].append(r)
        if not by_bf:
            for fallback_file in sorted(PRIMARY_BRANCH_FILES):
                by_bf[(PRIMARY_BRANCH, fallback_file)] = []

        for (branch, file), rows in by_bf.items():
            reads = [r.get("function_addr", "") for r in rows if "read" in (r.get("access_type", "") or "").lower()]
            writes = [r.get("function_addr", "") for r in rows if "write" in (r.get("access_type", "") or "").lower()]
            branches = [r.get("function_addr", "") for r in rows if "branch" in (r.get("notes", "") or "").lower()]
            exports = [r.get("function_addr", "") for r in rows if "packet" in (r.get("notes", "") or "").lower() or r.get("function_addr", "") in {"0x5A7F", "0x6833"}]
            total = len(rows) or 1
            score = (len(set(reads)) * 0.25 + len(set(writes)) * 0.3 + len(set(exports)) * 0.25 + len(set(branches)) * 0.2) / max(total * 0.35, 1)
            xdata_rows.append(
                {
                    "branch": branch,
                    "file": file,
                    "xdata_addr": target,
                    "range_group": "state_cluster" if target == "0x30EA..0x30F9" else "mode_or_output_flags",
                    "read_functions": uniq(reads),
                    "write_functions": uniq(writes),
                    "branch_functions": uniq(branches),
                    "export_functions": uniq(exports),
                    "probable_role": uniq(roles.get((branch, file, target), [])) if target != "0x30EA..0x30F9" else "sensor_or_zone_state_cluster",
                    "confidence": classify_confidence(min(score, 1.0)),
                    "evidence_sources": "xdata_confirmed_access.csv; xdata_state_mode_flag_map.csv",
                    "notes": "write-before-read order is static-only and partial",
                }
            )

    # State enum hypotheses
    enum_rows: list[dict[str, str]] = []
    seen_enum = set()
    for r in sensor:
        if r.get("file") not in PRIMARY_BRANCH_FILES:
            continue
        key = ("sensor", r.get("file", ""), r.get("state_candidate", ""), r.get("function_addr", ""), r.get("mnemonic", ""), r.get("operands", ""))
        if key in seen_enum:
            continue
        seen_enum.add(key)
        enum_rows.append(
            {
                "branch": r.get("branch", ""),
                "file": r.get("file", ""),
                "state_scope": "sensor",
                "state_name": r.get("state_candidate", "unknown"),
                "candidate_value": r.get("enum_value_hex", "") or "-",
                "candidate_bit": "-",
                "xdata_addr": r.get("xdata_addr", "") or "0x30EA..0x30F9",
                "function_addr": r.get("function_addr", ""),
                "branch_evidence": r.get("mnemonic", "") + " " + r.get("operands", ""),
                "downstream_path": "0x497A->0x737C->0x613C->0x84A6->0x728A",
                "confidence": r.get("confidence", "hypothesis"),
                "notes": r.get("notes", ""),
            }
        )
    for r in zone:
        if r.get("branch") != PRIMARY_BRANCH or r.get("file") not in PRIMARY_BRANCH_FILES:
            continue
        key = ("zone", r.get("file", ""), r.get("zone_state_candidate", ""), r.get("function_addr", ""), r.get("mnemonic", ""), r.get("operands", ""))
        if key in seen_enum:
            continue
        seen_enum.add(key)
        enum_rows.append(
            {
                "branch": r.get("branch", ""),
                "file": r.get("file", ""),
                "state_scope": "zone",
                "state_name": r.get("zone_state_candidate", "unknown"),
                "candidate_value": r.get("enum_value_hex", "") or "-",
                "candidate_bit": "-",
                "xdata_addr": r.get("xdata_addr", "") or "0x30EA..0x30F9",
                "function_addr": r.get("function_addr", ""),
                "branch_evidence": r.get("mnemonic", "") + " " + r.get("operands", ""),
                "downstream_path": "0x737C->0x613C->0x84A6->0x728A",
                "confidence": r.get("confidence", "hypothesis"),
                "notes": r.get("notes", ""),
            }
        )

    # auto/manual hypotheses
    mode_rows: list[dict[str, str]] = []
    seen_mode = set()
    for r in deep:
        if r.get("file") not in PRIMARY_BRANCH_FILES:
            continue
        fn = r.get("function_addr", "")
        if fn not in {"0x84A6", "0x728A", "0x6833"}:
            continue
        mode_key = (r.get("branch", ""), r.get("file", ""), fn)
        if mode_key in seen_mode:
            continue
        seen_mode.add(mode_key)
        mode_rows.append(
            {
                "branch": r.get("branch", ""),
                "file": r.get("file", ""),
                "xdata_addr": "0x315B",
                "function_addr": fn,
                "candidate_manual_value": "0x01",
                "candidate_auto_value": "0x00",
                "candidate_manual_bit": "bit0",
                "candidate_auto_bit": "bit0=0",
                "manual_path": "event + packet only -> 0x5A7F",
                "auto_path": "0x6833 output start -> 0x5A7F",
                "manual_confidence": "probable" if fn in {"0x84A6", "0x728A"} else "low",
                "auto_confidence": "probable" if fn in {"0x728A", "0x6833"} else "low",
                "notes": "value mapping is static hypothesis until bench validation",
            }
        )

    # output action map
    output_rows: list[dict[str, str]] = []
    for r in outc:
        fn = r.get("function_addr", "")
        role = (r.get("role_candidate", "") or "").lower()
        action = "unknown_output_action"
        phys = "unknown"
        if fn == "0x6833" or "relay" in role or "output" in role:
            action, phys = "output_start", "relay_or_extinguishing_actuator"
        elif fn == "0x5A7F" or "packet" in role:
            action, phys = "packet_export", "telemetry"
        elif fn == "0x613C":
            action, phys = "output_feedback", "feedback_sampler"
        elif "valve" in role:
            action, phys = "valve_control", "valve"
        elif "siren" in role:
            action, phys = "siren_control", "siren"
        output_rows.append(
            {
                "branch": r.get("branch", ""),
                "file": r.get("file", ""),
                "function_addr": fn,
                "action_candidate": action,
                "score": r.get("score", "0"),
                "confidence": r.get("confidence", "hypothesis"),
                "xdata_reads": r.get("xdata_read_count", "0"),
                "xdata_writes": r.get("xdata_write_count", "0"),
                "related_mode_function": "0x728A" if fn in {"0x6833", "0x5A7F", "0x613C"} else "-",
                "related_packet_function": "0x5A7F" if fn != "0x5A7F" else "self",
                "possible_physical_action": phys,
                "notes": r.get("notes", ""),
            }
        )

    # branch comparison
    branch_rows: list[dict[str, str]] = []
    seen = set()
    for r in bcmp:
        key = (r.get("comparison_branch", ""), r.get("comparison_file", ""), r.get("comparison_function", ""))
        if key in seen:
            continue
        seen.add(key)
        branch_rows.append(
            {
                "primary_branch": PRIMARY_BRANCH,
                "primary_file": PRIMARY_FILE,
                "primary_role": "runtime_state_machine",
                "primary_function": r.get("function_addr", "") or "0x737C",
                "comparison_branch": r.get("comparison_branch", ""),
                "comparison_file": r.get("comparison_file", ""),
                "comparison_function": r.get("comparison_function", ""),
                "match_type": r.get("match_type", "similar_call_chain") or "similar_call_chain",
                "confidence": r.get("confidence", "low") or "low",
                "notes": r.get("notes", "") or "checksum-limited evidence for non-identical images",
            }
        )

    # bench matrix
    scenarios = [
        "sensor normal", "sensor blocked", "sensor not detected", "address conflict", "one detector fire", "two detector fire",
        "zone attention", "zone fire", "zone fault", "zone disabled", "manual mode fire", "auto mode fire",
        "output start", "output feedback", "output reset/stop",
    ]
    bench_rows: list[dict[str, str]] = []
    for i, sc in enumerate(scenarios, 1):
        is_auto = "auto" in sc or "output" in sc
        bench_rows.append(
            {
                "test_id": f"BM-{i:02d}",
                "scenario": sc,
                "expected_manual_behavior": "event+packet only" if "fire" in sc else "state report only",
                "expected_auto_behavior": "event+output+packet" if is_auto or "fire" in sc else "state report",
                "expected_xdata_changes": "0x30EA..0x30F9 + 0x315B + output flags(0x3165/0x31BF/0x364B)",
                "expected_output_behavior": "no start in manual" if "manual" in sc else ("start/feedback/reset depending on scenario"),
                "expected_packet_behavior": "packet export via 0x5A7F",
                "functions_to_watch": " -> ".join(PRIMARY_CHAIN),
                "confidence": "low" if "blocked" in sc or "not detected" in sc else "probable",
                "notes": "bench required; static-only inference",
            }
        )

    write_csv(args.out_xdata, [
        "branch", "file", "xdata_addr", "range_group", "read_functions", "write_functions", "branch_functions", "export_functions", "probable_role", "confidence", "evidence_sources", "notes"
    ], xdata_rows)
    write_csv(args.out_enum, [
        "branch", "file", "state_scope", "state_name", "candidate_value", "candidate_bit", "xdata_addr", "function_addr", "branch_evidence", "downstream_path", "confidence", "notes"
    ], enum_rows)
    write_csv(args.out_mode, [
        "branch", "file", "xdata_addr", "function_addr", "candidate_manual_value", "candidate_auto_value", "candidate_manual_bit", "candidate_auto_bit", "manual_path", "auto_path", "manual_confidence", "auto_confidence", "notes"
    ], mode_rows)
    write_csv(args.out_output, [
        "branch", "file", "function_addr", "action_candidate", "score", "confidence", "xdata_reads", "xdata_writes", "related_mode_function", "related_packet_function", "possible_physical_action", "notes"
    ], output_rows)
    write_csv(args.out_branch, [
        "primary_branch", "primary_file", "primary_role", "primary_function", "comparison_branch", "comparison_file", "comparison_function", "match_type", "confidence", "notes"
    ], branch_rows)
    write_csv(args.out_bench, [
        "test_id", "scenario", "expected_manual_behavior", "expected_auto_behavior", "expected_xdata_changes", "expected_output_behavior", "expected_packet_behavior", "functions_to_watch", "confidence", "notes"
    ], bench_rows)

    lines = [
        "# State enum + technical documentation reconstruction (large milestone)",
        "Дата: 2026-04-26 (UTC).",
        "",
        "## 1. What is known now",
        "Runtime chain for 90CYE_DKS remains stable: `0x497A -> 0x737C -> 0x613C -> 0x84A6 -> 0x728A -> (manual:event+packet | auto:0x6833 output) -> 0x5A7F`.",
        "",
        "## 2. Strongest XDATA flags",
        "- `0x30EA..0x30F9`: sensor/zone state cluster (probable).",
        "- `0x315B`: manual/auto mode gate candidate (probable).",
        "- `0x3165`, `0x31BF`, `0x364B`: output/packet side flags (low..probable).",
        "",
        "## 3. State enum hypotheses",
        "Sensor hypotheses: normal/blocked/disabled/not_detected/communication_error/address_conflict/fire_alarm/fault.",
        "Zone hypotheses: normal/attention/fire/alarm/fault/disabled/blocked.",
        "Value-bit mapping remains static hypothesis until bench verification.",
        "",
        "## 4. Manual vs auto",
        "Current model: manual path exports event+packet without output start; auto path reaches `0x6833` then exports via `0x5A7F`.",
        "",
        "## 5. Output action map",
        "`0x6833` strongest output_start candidate, `0x613C` feedback-adjacent, `0x5A7F` packet export node.",
        "",
        "## 6. APS/manual vs extinguishing/auto",
        "APS/manual behaves as signaling/report path; extinguishing/auto adds actuator/output branch before packet export.",
        "",
        "## 7. Packet/export role",
        "Packet/export is modeled as common sink for both manual and auto branches; used as observable confirmation channel.",
        "",
        "## 8. Cross-branch matching",
        "Use `docs/state_machine_branch_comparison.csv` to separate same-address vs same-role vs similar-chain matches. Do not assume address identity between branches.",
        "",
        "## 9. Confidence scale",
        "- confirmed: structural chain presence and repeated call-flow motifs.",
        "- probable: flag/function role fit with multiple sources.",
        "- hypothesis: value-level mapping requiring bench.",
        "- unknown: unresolved enum bits, timer/interrupt side-effects.",
        "",
        "## 10. Bench validation required",
        "See `docs/bench_validation_matrix.csv` for mandatory scenarios and watch-list functions.",
        "",
        "## 11. Next manual decompile targets",
        "1) `0x84A6` 2) `0x728A` 3) `0x6833` 4) `0x5A7F` 5) branch internals in `0x737C/0x613C`.",
        "",
        "## 12. ASCII model",
        "```text",
        "Sensor state",
        "  -> Zone mapping",
        "  -> Zone state enum",
        "  -> Mode flag check",
        "      -> manual: event + packet only",
        "      -> auto: event + output start + packet",
        "  -> Output feedback",
        "  -> Packet/export",
        "```",
    ]

    if warnings:
        lines += ["", "## Warnings (missing inputs tolerated)"] + [f"- {w}" for w in sorted(set(warnings))]

    args.out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
