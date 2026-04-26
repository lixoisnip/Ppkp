#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

INPUTS = [
    "docs/firmware_manifest.json",
    "docs/firmware_inventory.csv",
    "docs/firmware_family_matrix.csv",
    "docs/vector_entrypoints.csv",
    "docs/xdata_confirmed_access.csv",
    "docs/xdata_map_by_branch.csv",
    "docs/call_targets_summary.csv",
    "docs/function_map.csv",
    "docs/basic_block_map.csv",
    "docs/string_index.csv",
    "docs/script_scope_matrix.csv",
    "docs/analysis_smoke_test_results.csv",
]

SUMMARY_FIELDS = [
    "branch",
    "files",
    "file_count",
    "valid_hex_count",
    "checksum_error_count",
    "avg_similarity_within_branch",
    "entry_vector_pattern",
    "xdata_cluster_summary",
    "function_count",
    "basic_block_count",
    "call_count",
    "string_count",
    "packet_like_function_count",
    "writer_like_function_count",
    "a03_a04_specific_evidence",
    "confidence",
    "notes",
]

PACKET_ROLES = {
    "state_reader_or_packet_builder",
    "service_or_runtime_worker",
    "dispatcher_or_router",
}

BRANCH_ORDER = ["A03_A04", "90CYE_DKS", "90CYE_v2_1", "90CYE_shifted_DKS", "RTOS_service"]


def load_csv(path: Path, warnings: list[str]) -> list[dict[str, str]]:
    if not path.exists():
        warnings.append(f"WARNING: missing input file: {path.relative_to(ROOT)}")
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_json(path: Path, warnings: list[str]) -> dict:
    if not path.exists():
        warnings.append(f"WARNING: missing input file: {path.relative_to(ROOT)}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        warnings.append(f"WARNING: failed to parse json: {path.relative_to(ROOT)}")
        return {}


def parse_int(value: str) -> int:
    try:
        return int((value or "").strip())
    except ValueError:
        return 0


def as_bool(value: str) -> bool:
    return (value or "").strip().lower() in {"true", "1", "yes"}


def confidence_from_coverage(file_count: int, has_similarity: bool, fn_count: int, bb_count: int) -> str:
    score = 0
    if file_count > 0:
        score += 1
    if has_similarity:
        score += 1
    if fn_count > 0:
        score += 1
    if bb_count > 0:
        score += 1
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def recommend_next_branch(rows: list[dict[str, str]]) -> tuple[str, str]:
    candidates = [r for r in rows if r["branch"] != "A03_A04"]
    if not candidates:
        return ("n/a", "Недостаточно данных для выбора следующей ветки.")
    scored = sorted(
        candidates,
        key=lambda r: (
            parse_int(r["file_count"]),
            parse_int(r["packet_like_function_count"]),
            parse_int(r["writer_like_function_count"]),
        ),
        reverse=True,
    )
    best = scored[0]
    reason = (
        f"Ветка {best['branch']} имеет наибольшее покрытие по образцам (files={best['file_count']}) "
        f"и достаточно глобальных структурных кандидатов (packet_like={best['packet_like_function_count']}, "
        f"writer_like={best['writer_like_function_count']})."
    )
    return best["branch"], reason


def main() -> int:
    parser = argparse.ArgumentParser(description="Build global branch comparison report after smoke-test.")
    parser.add_argument("--summary-out", type=Path, default=DOCS / "branch_comparison_summary.csv")
    parser.add_argument("--md-out", type=Path, default=DOCS / "global_branch_comparison.md")
    args = parser.parse_args()

    warnings: list[str] = []
    for rel in INPUTS:
        full = ROOT / rel
        if not full.exists():
            warnings.append(f"WARNING: missing input file: {rel}")

    manifest = load_json(ROOT / "docs/firmware_manifest.json", warnings)
    inventory = load_csv(ROOT / "docs/firmware_inventory.csv", warnings)
    family = load_csv(ROOT / "docs/firmware_family_matrix.csv", warnings)
    vectors = load_csv(ROOT / "docs/vector_entrypoints.csv", warnings)
    _xdata_confirmed = load_csv(ROOT / "docs/xdata_confirmed_access.csv", warnings)
    xdata_by_branch = load_csv(ROOT / "docs/xdata_map_by_branch.csv", warnings)
    call_targets = load_csv(ROOT / "docs/call_targets_summary.csv", warnings)
    function_map = load_csv(ROOT / "docs/function_map.csv", warnings)
    basic_block_map = load_csv(ROOT / "docs/basic_block_map.csv", warnings)
    string_index = load_csv(ROOT / "docs/string_index.csv", warnings)
    _scope_matrix = load_csv(ROOT / "docs/script_scope_matrix.csv", warnings)
    smoke_rows = load_csv(ROOT / "docs/analysis_smoke_test_results.csv", warnings)

    file_to_branch = {row["file"]: row.get("branch", "unknown") for row in inventory if row.get("file")}
    branches = list(BRANCH_ORDER)
    for row in inventory:
        br = row.get("branch", "")
        if br and br not in branches:
            branches.append(br)

    files_by_branch: dict[str, list[str]] = defaultdict(list)
    valid_by_branch: Counter[str] = Counter()
    checksum_by_branch: Counter[str] = Counter()
    for row in inventory:
        branch = row.get("branch", "unknown")
        fname = row.get("file", "")
        if fname:
            files_by_branch[branch].append(fname)
        if as_bool(row.get("valid_hex", "")):
            valid_by_branch[branch] += 1
        checksum_by_branch[branch] += parse_int(row.get("checksum_errors", "0"))

    sim_values: dict[str, list[float]] = defaultdict(list)
    for row in family:
        a = row.get("file_a", "")
        b = row.get("file_b", "")
        ba = file_to_branch.get(a)
        bb = file_to_branch.get(b)
        if not ba or not bb or ba != bb:
            continue
        try:
            sim_values[ba].append(float(row.get("similarity_pct_4000_BFFF", "0") or 0))
        except ValueError:
            continue

    vectors_by_branch: dict[str, Counter[str]] = defaultdict(Counter)
    for row in vectors:
        branch = row.get("branch_hint") or file_to_branch.get(row.get("file", ""), "unknown")
        pattern = "/".join(
            [
                row.get("vector_4000", "?"),
                row.get("vector_4006", "?"),
                row.get("vector_400C", "?"),
                row.get("vector_4012", "?"),
                row.get("vector_4018", "?"),
                row.get("vector_401E", "?"),
            ]
        )
        vectors_by_branch[branch][pattern] += 1

    xdata_summary: dict[str, str] = {}
    xdata_chunks: dict[str, list[str]] = defaultdict(list)
    for row in xdata_by_branch:
        branch = row.get("branch", "unknown")
        tag = row.get("cluster_tag", "unknown")
        start = row.get("address_start", "?")
        end = row.get("address_end", "?")
        conf = row.get("confidence", "unknown")
        xdata_chunks[branch].append(f"{tag}:{start}-{end}({conf})")
    for branch, values in xdata_chunks.items():
        xdata_summary[branch] = "; ".join(values[:5])

    fn_count: Counter[str] = Counter()
    packet_like: Counter[str] = Counter()
    writer_like: Counter[str] = Counter()
    for row in function_map:
        branch = row.get("branch", "unknown")
        fn_count[branch] += 1
        if row.get("role_candidate", "") in PACKET_ROLES:
            packet_like[branch] += 1
        if parse_int(row.get("xdata_write_count", "0")) > 0:
            writer_like[branch] += 1

    bb_count: Counter[str] = Counter(row.get("branch", "unknown") for row in basic_block_map)
    str_count: Counter[str] = Counter(row.get("branch", "unknown") for row in string_index)

    call_count: Counter[str] = Counter()
    for row in call_targets:
        branch = row.get("branch", "unknown")
        call_count[branch] += parse_int(row.get("lcall_count", "0")) + parse_int(row.get("ljmp_count", "0"))

    summary_rows: list[dict[str, str]] = []
    for branch in branches:
        files = sorted(files_by_branch.get(branch, []))
        similarity = sim_values.get(branch, [])
        avg_sim = f"{(sum(similarity) / len(similarity)):.4f}" if similarity else "n/a"

        common_vector = "n/a"
        if vectors_by_branch.get(branch):
            pattern, count = vectors_by_branch[branch].most_common(1)[0]
            common_vector = f"{pattern} (x{count})"

        a03_specific = ""
        notes = []
        if branch == "A03_A04":
            a03_specific = "A03/A04-only: address evidence 0x329C, 0x329D, 0x5003..0x5010; not global."
            notes.append("Contains specialized packet-window hypotheses; keep scoped to A03/A04.")
        else:
            a03_specific = "none"

        conf = confidence_from_coverage(len(files), bool(similarity), fn_count[branch], bb_count[branch])
        if avg_sim == "n/a" and len(files) <= 1:
            notes.append("Within-branch similarity unavailable for single-file branch.")

        summary_rows.append(
            {
                "branch": branch,
                "files": ";".join(files),
                "file_count": str(len(files)),
                "valid_hex_count": str(valid_by_branch[branch]),
                "checksum_error_count": str(checksum_by_branch[branch]),
                "avg_similarity_within_branch": avg_sim,
                "entry_vector_pattern": common_vector,
                "xdata_cluster_summary": xdata_summary.get(branch, "n/a"),
                "function_count": str(fn_count[branch]),
                "basic_block_count": str(bb_count[branch]),
                "call_count": str(call_count[branch]),
                "string_count": str(str_count[branch]),
                "packet_like_function_count": str(packet_like[branch]),
                "writer_like_function_count": str(writer_like[branch]),
                "a03_a04_specific_evidence": a03_specific,
                "confidence": conf,
                "notes": " ".join(notes) if notes else "",
            }
        )

    args.summary_out.parent.mkdir(parents=True, exist_ok=True)
    with args.summary_out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(summary_rows)

    total_cmds = len(smoke_rows)
    passed_cmds = sum(1 for r in smoke_rows if (r.get("status", "").lower() == "pass"))
    failed_cmds = total_cmds - passed_cmds

    next_branch, next_branch_reason = recommend_next_branch(summary_rows)
    manifest_count = manifest.get("count", "n/a")

    md_lines: list[str] = []
    md_lines.append("# Global branch comparison after smoke-test")
    md_lines.append("")
    md_lines.append("## Smoke-test verification")
    md_lines.append(
        f"- Проверено команд smoke-test: **{total_cmds}** (pass={passed_cmds}, fail={failed_cmds})."
    )
    md_lines.append(f"- Firmware count по manifest: **{manifest_count}**.")
    md_lines.append("- Глобальные скрипты считаются универсальными, A03/A04-скрипты считаются специализированными.")
    if warnings:
        md_lines.append("- Warnings:")
        for w in warnings:
            md_lines.append(f"  - {w}")
    md_lines.append("")

    md_lines.append("## Branches in scope")
    for branch in BRANCH_ORDER:
        md_lines.append(f"- {branch}")
    md_lines.append("")

    for row in summary_rows:
        md_lines.append(f"## Branch `{row['branch']}`")
        file_list = row["files"].split(";") if row["files"] else []
        md_lines.append(f"- Files ({len(file_list)}): {', '.join(file_list) if file_list else 'n/a'}")
        md_lines.append(
            f"- Valid/checksum: valid_hex={row['valid_hex_count']}/{row['file_count']}, checksum_errors={row['checksum_error_count']}"
        )
        md_lines.append(f"- Entry vectors: {row['entry_vector_pattern']}")
        md_lines.append(f"- XDATA clusters: {row['xdata_cluster_summary']}")
        md_lines.append(f"- Function count: {row['function_count']}")
        md_lines.append(f"- Basic block count: {row['basic_block_count']}")
        md_lines.append(f"- Packet-like functions (global roles only): {row['packet_like_function_count']}")
        md_lines.append(f"- Writer-like functions (xdata_write_count>0): {row['writer_like_function_count']}")
        md_lines.append(f"- Confidence: **{row['confidence']}**")
        if row["notes"]:
            md_lines.append(f"- Notes: {row['notes']}")
        md_lines.append("")

    md_lines.append("## Evidence separation")
    md_lines.append("### Global evidence")
    md_lines.append("- Firmware inventory/manifest, branch matrix, vector entrypoints, function/basic-block/call/string aggregates.")
    md_lines.append("- Packet-like and writer-like counts derived only from global `function_map.csv` attributes.")
    md_lines.append("")
    md_lines.append("### A03/A04-only evidence")
    md_lines.append("- Addresses 0x329C, 0x329D, 0x5003..0x5010 treated as branch-specific and excluded from global proof claims.")
    md_lines.append("- A03/A04 specialized scripts (packet candidates, local traces, packet-window writers) are scoped hypotheses.")
    md_lines.append("")
    md_lines.append("### Experimental evidence")
    md_lines.append("- Any role annotations with confidence `hypothesis`/`unknown` remain experimental until branch-independent confirmation.")
    md_lines.append("")

    md_lines.append("## Recommendation: next branch after A03/A04")
    md_lines.append(f"- Recommended branch: **{next_branch}**.")
    md_lines.append(f"- Why: {next_branch_reason}")
    md_lines.append("- Continue analysis is feasible without scope mixing if global-vs-specialized evidence boundary above is preserved.")

    args.md_out.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"Generated: {args.summary_out.relative_to(ROOT)}")
    print(f"Generated: {args.md_out.relative_to(ROOT)}")
    if warnings:
        for w in warnings:
            print(w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
