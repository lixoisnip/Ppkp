#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

BRANCH_ORDER = ["A03_A04", "90CYE_DKS", "90CYE_v2_1", "90CYE_shifted_DKS", "RTOS_service"]
ARCH_STAGES = [
    "sensor_zone",
    "zone_logic",
    "zone_state_feedback",
    "mode_event_bridge",
    "manual_auto_check",
    "output_start",
    "packet_export",
]

STAGE_LABELS = {
    "sensor_zone": "sensor/input entry",
    "zone_logic": "zone logic dispatcher",
    "zone_state_feedback": "zone state update",
    "mode_event_bridge": "mode/event bridge",
    "manual_auto_check": "manual/auto gate",
    "output_start": "output start",
    "packet_export": "packet/service export",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def pick_best(rows: list[dict[str, str]]) -> dict[str, str] | None:
    if not rows:
        return None
    rank = {"high": 4, "medium": 3, "probable": 3, "hypothesis": 2, "low": 1, "": 0}
    match_rank = {"same_address": 4, "similar_role": 3, "string_cluster_anchor": 2, "checksum_limited": 1, "": 0}
    return sorted(
        rows,
        key=lambda r: (
            rank.get((r.get("confidence") or "").lower(), 0),
            match_rank.get((r.get("match_type") or "").lower(), 0),
        ),
        reverse=True,
    )[0]


def main() -> int:
    p = argparse.ArgumentParser(description="Issue #52: compare all families and map shared module architecture")
    p.add_argument("--out-csv", type=Path, default=DOCS / "family_module_architecture_map.csv")
    p.add_argument("--out-md", type=Path, default=DOCS / "family_module_architecture_map.md")
    args = p.parse_args()

    inventory = read_csv(DOCS / "firmware_inventory.csv")
    runtime = read_csv(DOCS / "runtime_branch_comparison.csv")
    handlers = read_csv(DOCS / "module_handler_summary.csv")
    input_core = read_csv(DOCS / "input_board_core_matrix.csv")
    xdata_branch = read_csv(DOCS / "xdata_map_by_branch.csv")
    call_targets = read_csv(DOCS / "call_targets_summary.csv")

    files_by_branch: dict[str, list[str]] = defaultdict(list)
    for row in inventory:
        b = row.get("branch", "")
        f = row.get("file", "")
        if b and f:
            files_by_branch[b].append(f)

    runtime_by_branch_stage: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in runtime:
        key = (row.get("branch", ""), row.get("similar_function_or_role", ""))
        runtime_by_branch_stage[key].append(row)

    handlers_by_branch: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in handlers:
        b = row.get("branch", "")
        if b and b != "ALL":
            handlers_by_branch[b].append(row)

    command_by_branch: dict[str, str] = defaultdict(lambda: "no")
    cmd_candidates: dict[str, set[str]] = defaultdict(set)
    for row in input_core:
        b = row.get("branch", "")
        if not b:
            continue
        if (row.get("command_cluster_present", "").strip().lower() == "yes"):
            command_by_branch[b] = "yes"
        c = row.get("command_adjacent_candidate", "").strip()
        if c:
            cmd_candidates[b].add(c)

    xdata_tags: dict[str, list[str]] = defaultdict(list)
    for row in xdata_branch:
        b = row.get("branch", "")
        t = row.get("cluster_tag", "").strip()
        if b and t and t not in xdata_tags[b]:
            xdata_tags[b].append(t)

    packet_targets: dict[str, list[str]] = defaultdict(list)
    for row in call_targets:
        b = row.get("branch", "")
        role = (row.get("role_candidate", "") or "").strip()
        tgt = (row.get("target_addr", "") or "").strip()
        if b and tgt and role in {"state_reader_or_packet_builder", "service_or_runtime_worker", "dispatcher_or_router"}:
            if tgt not in packet_targets[b]:
                packet_targets[b].append(tgt)

    # csv
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "branch",
                "files",
                "shared_architecture_stages",
                "stage_anchor_addresses",
                "mash_candidates",
                "mas_candidates",
                "service_ui_candidates",
                "command_cluster_present",
                "command_adjacent_candidates",
                "xdata_cluster_tags",
                "packet_or_runtime_call_targets",
            ]
        )
        for branch in BRANCH_ORDER:
            files = sorted(files_by_branch.get(branch, []))
            stage_parts = []
            anchor_parts = []
            for stage in ARCH_STAGES:
                best = pick_best(runtime_by_branch_stage.get((branch, stage), []))
                if not best:
                    continue
                stage_parts.append(stage)
                anchor_parts.append(f"{stage}:{best.get('matched_function_addr','n/a')}({best.get('match_type','n/a')}/{best.get('confidence','n/a')})")

            mash = [r.get("function_addr", "") for r in handlers_by_branch.get(branch, []) if "МАШ" in (r.get("module_type", ""))]
            mas = [r.get("function_addr", "") for r in handlers_by_branch.get(branch, []) if "МАС" in (r.get("module_type", ""))]
            svc = [r.get("function_addr", "") for r in handlers_by_branch.get(branch, []) if "Другие" in (r.get("module_type", ""))]

            w.writerow(
                [
                    branch,
                    ";".join(files),
                    "|".join(stage_parts),
                    "|".join(anchor_parts),
                    "|".join(sorted(set(filter(None, mash)))),
                    "|".join(sorted(set(filter(None, mas)))),
                    "|".join(sorted(set(filter(None, svc)))),
                    command_by_branch[branch],
                    "|".join(sorted(cmd_candidates.get(branch, set()))),
                    "|".join(xdata_tags.get(branch, [])[:8]),
                    "|".join(packet_targets.get(branch, [])[:8]),
                ]
            )

    # markdown
    rows = read_csv(args.out_csv)
    shared_stage_count = {s: 0 for s in ARCH_STAGES}
    for row in rows:
        stages = set((row.get("shared_architecture_stages", "") or "").split("|"))
        for s in ARCH_STAGES:
            if s in stages:
                shared_stage_count[s] += 1

    lines: list[str] = []
    lines.append("# Family-wide shared module architecture map (Issue #52)")
    lines.append("")
    lines.append("Date: 2026-04-26 (UTC).")
    lines.append("")
    lines.append("Goal: compare all firmware families and produce a single map of shared module architecture anchors.")
    lines.append("")
    lines.append("## Shared stages across branches")
    lines.append("")
    lines.append("| stage | role | branches with evidence |")
    lines.append("|---|---|---:|")
    for s in ARCH_STAGES:
        lines.append(f"| `{s}` | {STAGE_LABELS[s]} | {shared_stage_count[s]}/{len(BRANCH_ORDER)} |")

    lines.append("")
    lines.append("## Branch comparison summary")
    lines.append("")
    lines.append("| branch | files | stage anchors | module handlers (МАШ / МАС / service) | command cluster |")
    lines.append("|---|---|---|---|---|")
    for row in rows:
        lines.append(
            "| {branch} | {files} | {anchors} | {mash} / {mas} / {svc} | {cmd} |".format(
                branch=row.get("branch", ""),
                files=(row.get("files", "") or "—").replace(";", "<br>"),
                anchors=(row.get("stage_anchor_addresses", "") or "—").replace("|", "<br>"),
                mash=row.get("mash_candidates", "") or "—",
                mas=row.get("mas_candidates", "") or "—",
                svc=row.get("service_ui_candidates", "") or "—",
                cmd=row.get("command_cluster_present", "") or "no",
            )
        )

    lines.append("")
    lines.append("## Machine-readable output")
    lines.append("")
    lines.append("- `docs/family_module_architecture_map.csv`")
    lines.append("- `docs/family_module_architecture_map.md`")
    lines.append("")
    lines.append("## Notes and limits")
    lines.append("")
    lines.append("1. Mapping is static-evidence based and does not assert full semantic equivalence of addresses across branches.")
    lines.append("2. Stages marked by `checksum_limited`/`hypothesis` remain tentative and require bench validation.")
    lines.append("3. Command cluster visibility differs by branch and depends on current string extraction coverage.")

    args.out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Generated: {args.out_csv}")
    print(f"Generated: {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
