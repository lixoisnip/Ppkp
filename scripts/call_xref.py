#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import csv
from collections import defaultdict

from pzu_common import discover_pzu_files, infer_branch, load_intel_hex
from disasm_8051 import CODE_END, CODE_START, disassemble_reachable


def extract_calls_legacy(mem: bytearray, start: int = CODE_START, end: int = CODE_END) -> list[tuple[int, str, int]]:
    rows: list[tuple[int, str, int]] = []
    for addr in range(start, end - 2):
        op = mem[addr]
        if op == 0x12:
            rows.append((addr, "LCALL", (mem[addr + 1] << 8) | mem[addr + 2]))
        elif op == 0x02:
            rows.append((addr, "LJMP", (mem[addr + 1] << 8) | mem[addr + 2]))
    return rows


def infer_role_candidate(lcall_count: int, ljmp_count: int, file_count: int) -> tuple[str, str]:
    total = lcall_count + ljmp_count
    if lcall_count > 0 and ljmp_count > 0 and total >= 8:
        role = "service_cluster_dispatch"
    elif lcall_count >= 6:
        role = "shared_service_call"
    elif ljmp_count >= 6:
        role = "jump_table_or_dispatch"
    elif total >= 4:
        role = "branch_local_hotspot"
    else:
        role = "unknown"

    if file_count >= 2 and total >= 8:
        confidence = "probable"
    elif total >= 4:
        confidence = "hypothesis"
    else:
        confidence = "unknown"
    return role, confidence


def main() -> int:
    p = argparse.ArgumentParser(description="Generate global call cross-reference tables for *.PZU images.")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--out", type=Path, default=Path("docs/call_xref.csv"))
    p.add_argument("--legacy-out", type=Path, default=Path("docs/call_xref_legacy.csv"))
    p.add_argument("--summary", type=Path, default=Path("docs/call_targets_summary.csv"))
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    summary: dict[tuple[str, int], dict[str, object]] = defaultdict(
        lambda: {"lcall_count": 0, "ljmp_count": 0, "files": set()}
    )

    with args.legacy_out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "branch", "code_addr", "call_type", "target_addr"])
        for path in files:
            mem, _st = load_intel_hex(path)
            branch = infer_branch(path.name)
            for code_addr, call_type, target_addr in extract_calls_legacy(mem):
                w.writerow([path.name, branch, f"0x{code_addr:04X}", call_type, f"0x{target_addr:04X}"])

    with args.out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "file",
                "branch",
                "code_addr",
                "call_type",
                "target_addr",
                "is_reachable",
                "target_in_code_range",
                "target_known_function",
                "confidence",
            ]
        )

        for path in files:
            mem, _st = load_intel_hex(path)
            branch = infer_branch(path.name)
            disasm_rows = disassemble_reachable(mem)
            known_code_addrs = {int(row["code_addr"], 16) for row in disasm_rows}
            for row in disasm_rows:
                call_type = row["mnemonic"]
                if call_type not in {"LCALL", "LJMP", "SJMP"}:
                    continue
                if not row["target_addr"]:
                    continue
                code_addr = int(row["code_addr"], 16)
                target_addr = int(row["target_addr"], 16)
                target_in_code_range = CODE_START <= target_addr < CODE_END
                target_known_function: str = ""
                if target_in_code_range:
                    target_known_function = "true" if target_addr in known_code_addrs else "false"

                w.writerow(
                    [
                        path.name,
                        branch,
                        f"0x{code_addr:04X}",
                        call_type,
                        f"0x{target_addr:04X}",
                        "true",
                        "true" if target_in_code_range else "false",
                        target_known_function,
                        row["confidence"].lower(),
                    ]
                )
                item = summary[(branch, target_addr)]
                item["files"].add(path.name)
                if call_type == "LCALL":
                    item["lcall_count"] += 1
                elif call_type == "LJMP":
                    item["ljmp_count"] += 1

    with args.summary.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "branch",
                "target_addr",
                "lcall_count",
                "ljmp_count",
                "files",
                "role_candidate",
                "confidence",
                "evidence_source",
            ]
        )
        for (branch, target_addr), item in sorted(summary.items(), key=lambda x: (x[0][0], x[0][1])):
            files_sorted = sorted(item["files"])
            role, confidence = infer_role_candidate(item["lcall_count"], item["ljmp_count"], len(files_sorted))
            w.writerow(
                [
                    branch,
                    f"0x{target_addr:04X}",
                    item["lcall_count"],
                    item["ljmp_count"],
                    ";".join(files_sorted),
                    role,
                    confidence,
                    "reachable_disasm",
                ]
            )

    print(f"Generated: {args.out}")
    print(f"Generated: {args.legacy_out}")
    print(f"Generated: {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
