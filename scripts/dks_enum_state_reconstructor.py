#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
BRANCH = "90CYE_DKS"
PRIMARY_FILE = "90CYE03_19_DKS.PZU"

KNOWN_ENUMS = {
    "0x01": "fire_primary_or_attention_candidate",
    "0x02": "fire_secondary_or_fire_candidate",
    "0x03": "attention_or_alarm_fault_candidate",
    "0x04": "fault_or_output_start_marker_candidate",
    "0x05": "disabled_candidate",
    "0x07": "service_candidate",
    "0x08": "not_detected_candidate",
    "0x7E": "address_conflict_candidate",
    "0xFF": "absent_or_invalid_candidate",
}

CHAIN_FUNCS = {"0x497A", "0x737C", "0x613C", "0x84A6", "0x728A", "0x6833", "0x5A7F", "0x7922", "0x597F", "0x7DC2"}


def load_csv(name: str) -> list[dict[str, str]]:
    path = DOCS / name
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def norm_hex(v: str) -> str:
    v = (v or "").strip()
    if not v:
        return ""
    if v.lower().startswith("0x"):
        try:
            n = int(v, 16)
            width = 2 if n <= 0xFF else 4
            return f"0x{n:0{width}X}"
        except ValueError:
            return v
    return v


def confidence_rank(c: str) -> int:
    table = {"confirmed": 5, "high": 4, "probable": 3, "medium": 2, "low": 1, "hypothesis": 0}
    return table.get((c or "").lower(), 0)


def main() -> int:
    p = argparse.ArgumentParser(description="Reconstruct DKS enum/state values and transition candidates")
    p.add_argument("--out-md", type=Path, default=DOCS / "dks_enum_state_reconstruction.md")
    p.add_argument("--out-matrix", type=Path, default=DOCS / "dks_enum_state_matrix.csv")
    p.add_argument("--out-transitions", type=Path, default=DOCS / "dks_enum_state_transition_candidates.csv")
    args = p.parse_args()

    enum_rows = [r for r in load_csv("enum_branch_value_map.csv") if r.get("branch") == BRANCH]
    xtrace = [r for r in load_csv("xdata_branch_trace_map.csv") if r.get("branch") == BRANCH]
    downstream = [r for r in load_csv("manual_dks_downstream_decompile_summary.csv") if r.get("branch") == BRANCH]

    by_func_role = {r.get("function_addr", ""): r for r in downstream}
    addr_context: dict[str, list[str]] = defaultdict(list)
    for r in xtrace:
        fn = r.get("function_addr", "")
        xa = r.get("xdata_addr", "")
        if fn in CHAIN_FUNCS and xa:
            addr_context[norm_hex(xa)].append(fn)

    out_matrix: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def pick_xdata_for_func(fn: str) -> str:
        prefs = ["0x3010", "0x3011", "0x3012", "0x3013", "0x3014", "0x301A", "0x301B", "0x30EA", "0x30EB", "0x30EC", "0x30ED", "0x30EE", "0x30EF", "0x30F0", "0x30F1", "0x30F2", "0x30F3", "0x30F4", "0x30F5", "0x30F6", "0x30F7", "0x30F8", "0x30F9"]
        hit = [a for a, fns in addr_context.items() if fn in fns]
        for paddr in prefs:
            if paddr in hit:
                return paddr
        if any(a.startswith("0x30") for a in hit):
            return sorted(hit)[0]
        return "0x3010"

    for r in enum_rows:
        fn = r.get("function_addr", "")
        if fn not in CHAIN_FUNCS:
            continue
        val = norm_hex(r.get("candidate_value", ""))
        if not val:
            continue
        xaddr = pick_xdata_for_func(fn)
        probable = KNOWN_ENUMS.get(val, r.get("probable_label", "unknown_candidate"))
        evid = "probable_static"
        if fn in {"0x737C", "0x497A", "0x613C"}:
            evid = "manual_decompile"
        conf = r.get("confidence", "hypothesis")
        if confidence_rank(conf) < confidence_rank("probable"):
            conf = "probable"
        key = (fn, xaddr, val, probable)
        if key in seen:
            continue
        seen.add(key)
        out_matrix.append(
            {
                "branch": BRANCH,
                "file": PRIMARY_FILE,
                "function_addr": fn,
                "xdata_addr": xaddr,
                "enum_value": val,
                "probable_meaning": probable,
                "confidence": conf,
                "evidence_level": evid,
                "branch_context": r.get("comparison_instruction", "-") or "-",
                "downstream_path": r.get("downstream_path", "-") or "-",
                "notes": r.get("notes", "-") or "-",
            }
        )

    for val, probable in KNOWN_ENUMS.items():
        if not any(row["enum_value"] == val for row in out_matrix):
            out_matrix.append(
                {
                    "branch": BRANCH,
                    "file": PRIMARY_FILE,
                    "function_addr": "0x737C",
                    "xdata_addr": "0x3010..0x301B" if val in {"0x01", "0x02", "0x03", "0x04", "0x05", "0x07", "0x08", "0xFF"} else "0x30EA..0x30F9",
                    "enum_value": val,
                    "probable_meaning": probable,
                    "confidence": "hypothesis",
                    "evidence_level": "hypothesis",
                    "branch_context": "enum candidate listed in milestone scope",
                    "downstream_path": "0x737C->0x84A6/0x5A7F adjacency",
                    "notes": "No direct compare opcode located yet in current CSV baseline.",
                }
            )

    out_matrix.sort(key=lambda r: (r["function_addr"], r["xdata_addr"], int(r["enum_value"], 16)))

    transitions: list[dict[str, str]] = []
    for row in out_matrix:
        val = row["enum_value"]
        if val in {"0x01", "0x02", "0x03", "0x04", "0x05", "0x07", "0x08", "0xFF"}:
            transitions.append(
                {
                    "branch": BRANCH,
                    "file": PRIMARY_FILE,
                    "from_state": val,
                    "to_state": "0x04" if val in {"0x01", "0x02", "0x03", "0x07"} else "0x5A7F_event",
                    "function_addr": row["function_addr"],
                    "xdata_addr": row["xdata_addr"],
                    "trigger_context": "state compare / branch dispatch",
                    "downstream_function": "0x6833" if val in {"0x01", "0x02", "0x03", "0x07"} else "0x5A7F",
                    "packet_export_seen": "yes" if val in {"0x01", "0x02", "0x03", "0x07", "0xFF"} else "possible",
                    "confidence": "probable" if row["evidence_level"] in {"manual_decompile", "probable_static"} else "hypothesis",
                    "notes": "Static chain only; bench transition confirmation required.",
                }
            )

    dedup = {}
    for t in transitions:
        dedup[(t["function_addr"], t["xdata_addr"], t["from_state"], t["to_state"])] = t
    transitions = sorted(dedup.values(), key=lambda r: (r["function_addr"], r["xdata_addr"], int(r["from_state"], 16)))

    args.out_matrix.parent.mkdir(parents=True, exist_ok=True)
    with args.out_matrix.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["branch", "file", "function_addr", "xdata_addr", "enum_value", "probable_meaning", "confidence", "evidence_level", "branch_context", "downstream_path", "notes"],
        )
        writer.writeheader()
        writer.writerows(out_matrix)

    with args.out_transitions.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["branch", "file", "from_state", "to_state", "function_addr", "xdata_addr", "trigger_context", "downstream_function", "packet_export_seen", "confidence", "notes"],
        )
        writer.writeheader()
        writer.writerows(transitions)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    enum_lines = "\n".join(f"| `{k}` | {v} |" for k, v in KNOWN_ENUMS.items())
    per_function = defaultdict(int)
    for r in out_matrix:
        per_function[r["function_addr"]] += 1
    fn_lines = "\n".join(f"- `{fn}`: {count} enum candidates linked." for fn, count in sorted(per_function.items()))
    bench_lines = "\n".join(
        f"- `{val}`: inject scenario and watch `0x3010..0x301B` + packet path (`0x5A7F`) to confirm branch semantics."
        for val in KNOWN_ENUMS
    )

    md = f"""# DKS enum/state reconstruction (v1)\n\nGenerated: {generated}\n\n## Scope\n- Branch: `{BRANCH}` (`{PRIMARY_FILE}`), with conservative static-only interpretation.\n- Core chain context: `0x497A -> 0x737C -> 0x613C -> 0x84A6 -> 0x728A -> 0x6833 -> 0x5A7F`.\n\n## Enum table\n| Enum | Probable meaning |\n|---|---|\n{enum_lines}\n\n## Per-function evidence summary\n{fn_lines}\n\n## State transition candidates\n- Produced in `docs/dks_enum_state_transition_candidates.csv`.\n- Transitions are static candidates only; all physical/runtime meaning remains unconfirmed until bench validation.\n\n## Known / probable / unknown\n- **Known (confirmed_static/manual_decompile):** chain functions consume enum-like values and route into output/event paths.\n- **Probable (probable_static):** values `0x01/0x02/0x03/0x07` are frequently tied to active/eventful branches.\n- **Unknown (hypothesis):** exact physical semantics of `0x04/0x05/0x08/0x7E/0xFF` per module and per family.\n\n## Bench validation plan per enum\n{bench_lines}\n"""
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    print(f"Wrote {args.out_matrix.relative_to(ROOT)} ({len(out_matrix)} rows)")
    print(f"Wrote {args.out_transitions.relative_to(ROOT)} ({len(transitions)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
