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
FILE = "90CYE03_19_DKS.PZU"
TARGETS = {"0x5A7F", "0x497A", "0x737C", "0x84A6", "0x728A", "0x6833"}
CTX_ADDR = {"0x31BF", "0x3640", "0x364B", "0x36D3", "0x36D9", "0x36EC", "0x36EE", "0x36EF", "0x36F2", "0x36F3", "0x36F4", "0x36FC", "0x36FD"}


def load_csv(name: str) -> list[dict[str, str]]:
    p = DOCS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def split_tokens(s: str) -> list[str]:
    out = []
    for t in (s or "").replace(";", "|").replace(",", "|").split("|"):
        t = t.strip()
        if t:
            out.append(t)
    return out


def norm(v: str) -> str:
    v = (v or "").strip()
    if v.lower().startswith("0x"):
        try:
            return f"0x{int(v,16):04X}"
        except ValueError:
            return v
    return v


def main() -> int:
    ap = argparse.ArgumentParser(description="Reconstruct DKS packet/export callsite and context hypotheses")
    ap.add_argument("--out-md", type=Path, default=DOCS / "dks_packet_export_reconstruction.md")
    ap.add_argument("--out-callsite", type=Path, default=DOCS / "dks_packet_export_callsite_matrix.csv")
    ap.add_argument("--out-xdata", type=Path, default=DOCS / "dks_packet_context_xdata_matrix.csv")
    ap.add_argument("--out-format", type=Path, default=DOCS / "dks_packet_format_hypothesis.csv")
    args = ap.parse_args()

    out_map = [r for r in load_csv("output_transition_map.csv") if r.get("branch") == BRANCH]
    xtrace = [r for r in load_csv("xdata_branch_trace_map.csv") if r.get("branch") == BRANCH]
    mdown = [r for r in load_csv("manual_dks_downstream_decompile_summary.csv") if r.get("branch") == BRANCH]
    call_x = [r for r in load_csv("call_xref.csv") if r.get("branch") == BRANCH]
    auto_map = [r for r in load_csv("manual_auto_branch_map.csv") if r.get("branch") == BRANCH]

    callsites: list[dict[str, str]] = []
    for r in out_map:
        caller = r.get("function_addr", "")
        callee = r.get("call_target", "")
        if callee != "0x5A7F" or caller not in TARGETS:
            continue
        callsites.append(
            {
                "branch": BRANCH,
                "file": FILE,
                "caller_addr": caller,
                "called_addr": callee,
                "pre_call_dptr": r.get("xdata_addr", "-") or "-",
                "pre_call_acc_or_reg": r.get("write_value_or_bit", "-") or "-",
                "post_call_operation": r.get("next_function", "-") or "-",
                "xdata_context": "packet_or_event_context",
                "probable_packet_role": "packet_export_bridge_call",
                "confidence": "probable" if caller in {"0x728A", "0x6833", "0x497A", "0x737C"} else "hypothesis",
                "notes": r.get("notes", "-") or "-",
            }
        )

    for r in mdown:
        fn = r.get("function_addr", "")
        if fn not in TARGETS:
            continue
        callees = set(split_tokens(r.get("callees", "")))
        if fn in {"0x728A", "0x6833", "0x497A", "0x737C"} and ("0x5A7F" in callees or "5A7F" in r.get("chain_relation", "")):
            callsites.append(
                {
                    "branch": BRANCH,
                    "file": FILE,
                    "caller_addr": fn,
                    "called_addr": "0x5A7F",
                    "pre_call_dptr": "context_dependent",
                    "pre_call_acc_or_reg": "context_dependent",
                    "post_call_operation": r.get("chain_relation", "-") or "-",
                    "xdata_context": r.get("xdata_refs", "-") or "-",
                    "probable_packet_role": "bridge_or_export_sink",
                    "confidence": "probable",
                    "notes": r.get("notes", "-") or "-",
                }
            )

    dptr_sites = [r for r in call_x if r.get("target_addr") == "0x5A7F"]
    for r in dptr_sites:
        callsites.append(
            {
                "branch": BRANCH,
                "file": r.get("file", FILE),
                "caller_addr": "unknown_from_callsite_only",
                "called_addr": "0x5A7F",
                "pre_call_dptr": "requires local disasm window",
                "pre_call_acc_or_reg": "requires local disasm window",
                "post_call_operation": r.get("code_addr", "-"),
                "xdata_context": "call_xref_only",
                "probable_packet_role": "high_fan_in_packet_bridge",
                "confidence": "hypothesis",
                "notes": "Call target evidence from call_xref; DPTR staging unresolved in this artifact pass.",
            }
        )

    # Dedup
    dd = {}
    for c in callsites:
        dd[(c["file"], c["caller_addr"], c["called_addr"], c["post_call_operation"])] = c
    callsites = sorted(dd.values(), key=lambda r: (r["caller_addr"], r["post_call_operation"]))

    readers: dict[str, set[str]] = defaultdict(set)
    writers: dict[str, set[str]] = defaultdict(set)
    for r in xtrace:
        xa = norm(r.get("xdata_addr", ""))
        fn = r.get("function_addr", "")
        if xa in CTX_ADDR and fn:
            at = (r.get("access_type", "") or "").lower()
            if "read" in at:
                readers[xa].add(fn)
            if "write" in at:
                writers[xa].add(fn)

    xrows: list[dict[str, str]] = []
    for xa in sorted(CTX_ADDR):
        rad = sorted(readers.get(xa, set()))
        wr = sorted(writers.get(xa, set()))
        role = "packet_context_candidate"
        if xa == "0x31BF":
            role = "selector_or_context_byte"
        if xa == "0x364B":
            role = "packet_window_anchor_candidate"
        xrows.append(
            {
                "branch": BRANCH,
                "file": FILE,
                "xdata_addr": xa,
                "context_role": role,
                "readers": ";".join(rad) if rad else "-",
                "writers": ";".join(wr) if wr else "-",
                "packet_adjacency": "yes" if rad or wr else "possible",
                "confidence": "probable" if rad else "hypothesis",
                "evidence_level": "probable_static" if rad or wr else "chain_adjacency",
                "notes": "Derived from xdata_branch_trace_map and downstream manual reconstruction.",
            }
        )

    format_rows = [
        {
            "field_candidate": "selector_byte",
            "xdata_source": "0x31BF",
            "source_function": "0x497A/0x737C",
            "probable_field_role": "object_or_context_selector",
            "confidence": "probable",
            "evidence": "xdata read adjacency + dispatcher role",
            "unknowns": "exact bit layout",
        },
        {
            "field_candidate": "state_cluster",
            "xdata_source": "0x36D3..0x36FD",
            "source_function": "0x737C/0x84A6",
            "probable_field_role": "state/event payload bytes",
            "confidence": "hypothesis",
            "evidence": "cluster reads near packet/export path",
            "unknowns": "byte order and packet framing",
        },
        {
            "field_candidate": "mode_flags",
            "xdata_source": "0x30E7/0x30E9",
            "source_function": "0x728A",
            "probable_field_role": "manual_auto_and_mode_gate context",
            "confidence": "probable",
            "evidence": "mode gate branch + downstream 0x5A7F adjacency",
            "unknowns": "whether exported directly or only control-flow metadata",
        },
        {
            "field_candidate": "output_start_marker",
            "xdata_source": "DPTR-target write 0x04",
            "source_function": "0x6833",
            "probable_field_role": "start command or output state code",
            "confidence": "hypothesis",
            "evidence": "manual decompile path 0x6833->0x5A7F",
            "unknowns": "physical meaning without bench trace",
        },
    ]

    for out_path, fieldnames, rows in [
        (args.out_callsite, ["branch", "file", "caller_addr", "called_addr", "pre_call_dptr", "pre_call_acc_or_reg", "post_call_operation", "xdata_context", "probable_packet_role", "confidence", "notes"], callsites),
        (args.out_xdata, ["branch", "file", "xdata_addr", "context_role", "readers", "writers", "packet_adjacency", "confidence", "evidence_level", "notes"], xrows),
        (args.out_format, ["field_candidate", "xdata_source", "source_function", "probable_field_role", "confidence", "evidence", "unknowns"], format_rows),
    ]:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    md = f"""# DKS packet/export reconstruction (v1)\n\nGenerated: {stamp}\n\n## Core answer: what is `0x5A7F`?\nCurrent best fit: **packet/export bridge helper** with high fan-in callsites; not yet proven as full packet builder and not proven as final sink in isolation.\n\n## Functions preparing data before `0x5A7F`\n- `0x497A`, `0x737C`, `0x84A6`, `0x728A`, `0x6833` appear in pre-export adjacency and call matrices.\n- DPTR/ACC exact staging is still partially unresolved from currently indexed windows and remains a follow-up item.\n\n## Likely packet-context XDATA\n- Selector/context: `0x31BF`.\n- Packet-adjacent cluster: `0x364B`, `0x36D3..0x36FD`, plus neighbor `0x3640`.\n\n## Best current packet format hypothesis\nSee `docs/dks_packet_format_hypothesis.csv`; model currently uses selector + state cluster + mode flags + output-start marker candidates.\n\n## Unknowns\n- Exact packet byte layout and ordering.\n- Whether `0x5A7F` directly emits transport frame or only resolves pointers/field bridge context.\n- Required bench capture points for proving framing boundaries.\n"""
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_md.relative_to(ROOT)}")
    print(f"Wrote {args.out_callsite.relative_to(ROOT)} ({len(callsites)} rows)")
    print(f"Wrote {args.out_xdata.relative_to(ROOT)} ({len(xrows)} rows)")
    print(f"Wrote {args.out_format.relative_to(ROOT)} ({len(format_rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
