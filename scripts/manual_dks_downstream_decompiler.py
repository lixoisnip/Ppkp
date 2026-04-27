#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
from pathlib import Path
import bisect

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

INPUT_FILES = [
    "disassembly_index.csv",
    "basic_block_map.csv",
    "function_map.csv",
    "call_xref.csv",
    "xdata_confirmed_access.csv",
    "xdata_xref.csv",
    "xdata_branch_trace_map.csv",
    "manual_auto_branch_map.csv",
    "output_transition_map.csv",
    "zone_to_output_chains.csv",
    "zone_logic_candidates.csv",
    "output_control_candidates.csv",
    "enum_branch_value_map.csv",
    "manual_dks_module_decompile_summary.csv",
    "manual_dks_module_pseudocode.csv",
    "manual_decompile_0x728A_0x6833.md",
    "string_index.csv",
    "code_table_candidates.csv",
]

PRIMARY_FILE = "90CYE03_19_DKS.PZU"
COMPARE_FILE = "90CYE04_19_DKS.PZU"
BRANCH = "90CYE_DKS"
TARGETS = ["0x5A7F", "0x737C", "0x84A6", "0x7922", "0x597F", "0x7DC2"]

MANUAL_ROLES = {
    "0x5A7F": "packet_export_bridge",
    "0x737C": "zone_object_logic",
    "0x84A6": "mode_event_bridge",
    "0x7922": "state_table_reader",
    "0x597F": "condition_check_helper",
    "0x7DC2": "output_downstream_transition",
}

KNOWN_CONTEXT = {
    "0x5A7F": "called from 0x497A/0x728A/0x6833 in packet-adjacent paths",
    "0x737C": "between 0x497A and 0x84A6 in prior deep-trace chain",
    "0x84A6": "between 0x737C and 0x728A in prior deep-trace chain",
    "0x7922": "frequent helper call in 0x728A and 0x6833 branches",
    "0x597F": "pre-check helper before 0x6833 output write",
    "0x7DC2": "downstream jump target from 0x6833 tail",
}

SUMMARY_HEADERS = [
    "branch",
    "file",
    "function_addr",
    "previous_role",
    "new_manual_role",
    "confidence",
    "evidence_sources",
    "xdata_refs",
    "callers",
    "callees",
    "chain_relation",
    "notes",
]

PSEUDOCODE_HEADERS = [
    "branch",
    "file",
    "function_addr",
    "pseudocode_block",
    "known_operations",
    "unknown_operations",
    "confidence",
    "notes",
]

CSV_PREVIOUS_ROLE = {
    "0x5A7F": "packet/export candidate",
    "0x737C": "zone logic candidate",
    "0x84A6": "mode/event bridge candidate",
    "0x7922": "service/event helper candidate",
    "0x597F": "condition check helper",
    "0x7DC2": "downstream output/service transition",
}

CSV_CONFIDENCE = {
    "0x5A7F": "probable",
    "0x737C": "probable",
    "0x84A6": "hypothesis",
    "0x7922": "probable",
    "0x597F": "probable",
    "0x7DC2": "hypothesis",
}

SPECIFIC_PSEUDOCODE = {
    "0x5A7F": """void fn_5A7F(uint8_t selector_or_index) {
    // update DPTR bytes from current selector/context
    // return pointer-like DPTR state for caller MOVX activity
}""",
    "0x737C": """void fn_737C(...) {
    // read object/zone context (0x31BF + 0x36xx cluster)
    // branch on masked enum/state values
    // call 0x84A6 and 0x5A7F on selected paths
    // update 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B state-table fields
}""",
    "0x84A6": """void fn_84A6(...) {
    // read mode/state cluster (0x315B/0x3181/0x3640/0x36D3/0x36D9)
    // evaluate branch flags / thresholds
    // call 0x728A for downstream gate path
    // call 0x5A7F for packet/pointer bridge on selected paths
}""",
    "0x7922": """void fn_7922(void) {
    // A = XDATA[DPTR]; R0 = A
    // DPTR++
    // A = XDATA[DPTR]; R1 = A
    // return
}""",
    "0x597F": """uint8_t fn_597F(uint8_t in_a) {
    // return in_a & 0x07
}""",
    "0x7DC2": """void fn_7DC2(...) {
    // downstream sub-block in parent routine (0x7D85)
    // call helper(s) (0x7121 and 0x7D9B), then continue output/service transition tail
}""",
}


def read_csv(name: str) -> list[dict[str, str]]:
    with (DOCS / name).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def parse_hex(v: str) -> int:
    if not v or not v.startswith("0x"):
        return -1
    return int(v, 16)


def confidence_bucket(score: float) -> str:
    if score >= 20:
        return "probable"
    if score >= 8:
        return "hypothesis"
    return "unknown"


def collect_function_instructions(
    file_name: str,
    func_addr: str,
    basic_blocks: list[dict[str, str]],
    disasm_rows: list[dict[str, str]],
) -> tuple[list[dict[str, str]], str | None]:
    rows = sorted(
        [r for r in disasm_rows if r["file"] == file_name and r["code_addr"].startswith("0x")],
        key=lambda r: parse_hex(r["code_addr"]),
    )
    int_addrs = [parse_hex(r["code_addr"]) for r in rows]

    blocks = [
        b for b in basic_blocks if b["file"] == file_name and b["parent_function_candidate"] == func_addr and b["block_addr"].startswith("0x")
    ]
    parent_fallback = None
    if not blocks:
        host_blocks = [b for b in basic_blocks if b["file"] == file_name and b.get("block_addr") == func_addr]
        if host_blocks:
            parent_fallback = host_blocks[0]["parent_function_candidate"]
            blocks = [
                b
                for b in basic_blocks
                if b["file"] == file_name
                and b["parent_function_candidate"] == parent_fallback
                and b["block_addr"].startswith("0x")
            ]

    picked: list[dict[str, str]] = []
    seen = set()
    for b in blocks:
        start = parse_hex(b["block_addr"])
        count = int(b.get("instruction_count") or 0)
        idx = bisect.bisect_left(int_addrs, start)
        for j in range(idx, min(idx + count, len(rows))):
            row = rows[j]
            if row["code_addr"] in seen:
                continue
            seen.add(row["code_addr"])
            picked.append(row)
    picked.sort(key=lambda r: parse_hex(r["code_addr"]))
    return picked, parent_fallback


def find_callsites_context(disasm_rows: list[dict[str, str]], call_rows: list[dict[str, str]], file_name: str, target: str) -> list[str]:
    rows = sorted([r for r in disasm_rows if r["file"] == file_name and r["code_addr"].startswith("0x")], key=lambda r: parse_hex(r["code_addr"]))
    idx = {r["code_addr"]: i for i, r in enumerate(rows)}
    out = []
    calls = [r for r in call_rows if r["file"] == file_name and r["target_addr"] == target and r["code_addr"].startswith("0x")]
    calls = sorted(calls, key=lambda r: parse_hex(r["code_addr"]))
    for c in calls[:8]:
        i = idx.get(c["code_addr"], 0)
        prev = rows[max(0, i - 2):i]
        snippet = " ; ".join(f"{p['code_addr']} {p['mnemonic']} {p['operands']}".strip() for p in prev)
        out.append(f"{c['code_addr']} <= {snippet}")
    return out


def main() -> int:
    missing = [name for name in INPUT_FILES if not (DOCS / name).exists()]
    if missing:
        raise SystemExit(f"Missing required inputs: {missing}")

    data = {name: read_csv(name) for name in INPUT_FILES if name.endswith('.csv')}

    basic_blocks = data["basic_block_map.csv"]
    disasm_rows = data["disassembly_index.csv"]
    call_rows = data["call_xref.csv"]
    xdata_confirmed = data["xdata_confirmed_access.csv"]
    xdata_branch = data["xdata_branch_trace_map.csv"]
    enum_map = data["enum_branch_value_map.csv"]
    zone_candidates = data["zone_logic_candidates.csv"]
    output_candidates = data["output_control_candidates.csv"]
    manual_auto = data["manual_auto_branch_map.csv"]
    output_transition = data["output_transition_map.csv"]

    sections: list[str] = []
    sections.append("# Manual downstream DKS decompile: 0x5A7F / 0x737C / 0x84A6 / 0x7922 / 0x597F / 0x7DC2\n")
    sections.append("Date: 2026-04-27 (UTC).\n")
    sections.append("## Machine-readable outputs")
    sections.append("- `docs/manual_dks_downstream_decompile_summary.csv`")
    sections.append("- `docs/manual_dks_downstream_pseudocode.csv`\n")
    sections.append("## Scope")
    sections.append("- Static semi-manual reconstruction only.")
    sections.append("- Targets selected because they sit downstream of 0x497A / 0x613C / 0x728A / 0x6833 chain.")
    sections.append("- 0x728A and 0x6833 already have a separate manual decompile and are not duplicated.")
    sections.append("- Cross-check is limited to identical-address/fingerprint matches in 90CYE04_19_DKS.PZU.")
    sections.append("- Physical semantics remain conservative: static code role != proven field action.\n")

    sections.append("## Target summary table")
    sections.append("| firmware_file | branch | function_addr | known_context | manual_role | confidence | key_evidence | next_step |")
    sections.append("|---|---|---|---|---|---|---|---|")

    evidence_by_target: dict[str, dict[str, object]] = {}

    for addr in TARGETS:
        inst, parent = collect_function_instructions(PRIMARY_FILE, addr, basic_blocks, disasm_rows)
        compare_inst, _ = collect_function_instructions(COMPARE_FILE, addr, basic_blocks, disasm_rows)
        callers = sorted({r["code_addr"] for r in call_rows if r["file"] == PRIMARY_FILE and r["target_addr"] == addr and r["code_addr"].startswith("0x")}, key=parse_hex)
        inst_addrs = {r["code_addr"] for r in inst}
        callees = sorted({r["target_addr"] for r in call_rows if r["file"] == PRIMARY_FILE and r["code_addr"] in inst_addrs and r["target_addr"].startswith("0x")}, key=parse_hex)
        xdata = sorted(
            {f"{r['dptr_addr']}({r['access_type']})" for r in xdata_confirmed if r["file"] == PRIMARY_FILE and r["code_addr"] in inst_addrs and r["dptr_addr"].startswith("0x")}
            | {f"{r['xdata_addr']}({r['access_type']})" for r in xdata_branch if r["file"] == PRIMARY_FILE and r["function_addr"] == addr and r["xdata_addr"].startswith("0x")},
            key=lambda v: parse_hex(v.split("(")[0]),
        )
        enum_vals = sorted({r["candidate_value"] for r in enum_map if r["file"] == PRIMARY_FILE and r["function_addr"] == addr}, key=parse_hex)
        zscore = max((float(r["score"]) for r in zone_candidates if r["file"] == PRIMARY_FILE and r["function_addr"] == addr), default=0.0)
        oscore = max((float(r["score"]) for r in output_candidates if r["file"] == PRIMARY_FILE and r["function_addr"] == addr), default=0.0)
        score = max(zscore, oscore)
        conf = confidence_bucket(score)

        fp_a = hashlib.sha256("\n".join(f"{r['mnemonic']}|{r['operands']}|{r['target_addr']}" for r in inst).encode()).hexdigest() if inst else ""
        fp_b = hashlib.sha256("\n".join(f"{r['mnemonic']}|{r['operands']}|{r['target_addr']}" for r in compare_inst).encode()).hexdigest() if compare_inst else ""
        same_fp = bool(fp_a and fp_b and fp_a == fp_b)

        key_evidence = [f"callers={len(callers)}", f"callees={','.join(callees[:4]) or 'none'}"]
        if xdata:
            key_evidence.append(f"xdata={','.join(xdata[:3])}")
        if same_fp:
            key_evidence.append("90CYE04_fingerprint_match")

        sections.append(
            f"| {PRIMARY_FILE} | {BRANCH} | {addr} | {KNOWN_CONTEXT[addr]} | {MANUAL_ROLES[addr]} | {conf} | {'; '.join(key_evidence)} | refine with targeted dynamic trace on this node |"
        )

        evidence_by_target[addr] = {
            "inst": inst,
            "parent": parent,
            "callers": callers,
            "callees": callees,
            "xdata": xdata,
            "enum_vals": enum_vals,
            "same_fp": same_fp,
            "score": score,
            "confidence": conf,
            "callsites": find_callsites_context(disasm_rows, call_rows, PRIMARY_FILE, addr),
        }

    # 0x5A7F
    ev = evidence_by_target["0x5A7F"]
    sections.append("\n## 0x5A7F packet/export bridge analysis")
    sections.append("- Repeated packet/export treatment is supported by high fan-in from dispatch/gate paths (0x497A, 0x728A, 0x6833 contexts) and frequent call sites that set `DPTR` + selector in `A` immediately before call.")
    sections.append(f"- Callers (sample): {', '.join(ev['callers'][:20])}.")
    sections.append("- Direct XDATA reads/writes inside 0x5A7F are not confirmed in `xdata_confirmed_access.csv`; function body is a tiny DPTR staging return helper.")
    sections.append("- Static shape suggests pointer/address resolver or packet-field bridge (not a full packet payload builder on its own).")
    sections.append("- Return behavior: moves into DPTR registers and returns, consistent with pointer-like handoff.")
    sections.append("- Interaction with 0x31BF/0x364B/0x30E7/0x30E9/0x30EA..0x30F9 appears indirect via caller-set DPTR contexts (e.g., 0x728A/0x6833 set these addresses then call 0x5A7F).")
    sections.append("- In 0x497A/0x728A/0x6833 neighborhoods it repeatedly appears as a bridge between state/mode branch and later `MOVX` reads/writes.")
    sections.append("- Cautious role: **packet_export_bridge** (probable), with unresolved split between packet sink vs pointer resolver contribution.")
    sections.append("\n```c\nvoid fn_5A7F(uint8_t selector_or_index) {\n    // very small helper\n    // update DPTR bytes from current selector/context\n    // return with pointer-like DPTR state for caller MOVX activity\n}\n```")

    ev = evidence_by_target["0x737C"]
    sections.append("\n## 0x737C zone/object logic analysis")
    sections.append("- Treated as zone/object candidate due to high branch density, state-table reads/writes, and links to 0x84A6 and 0x5A7F.")
    sections.append(f"- Confirmed XDATA in function: {', '.join(ev['xdata']) or 'none'}.")
    sections.append(f"- Enum-like value evidence from `enum_branch_value_map.csv`: {', '.join(ev['enum_vals']) or 'none in artifact'} (requested values 0x01/0x02/0x04/0x05/0x08/0x7E/0xFF are not confirmed in this node from provided enum map).")
    sections.append("- Calls observed: includes 0x84A6 and 0x5A7F; no direct call to 0x613C or 0x728A seen in this function body.")
    sections.append("- Writes to 0x3010/0x3011/0x3013/0x3014/0x301A/0x301B support state/object-table update behavior.")
    sections.append("- Cautious role: **zone_object_logic** (probable), but still compatible with branch-dispatcher interpretation.")
    sections.append("\n```c\nvoid fn_737C(...) {\n    // read object/zone context (e.g., 0x31BF + 0x36E* cluster)\n    // branch on masked enum/state values\n    // call sub-helpers and 0x84A6 bridge\n    // update 0x301* state table fields\n    // invoke 0x5A7F when packet/export-adjacent path is needed\n}\n```")

    ev = evidence_by_target["0x84A6"]
    manual = [r for r in manual_auto if r["file"] == PRIMARY_FILE and r["function_addr"] == "0x84A6"]
    sections.append("\n## 0x84A6 mode/event bridge analysis")
    sections.append("- Treated as mode/event bridge because it calls 0x728A and also calls 0x5A7F from a control-heavy dispatcher with multiple downstream service handlers.")
    sections.append(f"- Callers: {', '.join(ev['callers'])}.")
    sections.append(f"- Key XDATA reads: {', '.join(ev['xdata']) or 'none'}.")
    if manual:
        m = manual[0]
        sections.append(f"- Manual/auto map hints: manual_downstream={m['manual_downstream']}, auto_downstream={m['auto_downstream']} (confidence={m['confidence']}).")
    sections.append("- It appears to both bridge event generation and perform gating-like checks (bit tests + conditional dispatch), so role is mixed.")
    sections.append("- Manual-like vs auto-like physical semantics are still hypothesis-level; static evidence only proves branch/dispatch structure.")
    sections.append("\n```c\nvoid fn_84A6(...) {\n    // read mode/state cluster (0x315B/0x3181/0x36D3/0x36D9/0x3640)\n    // evaluate branch flags / thresholds\n    // call 0x728A for downstream gate path\n    // call 0x5A7F for packet/pointer bridge on selected paths\n    // dispatch to service/output helpers\n}\n```")

    ev = evidence_by_target["0x7922"]
    sections.append("\n## 0x7922 service/event helper analysis")
    sections.append("- Frequent calls from 0x728A/0x6833 are explained by tiny fixed behavior: read two bytes from `@DPTR` and place into R0/R1.")
    sections.append(f"- Callers (sample): {', '.join(ev['callers'])}.")
    sections.append("- Pre-call pattern repeatedly sets DPTR to table-like addresses (e.g., 0x7108/0x7128/0x7138/0x0001), so arguments are pointer-by-DPTR.")
    sections.append("- No direct XDATA writes by 0x7922 itself; no calls to packet/export functions from inside 0x7922.")
    sections.append("- Cautious role: table/service read helper used to load event/output context, not a standalone queue or packet routine.")
    sections.append("\n```c\nvoid fn_7922(void) {\n    // A = XDATA[DPTR]; R0 = A\n    // DPTR++\n    // A = XDATA[DPTR]; R1 = A\n    // return\n}\n```")

    ev = evidence_by_target["0x597F"]
    sections.append("\n## 0x597F condition-check helper analysis")
    sections.append("- 0x6833 calls 0x597F after loading A from R7 and before output-start write; this is consistent with a compact condition normalization/check helper.")
    sections.append("- Body-level static behavior is tiny (`ANL A,#0x07` + return paths), so result is likely returned in ACC-derived state used by caller branches.")
    sections.append("- No direct XDATA access in this helper from confirmed access map.")
    sections.append("- In 0x6833 specifically, result is moved to R2 and later branch-tested before writing 0x04 to target XDATA entry.")
    sections.append("- Cautious role: **condition_check_helper** (probable), exact semantic (permission/fault/mode) unknown.")
    sections.append("\n```c\nuint8_t fn_597F(uint8_t in_a) {\n    // reduce/normalize condition bits\n    // return (in_a & 0x07)\n}\n```")

    ev = evidence_by_target["0x7DC2"]
    trans = [r for r in output_transition if r["file"] == PRIMARY_FILE and (r.get("next_function") == "0x7DC2" or r.get("call_target") == "0x7DC2")]
    sections.append("\n## 0x7DC2 downstream output/service transition analysis")
    sections.append("- 0x6833 ends with `LJMP 0x7DC2` after packet/context setup calls; this supports downstream transition/finalization role.")
    sections.append(f"- Callers: {', '.join(ev['callers']) or 'none in call_xref (LJMP source from 0x6833 observed)'}.")
    sections.append(f"- Direct callees from 0x7DC2 block: {', '.join(ev['callees']) or '0x7121 within hosting parent block'}.")
    sections.append("- Basic-block map places 0x7DC2 inside parent 0x7D85, so this address is likely a sub-entry/tail block rather than an independent large function.")
    sections.append(f"- Output transition map references into this target: {len(trans)} rows.")
    sections.append("- Cautious role: output/service transition tail that writes final bytes to XDATA and returns; not enough evidence to call it packet finalizer exclusively.")
    sections.append("\n```c\nvoid fn_7DC2(...) {\n    // downstream sub-block in parent routine (0x7D85)\n    // call helper(s) (e.g., 0x7121), then emit several bytes via MOVX @DPTR\n    // return to caller chain tail\n}\n```")

    sections.append("\n## Relationship to existing chain")
    sections.append("```text")
    sections.append("0x497A shared runtime/state dispatcher")
    sections.append("  -> 0x737C zone/object logic candidate                [prior trace hypothesis + static adjacency]")
    sections.append("  -> 0x613C state latch/update                         [direct call (existing upstream report)]")
    sections.append("  -> 0x84A6 mode/event bridge candidate                [prior trace hypothesis + static adjacency]")
    sections.append("  -> 0x728A probable mode gate                         [direct call from 0x84A6]")
    sections.append("      manual-like -> 0x5A7F packet/export bridge      [direct call]")
    sections.append("      auto-like   -> 0x6833 probable output-start      [direct call (existing downstream context)]")
    sections.append("          -> 0x7922 service/event helper               [direct call]")
    sections.append("          -> 0x597F condition check                    [direct call]")
    sections.append("          -> XDATA[dptr] = 0x04                        [direct write in 0x6833]")
    sections.append("          -> 0x5A7F packet/export bridge               [direct call]")
    sections.append("          -> 0x7DC2 downstream transition              [direct LJMP to sub-block in 0x7D85]")
    sections.append("```")

    sections.append("\n## Evidence separation")
    sections.append("- **Static code evidence:** call graph edges, immediate constants, DPTR/XDATA accesses, and basic-block adjacency from CSV artifacts.")
    sections.append("- **Manual pseudocode interpretation:** helper roles inferred from compact instruction patterns (pointer bridge, table read helper, masked condition helper).")
    sections.append("- **Chain adjacency evidence:** prior reports (`manual_decompile_0x728A_0x6833.md`, `auto_manual_gating_deep_trace_analysis.md`) used only as contextual adjacency, not as proof of physical action.")
    sections.append("- **Unknown physical meaning:** no direct claim is made that these addresses correspond to specific field actuators or named physical devices.")

    sections.append("\n## Pseudocode section (specific, non-generic)")
    for addr in TARGETS:
        sections.append(f"\n### {addr}")
        sections.append("```c")
        sections.append(SPECIFIC_PSEUDOCODE[addr])
        sections.append("```")

    (DOCS / "manual_dks_downstream_decompile.md").write_text("\n".join(sections).rstrip() + "\n", encoding="utf-8")

    summary_rows = [
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x5A7F",
            "previous_role": CSV_PREVIOUS_ROLE["0x5A7F"],
            "new_manual_role": MANUAL_ROLES["0x5A7F"],
            "confidence": CSV_CONFIDENCE["0x5A7F"],
            "evidence_sources": "manual_dks_downstream_decompile.md;call_xref.csv;basic_block_map.csv;xdata_confirmed_access.csv;xdata_branch_trace_map.csv",
            "xdata_refs": "",
            "callers": "0x497A|0x728A|0x6833-context high fan-in",
            "callees": "",
            "chain_relation": "direct call adjacency from 0x728A/0x6833 paths",
            "notes": "tiny DPTR staging / pointer-like helper; high fan-in; not full packet builder by itself; packet/export role is bridge-like",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x737C",
            "previous_role": CSV_PREVIOUS_ROLE["0x737C"],
            "new_manual_role": MANUAL_ROLES["0x737C"],
            "confidence": CSV_CONFIDENCE["0x737C"],
            "evidence_sources": "manual_dks_downstream_decompile.md;enum_branch_value_map.csv;xdata_confirmed_access.csv;call_xref.csv",
            "xdata_refs": "0x3010|0x3011|0x3012|0x3013|0x3014|0x301A|0x301B|0x31BF|0x36D3|0x36EC|0x36EE|0x36EF|0x36F2|0x36F3|0x36F4|0x36FC|0x36FD",
            "callers": "0x73FD",
            "callees": "0x84A6|0x5A7F",
            "chain_relation": "static adjacency in 0x497A->0x737C->0x84A6 chain hypothesis",
            "notes": "reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like evidence 0x03/0x07",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x84A6",
            "previous_role": CSV_PREVIOUS_ROLE["0x84A6"],
            "new_manual_role": MANUAL_ROLES["0x84A6"],
            "confidence": CSV_CONFIDENCE["0x84A6"],
            "evidence_sources": "manual_dks_downstream_decompile.md;manual_auto_branch_map.csv;xdata_confirmed_access.csv;call_xref.csv",
            "xdata_refs": "0x315B|0x3181|0x3640|0x36D3|0x36D9",
            "callers": "0x7105|0x73FD",
            "callees": "0x728A|0x5A7F",
            "chain_relation": "direct call to 0x728A and direct call to 0x5A7F in selected paths",
            "notes": "reads 0x315B/0x3181/0x3640/0x36D3/0x36D9; calls 0x728A and 0x5A7F; possible manual/auto bridge but physical semantics unknown",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x7922",
            "previous_role": CSV_PREVIOUS_ROLE["0x7922"],
            "new_manual_role": MANUAL_ROLES["0x7922"],
            "confidence": CSV_CONFIDENCE["0x7922"],
            "evidence_sources": "manual_dks_downstream_decompile.md;call_xref.csv;basic_block_map.csv",
            "xdata_refs": "DPTR-indirect two-byte read helper",
            "callers": "0x728A/0x6833 paths",
            "callees": "",
            "chain_relation": "direct call helper in downstream gate/output paths",
            "notes": "tiny helper; reads two bytes from @DPTR into R0/R1; no direct packet/export call inside; called from 0x728A/0x6833 paths",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x597F",
            "previous_role": CSV_PREVIOUS_ROLE["0x597F"],
            "new_manual_role": MANUAL_ROLES["0x597F"],
            "confidence": CSV_CONFIDENCE["0x597F"],
            "evidence_sources": "manual_dks_downstream_decompile.md;call_xref.csv;basic_block_map.csv",
            "xdata_refs": "",
            "callers": "0x6833 path",
            "callees": "",
            "chain_relation": "direct helper call before downstream output-start write path",
            "notes": "compact helper; likely A & 0x07; result used by 0x6833 before output-start write; exact permission/fault/mode meaning unknown",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x7DC2",
            "previous_role": CSV_PREVIOUS_ROLE["0x7DC2"],
            "new_manual_role": MANUAL_ROLES["0x7DC2"],
            "confidence": CSV_CONFIDENCE["0x7DC2"],
            "evidence_sources": "manual_dks_downstream_decompile.md;output_transition_map.csv;basic_block_map.csv;call_xref.csv",
            "xdata_refs": "0x0001(read)",
            "callers": "0x6833 tail LJMP",
            "callees": "0x7121|0x7D9B",
            "chain_relation": "tail transition from 0x6833 into sub-block inside parent 0x7D85",
            "notes": "LJMP target from 0x6833 tail; sub-block inside parent 0x7D85; calls 0x7121 and 0x7D9B; not proven packet finalizer exclusively",
        },
    ]
    with (DOCS / "manual_dks_downstream_decompile_summary.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_HEADERS)
        writer.writeheader()
        writer.writerows(summary_rows)

    pseudocode_rows = [
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x5A7F",
            "pseudocode_block": SPECIFIC_PSEUDOCODE["0x5A7F"],
            "known_operations": "tiny helper; DPTR staging; high fan-in; caller performs MOVX after this helper; packet/export-adjacent bridge",
            "unknown_operations": "whether it is packet sink, pointer resolver, or packet-field bridge; exact selector/index meaning",
            "confidence": CSV_CONFIDENCE["0x5A7F"],
            "notes": "conservative role: bridge-like helper, not full builder by itself",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x737C",
            "pseudocode_block": SPECIFIC_PSEUDOCODE["0x737C"],
            "known_operations": "reads/writes 0x3010/0x3011/0x3012/0x3013/0x3014/0x301A/0x301B; reads 0x31BF and 0x36xx cluster; calls 0x84A6 and 0x5A7F; enum-like values 0x03/0x07",
            "unknown_operations": "exact physical semantics for branch outcomes and object-state meaning",
            "confidence": CSV_CONFIDENCE["0x737C"],
            "notes": "kept as zone/object logic candidate with conservative confidence",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x84A6",
            "pseudocode_block": SPECIFIC_PSEUDOCODE["0x84A6"],
            "known_operations": "reads 0x315B/0x3181/0x3640/0x36D3/0x36D9; calls 0x728A; calls 0x5A7F",
            "unknown_operations": "manual/auto physical mapping remains hypothesis; exact event semantics unknown",
            "confidence": CSV_CONFIDENCE["0x84A6"],
            "notes": "bridge interpretation kept conservative",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x7922",
            "pseudocode_block": SPECIFIC_PSEUDOCODE["0x7922"],
            "known_operations": "tiny helper; reads two bytes from XDATA @DPTR into R0/R1; no direct packet/export call inside",
            "unknown_operations": "exact table/service semantic meaning of fetched bytes",
            "confidence": CSV_CONFIDENCE["0x7922"],
            "notes": "usable as state-table reader/service-event helper without overclaiming semantics",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x597F",
            "pseudocode_block": SPECIFIC_PSEUDOCODE["0x597F"],
            "known_operations": "compact helper; likely A & 0x07; used by 0x6833 before output-start write",
            "unknown_operations": "exact permission/fault/mode semantics of bitmask result",
            "confidence": CSV_CONFIDENCE["0x597F"],
            "notes": "condition-check helper role preserved",
        },
        {
            "branch": BRANCH,
            "file": PRIMARY_FILE,
            "function_addr": "0x7DC2",
            "pseudocode_block": SPECIFIC_PSEUDOCODE["0x7DC2"],
            "known_operations": "LJMP target from 0x6833 tail; sub-block in parent 0x7D85; calls 0x7121 and 0x7D9B",
            "unknown_operations": "whether it is exclusively a packet finalizer remains unknown",
            "confidence": CSV_CONFIDENCE["0x7DC2"],
            "notes": "treated as downstream output/service transition tail",
        },
    ]
    with (DOCS / "manual_dks_downstream_pseudocode.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=PSEUDOCODE_HEADERS)
        writer.writeheader()
        writer.writerows(pseudocode_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
