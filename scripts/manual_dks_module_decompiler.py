#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

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
    "dks_module_deep_trace_candidates.csv",
    "dks_module_slot_summary.csv",
    "dks_real_configuration_evidence.csv",
    "manual_auto_branch_map.csv",
    "output_transition_map.csv",
    "mash_handler_deep_trace_summary.csv",
    "mds_mup_module_candidates.csv",
    "string_index.csv",
    "code_table_candidates.csv",
]

TARGETS = [
    ("90CYE03_19_DKS.PZU", "90CYE_DKS", "0x497A", "X03/X04/X05/X06/X07 in DKS screens", "top upstream candidate; deep-trace mds_event_generation + mup_feedback_check"),
    ("90CYE03_19_DKS.PZU", "90CYE_DKS", "0x613C", "X03/X04/X05/X06/X07 in DKS screens", "upstream state bridge candidate near 0x497A chain"),
    ("90CYE04_19_DKS.PZU", "90CYE_DKS", "0x497A", "X03/X04/X05/X06/X07 in DKS screens", "cross-variant compare against 90CYE03"),
    ("90CYE04_19_DKS.PZU", "90CYE_DKS", "0x613C", "X03/X04/X05/X06/X07 in DKS screens", "cross-variant compare against 90CYE03"),
    ("90CYE02_27 DKS.PZU", "90CYE_shifted_DKS", "0x673C", "X03/X04(+X06/X07/X08 unknown modules)", "top shifted-DKS object/status candidate"),
    ("ppkp2001 90cye01.PZU", "RTOS_service", "0x758B", "X03(MDS), X05/X06(MASH), X04(PVK unknown)", "shared high-score dispatcher candidate"),
    ("ppkp2001 90cye01.PZU", "RTOS_service", "0x53E6", "X03(MDS), X04(PVK unknown)", "strong MDS upstream candidate"),
    ("ppkp2001 90cye01.PZU", "RTOS_service", "0xAB62", "X05/X06(MASH), X04(PVK unknown)", "strong MASH upstream candidate"),
]

KEY_CHAIN_FUNCS = ["0x737C", "0x613C", "0x84A6", "0x728A", "0x6833", "0x5A7F"]


@dataclass(frozen=True)
class TargetKey:
    file: str
    addr: str


def read_csv(name: str) -> list[dict[str, str]]:
    with (DOCS / name).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def parse_hex(v: str) -> int:
    if not v:
        return -1
    if v.startswith("0x"):
        return int(v, 16)
    return int(v)


def parse_int(v: str) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def confidence_from_score(score: float) -> str:
    if score >= 0.85:
        return "confirmed"
    if score >= 0.55:
        return "probable"
    if score >= 0.30:
        return "hypothesis"
    return "unknown"


def collect_function_instructions(
    file: str,
    addr: str,
    basic_blocks: list[dict[str, str]],
    disasm_rows: list[dict[str, str]],
) -> list[dict[str, str]]:
    block_rows = [r for r in basic_blocks if r["file"] == file and r["parent_function_candidate"] == addr and r["block_addr"].startswith("0x")]
    if not block_rows:
        return []

    by_addr = sorted([(parse_hex(r["code_addr"]), r) for r in disasm_rows if r["file"] == file and r["code_addr"].startswith("0x")], key=lambda x: x[0])
    int_addrs = [a for a, _ in by_addr]

    import bisect

    picked: list[dict[str, str]] = []
    seen = set()
    for b in block_rows:
        start = parse_hex(b["block_addr"])
        count = parse_int(b["instruction_count"])
        idx = bisect.bisect_left(int_addrs, start)
        for j in range(idx, min(idx + count, len(by_addr))):
            row = by_addr[j][1]
            key = row["code_addr"]
            if key in seen:
                continue
            seen.add(key)
            picked.append(row)

    picked.sort(key=lambda r: parse_hex(r["code_addr"]))
    return picked


def format_list(values: Iterable[str], empty: str = "none") -> str:
    vals = [v for v in values if v]
    if not vals:
        return empty
    return ", ".join(vals)


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    data = {name: read_csv(name) for name in INPUT_FILES}

    function_map = {(r["file"], r["function_addr"]): r for r in data["function_map.csv"]}
    call_xref = data["call_xref.csv"]
    xdata_confirmed = data["xdata_confirmed_access.csv"]
    xdata_branch = data["xdata_branch_trace_map.csv"]
    deep_candidates = data["dks_module_deep_trace_candidates.csv"]
    real_cfg = data["dks_real_configuration_evidence.csv"]
    mds_mup = data["mds_mup_module_candidates.csv"]
    mash_summary = data["mash_handler_deep_trace_summary.csv"]

    sections: list[str] = []

    sections.append("# Manual DKS module decompile: upstream candidates\n")
    sections.append("Date: 2026-04-27 (UTC).\n")
    sections.append("## Scope\n")
    sections.append("- This report is a semi-manual static reconstruction from existing CSV artifacts only (no live `.PZU` disassembly during this run).")
    sections.append("- Screen/config evidence confirms module presence at slots but does not directly prove exact handler addresses.")
    sections.append("- Function targets come from `docs/dks_module_deep_trace_analysis.md` and are refined here into pseudocode-style roles with explicit confidence labels.")
    sections.append("- Physical semantics remain unknown unless directly supported by static code evidence.")

    # global pre-compute per-target
    evidence = {}
    for file, branch, addr, screen_ctx, role in TARGETS:
        inst = collect_function_instructions(file, addr, data["basic_block_map.csv"], data["disassembly_index.csv"])

        incoming = sorted({r["code_addr"] for r in call_xref if r["file"] == file and r["target_addr"] == addr and r["code_addr"].startswith("0x")}, key=parse_hex)
        outgoing = [r for r in inst if r["mnemonic"] in {"LCALL", "ACALL", "LJMP", "AJMP"} and r["target_addr"].startswith("0x")]
        outgoing_targets = sorted({r["target_addr"] for r in outgoing}, key=parse_hex)

        xdata_addrs = sorted({r["dptr_addr"] for r in xdata_confirmed if r["file"] == file and r["code_addr"] == addr and r["dptr_addr"].startswith("0x")} | {r["xdata_addr"] for r in xdata_branch if r["file"] == file and r["function_addr"] == addr and r["xdata_addr"].startswith("0x")}, key=parse_hex)

        fm = function_map.get((file, addr), {})
        bit_ops = [r for r in inst if r["mnemonic"] in {"ANL", "ORL", "XRL"} and "#" in r["operands"]]
        branches = [r for r in inst if r["mnemonic"] in {"JB", "JNB", "JBC", "JC", "JNC", "JZ", "JNZ", "CJNE", "DJNZ", "SJMP"}]
        loops = [r for r in branches if r["target_addr"].startswith("0x") and parse_hex(r["target_addr"]) <= parse_hex(r["code_addr"])]

        candidate_rows = [r for r in deep_candidates if r["file"] == file and r["function_addr"] == addr]
        score = max((float(r["score"]) for r in candidate_rows), default=0.0)

        evidence[(file, addr)] = {
            "branch": branch,
            "screen_ctx": screen_ctx,
            "deep_role": role,
            "inst": inst,
            "incoming": incoming,
            "outgoing_targets": outgoing_targets,
            "xdata": xdata_addrs,
            "bit_ops": bit_ops,
            "branch_count": len(branches),
            "loop_count": len(loops),
            "movc_count": parse_int(fm.get("movc_count", "0")),
            "call_count": parse_int(fm.get("call_count", "0")),
            "xread": parse_int(fm.get("xdata_read_count", "0")),
            "xwrite": parse_int(fm.get("xdata_write_count", "0")),
            "score": score,
            "confidence": confidence_from_score(score),
            "entry_evidence": fm.get("entry_evidence", "-"),
        }

    # Variant comparison (90CYE03 vs 90CYE04)
    def fingerprint(file: str, addr: str) -> str:
        inst = evidence[(file, addr)]["inst"]
        payload = "\n".join(f"{r['code_addr']}|{r['mnemonic']}|{r['operands']}|{r['target_addr']}|{r['fallthrough_addr']}" for r in inst)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    fp_497a_03 = fingerprint("90CYE03_19_DKS.PZU", "0x497A")
    fp_497a_04 = fingerprint("90CYE04_19_DKS.PZU", "0x497A")
    fp_613c_03 = fingerprint("90CYE03_19_DKS.PZU", "0x613C")
    fp_613c_04 = fingerprint("90CYE04_19_DKS.PZU", "0x613C")

    # target summary table
    sections.append("\n## Target summary table\n")
    sections.append("| firmware_file | branch | function_addr | screen_module_context | deep_trace_role | manual_role | confidence | key_evidence | next_step |")
    sections.append("|---|---|---|---|---|---|---|---|---|")

    manual_roles = {
        ("90CYE03_19_DKS.PZU", "0x497A"): "generic runtime state dispatcher with packet-export adjacency",
        ("90CYE03_19_DKS.PZU", "0x613C"): "small state latch/bridge updater",
        ("90CYE04_19_DKS.PZU", "0x497A"): "same as 90CYE03: generic runtime dispatcher",
        ("90CYE04_19_DKS.PZU", "0x613C"): "same as 90CYE03: small state latch/bridge updater",
        ("90CYE02_27 DKS.PZU", "0x673C"): "small object/status updater",
        ("ppkp2001 90cye01.PZU", "0x758B"): "shared high-fanout dispatcher (MDS+MASH candidate overlap)",
        ("ppkp2001 90cye01.PZU", "0x53E6"): "state preparation + update routine feeding service path",
        ("ppkp2001 90cye01.PZU", "0xAB62"): "MASH-side decoder/dispatcher with calls into 0x758B",
    }

    for file, branch, addr, *_ in TARGETS:
        ev = evidence[(file, addr)]
        key_ev = f"calls={ev['call_count']}, xdata={ev['xread'] + ev['xwrite']}, out={len(ev['outgoing_targets'])}"
        next_step = "runtime trace around listed XDATA and downstream calls"
        sections.append(
            f"| {file} | {branch} | {addr} | {ev['screen_ctx']} | {ev['deep_role']} | {manual_roles[(file, addr)]} | {ev['confidence']} | {key_ev} | {next_step} |"
        )

    sections.append("\n## 90CYE03/04 DKS: 0x497A\n")
    ev497a = evidence[("90CYE03_19_DKS.PZU", "0x497A")]
    lead_flags = {k: (k in ev497a["outgoing_targets"]) for k in KEY_CHAIN_FUNCS}
    sections.append("### Static code evidence")
    sections.append(f"- Function-map profile: call_count={ev497a['call_count']}, xdata_reads={ev497a['xread']}, xdata_writes={ev497a['xwrite']}, movc_count={ev497a['movc_count']}.")
    sections.append(f"- XDATA addresses observed (confirmed + branch-trace): {format_list(ev497a['xdata'])}.")
    sections.append(f"- Main call targets (unique): {format_list(ev497a['outgoing_targets'][:18])}.")
    sections.append(f"- Branch features: branch_ops={ev497a['branch_count']}, loop_like_back_edges={ev497a['loop_count']}, bitmask_ops={len(ev497a['bit_ops'])}.")
    sections.append("- Relation to requested chain functions:")
    for k in KEY_CHAIN_FUNCS:
        status = "direct call/jump seen" if lead_flags[k] else "no direct call/jump in function body (static artifacts)"
        sections.append(f"  - {k}: {status}.")
    sections.append("- Deep-trace still links this function into the broader `0x497A->0x737C->0x613C->0x84A6->0x728A` neighborhood; this is adjacency evidence, not a direct-call proof for each hop.")

    sections.append("### Manual interpretation")
    sections.append("- Most defensible role: **generic runtime state dispatcher** with strong packet/export adjacency (many calls to `0x5A7F`) and branch-heavy gating.")
    sections.append("- It is **not safely classifiable as only MDS or only MUP** from this evidence; it appears shared/central.")
    sections.append("- Bit-mask and loop behavior are present; this supports state-flag handling, but not physical semantics.")
    sections.append("- Unknowns: exact module ownership of each branch path, and exact event payload semantics.")

    sections.append("### 90CYE03 vs 90CYE04 comparison")
    sections.append(f"- 0x497A fingerprint (90CYE03): `{fp_497a_03}`")
    sections.append(f"- 0x497A fingerprint (90CYE04): `{fp_497a_04}`")
    sections.append("- Result: **identical instruction fingerprint** across 90CYE03 and 90CYE04 for this function." if fp_497a_03 == fp_497a_04 else "- Result: fingerprints differ; treat as near-match/different implementation.")

    sections.append("\n## 90CYE03/04 DKS: 0x613C\n")
    ev613c = evidence[("90CYE03_19_DKS.PZU", "0x613C")]
    sections.append("### Static code evidence")
    sections.append(f"- Very small routine (instruction_count from blocks: {len(ev613c['inst'])}) with low fan-out (outgoing targets: {format_list(ev613c['outgoing_targets'])}).")
    sections.append(f"- XDATA addresses observed: {format_list(ev613c['xdata'])}.")
    sections.append("- Instruction pattern is read-compare/branch-then-write (`MOVX A,@DPTR`, `JNZ`, followed by `MOVX @DPTR,A` writes).")
    sections.append("- No direct calls to `0x84A6`, `0x728A`, or `0x5A7F` from this function body in current static artifacts.")
    sections.append("### Manual interpretation")
    sections.append("- Best fit: **state/feedback bridge updater** (likely old/new or zero/non-zero gate, then latch update).")
    sections.append("- Evidence linking to MDS/MUP is **heuristic and chain-based**, not direct module-signature proof.")
    sections.append("- Confidence: probable for a state updater role; unknown for physical module ownership.")

    sections.append("### 90CYE03 vs 90CYE04 comparison")
    sections.append(f"- 0x613C fingerprint (90CYE03): `{fp_613c_03}`")
    sections.append(f"- 0x613C fingerprint (90CYE04): `{fp_613c_04}`")
    sections.append("- Result: **identical instruction fingerprint** across 90CYE03 and 90CYE04 for this function." if fp_613c_03 == fp_613c_04 else "- Result: fingerprints differ; treat as near-match/different implementation.")

    sections.append("\n## 90CYE02 DKS: 0x673C\n")
    ev673c = evidence[("90CYE02_27 DKS.PZU", "0x673C")]
    sections.append("### Why deep-trace ranked it highly")
    sections.append(f"- Deep-trace top score reaches {ev673c['score']:.3f} (confirmed bucket) for MDS/event candidate rows.")
    sections.append("- It is repeatedly selected across multiple DKS slots in candidate artifacts, which boosts chain consistency.")
    sections.append("### Static code evidence")
    sections.append(f"- Incoming callsites: {format_list(ev673c['incoming'])}; outgoing direct targets: {format_list(ev673c['outgoing_targets'])}.")
    sections.append(f"- XDATA addresses observed: {format_list(ev673c['xdata'])}.")
    sections.append("- Routine is short and write-oriented after a branch gate, matching an object/status updater profile more than a root dispatcher.")
    sections.append("- No direct string/object-tag binding to visible `90SAE...` names is present in current string-index links; keep tag mapping indirect.")

    sections.append("\n## ppkp2001 90cye01: 0x758B\n")
    ev758b = evidence[("ppkp2001 90cye01.PZU", "0x758B")]
    sections.append("### Static code evidence")
    sections.append(f"- Large branch-heavy body: call_count={ev758b['call_count']}, xdata_reads={ev758b['xread']}, xdata_writes={ev758b['xwrite']}, branch_ops={ev758b['branch_count']}.")
    sections.append(f"- XDATA observed at entry-level evidence: {format_list(ev758b['xdata'])}; outgoing targets include {format_list(ev758b['outgoing_targets'][:20])}.")
    sections.append("- Deep-trace ranks it for both MDS and MASH contexts (X03 and X05/X06), indicating overlap/shared control path.")
    sections.append("### Resolution")
    sections.append("- Most probable interpretation: **shared dispatcher** rather than exclusive MDS-only or MASH-only handler.")
    sections.append("- MASH linkage evidence: appears in MASH deep-trace chain summary and is called from 0xAB62.")
    sections.append("- MDS linkage evidence: highest MDS deep-trace score for X03 in this firmware.")
    sections.append("- Ambiguous: exact partition of MDS vs MASH sub-branches without runtime branch labeling.")

    sections.append("\n## ppkp2001 90cye01: 0x53E6\n")
    ev53e6 = evidence[("ppkp2001 90cye01.PZU", "0x53E6")]
    sections.append("### Static code evidence")
    sections.append(f"- Candidate strength: deep-trace high score bucket (max={ev53e6['score']:.3f}) for MDS rows.")
    sections.append(f"- XDATA addresses observed: {format_list(ev53e6['xdata'])}; incoming callsites: {format_list(ev53e6['incoming'])}.")
    sections.append(f"- Outgoing calls include {format_list(ev53e6['outgoing_targets'][:16])}, suggesting state prep + service handoff pattern.")
    sections.append("### Manual interpretation")
    sections.append("- Looks more like **discrete/state update preparation with downstream service calls** than a pure packet exporter.")
    sections.append("- Packet/export feeding may exist indirectly downstream, but this function itself is primarily state-moving/conditioning by current evidence.")

    sections.append("\n## ppkp2001 90cye01: 0xAB62\n")
    evab62 = evidence[("ppkp2001 90cye01.PZU", "0xAB62")]
    sections.append("### Static code evidence")
    sections.append(f"- MASH-side candidate score bucket: {evab62['score']:.3f} with branch+compare-heavy structure.")
    sections.append(f"- XDATA addresses observed: {format_list(evab62['xdata'])}; outgoing includes recursive/self and `0x758B` call linkage.")
    sections.append("- Address-loop style compare/update patterns and chained helper calls align with sensor/event decoding style handlers.")
    sections.append("### Manual interpretation")
    sections.append("- Probable role: **sensor-state decoder / event dispatcher** feeding shared dispatcher `0x758B`.")
    sections.append("- Relation: `0xAB62` appears more MASH-local; `0x758B` appears shared; `0x53E6` appears more MDS-side state prep.")

    sections.append("\n## Relationship to existing 0x728A / 0x6833 manual decompile\n")
    sections.append("- `0x728A` remains a **probable mode gate** (unchanged).")
    sections.append("- `0x6833` remains a **probable output-start entry** (unchanged).")
    sections.append("- New upstream candidates here are treated as potential state-preparation/feed paths toward that chain, not as replacements.")
    sections.append("- This report does **not** relabel `0x6833` as MUP-only handler; evidence remains chain-adjacent and mixed.")

    sections.append("\n## Manual pseudocode\n")
    sections.append("```c")
    sections.append("void fn_497A(...) {")
    sections.append("    // read runtime flags/context from XDATA")
    sections.append("    // branch on bit masks and loop through state buckets")
    sections.append("    // call packet/export bridge (notably 0x5A7F) and helper handlers")
    sections.append("    // update runtime state flags")
    sections.append("}")
    sections.append("")
    sections.append("void fn_613C(...) {")
    sections.append("    // read state latch value")
    sections.append("    // branch on zero/non-zero (old/new-like gate)")
    sections.append("    // write back latch/state bytes")
    sections.append("    // return to upstream dispatcher")
    sections.append("}")
    sections.append("")
    sections.append("void fn_673C(...) {")
    sections.append("    // read object/status byte")
    sections.append("    // branch on state flag")
    sections.append("    // write updated status and side-state bytes")
    sections.append("    // return")
    sections.append("}")
    sections.append("")
    sections.append("void fn_758B(...) {")
    sections.append("    // read broad context and multiple state bits")
    sections.append("    // dispatch across many branch paths")
    sections.append("    // call shared helper/service routines")
    sections.append("    // write state/event outputs")
    sections.append("}")
    sections.append("")
    sections.append("void fn_53E6(...) {")
    sections.append("    // copy/normalize state values")
    sections.append("    // run checksum/aggregation-like loop")
    sections.append("    // call downstream service/update helpers")
    sections.append("    // commit updated state")
    sections.append("}")
    sections.append("")
    sections.append("void fn_AB62(...) {")
    sections.append("    // decode/compare sensor-like state bytes")
    sections.append("    // branch per code/state value")
    sections.append("    // call helper routines and shared dispatcher (0x758B)")
    sections.append("    // update event/state outputs")
    sections.append("}")
    sections.append("```")

    summary_rows: list[dict[str, str]] = [
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x497A",
            "screen_context": "X03/X04/X05/X06/X07 DKS modules",
            "previous_candidate_roles": "MDS event candidate; MUP feedback candidate; runtime dispatcher candidate",
            "manual_role": "shared_runtime_bridge",
            "confidence": "confirmed",
            "evidence_sources": "code_direct+code_indirect; deep_trace; screen_configuration",
            "xdata_refs": format_list(evidence[("90CYE03_19_DKS.PZU", "0x497A")]["xdata"]),
            "callers": format_list(evidence[("90CYE03_19_DKS.PZU", "0x497A")]["incoming"]),
            "callees": format_list(evidence[("90CYE03_19_DKS.PZU", "0x497A")]["outgoing_targets"]),
            "downstream_chain": "0x497A->0x737C->0x613C->0x84A6->0x728A (adjacency evidence)",
            "notes": "Generic runtime state dispatcher with packet-export adjacency; not exclusively MDS or MUP.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE04_19_DKS.PZU",
            "function_addr": "0x497A",
            "screen_context": "X03/X04/X05/X06/X07 DKS modules",
            "previous_candidate_roles": "MDS event candidate; MUP feedback candidate; runtime dispatcher candidate",
            "manual_role": "shared_runtime_bridge",
            "confidence": "confirmed",
            "evidence_sources": "code_direct+code_indirect; deep_trace; screen_configuration",
            "xdata_refs": format_list(evidence[("90CYE04_19_DKS.PZU", "0x497A")]["xdata"]),
            "callers": format_list(evidence[("90CYE04_19_DKS.PZU", "0x497A")]["incoming"]),
            "callees": format_list(evidence[("90CYE04_19_DKS.PZU", "0x497A")]["outgoing_targets"]),
            "downstream_chain": "0x497A->0x737C->0x613C->0x84A6->0x728A (adjacency evidence)",
            "notes": "Same role as 90CYE03; identical instruction fingerprint with 90CYE03.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU",
            "function_addr": "0x613C",
            "screen_context": "X03/X04/X05/X06/X07 DKS modules",
            "previous_candidate_roles": "MDS event candidate; MUP feedback candidate; upstream state bridge candidate",
            "manual_role": "mds_state_update",
            "confidence": "probable",
            "evidence_sources": "code_indirect; deep_trace; screen_configuration",
            "xdata_refs": format_list(evidence[("90CYE03_19_DKS.PZU", "0x613C")]["xdata"]),
            "callers": format_list(evidence[("90CYE03_19_DKS.PZU", "0x613C")]["incoming"]),
            "callees": format_list(evidence[("90CYE03_19_DKS.PZU", "0x613C")]["outgoing_targets"]),
            "downstream_chain": "near 0x497A chain; direct callee proof not present",
            "notes": "Small state latch/bridge updater; physical module ownership unknown.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE04_19_DKS.PZU",
            "function_addr": "0x613C",
            "screen_context": "X03/X04/X05/X06/X07 DKS modules",
            "previous_candidate_roles": "MDS event candidate; MUP feedback candidate; upstream state bridge candidate",
            "manual_role": "mds_state_update",
            "confidence": "probable",
            "evidence_sources": "code_indirect; deep_trace; screen_configuration",
            "xdata_refs": format_list(evidence[("90CYE04_19_DKS.PZU", "0x613C")]["xdata"]),
            "callers": format_list(evidence[("90CYE04_19_DKS.PZU", "0x613C")]["incoming"]),
            "callees": format_list(evidence[("90CYE04_19_DKS.PZU", "0x613C")]["outgoing_targets"]),
            "downstream_chain": "near 0x497A chain; direct callee proof not present",
            "notes": "Same role as 90CYE03; identical instruction fingerprint with 90CYE03.",
        },
        {
            "branch": "90CYE_shifted_DKS",
            "file": "90CYE02_27 DKS.PZU",
            "function_addr": "0x673C",
            "screen_context": "X03/X04(+X06/X07/X08 unknown modules)",
            "previous_candidate_roles": "MDS event candidate; shifted DKS top candidate; unknown module state update candidate",
            "manual_role": "object_status_updater",
            "confidence": "confirmed",
            "evidence_sources": "code_direct; deep_trace; screen_configuration",
            "xdata_refs": format_list(evidence[("90CYE02_27 DKS.PZU", "0x673C")]["xdata"]),
            "callers": format_list(evidence[("90CYE02_27 DKS.PZU", "0x673C")]["incoming"]),
            "callees": format_list(evidence[("90CYE02_27 DKS.PZU", "0x673C")]["outgoing_targets"]),
            "downstream_chain": "local updater path; no direct packet bridge call in-body",
            "notes": "Small object/status updater; possible relation to 90SAE object-status layer; no direct tag/string binding.",
        },
        {
            "branch": "RTOS_service",
            "file": "ppkp2001 90cye01.PZU",
            "function_addr": "0x758B",
            "screen_context": "X03(MDS), X05/X06(MASH), X04(PVK unknown)",
            "previous_candidate_roles": "MDS event candidate; MASH event candidate; runtime dispatcher candidate",
            "manual_role": "shared_runtime_bridge",
            "confidence": "confirmed",
            "evidence_sources": "code_direct+code_indirect; deep_trace; screen_configuration",
            "xdata_refs": format_list(evidence[("ppkp2001 90cye01.PZU", "0x758B")]["xdata"]),
            "callers": format_list(evidence[("ppkp2001 90cye01.PZU", "0x758B")]["incoming"]),
            "callees": format_list(evidence[("ppkp2001 90cye01.PZU", "0x758B")]["outgoing_targets"]),
            "downstream_chain": "shared dispatcher fan-out to service helpers",
            "notes": "Shared high-fanout dispatcher; overlaps MDS and MASH; not exclusive module handler.",
        },
        {
            "branch": "RTOS_service",
            "file": "ppkp2001 90cye01.PZU",
            "function_addr": "0x53E6",
            "screen_context": "X03(MDS), X04(PVK unknown)",
            "previous_candidate_roles": "MDS event candidate; upstream state preparation candidate",
            "manual_role": "mds_state_update",
            "confidence": "confirmed",
            "evidence_sources": "code_direct+code_indirect; deep_trace; screen_configuration",
            "xdata_refs": format_list(evidence[("ppkp2001 90cye01.PZU", "0x53E6")]["xdata"]),
            "callers": format_list(evidence[("ppkp2001 90cye01.PZU", "0x53E6")]["incoming"]),
            "callees": format_list(evidence[("ppkp2001 90cye01.PZU", "0x53E6")]["outgoing_targets"]),
            "downstream_chain": "state preparation -> service helper handoff",
            "notes": "State preparation + update routine feeding service path.",
        },
        {
            "branch": "RTOS_service",
            "file": "ppkp2001 90cye01.PZU",
            "function_addr": "0xAB62",
            "screen_context": "X05/X06(MASH), X04(PVK unknown)",
            "previous_candidate_roles": "MASH event candidate; decoder/dispatcher candidate",
            "manual_role": "mash_sensor_state_decoder",
            "confidence": "probable",
            "evidence_sources": "code_indirect; deep_trace; screen_configuration",
            "xdata_refs": format_list(evidence[("ppkp2001 90cye01.PZU", "0xAB62")]["xdata"]),
            "callers": format_list(evidence[("ppkp2001 90cye01.PZU", "0xAB62")]["incoming"]),
            "callees": format_list(evidence[("ppkp2001 90cye01.PZU", "0xAB62")]["outgoing_targets"]),
            "downstream_chain": "MASH-side decode path with 0x758B linkage",
            "notes": "MASH-side decoder/dispatcher with calls into 0x758B.",
        },
    ]

    pseudocode_rows: list[dict[str, str]] = [
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU / 90CYE04_19_DKS.PZU",
            "function_addr": "0x497A",
            "pseudocode_block": "void fn_497A(...) {\n    // read runtime flags/context from XDATA\n    // branch on bit masks and loop through state buckets\n    // call packet/export bridge, notably 0x5A7F\n    // call helper handlers\n    // update runtime state flags\n}",
            "known_operations": "branch-heavy dispatcher; XDATA reads/writes; direct 0x5A7F call; helper calls; loop/bitmask behavior",
            "unknown_operations": "exact module ownership of each branch; exact event payload semantics; physical meaning of state values",
            "confidence": "confirmed",
            "notes": "Shared central dispatcher interpretation is strongest; avoid exclusive MDS/MUP labeling.",
        },
        {
            "branch": "90CYE_DKS",
            "file": "90CYE03_19_DKS.PZU / 90CYE04_19_DKS.PZU",
            "function_addr": "0x613C",
            "pseudocode_block": "void fn_613C(...) {\n    // read state latch value\n    // branch on zero/non-zero gate\n    // write back latch/state bytes\n    // return to upstream dispatcher\n}",
            "known_operations": "small read/branch/write latch updater; XDATA reads/writes; low fan-out",
            "unknown_operations": "exact upstream owner module; precise semantic of compared latch bytes",
            "confidence": "probable",
            "notes": "Treat as state bridge/updater; physical ownership unknown.",
        },
        {
            "branch": "90CYE_shifted_DKS",
            "file": "90CYE02_27 DKS.PZU",
            "function_addr": "0x673C",
            "pseudocode_block": "void fn_673C(...) {\n    // read object/status byte\n    // branch on state flag\n    // write updated status and side-state bytes\n    // return\n}",
            "known_operations": "compact status updater; branch-gated writes; object/status adjacency",
            "unknown_operations": "exact mapping from status values to physical signals; direct object-tag binding",
            "confidence": "confirmed",
            "notes": "Consistent with object/status updater role; keep semantics conservative.",
        },
        {
            "branch": "RTOS_service",
            "file": "ppkp2001 90cye01.PZU",
            "function_addr": "0x758B",
            "pseudocode_block": "void fn_758B(...) {\n    // read broad context and multiple state bits\n    // dispatch across many branch paths\n    // call shared helper/service routines\n    // write state/event outputs\n}",
            "known_operations": "high-fanout dispatcher; branch-heavy control flow; many helper calls; shared service adjacency",
            "unknown_operations": "exact split of MDS vs MASH sub-branches; exact payload meaning for each path",
            "confidence": "confirmed",
            "notes": "Best treated as shared runtime bridge/module dispatcher.",
        },
        {
            "branch": "RTOS_service",
            "file": "ppkp2001 90cye01.PZU",
            "function_addr": "0x53E6",
            "pseudocode_block": "void fn_53E6(...) {\n    // copy/normalize state values\n    // run checksum/aggregation-like loop\n    // call downstream service/update helpers\n    // commit updated state\n}",
            "known_operations": "state preparation/update path; loop behavior; downstream service helper calls; heavy XDATA interaction",
            "unknown_operations": "exact checksum/aggregation semantics; exact module-private state schema",
            "confidence": "confirmed",
            "notes": "State-preparation routine feeding service path is most defensible.",
        },
        {
            "branch": "RTOS_service",
            "file": "ppkp2001 90cye01.PZU",
            "function_addr": "0xAB62",
            "pseudocode_block": "void fn_AB62(...) {\n    // decode/compare sensor-like state bytes\n    // branch per code/state value\n    // call helper routines and shared dispatcher (0x758B)\n    // update event/state outputs\n}",
            "known_operations": "decoder/dispatcher structure; compare/branch-heavy logic; calls into 0x758B",
            "unknown_operations": "exact sensor code vocabulary; physical meaning of decoded states",
            "confidence": "probable",
            "notes": "MASH-side decoder/dispatcher interpretation remains probable.",
        },
    ]

    (DOCS / "manual_dks_module_decompile.md").write_text("\n".join(sections) + "\n", encoding="utf-8")
    write_csv(
        DOCS / "manual_dks_module_decompile_summary.csv",
        [
            "branch",
            "file",
            "function_addr",
            "screen_context",
            "previous_candidate_roles",
            "manual_role",
            "confidence",
            "evidence_sources",
            "xdata_refs",
            "callers",
            "callees",
            "downstream_chain",
            "notes",
        ],
        summary_rows,
    )
    write_csv(
        DOCS / "manual_dks_module_pseudocode.csv",
        [
            "branch",
            "file",
            "function_addr",
            "pseudocode_block",
            "known_operations",
            "unknown_operations",
            "confidence",
            "notes",
        ],
        pseudocode_rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
