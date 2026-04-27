#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

CANDIDATE_FIELDS = [
    "branch",
    "file",
    "screen_name",
    "device_version",
    "slot",
    "module_label",
    "label_confidence",
    "function_addr",
    "candidate_role",
    "module_presence_confidence",
    "function_candidate_confidence",
    "evidence_level",
    "evidence_sources",
    "xdata_refs",
    "calls_in",
    "calls_out",
    "call_targets",
    "packet_export_path",
    "related_known_chain",
    "score",
    "notes",
]

SLOT_FIELDS = [
    "branch",
    "file",
    "screen_name",
    "device_version",
    "slot",
    "module_label",
    "label_confidence",
    "screen_presence_confidence",
    "strongest_function_candidates",
    "strongest_candidate_roles",
    "function_resolution_status",
    "confidence",
    "notes",
]

MODULE_TO_ROLES = {
    "MDS": ["mds_discrete_scan", "mds_state_update", "mds_event_generation", "packet_export_bridge"],
    "MUP": ["mup_command_builder", "mup_start_or_control_action", "mup_feedback_check", "mup_fault_detection", "packet_export_bridge"],
    "MASH": ["mash_address_loop_handler", "mash_sensor_state_decode", "mash_event_generation", "packet_export_bridge"],
    "PVK": ["pvk_unknown_dispatcher", "pvk_state_or_feedback", "packet_export_bridge"],
    "unknown_MSHS_like": ["unknown_module_dispatcher", "unknown_module_state_update", "packet_export_bridge"],
    "unknown_MEK_like": ["unknown_module_dispatcher", "unknown_module_state_update", "packet_export_bridge"],
    "MZK_or_PZK": ["unknown_module_dispatcher", "unknown_module_state_update", "packet_export_bridge"],
    "MDS_or_MAS": ["unknown_module_dispatcher", "unknown_module_state_update", "packet_export_bridge"],
}

KNOWN_CHAIN = {
    "0x497A": "0x497A->0x737C->0x613C->0x84A6->0x728A",
    "0x737C": "0x497A->0x737C->0x613C->0x84A6->0x728A",
    "0x613C": "0x497A->0x737C->0x613C->0x84A6->0x728A",
    "0x84A6": "0x497A->0x737C->0x613C->0x84A6->0x728A",
    "0x728A": "mode_gate (manual packet-only vs auto output+packet)",
    "0x6833": "auto-like output start path",
    "0x5A7F": "packet/export path",
}

OBJECT_TAGS_90CYE02 = [
    "90SAE01AA005",
    "90SAE01AA006",
    "90SAE06AA002",
    "90SAE06AA003",
    "90SAE02AA001",
    "90SAE05AA007",
    "90SAE05AA008",
    "90SAE15AA003",
    "90SAE15AA004",
]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def parse_int(v: str) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def parse_score(v: str) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def conf_from_score(score: float) -> str:
    if score >= 0.85:
        return "confirmed"
    if score >= 0.55:
        return "probable"
    if score >= 0.30:
        return "hypothesis"
    return "unknown"


def presence_conf(label_confidence: str) -> str:
    mapping = {
        "confirmed_from_screen": "confirmed",
        "probable_from_screen": "probable",
        "uncertain_from_screen": "hypothesis",
    }
    return mapping.get(label_confidence, "unknown")


def evidence_level(score: float, sources: set[str]) -> str:
    if "screen_configuration" in sources and len(sources) == 1:
        return "screen_configuration"
    if score >= 0.75:
        return "code_direct"
    if score >= 0.35:
        return "code_indirect"
    return "heuristic_only"


def main() -> int:
    dks_rows = read_csv(DOCS / "dks_real_configuration_evidence.csv")
    function_map = read_csv(DOCS / "function_map.csv")
    call_xref = read_csv(DOCS / "call_xref.csv")
    mds_mup = read_csv(DOCS / "mds_mup_module_candidates.csv")
    mash_summary = read_csv(DOCS / "mash_handler_deep_trace_summary.csv")
    input_core = read_csv(DOCS / "input_board_core_matrix.csv")
    xdata_branch = read_csv(DOCS / "xdata_branch_trace_map.csv")
    output_control = read_csv(DOCS / "output_control_candidates.csv")
    manual_auto = read_csv(DOCS / "manual_auto_branch_map.csv")

    target_slots = [r for r in dks_rows if r["label_confidence"] in {"confirmed_from_screen", "probable_from_screen", "uncertain_from_screen"}]

    func_by_file: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for r in function_map:
        func_by_file[r["file"]][r["function_addr"]] = r

    calls_out: dict[tuple[str, str], set[str]] = defaultdict(set)
    calls_in: dict[tuple[str, str], int] = defaultdict(int)
    for r in call_xref:
        f = r["file"]
        src = r["code_addr"] if r["call_type"] == "internal_jump" else r["code_addr"]
        # call_xref has code_addr callsite, so anchor using target-known function where available
        tgt = r["target_addr"]
        if tgt.startswith("0x"):
            calls_in[(f, tgt)] += 1
        if src.startswith("0x"):
            calls_out[(f, src)].add(tgt)

    mds_mup_by_file_module: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for r in mds_mup:
        if r["function_addr"].startswith("0x"):
            mds_mup_by_file_module[(r["file"], r["module_type"])].append(r)

    mash_funcs_by_file: dict[str, set[str]] = defaultdict(set)
    for r in mash_summary:
        for k in ("caller_function", "core_function", "callee_function"):
            if r[k].startswith("0x"):
                mash_funcs_by_file[r["file"]].add(r[k])

    input_core_by_file = {r["file"]: r for r in input_core}

    xbranch_by_file_func: dict[tuple[str, str], int] = defaultdict(int)
    for r in xdata_branch:
        if r["function_addr"].startswith("0x"):
            xbranch_by_file_func[(r["file"], r["function_addr"])] += 1

    out_ctl_by_file_func = {(r["file"], r["function_addr"]): r for r in output_control if r["function_addr"].startswith("0x")}

    manual_auto_set = {(r["file"], r["function_addr"]) for r in manual_auto if r["function_addr"].startswith("0x")}

    candidate_rows: list[dict[str, str]] = []

    for slot in target_slots:
        file = slot["firmware_file"]
        module = slot["module_label"]
        pres = presence_conf(slot["label_confidence"])

        candidate_funcs: set[str] = set()
        if module in {"MDS", "MUP"}:
            for r in mds_mup_by_file_module.get((file, module), []):
                candidate_funcs.add(r["function_addr"])
        if module == "MASH":
            candidate_funcs.update(mash_funcs_by_file.get(file, set()))
        if module in {"PVK", "unknown_MSHS_like", "unknown_MEK_like", "MZK_or_PZK", "MDS_or_MAS"}:
            # conservative unknown-module candidates: top static hubs from function_map and output-control
            for addr, fr in func_by_file[file].items():
                if parse_int(fr.get("call_count", "0")) >= 20 or parse_int(fr.get("xdata_read_count", "0")) >= 20:
                    candidate_funcs.add(addr)
            for (f, addr), _r in out_ctl_by_file_func.items():
                if f == file:
                    candidate_funcs.add(addr)

        if module in {"MUP", "PVK"}:
            for (f, addr) in manual_auto_set:
                if f == file:
                    candidate_funcs.add(addr)

        if not candidate_funcs:
            candidate_rows.append(
                {
                    "branch": slot["branch"],
                    "file": file,
                    "screen_name": slot["screen_name"],
                    "device_version": slot["device_version"],
                    "slot": slot["slot"],
                    "module_label": module,
                    "label_confidence": slot["label_confidence"],
                    "function_addr": "unknown",
                    "candidate_role": "unknown",
                    "module_presence_confidence": pres,
                    "function_candidate_confidence": "unknown",
                    "evidence_level": "screen_configuration",
                    "evidence_sources": "screen_configuration",
                    "xdata_refs": "0",
                    "calls_in": "0",
                    "calls_out": "0",
                    "call_targets": "",
                    "packet_export_path": "unknown",
                    "related_known_chain": "",
                    "score": "0.000",
                    "notes": "screen confirms module presence only; no static function candidate extracted",
                }
            )
            continue

        for addr in sorted(candidate_funcs):
            fm = func_by_file[file].get(addr, {})
            sources: set[str] = set()
            score = 0.0
            xrefs = parse_int(fm.get("xdata_read_count", "0")) + parse_int(fm.get("xdata_write_count", "0"))
            score += min(0.20, xrefs / 250)
            if fm:
                sources.add("function_map")

            mm_match = None
            if module in {"MDS", "MUP"}:
                for r in mds_mup_by_file_module.get((file, module), []):
                    if r["function_addr"] == addr:
                        mm_match = r
                        break
            if mm_match:
                score += 0.30 + min(0.20, parse_score(mm_match["score"]) * 0.40)
                sources.add("mds_mup_module_candidates")

            if addr in mash_funcs_by_file.get(file, set()):
                score += 0.30 if module == "MASH" else 0.08
                sources.add("mash_handler_deep_trace_summary")

            xb = xbranch_by_file_func.get((file, addr), 0)
            if xb:
                score += min(0.12, xb / 500)
                sources.add("xdata_branch_trace_map")

            oc = out_ctl_by_file_func.get((file, addr))
            packet_path = "unknown"
            if oc:
                sources.add("output_control_candidates")
                score += min(0.12, parse_score(oc.get("score", "0")) * 0.20)
                if parse_int(oc.get("packet_export_hits", "0")) > 0:
                    packet_path = "possible"
                    score += 0.05

            if (file, addr) in manual_auto_set:
                score += 0.12 if module == "MUP" else 0.05
                sources.add("manual_auto_branch_map")
                if addr in {"0x728A", "0x6833", "0x5A7F"}:
                    packet_path = "hypothesis"

            input_row = input_core_by_file.get(file)
            if input_row and input_row.get("core_function_addr") == addr:
                score += 0.05
                sources.add("input_board_core_matrix")

            if module in {"PVK", "unknown_MSHS_like", "unknown_MEK_like", "MZK_or_PZK", "MDS_or_MAS"}:
                score = min(score, 0.58)
            if module == "MUP" and addr == "0x6833":
                score = min(score, 0.52)

            score = min(score, 0.92)
            fconf = conf_from_score(score)
            elev = evidence_level(score, sources)

            role = "unknown"
            roles = MODULE_TO_ROLES.get(module, ["unknown"])
            if module == "MDS":
                role = "mds_discrete_scan" if xrefs >= 20 else "mds_state_update"
                if packet_path != "unknown":
                    role = "mds_event_generation"
            elif module == "MUP":
                if addr == "0x6833":
                    role = "mup_start_or_control_action"
                elif addr == "0x728A":
                    role = "mup_command_builder"
                elif addr == "0x5A7F":
                    role = "packet_export_bridge"
                else:
                    role = "mup_feedback_check"
            elif module == "MASH":
                role = "mash_address_loop_handler" if addr in {"0x497A", "0x497F", "0x737C"} else "mash_event_generation"
            elif module == "PVK":
                role = "pvk_unknown_dispatcher" if parse_int(fm.get("call_count", "0")) > 10 else "pvk_state_or_feedback"
            else:
                role = "unknown_module_dispatcher" if parse_int(fm.get("call_count", "0")) > 10 else "unknown_module_state_update"
            if role not in roles:
                role = roles[0]

            calls_out_list = sorted(calls_out.get((file, addr), set()))
            c_out = len(calls_out_list)
            c_in = calls_in.get((file, addr), parse_int(fm.get("incoming_lcalls", "0")))
            rel_chain = KNOWN_CHAIN.get(addr, "")

            notes = []
            notes.append("screen-level module presence is separate from function candidate confidence")
            if module == "PVK":
                notes.append("PVK role unresolved; kept as unknown candidate family")
            if module == "MDS":
                notes.append("MDS kept separate from generic input-board logic")
            if module == "MUP":
                notes.append("MUP not equated with MVK/output module")
            if file in {"90CYE03_19_DKS.PZU", "90CYE04_19_DKS.PZU"} and addr in {"0x728A", "0x6833", "0x5A7F"}:
                notes.append("link to 0x728A/0x6833/0x5A7F chain remains hypothesis unless direct module dispatch proof appears")

            candidate_rows.append(
                {
                    "branch": slot["branch"],
                    "file": file,
                    "screen_name": slot["screen_name"],
                    "device_version": slot["device_version"],
                    "slot": slot["slot"],
                    "module_label": module,
                    "label_confidence": slot["label_confidence"],
                    "function_addr": addr,
                    "candidate_role": role,
                    "module_presence_confidence": pres,
                    "function_candidate_confidence": fconf,
                    "evidence_level": elev,
                    "evidence_sources": "|".join(sorted(sources)) if sources else "screen_configuration",
                    "xdata_refs": str(xrefs),
                    "calls_in": str(c_in),
                    "calls_out": str(c_out),
                    "call_targets": ";".join(calls_out_list[:8]),
                    "packet_export_path": packet_path,
                    "related_known_chain": rel_chain,
                    "score": f"{score:.3f}",
                    "notes": "; ".join(notes),
                }
            )

    candidate_rows.sort(key=lambda r: (r["file"], r["slot"], -float(r["score"]), r["function_addr"]))
    write_csv(DOCS / "dks_module_deep_trace_candidates.csv", CANDIDATE_FIELDS, candidate_rows)

    by_slot: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for r in candidate_rows:
        by_slot[(r["file"], r["slot"], r["module_label"])].append(r)

    slot_rows: list[dict[str, str]] = []
    for slot in target_slots:
        key = (slot["firmware_file"], slot["slot"], slot["module_label"])
        rows = sorted(by_slot.get(key, []), key=lambda r: -float(r["score"]))
        top = rows[:3]
        top_funcs = ", ".join(r["function_addr"] for r in top) if top else "unknown"
        top_roles = ", ".join(r["candidate_role"] for r in top) if top else "unknown"
        top_score = max((float(r["score"]) for r in rows), default=0.0)
        if top_score >= 0.75:
            status = "strong_candidate"
        elif top_score >= 0.55:
            status = "probable_candidate"
        elif top_score >= 0.30:
            status = "weak_candidate"
        else:
            status = "screen_only"

        slot_rows.append(
            {
                "branch": slot["branch"],
                "file": slot["firmware_file"],
                "screen_name": slot["screen_name"],
                "device_version": slot["device_version"],
                "slot": slot["slot"],
                "module_label": slot["module_label"],
                "label_confidence": slot["label_confidence"],
                "screen_presence_confidence": presence_conf(slot["label_confidence"]),
                "strongest_function_candidates": top_funcs,
                "strongest_candidate_roles": top_roles,
                "function_resolution_status": status,
                "confidence": conf_from_score(top_score),
                "notes": "screen evidence and handler candidates are separated; conservative labels only",
            }
        )

    slot_rows.sort(key=lambda r: (r["file"], r["slot"]))
    write_csv(DOCS / "dks_module_slot_summary.csv", SLOT_FIELDS, slot_rows)

    # Markdown
    def top_rows(file: str, module: str, n: int = 5) -> list[dict[str, str]]:
        rows = [r for r in candidate_rows if r["file"] == file and r["module_label"] == module]
        return sorted(rows, key=lambda r: -float(r["score"]))[:n]

    lines: list[str] = []
    lines.append("# DKS module deep-trace analysis (screen-confirmed modules to static code candidates)")
    lines.append("")
    lines.append("Date: 2026-04-27 (UTC).")
    lines.append("")
    lines.append("## Scope and limits")
    lines.append("")
    lines.append("- Scope: static evidence only from repository CSV artifacts; no runtime execution or bench validation.")
    lines.append("- Screen-level module presence and code-level handler candidates are separated explicitly.")
    lines.append("- Screen evidence does **not** prove exact function addresses.")
    lines.append("- MDS is not merged with generic input-board logic without code evidence.")
    lines.append("- MUP is not merged with MVK/output logic without code evidence.")
    lines.append("- PVK remains unknown module family unless stronger direct code evidence appears.")
    lines.append("")
    lines.append("## Screen-level vs code-level interpretation")
    lines.append("")
    lines.append("- `module_presence_confidence` is derived from DKS screen labels (`confirmed/probable/hypothesis`).")
    lines.append("- `function_candidate_confidence` is independent and derived from static features (calls, XDATA, branch traces, chain overlap).")
    lines.append("- Evidence levels: `screen_configuration`, `code_direct`, `code_indirect`, `heuristic_only`.")
    lines.append("")

    per_fw = [
        "ppkp2001 90cye01.PZU",
        "90CYE02_27 DKS.PZU",
        "90CYE03_19_DKS.PZU",
        "90CYE04_19_DKS.PZU",
    ]
    lines.append("## Per-firmware findings")
    lines.append("")
    for fw in per_fw:
        lines.append(f"### {fw}")
        for module in sorted({r['module_label'] for r in candidate_rows if r['file'] == fw}):
            t = top_rows(fw, module, n=3)
            if not t:
                continue
            summary = "; ".join(f"{r['function_addr']} ({r['candidate_role']}, {r['function_candidate_confidence']}, score={r['score']})" for r in t)
            lines.append(f"- {module}: {summary}.")
        if fw == "90CYE02_27 DKS.PZU":
            lines.append(f"- Visible object tags from screen evidence: {', '.join(OBJECT_TAGS_90CYE02)}.")
        lines.append("")

    lines.append("## Per-module view")
    lines.append("")
    for module in ["MDS", "MUP", "MASH", "PVK", "unknown_MSHS_like", "unknown_MEK_like", "MZK_or_PZK", "MDS_or_MAS"]:
        rows = sorted([r for r in candidate_rows if r["module_label"] == module], key=lambda r: -float(r["score"]))[:8]
        lines.append(f"### {module}")
        if not rows:
            lines.append("- No static candidates extracted.")
        else:
            for r in rows:
                lines.append(
                    f"- {r['file']} {r['slot']} -> {r['function_addr']} ({r['candidate_role']}, {r['function_candidate_confidence']}, {r['evidence_level']}, score={r['score']})."
                )
        lines.append("")

    lines.append("## 90CYE03/04 MUP vs known 0x728A/0x6833 chain")
    lines.append("")
    lines.append("- Static evidence links `0x728A`, `0x6833`, and `0x5A7F` through manual/auto branch maps and packet adjacency, but this linkage remains `hypothesis` for MUP module attribution.")
    lines.append("- `0x728A` appears as a mode gate candidate with manual-like packet-only vs auto-like output+packet split in current artifacts.")
    lines.append("- `0x6833` appears on the auto-like output-start side, but this does not by itself prove MUP handler identity.")
    lines.append("- `0x5A7F` is treated as packet/export bridge adjacency, not module identity proof.")
    lines.append("")

    lines.append("## DKS object-status layer")
    lines.append("")
    lines.append("- In `90CYE02_27 DKS.PZU`, screen evidence shows object tags: " + ", ".join(OBJECT_TAGS_90CYE02) + ".")
    lines.append("- Current static artifacts support existence of an object-status/state-event layer, but physical meaning of each object tag is unknown.")
    lines.append("- Candidate state/event/packet paths are reported as probable/hypothesis only; no physical semantics are assigned without direct code/string evidence.")
    lines.append("")

    lines.append("## Next manual decompile targets")
    lines.append("")
    for module, title in [
        ("MDS", "MDS"),
        ("MUP", "MUP"),
        ("MASH", "MASH"),
        ("PVK", "PVK"),
    ]:
        rows = sorted([r for r in candidate_rows if r["module_label"] == module], key=lambda r: -float(r["score"]))[:5]
        picks = ", ".join(f"{r['file']}:{r['function_addr']} ({r['score']})" for r in rows) if rows else "none"
        lines.append(f"- {title}: {picks}.")
    obj_rows = sorted([r for r in candidate_rows if r["file"] == "90CYE02_27 DKS.PZU"], key=lambda r: -float(r["score"]))[:5]
    lines.append("- object-status layer: " + ", ".join(f"{r['function_addr']} ({r['module_label']}, {r['score']})" for r in obj_rows) + ".")

    (DOCS / "dks_module_deep_trace_analysis.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("Generated: docs/dks_module_deep_trace_candidates.csv")
    print("Generated: docs/dks_module_slot_summary.csv")
    print("Generated: docs/dks_module_deep_trace_analysis.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
