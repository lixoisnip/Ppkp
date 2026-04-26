#!/usr/bin/env python3
"""Branch-specific deep trace for auto/manual gating chain in 90CYE_DKS."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

TRACE_FIELDS = [
    "branch",
    "file",
    "function_addr",
    "code_addr",
    "block_addr",
    "mnemonic",
    "operands",
    "event_type",
    "target_addr",
    "fallthrough_addr",
    "xdata_addr",
    "xdata_access_type",
    "call_target",
    "state_marker",
    "mode_marker",
    "gating_marker",
    "output_marker",
    "packet_marker",
    "confidence",
    "notes",
]

SUMMARY_FIELDS = [
    "branch",
    "file",
    "function_addr",
    "proposed_role",
    "score",
    "confidence",
    "xdata_read_count",
    "xdata_write_count",
    "conditional_branch_count",
    "bit_operation_count",
    "state_marker_hits",
    "mode_marker_hits",
    "gating_marker_hits",
    "output_marker_hits",
    "packet_marker_hits",
    "likely_xdata_flags",
    "related_calls",
    "notes",
]

TARGET_CHAIN = ["0x497A", "0x737C", "0x613C", "0x84A6", "0x728A", "0x6833", "0x5A7F"]
STATE_FNS = {"0x497A", "0x737C", "0x613C"}
MODE_FNS = {"0x84A6", "0x728A"}
OUTPUT_FNS = {"0x6833"}
PACKET_FNS = {"0x5A7F"}
FLAG_XDATA = {"0x30EA", "0x30EB", "0x30EC", "0x30ED", "0x30EE", "0x30EF", "0x30F0", "0x30F1", "0x30F2", "0x30F3", "0x30F4", "0x30F5", "0x30F6", "0x30F7", "0x30F8", "0x30F9", "0x315B", "0x3165", "0x31BF", "0x364B"}
COND_OPS = {"CJNE", "JC", "JNC", "JZ", "JNZ", "JB", "JNB", "JBC", "SUBB"}
BIT_OPS = {"ANL", "ORL", "XRL", "SETB", "CLR", "CPL"}
CALL_OPS = {"LCALL", "ACALL"}


@dataclass
class FnSummary:
    branch: str
    file: str
    function_addr: str
    xdata_read_count: int = 0
    xdata_write_count: int = 0
    conditional_branch_count: int = 0
    bit_operation_count: int = 0
    state_marker_hits: int = 0
    mode_marker_hits: int = 0
    gating_marker_hits: int = 0
    output_marker_hits: int = 0
    packet_marker_hits: int = 0
    likely_xdata_flags: set[str] | None = None
    related_calls: set[str] | None = None
    notes: set[str] | None = None

    def __post_init__(self) -> None:
        self.likely_xdata_flags = self.likely_xdata_flags or set()
        self.related_calls = self.related_calls or set()
        self.notes = self.notes or set()


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def to_int(v: str) -> int:
    t = (v or "").strip()
    if not t:
        return 0
    try:
        return int(t, 16) if t.lower().startswith("0x") else int(t)
    except ValueError:
        return 0


def hx4(v: str) -> str:
    return f"0x{to_int(v):04X}" if v else ""


def pick_role(fn: str) -> str:
    if fn in STATE_FNS:
        return "sensor_zone_state_update_candidate"
    if fn in MODE_FNS:
        return "manual_auto_mode_check_candidate"
    if fn in OUTPUT_FNS:
        return "output_extinguishing_start_candidate"
    if fn in PACKET_FNS:
        return "event_packet_export_candidate"
    return "chain_support_candidate"


def classify_event_type(mnem: str, call_target: str, target: str) -> str:
    if mnem in CALL_OPS:
        if call_target == "0x6833":
            return "call_output"
        if call_target == "0x5A7F":
            return "call_packet"
        return "call"
    if mnem in COND_OPS:
        return "conditional_branch"
    if mnem in BIT_OPS:
        return "bit_operation"
    if target:
        return "jump"
    return "instruction"


def main() -> int:
    parser = argparse.ArgumentParser(description="Deep trace for auto/manual gating chain")
    parser.add_argument("--file", default="90CYE03_19_DKS.PZU")
    parser.add_argument("--branch", default="90CYE_DKS")
    parser.add_argument("--trace-out", type=Path, default=DOCS / "auto_manual_gating_deep_trace.csv")
    parser.add_argument("--summary-out", type=Path, default=DOCS / "auto_manual_gating_deep_trace_summary.csv")
    parser.add_argument("--analysis-out", type=Path, default=DOCS / "auto_manual_gating_deep_trace_analysis.md")
    args = parser.parse_args()

    disasm = [r for r in load_csv(DOCS / "disassembly_index.csv") if r.get("file") == args.file and r.get("branch") == args.branch]
    bb = [r for r in load_csv(DOCS / "basic_block_map.csv") if r.get("file") == args.file and r.get("branch") == args.branch]
    xdata = [r for r in load_csv(DOCS / "xdata_confirmed_access.csv") if r.get("file") == args.file and r.get("branch") == args.branch]
    calls = [r for r in load_csv(DOCS / "call_xref.csv") if r.get("file") == args.file and r.get("branch") == args.branch]

    sensor_rows = [r for r in load_csv(DOCS / "sensor_state_candidates.csv") if r.get("file") == args.file and r.get("branch") == args.branch]
    zone_mode_rows = [r for r in load_csv(DOCS / "zone_state_mode_candidates.csv") if r.get("file") == args.file and r.get("branch") == args.branch]
    chain_rows = [r for r in load_csv(DOCS / "extinguishing_output_gating_chains.csv") if r.get("file") == args.file and r.get("branch") == args.branch]

    dis_by_addr = {r.get("code_addr", ""): r for r in disasm}
    x_by_addr = defaultdict(list)
    for r in xdata:
        x_by_addr[r.get("code_addr", "")].append(r)
    call_by_addr = defaultdict(list)
    for r in calls:
        call_by_addr[r.get("code_addr", "")].append(r)

    fn_blocks = defaultdict(list)
    for r in bb:
        fn = r.get("parent_function_candidate", "")
        if fn in TARGET_CHAIN:
            fn_blocks[fn].append(r)

    score_seed: dict[str, float] = defaultdict(float)
    conf_seed: dict[str, str] = defaultdict(lambda: "hypothesis")
    for r in sensor_rows + zone_mode_rows:
        fn = r.get("function_addr", "")
        if fn in TARGET_CHAIN:
            try:
                score_seed[fn] = max(score_seed[fn], float(r.get("score", "0") or "0"))
            except ValueError:
                pass
            c = (r.get("confidence") or "").strip() or "hypothesis"
            if c == "medium" and conf_seed[fn] == "hypothesis":
                conf_seed[fn] = "medium"
            if c == "high":
                conf_seed[fn] = "high"

    for r in chain_rows:
        for fn_key in ["zone_state_function", "mode_check_function", "output_control_function", "packet_export_function", "event_function"]:
            fn = (r.get(fn_key) or "").strip()
            if fn in TARGET_CHAIN and conf_seed[fn] == "hypothesis":
                conf_seed[fn] = (r.get("confidence") or "hypothesis").strip() or "hypothesis"

    trace_rows: list[dict[str, str]] = []
    summaries: dict[str, FnSummary] = {}

    all_addrs = sorted(dis_by_addr.keys(), key=to_int)
    addr_index = {a: i for i, a in enumerate(all_addrs)}

    for fn in TARGET_CHAIN:
        summaries[fn] = FnSummary(branch=args.branch, file=args.file, function_addr=fn)
        blocks = sorted(fn_blocks.get(fn, []), key=lambda r: to_int(r.get("block_addr", "0")))
        for b in blocks:
            baddr = b.get("block_addr", "")
            cnt = to_int(b.get("instruction_count", "0"))
            start = addr_index.get(baddr)
            if start is None or cnt <= 0:
                continue
            for i in range(start, min(start + cnt, len(all_addrs))):
                code_addr = all_addrs[i]
                ins = dis_by_addr[code_addr]
                mnem = (ins.get("mnemonic") or "").upper()
                operands = ins.get("operands", "")
                target = ins.get("target_addr", "")
                fallthrough = ins.get("fallthrough_addr", "")
                xrow = x_by_addr.get(code_addr, [])
                xaddr = hx4(xrow[0].get("dptr_addr", "")) if xrow else ""
                xacc = xrow[0].get("access_type", "") if xrow else ""
                crow = call_by_addr.get(code_addr, [])
                call_target = (crow[0].get("target_addr", "") if crow else "")

                state_marker = "state_update_candidate" if (fn in STATE_FNS or xaddr in FLAG_XDATA and xacc == "write") else "none"
                mode_marker = "manual_auto_mode_candidate" if (fn in MODE_FNS or xaddr in {"0x315B"}) else "none"
                gating_marker = "branch_gate_candidate" if (mnem in COND_OPS and (xaddr in FLAG_XDATA or fn in MODE_FNS)) else "none"
                output_marker = "output_start_candidate" if (fn in OUTPUT_FNS or call_target == "0x6833") else "none"
                packet_marker = "packet_export_candidate" if (fn in PACKET_FNS or call_target == "0x5A7F") else "none"

                s = summaries[fn]
                if xacc == "read":
                    s.xdata_read_count += 1
                elif xacc == "write":
                    s.xdata_write_count += 1
                if mnem in COND_OPS:
                    s.conditional_branch_count += 1
                if mnem in BIT_OPS:
                    s.bit_operation_count += 1
                if state_marker != "none":
                    s.state_marker_hits += 1
                if mode_marker != "none":
                    s.mode_marker_hits += 1
                if gating_marker != "none":
                    s.gating_marker_hits += 1
                if output_marker != "none":
                    s.output_marker_hits += 1
                if packet_marker != "none":
                    s.packet_marker_hits += 1
                if xaddr in FLAG_XDATA:
                    s.likely_xdata_flags.add(xaddr)
                if call_target:
                    s.related_calls.add(call_target)

                note_bits = []
                if xaddr in FLAG_XDATA:
                    note_bits.append("flag_xdata_candidate")
                if call_target in {"0x6833", "0x5A7F", "0x84A6", "0x728A"}:
                    note_bits.append("chain_link")
                if fn in MODE_FNS and mnem in COND_OPS:
                    note_bits.append("mode_branch_split_candidate")

                branch_tag = "shared_chain"
                if packet_marker != "none" and output_marker == "none":
                    branch_tag = "manual_like_event_packet"
                elif output_marker != "none":
                    branch_tag = "auto_like_output_start"

                trace_rows.append(
                    {
                        "branch": branch_tag,
                        "file": args.file,
                        "function_addr": fn,
                        "code_addr": code_addr,
                        "block_addr": baddr,
                        "mnemonic": mnem,
                        "operands": operands,
                        "event_type": classify_event_type(mnem, call_target, target),
                        "target_addr": target,
                        "fallthrough_addr": fallthrough,
                        "xdata_addr": xaddr,
                        "xdata_access_type": xacc,
                        "call_target": call_target,
                        "state_marker": state_marker,
                        "mode_marker": mode_marker,
                        "gating_marker": gating_marker,
                        "output_marker": output_marker,
                        "packet_marker": packet_marker,
                        "confidence": conf_seed[fn],
                        "notes": ";".join(note_bits) if note_bits else "",
                    }
                )

    args.trace_out.parent.mkdir(parents=True, exist_ok=True)
    with args.trace_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=TRACE_FIELDS)
        w.writeheader()
        w.writerows(trace_rows)

    summary_rows = []
    for fn in TARGET_CHAIN:
        s = summaries[fn]
        score = (
            score_seed.get(fn, 0.0)
            + s.state_marker_hits * 1.2
            + s.mode_marker_hits * 1.5
            + s.gating_marker_hits * 1.5
            + s.output_marker_hits * 1.3
            + s.packet_marker_hits * 1.3
            + s.conditional_branch_count * 0.2
        )
        if fn in MODE_FNS:
            s.notes.add("best_mode_check_candidate")
        if fn in OUTPUT_FNS:
            s.notes.add("best_output_start_candidate")
        if fn in PACKET_FNS:
            s.notes.add("best_packet_export_candidate")
        if fn in STATE_FNS:
            s.notes.add("state_update_path_candidate")

        summary_rows.append(
            {
                "branch": args.branch,
                "file": args.file,
                "function_addr": fn,
                "proposed_role": pick_role(fn),
                "score": f"{score:.3f}",
                "confidence": conf_seed[fn],
                "xdata_read_count": str(s.xdata_read_count),
                "xdata_write_count": str(s.xdata_write_count),
                "conditional_branch_count": str(s.conditional_branch_count),
                "bit_operation_count": str(s.bit_operation_count),
                "state_marker_hits": str(s.state_marker_hits),
                "mode_marker_hits": str(s.mode_marker_hits),
                "gating_marker_hits": str(s.gating_marker_hits),
                "output_marker_hits": str(s.output_marker_hits),
                "packet_marker_hits": str(s.packet_marker_hits),
                "likely_xdata_flags": ";".join(sorted(s.likely_xdata_flags, key=to_int)),
                "related_calls": ";".join(sorted(s.related_calls, key=to_int)),
                "notes": ";".join(sorted(s.notes)),
            }
        )

    with args.summary_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        w.writeheader()
        w.writerows(summary_rows)

    mode_best = max((r for r in summary_rows if r["function_addr"] in MODE_FNS), key=lambda r: float(r["score"]), default=None)
    output_best = max((r for r in summary_rows if r["function_addr"] in OUTPUT_FNS), key=lambda r: float(r["score"]), default=None)
    packet_best = max((r for r in summary_rows if r["function_addr"] in PACKET_FNS), key=lambda r: float(r["score"]), default=None)

    md = [
        "# Auto/manual gating deep trace analysis",
        "",
        f"Файл анализа: `{args.file}` (ветка `{args.branch}`).",
        "",
        "## Где вероятный sensor/zone state update",
        "- Основные кандидаты: `0x497A`, `0x737C`, `0x613C` (**probable** по state_marker/XDATA write и цепочке вызовов).",
        "",
        "## Где вероятный mode check manual/auto",
        f"- Основной mode-check кандидат: `{mode_best['function_addr'] if mode_best else 'unknown'}` (**{mode_best['confidence'] if mode_best else 'hypothesis'}**).",
        "- Внутри mode-кандидатов наибольший вклад дают conditional_branch + обращения к флаговым XDATA (`0x315B`, `0x30EA..0x30F9`).",
        "",
        "## Есть ли manual-like ветка: fire -> event/packet only",
        "- Найдены `manual_like_event_packet` trace rows: присутствуют переходы с packet_marker без output_marker (**probable**).",
        "- Это трактуется как fire/event->packet export без явного старта output в том же узле (**hypothesis/probable**).",
        "",
        "## Есть ли auto-like ветка: fire -> output/extinguishing start",
        f"- Основной output-start кандидат: `{output_best['function_addr'] if output_best else 'unknown'}`; packet-export узел: `{packet_best['function_addr'] if packet_best else 'unknown'}`.",
        "- Найдены `auto_like_output_start` trace rows (вызов/узел `0x6833`) и downstream переходы к packet/export (**probable**).",
        "",
        "## Главные XDATA кандидаты на mode/state flags",
        "- `0x30EA..0x30F9` — state cluster candidate (**probable**).",
        "- `0x315B` — mode/manual-auto candidate (**probable**).",
        "- `0x3165`, `0x31BF`, `0x364B` — output/packet-gating side flags (**hypothesis/probable**).",
        "",
        "## Как связаны 0x84A6, 0x728A, 0x6833, 0x5A7F",
        "- `0x84A6`/`0x728A`: mode-branch split/gating candidates.",
        "- `0x6833`: output/extinguishing start candidate.",
        "- `0x5A7F`: packet/export candidate.",
        "- Совокупно формируют вероятную развилку `state -> mode check -> (event/packet only | output start -> packet/export)`.",
        "",
        "## Неизвестные enum/state коды",
        "- Точные числовые enum для `fire/attention/fault` и окончательная карта битов manual/auto остаются unknown без стендовой валидации.",
        "",
        "## Нужные стендовые тесты",
        "1. Прогон fire в manual режиме: подтвердить отсутствие запуска тушения и наличие event/packet.",
        "2. Прогон fire в auto режиме: подтвердить запуск output/extinguishing и последующий packet/export.",
        "3. Fault/attention сценарии по зоне: сверка XDATA-флагов (`0x30EA..0x30F9`, `0x315B`, `0x3165`).",
        "",
        "## Ограничения",
        "- Это branch-specific static trace; полное восстановление логики пожаротушения без стенда **не утверждается**.",
    ]
    args.analysis_out.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"Wrote {args.trace_out.relative_to(ROOT)} ({len(trace_rows)} rows)")
    print(f"Wrote {args.summary_out.relative_to(ROOT)} ({len(summary_rows)} rows)")
    print(f"Wrote {args.analysis_out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
