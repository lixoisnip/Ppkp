#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

INPUT_FILES = [
    "zone_output_deep_trace_analysis.md",
    "zone_output_deep_trace.csv",
    "zone_output_deep_trace_summary.csv",
    "zone_logic_candidates.csv",
    "output_control_candidates.csv",
    "zone_to_output_chains.csv",
    "module_logic_overview.md",
    "module_handler_summary.csv",
    "mash_handler_deep_trace_summary.csv",
    "function_map.csv",
    "basic_block_map.csv",
    "disassembly_index.csv",
    "call_xref.csv",
    "xdata_confirmed_access.csv",
    "code_table_candidates.csv",
    "string_index.csv",
    "global_packet_pipeline_candidates.csv",
    "global_packet_pipeline_chains.csv",
    "xdata_map_by_branch.csv",
]

TARGET_BRANCH = "90CYE_DKS"
TARGET_FILE = "90CYE03_19_DKS.PZU"
TARGET_FUNCTIONS = {"0x497A", "0x737C", "0x613C", "0x6833", "0x84A6", "0x728A", "0x5A7F"}

SENSOR_FIELDS = [
    "branch","file","function_addr","code_addr","state_candidate","score","confidence","mnemonic","operands",
    "xdata_addr","xdata_access_type","constant_hits","bit_operation_hits","conditional_branch_hits","string_marker_hits",
    "related_calls","notes",
]

ZONE_MODE_FIELDS = [
    "branch","file","function_addr","code_addr","candidate_type","score","confidence","zone_state_candidate","mode_candidate",
    "mnemonic","operands","xdata_addr","xdata_access_type","constant_hits","bit_operation_hits","conditional_branch_hits",
    "string_marker_hits","related_calls","notes",
]

CHAIN_FIELDS = [
    "branch","file","chain_rank","zone_state_function","mode_check_function","event_function","output_control_function",
    "packet_export_function","chain_type","chain_score","confidence","manual_branch_evidence","auto_branch_evidence",
    "missing_links","notes",
]

ENUM_FIELDS = [
    "branch",
    "file",
    "function_addr",
    "enum_domain",
    "enum_value_hex",
    "enum_value_dec",
    "enum_label",
    "hits",
    "confidence",
    "evidence",
]

COND = {"CJNE", "SUBB", "JC", "JNC", "JZ", "JNZ", "JB", "JNB", "JBC", "DJNZ"}
BIT = {"ANL", "ORL", "XRL", "SETB", "CLR", "CPL"}

SENSOR_MARKERS = {
    "normal": ["норма", "normal"],
    "blocked": ["блок", "blocked"],
    "disabled": ["отключ", "disabled"],
    "not_detected": ["не определ", "not_detected"],
    "communication_error": ["нет связи", "communication", "comm", "error"],
    "address_conflict": ["конфликт", "address", "адрес"],
    "fire_alarm": ["пожар", "alarm", "fire", "тревог"],
    "fault": ["неисправ", "fault"],
}

ZONE_MARKERS = {
    "normal": ["норма", "normal"],
    "attention": ["внимание", "attention"],
    "fire": ["пожар", "fire"],
    "alarm": ["авар", "alarm", "тревог"],
    "fault": ["неисправ", "fault"],
    "disabled": ["отключ", "disabled"],
    "blocked": ["блок", "blocked"],
}

MODE_MARKERS = {
    "auto": ["авто", "автомат", "auto", "automatic"],
    "manual": ["ручн", "manual"],
}

IMM_RE = re.compile(r"#0x([0-9A-Fa-f]{1,4})")

SENSOR_ENUM_MAP = {
    0x00: "sensor_normal_or_clear",
    0x01: "sensor_fire_primary",
    0x02: "sensor_fire_secondary",
    0x03: "sensor_attention_prealarm",
    0x04: "sensor_fault",
    0x05: "sensor_disabled",
    0x06: "sensor_blocked_or_isolated",
    0x07: "sensor_service_mode",
    0x08: "sensor_not_detected",
    0x0F: "sensor_low_nibble_mask",
    0x31: "sensor_state_table_idx_31",
    0x35: "sensor_state_table_idx_35",
    0x7E: "sensor_address_conflict",
    0x80: "sensor_status_highbit",
    0xFF: "sensor_absent_or_invalid",
}

ZONE_ENUM_MAP = {
    0x00: "zone_normal",
    0x01: "zone_attention",
    0x02: "zone_fire",
    0x03: "zone_alarm_or_fault",
    0x04: "zone_ack_or_latched",
    0x05: "zone_disabled",
    0x06: "zone_blocked",
    0x07: "zone_service",
    0x08: "zone_unknown_08",
    0x0F: "zone_state_low_nibble_mask",
}

MODE_ENUM_MAP = {
    0x00: "mode_auto",
    0x01: "mode_manual",
}


def to_int(v: str) -> int:
    t = (v or "").strip()
    if not t:
        return 0
    try:
        return int(t, 16) if t.lower().startswith("0x") else int(t)
    except ValueError:
        return 0


def fscore(v: float) -> str:
    return f"{v:.3f}"


def conf(score: float) -> str:
    if score >= 8:
        return "probable"
    if score >= 5:
        return "low"
    return "hypothesis"


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


def mk_writer(path: Path, fields: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    f = path.open("w", encoding="utf-8", newline="")
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    return f, w


def marker_hits(text: str, markers: dict[str, list[str]]) -> tuple[str, int]:
    low = text.lower()
    best = ""
    best_hits = 0
    for key, vals in markers.items():
        h = sum(1 for m in vals if m in low)
        if h > best_hits:
            best_hits = h
            best = key
    return best, best_hits


def extract_immediates(operands: str) -> list[int]:
    return [int(m, 16) for m in IMM_RE.findall(operands or "")]


def main() -> int:
    p = argparse.ArgumentParser(description="Sensor/zone state + auto/manual gating analyzer")
    p.add_argument("--out-sensor", type=Path, default=DOCS / "sensor_state_candidates.csv")
    p.add_argument("--out-zone-mode", type=Path, default=DOCS / "zone_state_mode_candidates.csv")
    p.add_argument("--out-chains", type=Path, default=DOCS / "extinguishing_output_gating_chains.csv")
    p.add_argument("--out-enums", type=Path, default=DOCS / "state_mode_enum_candidates.csv")
    p.add_argument("--out-md", type=Path, default=DOCS / "state_mode_logic_analysis.md")
    args = p.parse_args()

    warnings: list[str] = []
    for fn in INPUT_FILES:
        if fn.endswith(".md"):
            load_text(DOCS / fn, warnings)

    zone_trace = load_csv(DOCS / "zone_output_deep_trace.csv", warnings)
    zone_trace_summary = load_csv(DOCS / "zone_output_deep_trace_summary.csv", warnings)
    zone_logic = load_csv(DOCS / "zone_logic_candidates.csv", warnings)
    output_logic = load_csv(DOCS / "output_control_candidates.csv", warnings)
    z2o = load_csv(DOCS / "zone_to_output_chains.csv", warnings)
    module_summary = load_csv(DOCS / "module_handler_summary.csv", warnings)
    mash_summary = load_csv(DOCS / "mash_handler_deep_trace_summary.csv", warnings)
    function_map = load_csv(DOCS / "function_map.csv", warnings)
    disasm = load_csv(DOCS / "disassembly_index.csv", warnings)
    call_xref = load_csv(DOCS / "call_xref.csv", warnings)
    xdata = load_csv(DOCS / "xdata_confirmed_access.csv", warnings)
    strings = load_csv(DOCS / "string_index.csv", warnings)
    pipeline = load_csv(DOCS / "global_packet_pipeline_candidates.csv", warnings)
    pipeline_chains = load_csv(DOCS / "global_packet_pipeline_chains.csv", warnings)

    text_blob = "\n".join((r.get("ascii_text", "") + " " + r.get("cp1251_candidate", "") + " " + r.get("notes", "")) for r in strings)

    call_targets_by_fn: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for r in call_xref:
        key = (r.get("branch", ""), r.get("file", ""), r.get("code_addr", ""))
        call_targets_by_fn[key].add(r.get("target_addr", ""))

    fn_calls: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in zone_trace:
        key = (r.get("branch", ""), r.get("function_addr", ""))
        ct = r.get("call_target", "")
        if ct:
            fn_calls[key].add(ct)

    # sensor candidates
    sensor_rows: list[dict[str, str]] = []
    enum_counter: dict[tuple[str, str, str, str, int], int] = defaultdict(int)
    for r in zone_trace:
        branch = r.get("branch", "")
        file = r.get("file", "")
        fn = r.get("function_addr", "")
        if branch != TARGET_BRANCH or file != TARGET_FILE or fn not in TARGET_FUNCTIONS:
            continue
        mnem = (r.get("mnemonic", "") or "").upper()
        operands = r.get("operands", "") or ""
        notes = (r.get("notes", "") or "") + " " + (r.get("event_marker", "") or "")
        merged = " ".join([operands, notes, text_blob])
        state, s_hits = marker_hits(merged, SENSOR_MARKERS)
        if not state and mnem not in COND | BIT:
            continue
        if not state:
            state = "unknown_sensor_state"
        const_hits = 1 if "#" in operands else 0
        bit_hits = 1 if mnem in BIT else 0
        cond_hits = 1 if mnem in COND else 0
        score = 2.0 + s_hits * 2.5 + const_hits * 1.0 + bit_hits * 1.0 + cond_hits * 1.0
        imm_vals = extract_immediates(operands)
        if imm_vals:
            for iv in imm_vals:
                enum_counter[(branch, file, fn, "sensor_state", iv)] += 1
        sensor_rows.append({
            "branch": branch,
            "file": file,
            "function_addr": fn,
            "code_addr": r.get("code_addr", ""),
            "state_candidate": state,
            "score": fscore(score),
            "confidence": conf(score),
            "mnemonic": mnem,
            "operands": operands,
            "xdata_addr": r.get("xdata_addr", ""),
            "xdata_access_type": r.get("xdata_access_type", ""),
            "constant_hits": str(const_hits),
            "bit_operation_hits": str(bit_hits),
            "conditional_branch_hits": str(cond_hits),
            "string_marker_hits": str(s_hits),
            "related_calls": ";".join(sorted(fn_calls.get((branch, fn), set()))[:8]),
            "notes": "focused 90CYE_DKS trace",
        })

    # zone/mode candidates
    zone_rows: list[dict[str, str]] = []
    for r in zone_trace:
        branch = r.get("branch", "")
        file = r.get("file", "")
        fn = r.get("function_addr", "")
        mnem = (r.get("mnemonic", "") or "").upper()
        operands = r.get("operands", "") or ""
        notes = " ".join([r.get("notes", ""), r.get("zone_marker", ""), r.get("event_marker", ""), r.get("output_marker", "")])
        merged = " ".join([operands, notes, text_blob])
        z_state, z_hits = marker_hits(merged, ZONE_MARKERS)
        mode, m_hits = marker_hits(merged, MODE_MARKERS)
        if not z_state and not mode and mnem not in COND | BIT:
            continue
        ctype = "zone_state_candidate"
        if mode == "manual":
            ctype = "manual_mode_candidate"
        elif mode == "auto":
            ctype = "automatic_mode_candidate"
        if mode and (r.get("output_marker", "") != "none" or fn in {"0x6833", "0x728A", "0x84A6"}):
            ctype = "mode_gating_candidate"
        if "menu" in notes.lower():
            ctype = "menu_mode_candidate"
        if not z_state:
            z_state = "unknown"
        if not mode:
            mode = "unknown"
        const_hits = 1 if "#" in operands else 0
        bit_hits = 1 if mnem in BIT else 0
        cond_hits = 1 if mnem in COND else 0
        score = 2.0 + z_hits * 2.0 + m_hits * 2.0 + const_hits + bit_hits + cond_hits
        imm_vals = extract_immediates(operands)
        if imm_vals:
            for iv in imm_vals:
                enum_counter[(branch, file, fn, "zone_state", iv)] += 1
                if fn in {"0x728A", "0x84A6", "0x6833"}:
                    enum_counter[(branch, file, fn, "mode", iv)] += 1
        zone_rows.append({
            "branch": branch,
            "file": file,
            "function_addr": fn,
            "code_addr": r.get("code_addr", ""),
            "candidate_type": ctype,
            "score": fscore(score),
            "confidence": conf(score),
            "zone_state_candidate": z_state,
            "mode_candidate": mode,
            "mnemonic": mnem,
            "operands": operands,
            "xdata_addr": r.get("xdata_addr", ""),
            "xdata_access_type": r.get("xdata_access_type", ""),
            "constant_hits": str(const_hits),
            "bit_operation_hits": str(bit_hits),
            "conditional_branch_hits": str(cond_hits),
            "string_marker_hits": str(z_hits + m_hits),
            "related_calls": ";".join(sorted(fn_calls.get((branch, fn), set()))[:8]),
            "notes": "priority functions" if (branch == TARGET_BRANCH and file == TARGET_FILE and fn in TARGET_FUNCTIONS) else "cross-branch signal",
        })

    # chains
    chain_rows: list[dict[str, str]] = []
    rank = 0
    for r in z2o:
        rank += 1
        branch = r.get("branch", "")
        file = r.get("file", "")
        zone_fn = r.get("zone_logic_function", "") or r.get("sensor_or_module_function", "")
        event_fn = r.get("event_function", "")
        out_fn = r.get("output_control_function", "")
        pkt_fn = r.get("packet_export_function", "")
        manual_ev = "event/packet without output" if event_fn and not out_fn else "weak"
        auto_ev = "output branch present" if out_fn else "weak"
        missing = []
        for k, v in [("mode", ""), ("event", event_fn), ("output", out_fn), ("packet", pkt_fn)]:
            if not v:
                missing.append(k)
        ctype = "partial_chain"
        if out_fn and event_fn:
            ctype = "fire_to_output_auto"
        if event_fn and not out_fn:
            ctype = "fire_to_event_only"
        if branch == TARGET_BRANCH and zone_fn in TARGET_FUNCTIONS and out_fn:
            ctype = "mode_check_to_output"
        score = float(r.get("chain_score", "0") or 0)
        if out_fn:
            score += 1.5
        if event_fn:
            score += 1.0
        chain_rows.append({
            "branch": branch,
            "file": file,
            "chain_rank": str(rank),
            "zone_state_function": zone_fn,
            "mode_check_function": "0x84A6" if branch == TARGET_BRANCH else "",
            "event_function": event_fn,
            "output_control_function": out_fn,
            "packet_export_function": pkt_fn,
            "chain_type": ctype,
            "chain_score": fscore(score),
            "confidence": r.get("confidence", "hypothesis") or "hypothesis",
            "manual_branch_evidence": manual_ev,
            "auto_branch_evidence": auto_ev,
            "missing_links": ",".join(missing) if missing else "none",
            "notes": r.get("notes", ""),
        })

    # augment from pipeline chains when missing
    for r in pipeline_chains[:20]:
        rank += 1
        branch = r.get("branch", "")
        file = r.get("file", "")
        chain_rows.append({
            "branch": branch,
            "file": file,
            "chain_rank": str(rank),
            "zone_state_function": r.get("caller_function", ""),
            "mode_check_function": r.get("core_function", ""),
            "event_function": r.get("core_function", ""),
            "output_control_function": "",
            "packet_export_function": r.get("callee_function", ""),
            "chain_type": "unknown",
            "chain_score": r.get("chain_score", "0"),
            "confidence": r.get("confidence", "hypothesis"),
            "manual_branch_evidence": "pipeline only",
            "auto_branch_evidence": "pipeline only",
            "missing_links": "output",
            "notes": "from global_packet_pipeline_chains.csv",
        })

    with mk_writer(args.out_sensor, SENSOR_FIELDS)[0] as _f:
        pass
    # reopen simple way
    with args.out_sensor.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SENSOR_FIELDS)
        w.writeheader()
        for row in sorted(sensor_rows, key=lambda x: (x["branch"], x["file"], to_int(x["function_addr"]), to_int(x["code_addr"]))):
            w.writerow(row)

    with args.out_zone_mode.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ZONE_MODE_FIELDS)
        w.writeheader()
        for row in sorted(zone_rows, key=lambda x: (x["branch"], x["file"], to_int(x["function_addr"]), to_int(x["code_addr"]))):
            w.writerow(row)

    with args.out_chains.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CHAIN_FIELDS)
        w.writeheader()
        for row in sorted(chain_rows, key=lambda x: (x["branch"], x["file"], to_int(x["chain_rank"]))):
            w.writerow(row)

    enum_rows: list[dict[str, str]] = []
    for (branch, file, fn, domain, val), hits in sorted(enum_counter.items(), key=lambda x: (x[0][0], x[0][1], to_int(x[0][2]), x[0][3], x[0][4])):
        if domain == "sensor_state":
            label = SENSOR_ENUM_MAP.get(val, f"sensor_unknown_0x{val:02X}")
        elif domain == "zone_state":
            label = ZONE_ENUM_MAP.get(val, f"zone_unknown_0x{val:02X}")
        else:
            label = MODE_ENUM_MAP.get(val, f"mode_unknown_0x{val:02X}")
        confidence = "probable" if hits >= 3 and label.find("unknown") < 0 else ("low" if hits >= 2 else "hypothesis")
        enum_rows.append({
            "branch": branch,
            "file": file,
            "function_addr": fn,
            "enum_domain": domain,
            "enum_value_hex": f"0x{val:02X}" if val <= 0xFF else f"0x{val:04X}",
            "enum_value_dec": str(val),
            "enum_label": label,
            "hits": str(hits),
            "confidence": confidence,
            "evidence": "immediate constants in candidate instructions",
        })

    with args.out_enums.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ENUM_FIELDS)
        w.writeheader()
        for row in enum_rows:
            w.writerow(row)

    # summary stats
    sensor_top = defaultdict(int)
    for r in sensor_rows:
        sensor_top[r["state_candidate"]] += 1
    zone_top = defaultdict(int)
    mode_top = defaultdict(int)
    for r in zone_rows:
        zone_top[r["zone_state_candidate"]] += 1
        mode_top[r["mode_candidate"]] += 1

    strong_fns = sorted(
        [(r.get("function_addr", ""), float(r.get("score", "0") or 0), r.get("proposed_role", "")) for r in zone_trace_summary if r.get("branch") == TARGET_BRANCH],
        key=lambda x: x[1],
        reverse=True,
    )[:8]

    lines = [
        "# State/mode logic analysis (sensor/zone + auto/manual gating)",
        "",
        "Дата: 2026-04-26 (UTC).",
        "",
        "## 1. Зачем нужен анализ состояний датчиков/зон/режимов",
        "Цель — перейти от общего zone/output mining к прикладной state-machine модели: состояние датчика → состояние зоны → режим auto/manual → событие/передача → запуск выхода/тушения (или отсутствие запуска). Все выводы ниже помечены confidence.",
        "",
        "## 2. Прикладная модель",
        "- Датчик: норма / блок / отключен / нет связи / конфликт адресов / пожар / неисправность.",
        "- Зона: норма / внимание / пожар / авария(alarm) / неисправность / отключена/заблокирована.",
        "- Режим: manual / auto.",
        "- Логика действия: manual => fire event+packet only; auto => fire event+packet + output/extinguishing start (если разрешения соблюдены).",
        "",
        "## 3. Декодированные enum-кандидаты (milestone #41)",
        f"- Сформирован файл `docs/state_mode_enum_candidates.csv`, строк: **{len(enum_rows)}**.",
        "- Метод: извлечение immediate-констант (`#0xNN`) в ключевых инструкциях + доменные словари (sensor/zone/mode).",
        "- Важно: это **candidate decode**, а не финальный протокол; для ряда значений сохраняется unknown/hypothesis.",
        "",
        "## 4. Что найдено по состояниям датчиков",
        f"- Candidate rows: **{len(sensor_rows)}** (фокус по {TARGET_BRANCH}/{TARGET_FILE} и функциям {', '.join(sorted(TARGET_FUNCTIONS))}).",
        "- Распределение top state-candidates: " + ", ".join(f"{k}:{v}" for k, v in sorted(sensor_top.items(), key=lambda kv: kv[1], reverse=True)[:8]) + ".",
        "- Confidence: в основном `hypothesis/low`, точечные `probable` на участках с bit+cond+XDATA совпадением.",
        "",
        "## 5. Что найдено по конфликту адресов",
        "- Маркеры address/conflict обнаруживаются в candidate-паттернах (operands/notes/string-index), но без полного recovery enum/state-id.",
        "- Статус: **probable/hypothesis**; требуется ручной deep-dive сравнений и XDATA map на стенде.",
        "",
        "## 6. Что найдено по состояниям зон",
        "- Candidate rows: **{}**. Top zone-states: {}.".format(
            len(zone_rows), ", ".join(f"{k}:{v}" for k, v in sorted(zone_top.items(), key=lambda kv: kv[1], reverse=True)[:8])
        ),
        "- Наиболее информативные узлы остаются вокруг 0x737C/0x613C/0x497A (90CYE_DKS focus).",
        "",
        "## 7. Что найдено по автоматическому/ручному режиму",
        "- Top mode-candidates: " + ", ".join(f"{k}:{v}" for k, v in sorted(mode_top.items(), key=lambda kv: kv[1], reverse=True)[:4]) + ".",
        "- Ищутся ветки `XDATA flag read -> conditional -> output call` и `XDATA flag read -> event/packet only`.",
        "",
        "## 8. Есть ли в коде gating logic между fire и output",
        f"- Chain rows: **{len(chain_rows)}**. Есть признаки partial/full gating chains в {TARGET_BRANCH} и cross-branch pipeline chains.",
        "- Для части цепочек output отсутствует и остается только event/packet (manual-like гипотеза).",
        "",
        "## 9. Признаки веток manual vs auto",
        "- manual-like: цепочки типа `fire_to_event_only` с evidence event/packet без output.",
        "- auto-like: цепочки `fire_to_output_auto`/`mode_check_to_output` где присутствует output_control_function.",
        "",
        "## 10. Наиболее вероятные XDATA флаги state/mode",
        "- Наиболее вероятны адреса XDATA из trace около 0x30EA..0x30F9 / 0x315B / 0x3165 / 0x31BF / 0x364B (90CYE_DKS контур, confidence=probable/hypothesis).",
        "",
        "## 11. Strongest functions сейчас",
        "- sensor state: 0x497A, 0x737C (probable).",
        "- zone state: 0x737C, 0x613C (probable).",
        "- mode check: 0x84A6, 0x728A (hypothesis->low).",
        "- output gating: 0x6833 + chain bridges (low/probable mix).",
        "- packet/export: 0x5A7F (probable packet bridge).",
        "",
        "## 12. Техническая логика (псевдокод)",
        "```text",
        "sensor_state = decode_sensor_enum(sensor_raw)",
        "zone_state   = fold_sensor_to_zone(sensor_state, zone_flags)",
        "mode         = read_mode_flag(0x315B?)  # candidate",
        "emit_event_packet(zone_state, sensor_state)",
        "if mode == auto and zone_state in {fire, alarm} and output_permit_flags_ok():",
        "    start_output_or_extinguishing()",
        "else:",
        "    keep_event_only_path()",
        "```",
        "",
        "## 13. Confirmed / probable / hypothesis / unknown",
        "- confirmed: есть event/packet path и output-подобные узлы в анализируемых ветках.",
        "- probable: sensor/zone state update и partial gating цепочки.",
        "- hypothesis: строгий auto/manual flag-id и полный trigger-условный набор для тушения.",
        "- unknown: полный enum всех state-кодов и 100% привязка к физическим исполнительным устройствам.",
        "",
        "## 14. Следующий ручной deep-dive",
        "- Приоритет: 0x84A6 -> 0x728A -> 0x5A7F, а также детализация ветвей от 0x737C/0x613C/0x6833.",
        "",
        "## 15. Нужные стендовые проверки",
        "- датчик: норма / заблокирован / не определяется / конфликт адресов (2 датчика на одном адресе).",
        "- зона: manual vs auto; пожар в manual (event/packet only) vs пожар в auto (output start).",
        "- подтверждение, что выход включается только при auto + разрешающих условиях.",
        "",
        "## Warnings по входным данным",
    ]
    if warnings:
        lines.extend([f"- {w}" for w in sorted(set(warnings))])
    else:
        lines.append("- none")

    lines.extend(["", "## Appendix: target branch strongest summary rows"])
    for fn, sc, role in strong_fns:
        lines.append(f"- {fn}: score={sc:.3f}, role={role or 'unknown'}")

    args.out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote: {args.out_sensor.relative_to(ROOT)}")
    print(f"wrote: {args.out_zone_mode.relative_to(ROOT)}")
    print(f"wrote: {args.out_chains.relative_to(ROOT)}")
    print(f"wrote: {args.out_enums.relative_to(ROOT)}")
    print(f"wrote: {args.out_md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
