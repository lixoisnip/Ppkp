#!/usr/bin/env python3
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

TRACE_COLUMNS = [
    "run_id",
    "firmware_file",
    "function_addr",
    "step",
    "pc",
    "op",
    "args",
    "acc_before",
    "acc_after",
    "dptr_before",
    "dptr_after",
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "xdata_addr",
    "xdata_value",
    "sfr_addr",
    "sfr_value",
    "sp_before_ret",
    "popped_low",
    "popped_high",
    "continued_pc",
    "continued_inside_image",
    "trace_type",
    "notes",
]


@dataclass
class TraceContext:
    run_id: str
    firmware_file: str
    function_addr: int


class TraceLog:
    def __init__(self, ctx: TraceContext) -> None:
        self.ctx = ctx
        self.rows: list[dict[str, str]] = []

    def add(self, row: dict[str, object]) -> None:
        base = {
            "run_id": self.ctx.run_id,
            "firmware_file": self.ctx.firmware_file,
            "function_addr": f"0x{self.ctx.function_addr:04X}",
            "xdata_addr": "",
            "xdata_value": "",
            "sfr_addr": "",
            "sfr_value": "",
            "notes": "",
            "args": "",
        }
        for k, v in row.items():
            if v is None:
                continue
            base[k] = f"0x{v:04X}" if k in {"pc", "dptr_before", "dptr_after", "xdata_addr", "sfr_addr"} and isinstance(v, int) else str(v)
        self.rows.append({k: str(base.get(k, "")) for k in TRACE_COLUMNS})

    def write_csv(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=TRACE_COLUMNS)
            writer.writeheader()
            writer.writerows(self.rows)
