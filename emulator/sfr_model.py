#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass


SFR_ROLE_HINTS: dict[int, str] = {
    0x81: "SP",
    0x82: "DPL",
    0x83: "DPH",
    0x87: "PCON_candidate",
    0x88: "TCON_candidate",
    0x89: "TMOD_candidate",
    0x8A: "TL0_candidate",
    0x8B: "TL1_candidate",
    0x8C: "TH0_candidate",
    0x8D: "TH1_candidate",
    0x98: "SCON0_candidate",
    0x99: "SBUF0_candidate",
    0x9A: "SBUF1_candidate",
    0xA8: "IE_candidate",
    0xB8: "IP_candidate",
    0xD0: "PSW",
    0xE0: "ACC",
    0xF0: "B",
    0xC8: "T2CON_or_uart1_control",
    0x86: "DPS_dual_dptr",
}

SBUF_CANDIDATE_ADDRS = {0x99, 0x9A}


@dataclass
class SfrTraceEvent:
    step: int
    pc: int
    sfr_addr: int
    access_type: str
    value: int
    previous_value: int | None
    possible_role: str
    notes: str


class SfrModel:
    """Minimal dictionary-backed SFR model with explicit access tracing.

    Unknown SFRs are kept as plain bytes with role `unknown_sfr` and never receive
    synthetic behavioral side effects.
    """

    def __init__(self) -> None:
        self._values: dict[int, int] = {}
        self.events: list[SfrTraceEvent] = []

    def read(self, addr: int, *, step: int, pc: int, notes: str = "") -> int:
        a = addr & 0xFF
        value = self._values.get(a, 0)
        self.events.append(
            SfrTraceEvent(
                step=step,
                pc=pc,
                sfr_addr=a,
                access_type="read",
                value=value,
                previous_value=None,
                possible_role=SFR_ROLE_HINTS.get(a, "unknown_sfr"),
                notes=notes,
            )
        )
        return value

    def write(self, addr: int, value: int, *, step: int, pc: int, notes: str = "") -> None:
        a = addr & 0xFF
        v = value & 0xFF
        prev = self._values.get(a)
        self._values[a] = v
        self.events.append(
            SfrTraceEvent(
                step=step,
                pc=pc,
                sfr_addr=a,
                access_type="write",
                value=v,
                previous_value=prev,
                possible_role=SFR_ROLE_HINTS.get(a, "unknown_sfr"),
                notes=notes,
            )
        )

    def get(self, addr: int, default: int = 0) -> int:
        return self._values.get(addr & 0xFF, default) & 0xFF
