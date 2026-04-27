#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass

from emulator.watchpoints import default_dks_watchpoints, default_rtos_service_watchpoints, default_shifted_dks_watchpoints, expand_range


@dataclass(frozen=True)
class Scenario:
    name: str
    firmware_file: str
    functions: list[int]
    seed_xdata: dict[int, int]
    watchpoints: list[int]
    purpose: str


def _seed_addrs(addrs: list[int], base: int = 1) -> dict[int, int]:
    return {a: (base + i) & 0xFF for i, a in enumerate(addrs)}


SCENARIOS = {
    "packet_bridge_default": Scenario(
        name="packet_bridge_default",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602, 0x5A7F],
        seed_xdata=_seed_addrs([0x30BC, 0x30E1, 0x7160], base=0x10),
        watchpoints=default_dks_watchpoints(),
        purpose="Observe pointer/index staging and MOVX writes around packet/event bridge hypotheses.",
    ),
    "zone_fire_candidate": Scenario(
        name="zone_fire_candidate",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x497A, 0x737C],
        seed_xdata=_seed_addrs(expand_range("0x3010..0x301B") + [0x31BF] + expand_range("0x36D3..0x36FD"), base=0x20),
        watchpoints=default_dks_watchpoints(),
        purpose="Observe state/event record write patterns.",
    ),
    "aerosol_start_candidate": Scenario(
        name="aerosol_start_candidate",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x84A6, 0x6833, 0x7DC2],
        seed_xdata=_seed_addrs([0x30E7, 0x30E9, 0x3640, 0x364B], base=0x30),
        watchpoints=default_dks_watchpoints(),
        purpose="Observe output-start marker behavior and downstream writes.",
    ),
    "shifted_valve_status_candidate": Scenario(
        name="shifted_valve_status_candidate",
        firmware_file="90CYE02_27 DKS.PZU",
        functions=[0x673C, 0x613C, 0x7773],
        seed_xdata=_seed_addrs([0x3104, 0x3108, 0x31DD, 0x32B2, 0x32B3], base=0x40),
        watchpoints=default_shifted_dks_watchpoints(),
        purpose="Observe status-table writes in shifted_DKS branch.",
    ),
    "rtos_service_candidate": Scenario(
        name="rtos_service_candidate",
        firmware_file="ppkp2001 90cye01.PZU",
        functions=[0x920C, 0x4374, 0x9255, 0x9275, 0x758B],
        seed_xdata=_seed_addrs([0x30BC, 0x30E1, 0x31BF, 0x3640, 0x364B], base=0x50),
        watchpoints=default_rtos_service_watchpoints(),
        purpose="Observe service-table reads/writes from RTOS_service candidates.",
    ),
    "boot_probe_static": Scenario(
        name="boot_probe_static",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x4000, 0x4100],
        seed_xdata={},
        watchpoints=default_dks_watchpoints(),
        purpose="Diagnostic boot-entry probe only; stop on unsupported low-level behavior without claiming full emulation.",
    ),
}


def list_scenarios() -> list[Scenario]:
    return list(SCENARIOS.values())


def get_scenario(name: str) -> Scenario:
    return SCENARIOS[name]
