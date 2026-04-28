#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, field

from emulator.watchpoints import default_dks_watchpoints, default_rtos_service_watchpoints, default_shifted_dks_watchpoints, expand_range


@dataclass(frozen=True)
class Scenario:
    name: str
    firmware_file: str
    functions: list[int]
    seed_xdata: dict[int, int]
    watchpoints: list[int]
    purpose: str
    init_regs: dict[int, dict[str, int]] = field(default_factory=dict)


def _seed_addrs(addrs: list[int], base: int = 1) -> dict[int, int]:
    return {a: (base + i) & 0xFF for i, a in enumerate(addrs)}


def _seed_with_pattern(addrs: list[int], pattern: list[int]) -> dict[int, int]:
    return {a: pattern[i % len(pattern)] & 0xFF for i, a in enumerate(addrs)}


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
    "packet_bridge_seeded_context": Scenario(
        name="packet_bridge_seeded_context",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602, 0x5A7F],
        seed_xdata=_seed_with_pattern(
            [0x30BC, 0x30E1, 0x7160] + expand_range("0x3010..0x301B") + [0x31BF] + expand_range("0x36D3..0x36FD"),
            [0x00, 0x01, 0x02, 0x04, 0x07, 0x55, 0xAA],
        ),
        watchpoints=default_dks_watchpoints(),
        purpose="Seed context bytes for packet bridge candidates while preserving conservative trace-only interpretation.",
    ),
    "packet_bridge_stub_5a7f": Scenario(
        name="packet_bridge_stub_5a7f",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x5A7F],
        seed_xdata=_seed_with_pattern(
            [0x30BC, 0x30E1, 0x7160, 0x31BF],
            [0x00, 0x01, 0x02, 0x04, 0x07, 0x55, 0xAA],
        ),
        watchpoints=default_dks_watchpoints(),
        purpose="Focused 0x5A7F probe with deterministic seed context to inspect opcode coverage and trace outputs.",
    ),

    "packet_bridge_seeded_context_base": Scenario(
        name="packet_bridge_seeded_context_base",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602],
        seed_xdata={},
        watchpoints=default_dks_watchpoints(),
        purpose="Baseline compact variant with unmodified seeded-context watchpoints.",
    ),
    "packet_bridge_seeded_context_zeroed": Scenario(
        name="packet_bridge_seeded_context_zeroed",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602],
        seed_xdata={
            a: 0x00
            for a in [
                0x30BC, 0x30E1, 0x30E7, 0x30E9, 0x31BF, 0x3165, 0x364B, 0x30AC, 0x30B4, 0x30CC, 0x30D4, 0x30E0,
                *expand_range("0x30EA..0x30F9"), *expand_range("0x36D3..0x36FF"),
            ]
        },
        watchpoints=default_dks_watchpoints(),
        purpose="Variant with deterministic 0x00 seed across candidate state bytes.",
    ),
    "packet_bridge_seeded_context_ff": Scenario(
        name="packet_bridge_seeded_context_ff",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602],
        seed_xdata={
            a: 0xFF
            for a in [
                0x30BC, 0x30E1, 0x30E7, 0x30E9, 0x31BF, 0x3165, 0x364B, 0x30AC, 0x30B4, 0x30CC, 0x30D4, 0x30E0,
                *expand_range("0x30EA..0x30F9"), *expand_range("0x36D3..0x36FF"),
            ]
        },
        watchpoints=default_dks_watchpoints(),
        purpose="Variant with deterministic 0xFF seed across candidate state bytes.",
    ),
    "packet_bridge_seeded_context_mode_e0": Scenario(
        name="packet_bridge_seeded_context_mode_e0",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602],
        seed_xdata={0x30E0: 0xE0, 0x30E1: 0x00, 0x30E7: 0x00, 0x30E9: 0x00},
        watchpoints=default_dks_watchpoints(),
        purpose="Mode-byte focused variant forcing 0x30E0=0xE0.",
    ),
    "packet_bridge_seeded_context_mode_e1": Scenario(
        name="packet_bridge_seeded_context_mode_e1",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602],
        seed_xdata={0x30E0: 0xE1, 0x30E1: 0x01, 0x30E7: 0x01, 0x30E9: 0x01},
        watchpoints=default_dks_watchpoints(),
        purpose="Mode-byte focused variant forcing 0x30E0=0xE1.",
    ),
    "packet_bridge_seeded_context_mode_e2": Scenario(
        name="packet_bridge_seeded_context_mode_e2",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602],
        seed_xdata={0x30E0: 0xE2, 0x30E1: 0x02, 0x30E7: 0x02, 0x30E9: 0x02},
        watchpoints=default_dks_watchpoints(),
        purpose="Mode-byte focused variant forcing 0x30E0=0xE2.",
    ),
    "packet_bridge_seeded_context_output_flags": Scenario(
        name="packet_bridge_seeded_context_output_flags",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602],
        seed_xdata={
            0x30AC: 0x55,
            0x30B4: 0xAA,
            0x30CC: 0x10,
            0x30D4: 0x20,
            0x30E7: 0x40,
            0x30E9: 0x80,
            0x31BF: 0x01,
            0x364B: 0x02,
        },
        watchpoints=default_dks_watchpoints(),
        purpose="Output-flag walk variant using deterministic flag-like seed values.",
    ),
    "packet_bridge_seeded_context_bitmask_walk": Scenario(
        name="packet_bridge_seeded_context_bitmask_walk",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x55AD, 0x5602],
        seed_xdata={a: v for a, v in zip(expand_range("0x36F0..0x36FF"), [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x55, 0xAA, 0xFF, 0x00, 0x01, 0x02, 0x04, 0x08])},
        watchpoints=default_dks_watchpoints(),
        purpose="Bitmask walk across 0x36F0..0x36FF with deterministic seed set.",
    ),

    "packet_bridge_loop_force_r3_00": Scenario(
        name="packet_bridge_loop_force_r3_00",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x5715],
        seed_xdata={},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis experiment: force R3=0 at loop entry to test DJNZ behavior.",
        init_regs={0x5715: {"R3": 0x00}},
    ),
    "packet_bridge_loop_force_r3_01": Scenario(
        name="packet_bridge_loop_force_r3_01",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x5715],
        seed_xdata={},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis experiment: force R3=1 at loop entry to test DJNZ behavior.",
        init_regs={0x5715: {"R3": 0x01}},
    ),
    "packet_bridge_loop_force_acc0_clear": Scenario(
        name="packet_bridge_loop_force_acc0_clear",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x5715],
        seed_xdata={},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis experiment: force ACC.0 clear at loop entry to test JB bit 0xE0 path.",
        init_regs={0x5715: {"A": 0x80}},
    ),
    "packet_bridge_loop_force_acc0_set": Scenario(
        name="packet_bridge_loop_force_acc0_set",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x5715],
        seed_xdata={},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis experiment: force ACC.0 set at loop entry to test JB bit 0xE0 path.",
        init_regs={0x5715: {"A": 0x81}},
    ),
    "packet_bridge_loop_force_jb_not_taken_candidate": Scenario(
        name="packet_bridge_loop_force_jb_not_taken_candidate",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x5715],
        seed_xdata={},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis experiment: JB-not-taken candidate by forcing ACC.0 clear and R3 nonzero.",
        init_regs={0x5715: {"A": 0x80, "R3": 0x02}},
    ),
    "packet_bridge_loop_force_djnz_exit_candidate": Scenario(
        name="packet_bridge_loop_force_djnz_exit_candidate",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x5715],
        seed_xdata={},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis experiment: DJNZ-exit candidate by forcing R3=1 at loop entry.",
        init_regs={0x5715: {"R3": 0x01, "A": 0x80}},
    ),
    "packet_bridge_post_loop_from_574E_context": Scenario(
        name="packet_bridge_post_loop_from_574E_context",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x574E],
        seed_xdata={0x30E1: 0x01, 0x30C4: 0x00},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis forced_entry at 0x574E with compact register/XDATA context; not treated as hardware-faithful behavior.",
        init_regs={0x574E: {"R0": 0x00, "R1": 0x01, "A": 0x00, "DPTR": 0x30C4}},
    ),
    "packet_bridge_post_loop_from_5765_context": Scenario(
        name="packet_bridge_post_loop_from_5765_context",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x5765],
        seed_xdata={0x30E1: 0x00},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis forced_entry at 0x5765 to decode downstream call/branch behavior only.",
        init_regs={0x5765: {"R0": 0x00, "R1": 0x01, "A": 0x00}},
    ),
    "packet_bridge_post_loop_from_58B1_context": Scenario(
        name="packet_bridge_post_loop_from_58B1_context",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x58B1],
        seed_xdata={0x30E1: 0x00},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis forced_entry at 0x58B1 to inspect compact downstream UART-adjacent path only.",
        init_regs={0x58B1: {"A": 0x00, "R0": 0x00, "R1": 0x01}},
    ),
    "packet_bridge_post_loop_from_58CA_context": Scenario(
        name="packet_bridge_post_loop_from_58CA_context",
        firmware_file="90CYE03_19_DKS.PZU",
        functions=[0x58CA],
        seed_xdata={0x30E1: 0x00},
        watchpoints=default_dks_watchpoints(),
        purpose="Hypothesis forced_entry at 0x58CA to inspect near-target branch/call flow without firmware patching.",
        init_regs={0x58CA: {"A": 0x00, "R0": 0x00, "R1": 0x01}},
    ),
}


def list_scenarios() -> list[Scenario]:
    return list(SCENARIOS.values())


def get_scenario(name: str) -> Scenario:
    return SCENARIOS[name]
