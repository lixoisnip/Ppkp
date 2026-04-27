#!/usr/bin/env python3
from __future__ import annotations


def expand_range(spec: str) -> list[int]:
    left, right = spec.split("..")
    start = int(left, 16)
    end = int(right, 16)
    return list(range(start, end + 1))


def _sorted_unique(values: list[int]) -> list[int]:
    return sorted(set(v & 0xFFFF for v in values))


def default_dks_watchpoints() -> list[int]:
    values = [0x30BC, 0x30E1, 0x7160, 0x30E7, 0x30E9, 0x31BF, 0x3640, 0x364B, 0x3104, 0x3108, 0x31DD, 0x32B2, 0x32B3]
    values += expand_range("0x3010..0x301B")
    values += expand_range("0x36D3..0x36FD")
    return _sorted_unique(values)


def default_shifted_dks_watchpoints() -> list[int]:
    return _sorted_unique([0x3104, 0x3108, 0x31DD, 0x32B2, 0x32B3])


def default_rtos_service_watchpoints() -> list[int]:
    return _sorted_unique([0x30BC, 0x30E1, 0x31BF, 0x3640, 0x364B])
