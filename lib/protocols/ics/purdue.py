#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Purdue model assignment and cross-zone violation heuristics."""

from __future__ import annotations

from typing import Any

DEVICE_PURDUE_LEVEL: dict[str, int] = {
    "PLC": 1,
    "PLC/RTU": 1,
    "RTU/IED": 1,
    "Industrial Controller": 1,
    "Building Controller": 2,
    "SCADA/HMI": 2,
    "Engineering Workstation": 3,
    "ICS Endpoint": 2,
    "Unknown": 0,
}

ROLE_PURDUE_HINTS: dict[str, int] = {
    "modbus-slave": 1,
    "s7-plc": 1,
    "dnp3-outstation": 1,
    "iec104-server": 1,
    "bacnet-device": 1,
    "modbus-master": 2,
    "modbus-master-write": 2,
    "dnp3-master": 2,
    "bacnet-client": 2,
    "iec104-client": 2,
    "s7-client": 3,
    "client": 3,
    "server": 1,
}


def assign_purdue_level(device: dict[str, Any]) -> int:
    device_type = device.get("device_type", "Unknown")
    level = DEVICE_PURDUE_LEVEL.get(device_type, 0)
    if level:
        return level

    roles = device.get("roles") or set()
    role_levels = [ROLE_PURDUE_HINTS[r] for r in roles if r in ROLE_PURDUE_HINTS]
    return max(role_levels) if role_levels else 0


def apply_purdue_levels(devices: dict[str, dict[str, Any]]) -> None:
    for device in devices.values():
        device["purdue_level"] = assign_purdue_level(device)


def detect_purdue_violations(
    devices: dict[str, dict[str, Any]],
    flows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Flag flows where a higher Purdue level initiates risky control toward a lower level.

    Heuristic only — requires corroboration in real OT assessments.
    """
    violations: list[dict[str, Any]] = []

    for flow in flows:
        src = flow.get("src")
        dst = flow.get("dst")
        if not src or not dst:
            continue

        src_dev = devices.get(src, {})
        dst_dev = devices.get(dst, {})
        src_level = int(src_dev.get("purdue_level") or 0)
        dst_level = int(dst_dev.get("purdue_level") or 0)
        if not src_level or not dst_level:
            continue

        is_write = bool(flow.get("is_write"))
        is_program = bool(flow.get("is_program_transfer"))
        protocol = flow.get("protocol", "unknown")

        if src_level >= 3 and dst_level <= 1 and (is_write or is_program):
            violations.append(
                {
                    "severity": "critical" if is_program else "high",
                    "type": "purdue_cross_zone_write",
                    "protocol": protocol,
                    "src": src,
                    "dst": dst,
                    "src_level": src_level,
                    "dst_level": dst_level,
                    "detail": (
                        f"Purdue L{src_level} ({src}) initiated "
                        f"{'program transfer' if is_program else 'write'} "
                        f"toward L{dst_level} ({dst}) over {protocol}"
                    ),
                }
            )
            continue

        if src_level - dst_level >= 2 and is_write:
            violations.append(
                {
                    "severity": "medium",
                    "type": "purdue_level_skip",
                    "protocol": protocol,
                    "src": src,
                    "dst": dst,
                    "src_level": src_level,
                    "dst_level": dst_level,
                    "detail": (
                        f"Purdue level skip: L{src_level} ({src}) -> "
                        f"L{dst_level} ({dst}) with write on {protocol}"
                    ),
                }
            )

    return violations
