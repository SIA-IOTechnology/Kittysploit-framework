#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive IEC 60870-5-104 APDU detection (TCP port 2404)."""

from __future__ import annotations

IEC104_COMMAND_TYPE_IDS = frozenset(
    {
        45,
        46,
        47,
        48,
        49,
        50,
        51,
        58,
        59,
        60,
        61,
        62,
        63,
        64,
        70,
        71,
        72,
        73,
        74,
        75,
        76,
        77,
        78,
        79,
        80,
        81,
        82,
        83,
        84,
        85,
        86,
    }
)


def parse_iec104(payload: bytes) -> dict | None:
    if len(payload) < 6 or payload[0] != 0x68:
        return None

    length = payload[1]
    if length < 4:
        return None

    control_1 = payload[2]
    control_2 = payload[3]
    control_3 = payload[4]
    control_4 = payload[5]

    apdu_type = "unknown"
    type_id = None
    is_command = False

    # I-format: bit 0 of first control octet == 0
    if (control_1 & 0x01) == 0:
        apdu_type = "I-format"
        if len(payload) >= 8:
            type_id = payload[6]
            is_command = type_id in IEC104_COMMAND_TYPE_IDS
    elif (control_1 & 0x03) == 0x01:
        apdu_type = "S-format"
    elif (control_1 & 0x03) == 0x03:
        apdu_type = "U-format"

    return {
        "protocol": "iec104",
        "length": length,
        "apdu_type": apdu_type,
        "type_id": type_id,
        "is_command": is_command,
        "control": [control_1, control_2, control_3, control_4],
    }
