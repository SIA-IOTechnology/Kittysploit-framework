#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive Modbus TCP dissection (no active probing)."""

from __future__ import annotations

from lib.protocols.ics.constants import MODBUS_WRITE_FUNCTION_CODES


def parse_modbus_tcp(payload: bytes) -> dict | None:
    """
    Parse a Modbus TCP ADU from raw TCP payload bytes.

    Returns None when the payload does not look like Modbus TCP.
    """
    if len(payload) < 8:
        return None

    trans_id = int.from_bytes(payload[0:2], "big")
    proto_id = int.from_bytes(payload[2:4], "big")
    length = int.from_bytes(payload[4:6], "big")
    unit_id = payload[6]
    function_code = payload[7]

    if proto_id != 0:
        return None
    if length < 2 or length > 260:
        return None
    if len(payload) < 6 + length:
        return None

    is_exception = bool(function_code & 0x80)
    base_fc = function_code & 0x7F
    is_write = base_fc in MODBUS_WRITE_FUNCTION_CODES and not is_exception
    is_request = not is_exception

    register = None
    if not is_exception and len(payload) >= 10 and base_fc in {3, 4, 6, 16}:
        register = int.from_bytes(payload[8:10], "big")

    return {
        "transaction_id": trans_id,
        "unit_id": unit_id,
        "function_code": base_fc,
        "raw_function_code": function_code,
        "is_exception": is_exception,
        "is_write": is_write,
        "is_request": is_request,
        "register": register,
        "protocol": "modbus-tcp",
    }
