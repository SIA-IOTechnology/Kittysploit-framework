#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive DNP3 link-layer detection (TCP port 20000)."""

from __future__ import annotations

DNP3_WRITE_FUNCTION_CODES = frozenset({2, 3, 4, 5, 13, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31})


def parse_dnp3(payload: bytes) -> dict | None:
    if len(payload) < 10:
        return None
    if payload[0:2] != b"\x05\x64":
        return None

    length = payload[2]
    control = payload[3]
    dest = int.from_bytes(payload[4:6], "little")
    src = int.from_bytes(payload[6:8], "little")

    if length < 5 or length > 250:
        return None

    dir_bit = bool(control & 0x80)
    prm_bit = bool(control & 0x40)
    is_master = prm_bit

    function_code = None
    is_write = False
    if len(payload) >= 11:
        # Application layer often follows link header + transport header.
        for offset in range(10, min(len(payload) - 1, 20)):
            candidate = payload[offset]
            if candidate in DNP3_WRITE_FUNCTION_CODES:
                function_code = candidate
                is_write = True
                break
            if 0 <= candidate <= 31:
                function_code = candidate
                break

    return {
        "protocol": "dnp3",
        "length": length,
        "control": control,
        "dest": dest,
        "src": src,
        "is_master": is_master,
        "dir_bit": dir_bit,
        "function_code": function_code,
        "is_write": is_write,
    }
