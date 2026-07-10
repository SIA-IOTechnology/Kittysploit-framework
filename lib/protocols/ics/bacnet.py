#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive BACnet/IP BVLC detection (UDP/TCP port 47808)."""

from __future__ import annotations

BVLC_FUNCTIONS: dict[int, str] = {
    0x00: "bvlc-result",
    0x01: "write-bdt",
    0x02: "read-bdt",
    0x03: "read-bdt-ack",
    0x04: "forwarded-npdu",
    0x05: "register-foreign-device",
    0x06: "distribute-broadcast",
    0x0A: "who-is",
    0x0B: "i-am",
    0x0C: "who-has",
    0x0D: "i-have",
    0x0E: "unconfirmed-cov",
    0x0F: "i-am-router-to-network",
    0x10: "init-routing-table",
    0x11: "init-routing-table-ack",
}

BACNET_WRITE_CONFIRMED = frozenset({0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16})


def parse_bacnet(payload: bytes) -> dict | None:
    if len(payload) < 4:
        return None
    if payload[0] != 0x81:
        return None

    function = payload[1]
    bvlc_length = int.from_bytes(payload[2:4], "big")
    if bvlc_length < 4:
        return None
    if bvlc_length > len(payload):
        # Some captures truncate padding; keep parsing the bytes we have.
        bvlc_length = len(payload)

    npdu_offset = 4
    apdu_service = None
    is_discovery = function in (0x0A, 0x0B, 0x0C, 0x0D)
    is_write = False

    if len(payload) > npdu_offset + 3:
        # NPDU control + optional DNET/DADR then APDU.
        apdu_type = payload[npdu_offset + 1] if len(payload) > npdu_offset + 1 else None
        if apdu_type is not None and apdu_type & 0xF0 == 0x00:
            apdu_service = payload[npdu_offset + 2] if len(payload) > npdu_offset + 2 else None
            if apdu_service in BACNET_WRITE_CONFIRMED:
                is_write = True

    return {
        "protocol": "bacnet",
        "bvlc_function": function,
        "bvlc_function_name": BVLC_FUNCTIONS.get(function, f"unknown-0x{function:02X}"),
        "bvlc_length": bvlc_length,
        "is_discovery": is_discovery,
        "apdu_service": apdu_service,
        "is_write": is_write,
    }
