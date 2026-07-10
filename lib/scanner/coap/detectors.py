#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CoAP protocol detection helpers."""

from __future__ import annotations

import socket
from typing import Dict


def _coap_well_known_core_request() -> bytes:
    # CON GET msg-id=0x3039, Uri-Path .well-known, Uri-Path core
    return bytes(
        [
            0x40,
            0x01,
            0x30,
            0x39,
            0xBB,
            0x2E,
            0x77,
            0x65,
            0x6C,
            0x6C,
            0x2D,
            0x6B,
            0x6E,
            0x6F,
            0x77,
            0x6E,
            0x04,
            0x63,
            0x6F,
            0x72,
            0x65,
        ]
    )


def probe_coap(host: str, port: int = 5683, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_coap_well_known_core_request(), (host, int(port)))
        data, _addr = sock.recvfrom(2048)
        if not data or len(data) < 4:
            result["error"] = "empty_response"
            return result
        # CoAP response: version 1 in top 2 bits
        if (data[0] >> 6) == 1:
            result["detected"] = True
            return result
        result["error"] = "invalid_coap_version"
        return result
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
