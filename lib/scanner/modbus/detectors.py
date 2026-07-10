#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modbus UDP probe helpers."""

from __future__ import annotations

import socket
import struct
from typing import Dict


def probe_modbus_udp(host: str, port: int = 502, unit_id: int = 1, timeout: float = 5.0) -> Dict[str, object]:
    """Send Modbus UDP read holding registers (func 3) probe."""
    result: Dict[str, object] = {"detected": False, "unit_id": unit_id, "error": ""}
    pdu = struct.pack(">BHH", 0x03, 0, 1)
    header = struct.pack(">HHHB", 1, 0, len(pdu) + 1, unit_id & 0xFF)
    packet = header + pdu
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (host, int(port)))
        data, _addr = sock.recvfrom(256)
        if len(data) < 9:
            result["error"] = "short_response"
            return result
        func = data[7]
        if func & 0x80:
            result["error"] = f"modbus_exception_{data[8] if len(data) > 8 else 'unknown'}"
            result["detected"] = True
            return result
        if func == 0x03:
            result["detected"] = True
            return result
        result["error"] = f"unexpected_function_{func}"
        return result
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
