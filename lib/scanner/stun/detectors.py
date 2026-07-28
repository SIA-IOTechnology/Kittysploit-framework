#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STUN Binding Request helpers (RFC 5389)."""

from __future__ import annotations

import os
import socket
import struct
from typing import Dict

STUN_MAGIC = 0x2112A442


def _binding_request() -> bytes:
    # Type Binding Request (0x0001), length 0, magic cookie, 12-byte TXID
    txid = os.urandom(12)
    return struct.pack("!HHI", 0x0001, 0, STUN_MAGIC) + txid


def probe_stun(host: str, port: int = 3478, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "mapped_address": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_binding_request(), (host, int(port)))
        data, _addr = sock.recvfrom(2048)
        if len(data) < 20:
            result["error"] = "short_response"
            return result
        msg_type, length, magic = struct.unpack("!HHI", data[:8])
        if magic != STUN_MAGIC:
            result["error"] = "bad_magic"
            return result
        # Success Binding Response = 0x0101
        if msg_type != 0x0101:
            result["error"] = f"unexpected_type=0x{msg_type:04x}"
            return result
        result["detected"] = True
        # Parse XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001) if present
        offset = 20
        end = min(len(data), 20 + length)
        while offset + 4 <= end:
            attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4
            value = data[offset : offset + attr_len]
            pad = (4 - (attr_len % 4)) % 4
            offset += attr_len + pad
            if attr_type in (0x0001, 0x0020) and len(value) >= 8:
                family = value[1]
                port_raw = struct.unpack("!H", value[2:4])[0]
                if attr_type == 0x0020:
                    port_raw ^= STUN_MAGIC >> 16
                if family == 0x01 and len(value) >= 8:
                    ip_bytes = bytearray(value[4:8])
                    if attr_type == 0x0020:
                        magic_bytes = struct.pack("!I", STUN_MAGIC)
                        ip_bytes = bytes(b ^ m for b, m in zip(ip_bytes, magic_bytes))
                    result["mapped_address"] = (
                        f"{'.'.join(str(b) for b in ip_bytes)}:{port_raw}"
                    )
                break
        return result
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass
