#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WireGuard UDP handshake probe (best-effort)."""

from __future__ import annotations

import os
import socket
import struct
from typing import Dict

# message types
WG_INITIATION = 1
WG_RESPONSE = 2
WG_COOKIE_REPLY = 3
WG_TRANSPORT = 4

WG_INITIATION_LEN = 148
WG_RESPONSE_LEN = 92
WG_COOKIE_REPLY_LEN = 64


def _handshake_initiation() -> bytes:
    # Random invalid keys; peers with cookie defense may reply type=3,
    # valid peers may reply type=2 if they accept the ephemeral (rare without key match).
    # Any well-formed WireGuard message type is a positive detection.
    msg = bytearray(WG_INITIATION_LEN)
    msg[0] = WG_INITIATION
    # reserved 1..3 already 0
    struct.pack_into("<I", msg, 4, int.from_bytes(os.urandom(4), "little"))
    msg[8:] = os.urandom(WG_INITIATION_LEN - 8)
    return bytes(msg)


def probe_wireguard(host: str, port: int = 51820, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "message_type": None,
        "response_len": 0,
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_handshake_initiation(), (host, int(port)))
        data, _addr = sock.recvfrom(2048)
        if not data:
            result["error"] = "empty"
            return result
        msg_type = data[0]
        result["message_type"] = msg_type
        result["response_len"] = len(data)
        if msg_type == WG_RESPONSE and len(data) >= WG_RESPONSE_LEN:
            result["detected"] = True
            return result
        if msg_type == WG_COOKIE_REPLY and len(data) >= WG_COOKIE_REPLY_LEN:
            result["detected"] = True
            return result
        if msg_type == WG_INITIATION and len(data) >= WG_INITIATION_LEN:
            # Unusual but still WireGuard-shaped
            result["detected"] = True
            return result
        result["error"] = f"unexpected_type={msg_type} len={len(data)}"
        return result
    except socket.timeout:
        # WireGuard is intentionally silent to invalid handshakes — timeout is common.
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
