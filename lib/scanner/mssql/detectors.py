#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MSSQL detection helpers for scanner modules."""

from __future__ import annotations

import socket
import struct
from typing import Dict, Optional


TDS_PRELOGIN = bytes.fromhex(
    "120100003400000100001f000600012a000102000300042400000400"
)


def _recv_packet(sock: socket.socket, timeout: float) -> Optional[bytes]:
    sock.settimeout(timeout)
    try:
        header = sock.recv(8)
        if len(header) < 8:
            return None
        length = struct.unpack(">H", header[2:4])[0]
        body = header
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        return body
    except Exception:
        return None


def probe_mssql(host: str, port: int = 1433, timeout: float = 5.0) -> Dict[str, object]:
    """Detect MSSQL via TDS prelogin and infer encryption support."""
    result: Dict[str, object] = {
        "success": False,
        "host": host,
        "port": port,
        "detected": False,
        "version_hint": "",
        "encryption": "unknown",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(TDS_PRELOGIN)
        packet = _recv_packet(sock, timeout)
        if not packet or packet[0] != 0x04:
            result["error"] = "No TDS prelogin response"
            return result
        result["success"] = True
        result["detected"] = True
        payload = packet[8:]
        offset = 0
        while offset + 5 <= len(payload):
            token = payload[offset]
            if token == 0xFF:
                break
            rec_len = struct.unpack(">H", payload[offset + 1 : offset + 3])[0]
            value = payload[offset + 3 : offset + 3 + rec_len]
            if token == 0x00 and value:
                result["version_hint"] = value.decode("utf-8", errors="replace").strip("\x00")
            elif token == 0x01 and value:
                enc = value[0] if value else 0
                result["encryption"] = {
                    0: "encryption_off",
                    1: "encryption_on",
                    2: "encryption_not_supported",
                    3: "encryption_required",
                }.get(enc, "unknown")
            offset += 3 + rec_len
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
