#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cassandra CQL native protocol detection helpers."""

from __future__ import annotations

import socket
import struct
from typing import Dict


def probe_cassandra_native(host: str, port: int = 9042, timeout: float = 5.0) -> Dict[str, object]:
    """Send CQL native protocol OPTIONS and expect SUPPORTED response."""
    result: Dict[str, object] = {
        "detected": False,
        "cql_version": "",
        "error": "",
    }
    # v4 frame: version=4, flags=0, stream=0, opcode=OPTIONS(5), length=0
    frame = struct.pack(">BBHBi", 4, 0, 0, 5, 0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(frame)
        header = sock.recv(9)
        if len(header) < 9:
            result["error"] = "short_response"
            return result
        _version, _flags, _stream, opcode, length = struct.unpack(">BBHBi", header)
        if opcode != 6:  # SUPPORTED
            result["error"] = f"unexpected_opcode_{opcode}"
            return result
        body = sock.recv(min(int(length or 0), 4096)) if length else b""
        result["detected"] = True
        if body:
            result["cql_version"] = body[:80].decode("utf-8", errors="replace")
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
