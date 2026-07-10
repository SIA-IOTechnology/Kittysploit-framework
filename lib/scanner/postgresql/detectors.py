#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PostgreSQL detection helpers for scanner modules."""

from __future__ import annotations

import socket
import struct
from typing import Dict


def _startup_packet(user: str = "postgres", database: str = "postgres") -> bytes:
    params = (
        f"user\x00{user}\x00database\x00{database}\x00application_name\x00kittysploit\x00\x00"
    ).encode("utf-8")
    length = 4 + 4 + len(params)
    return struct.pack("!I", length) + struct.pack("!I", 196608) + params


def probe_postgresql(host: str, port: int = 5432, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "auth_required": False,
        "version": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(_startup_packet())
        data = sock.recv(512)
        if not data:
            result["error"] = "empty_response"
            return result

        msg_type = chr(data[0]) if data else ""
        if msg_type == "R":
            result["detected"] = True
            result["auth_required"] = True
            return result
        if msg_type == "E":
            text = data.decode("utf-8", errors="replace")
            if "postgresql" in text.lower() or "password" in text.lower():
                result["detected"] = True
                result["auth_required"] = True
            result["error"] = text[:200]
            return result
        if msg_type == "N":
            text = data.decode("utf-8", errors="replace")
            if "postgresql" in text.lower():
                result["detected"] = True
            return result
        if msg_type == "S":
            result["detected"] = True
            return result
        result["error"] = f"unexpected_message:{msg_type}"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
