#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Memcached detection helpers."""

from __future__ import annotations

import socket
from typing import Dict, List


def probe_memcached(host: str, port: int = 11211, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "unauthenticated": False,
        "stats": {},
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(b"stats\r\n")
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"END\r\n" in data:
                break
        text = data.decode("utf-8", errors="replace")
        if "STAT " not in text:
            result["error"] = "no_stats_response"
            return result
        result["detected"] = True
        result["unauthenticated"] = True
        stats: Dict[str, str] = {}
        for line in text.splitlines():
            if line.startswith("STAT "):
                parts = line.split()
                if len(parts) >= 3:
                    stats[parts[1]] = parts[2]
        result["stats"] = stats
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
