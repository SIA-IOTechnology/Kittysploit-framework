#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Telnet banner detection helpers."""

from __future__ import annotations

import socket
from typing import Dict


def probe_telnet_banner(host: str, port: int = 23, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "banner": "", "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        data = sock.recv(256)
        if not data:
            result["error"] = "empty_banner"
            return result
        banner = data.decode("utf-8", errors="replace").strip()
        result["banner"] = banner
        if banner:
            result["detected"] = True
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
