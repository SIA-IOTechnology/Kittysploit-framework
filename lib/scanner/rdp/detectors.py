#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RDP service detection helpers."""

from __future__ import annotations

import socket
from typing import Dict


def probe_rdp(host: str, port: int = 3389, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        data = sock.recv(11)
        if len(data) >= 4 and data[0] == 0x03 and data[1] == 0x00:
            result["detected"] = True
            return result
        result["error"] = "unexpected_rdp_banner"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
