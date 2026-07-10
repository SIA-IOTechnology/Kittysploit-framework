#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VNC/RFB service detection helpers."""

from __future__ import annotations

import re
import socket
from typing import Dict, Optional


def probe_vnc(host: str, port: int = 5900, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "version": "", "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        data = sock.recv(32)
        if not data:
            result["error"] = "empty_banner"
            return result
        banner = data.decode("utf-8", errors="replace").strip()
        match = re.match(r"RFB\s+(\d+\.\d+)", banner)
        if match:
            result["detected"] = True
            result["version"] = match.group(1)
            return result
        result["error"] = "unexpected_vnc_banner"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
