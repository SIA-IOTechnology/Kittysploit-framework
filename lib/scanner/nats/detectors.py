#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NATS messaging protocol detection helpers."""

from __future__ import annotations

import socket
from typing import Dict


def probe_nats(host: str, port: int = 4222, timeout: float = 5.0) -> Dict[str, object]:
    """
    NATS servers greet clients with a single INFO line:
    INFO {"server_id":"...","version":"...","auth_required":false,...}\\r\\n
    """
    result: Dict[str, object] = {
        "detected": False,
        "auth_required": False,
        "version": "",
        "server_id": "",
        "banner": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        data = b""
        while b"\n" not in data and len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        text = data.decode("utf-8", errors="replace").strip()
        result["banner"] = text[:500]
        if not text.upper().startswith("INFO"):
            result["error"] = "no_nats_info"
            return result
        result["detected"] = True
        low = text.lower()
        if '"auth_required":true' in low or '"auth_required": true' in low:
            result["auth_required"] = True
        # Best-effort field scrape without requiring json (banner may truncate).
        for key, dest in (("version", "version"), ("server_id", "server_id")):
            token = f'"{key}":"'
            idx = text.find(token)
            if idx >= 0:
                start = idx + len(token)
                end = text.find('"', start)
                if end > start:
                    result[dest] = text[start:end][:80]
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
