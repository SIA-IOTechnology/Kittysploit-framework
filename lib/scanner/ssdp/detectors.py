#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSDP / UPnP discovery helpers."""

from __future__ import annotations

import socket
from typing import Dict


def _msearch() -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode("utf-8")


def probe_ssdp(host: str, port: int = 1900, timeout: float = 3.0) -> Dict[str, object]:
    """Unicast M-SEARCH against a target host (typical IoT/gateway UPnP)."""
    result: Dict[str, object] = {
        "detected": False,
        "st": "",
        "server": "",
        "location": "",
        "usn": "",
        "banner": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_msearch(), (host, int(port)))
        data, _addr = sock.recvfrom(4096)
        text = data.decode("utf-8", errors="replace")
        result["banner"] = text[:800]
        first = (text.splitlines() or [""])[0].upper()
        if "HTTP/1.1 200" not in first and "NOTIFY" not in first:
            # Some stacks reply with 200 OK variants
            if "HTTP/" not in first:
                result["error"] = "not_ssdp"
                return result
        result["detected"] = True
        for line in text.splitlines():
            low = line.lower()
            if low.startswith("st:"):
                result["st"] = line.split(":", 1)[1].strip()[:200]
            elif low.startswith("server:"):
                result["server"] = line.split(":", 1)[1].strip()[:200]
            elif low.startswith("location:"):
                result["location"] = line.split(":", 1)[1].strip()[:300]
            elif low.startswith("usn:"):
                result["usn"] = line.split(":", 1)[1].strip()[:300]
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
