#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mDNS / DNS-SD probe helpers."""

from __future__ import annotations

import socket
import struct
from typing import Dict, List


def _dns_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _mdns_query(name: str = "_services._dns-sd._udp.local") -> bytes:
    # Standard DNS query header + one question (PTR)
    header = struct.pack("!HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
    question = _dns_name(name) + struct.pack("!HH", 12, 1)  # PTR IN
    return header + question


def _parse_answer_names(data: bytes) -> List[str]:
    """Best-effort extraction of printable DNS labels from an mDNS response."""
    names: List[str] = []
    # Walk for length-prefixed labels sequences ending with 0x00
    i = 12
    while i < len(data) - 1:
        labels = []
        j = i
        hops = 0
        while j < len(data) and hops < 20:
            length = data[j]
            if length == 0:
                j += 1
                break
            if length & 0xC0 == 0xC0:
                # compression pointer — skip
                j += 2
                break
            if length > 63 or j + 1 + length > len(data):
                break
            labels.append(data[j + 1 : j + 1 + length].decode("utf-8", errors="ignore"))
            j += 1 + length
            hops += 1
        if labels:
            joined = ".".join(labels)
            if any(x in joined.lower() for x in ("local", "_tcp", "_udp", "service")):
                names.append(joined[:120])
        i += 1
        if len(names) >= 8:
            break
    # unique preserve order
    seen = set()
    out = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def probe_mdns(host: str, port: int = 5353, timeout: float = 3.0) -> Dict[str, object]:
    """Unicast mDNS query to a target (many IoT stacks answer unicast)."""
    result: Dict[str, object] = {
        "detected": False,
        "services": [],
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_mdns_query(), (host, int(port)))
        data, _addr = sock.recvfrom(4096)
        if len(data) < 12:
            result["error"] = "short_response"
            return result
        # QR bit set in response
        flags = struct.unpack("!H", data[2:4])[0]
        if (flags & 0x8000) == 0 and len(data) < 20:
            result["error"] = "not_dns_response"
            return result
        result["detected"] = True
        result["services"] = _parse_answer_names(data)
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
