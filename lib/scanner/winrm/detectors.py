#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WinRM authentication enumeration helpers."""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class WinrmProbeResult:
    host: str
    port: int
    use_ssl: bool
    reachable: bool = False
    status_code: Optional[int] = None
    auth_methods: List[str] = field(default_factory=list)
    server_header: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "ssl": self.use_ssl,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "auth_methods": self.auth_methods,
            "server_header": self.server_header,
            "error": self.error,
        }


def _parse_auth_methods(www_authenticate: str) -> List[str]:
    values = []
    for chunk in re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", www_authenticate or ""):
        token = chunk.strip().split(" ", 1)[0].strip()
        if token:
            values.append(token)
    return sorted(set(values))


def _read_http_response(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="replace")


def probe_winrm(
    host: str,
    port: int = 5985,
    use_ssl: bool = False,
    timeout: float = 5.0,
) -> WinrmProbeResult:
    result = WinrmProbeResult(host=host, port=int(port), use_ssl=use_ssl)
    request = (
        f"GET /wsman HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"User-Agent: KittySploit-WinRM-Probe\r\n"
        f"\r\n"
    ).encode("utf-8")

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((host, int(port)))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        sock.sendall(request)
        response = _read_http_response(sock, timeout)
    except Exception as exc:
        result.error = str(exc)
        return result
    finally:
        try:
            raw.close()
        except Exception:
            pass

    if not response:
        result.error = "Empty HTTP response"
        return result

    lines = response.split("\r\n")
    if not lines:
        result.error = "Malformed HTTP response"
        return result

    status_line = lines[0]
    try:
        result.status_code = int(status_line.split(" ", 2)[1])
    except Exception:
        result.status_code = None
    result.reachable = True

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    result.server_header = headers.get("server", "")
    auth = headers.get("www-authenticate", "")
    result.auth_methods = _parse_auth_methods(auth)
    return result
