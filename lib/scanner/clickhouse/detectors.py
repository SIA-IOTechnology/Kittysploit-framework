#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ClickHouse HTTP query probe helpers."""

from __future__ import annotations

import socket
import urllib.parse
from typing import Dict, List


def probe_clickhouse_query(
    host: str,
    port: int = 8123,
    query: str = "SELECT 1",
    timeout: float = 5.0,
) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "rows": [], "error": ""}
    path = "/?" + urllib.parse.urlencode({"query": query})
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(request)
        chunks: List[bytes] = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            if len(b"".join(chunks)) > 65536:
                break
        raw = b"".join(chunks)
        if b"\r\n\r\n" not in raw:
            result["error"] = "short_response"
            return result
        _headers, body = raw.split(b"\r\n\r\n", 1)
        text = body.decode("utf-8", errors="replace").strip()
        if text == "1" or text.startswith("1\n") or "Ok." in text:
            result["detected"] = True
            result["rows"] = [line for line in text.splitlines() if line.strip()][:20]
            return result
        if text and not text.lower().startswith("<!doctype"):
            result["detected"] = True
            result["rows"] = [line for line in text.splitlines() if line.strip()][:20]
            return result
        result["error"] = "unexpected_body"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
