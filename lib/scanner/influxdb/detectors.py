#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""InfluxDB HTTP probe helpers."""

from __future__ import annotations

import json
import socket
from typing import Dict, List


def probe_influxdb_query(
    host: str,
    port: int = 8086,
    query: str = "SHOW DATABASES",
    timeout: float = 5.0,
) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "databases": [], "error": ""}
    path = f"/query?q={query.replace(' ', '+')}"
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
        raw = sock.recv(65536)
        if b"\r\n\r\n" not in raw:
            result["error"] = "short_response"
            return result
        _headers, body = raw.split(b"\r\n\r\n", 1)
        text = body.decode("utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            result["error"] = "invalid_json"
            return result
        results = data.get("results") or []
        dbs: List[str] = []
        for block in results:
            for series in block.get("series") or []:
                for value in series.get("values") or []:
                    if value:
                        dbs.append(str(value[0]))
        if dbs:
            result["detected"] = True
            result["databases"] = dbs[:20]
            return result
        if results and not any(r.get("error") for r in results):
            result["detected"] = True
            return result
        result["error"] = "no_databases"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
