#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Docker Engine API probe helpers."""

from __future__ import annotations

import json
import socket
from typing import Dict, List


def _http_get(host: str, port: int, path: str, timeout: float) -> Dict[str, object]:
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
        raw = sock.recv(131072)
        if b"\r\n\r\n" not in raw:
            return {"status": 0, "body": "", "error": "short_response"}
        header_blob, body = raw.split(b"\r\n\r\n", 1)
        status_line = header_blob.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        status = 0
        parts = status_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
        return {"status": status, "body": body.decode("utf-8", errors="replace"), "error": ""}
    except Exception as exc:
        return {"status": 0, "body": "", "error": str(exc)}
    finally:
        sock.close()


def probe_docker_api(host: str, port: int = 2375, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "version": "",
        "containers": [],
        "error": "",
    }
    version_resp = _http_get(host, port, "/version", timeout)
    if version_resp.get("error"):
        result["error"] = version_resp["error"]
        return result
    if int(version_resp.get("status") or 0) != 200:
        result["error"] = f"version_status_{version_resp.get('status')}"
        return result
    try:
        version_data = json.loads(version_resp.get("body") or "{}")
    except json.JSONDecodeError:
        result["error"] = "invalid_version_json"
        return result
    if not version_data.get("ApiVersion"):
        result["error"] = "not_docker_api"
        return result
    result["detected"] = True
    result["version"] = str(version_data.get("Version") or version_data.get("ApiVersion") or "")

    containers_resp = _http_get(host, port, "/containers/json", timeout)
    if int(containers_resp.get("status") or 0) == 200:
        try:
            containers = json.loads(containers_resp.get("body") or "[]")
            if isinstance(containers, list):
                result["containers"] = [
                    str(item.get("Names") or item.get("Id") or "")[:80] for item in containers[:10]
                ]
        except json.JSONDecodeError:
            pass
    return result
