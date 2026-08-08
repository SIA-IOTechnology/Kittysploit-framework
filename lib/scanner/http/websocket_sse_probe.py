#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe WebSocket (Socket.io) and SSE endpoints for missing auth / weak Origin checks."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

_WS_PATHS = (
    "/socket.io/?EIO=4&transport=polling",
    "/socket.io/?EIO=3&transport=polling",
    "/ws",
    "/websocket",
    "/api/ws",
    "/api/socket",
    "/realtime/v1/websocket",
)

_SSE_PATHS = (
    "/sse",
    "/events",
    "/api/events",
    "/api/stream",
    "/stream",
    "/mcp/sse",
)

_SOCKETIO_OK = re.compile(r'^\d+\{"sid":', re.M)
_SSE_MARKERS = ("text/event-stream", "event:", "data:")


def probe_socketio(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(
        method="GET",
        path=path,
        allow_redirects=False,
        headers={"Accept": "*/*"},
        timeout=10,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    if status != 200 or not _SOCKETIO_OK.search(body):
        return None
    return {
        "protocol": "socket.io",
        "path": path,
        "kind": "socketio_polling_open",
        "status_code": status,
        "preview": body[:200],
        "severity": "medium",
    }


def probe_sse(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(
        method="GET",
        path=path,
        allow_redirects=False,
        headers={"Accept": "text/event-stream"},
        timeout=8,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    if status not in (200, 406):
        return None
    body = str(getattr(response, "text", "") or "")
    headers = "\n".join(f"{k}: {v}" for k, v in (getattr(response, "headers", None) or {}).items()).lower()
    if not any(m in headers or m in body.lower() for m in _SSE_MARKERS):
        return None
    return {
        "protocol": "sse",
        "path": path,
        "kind": "sse_stream_open",
        "status_code": status,
        "preview": body[:300],
        "severity": "medium",
    }


def probe_origin_bypass(
    http_request: Callable[..., Any],
    path: str,
) -> Optional[Dict[str, Any]]:
    response = http_request(
        method="GET",
        path=path,
        allow_redirects=False,
        headers={
            "Origin": "https://evil.example",
            "Accept": "*/*",
        },
        timeout=10,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    if status not in (200, 101):
        return None
    acao = str((getattr(response, "headers", None) or {}).get("Access-Control-Allow-Origin") or "")
    if acao in ("*", "https://evil.example", "null"):
        return {
            "path": path,
            "kind": "websocket_cors_wildcard",
            "acao": acao,
            "severity": "high",
        }
    body = str(getattr(response, "text", "") or "")
    if status == 200 and ("sid" in body or "event:" in body.lower()):
        return {
            "path": path,
            "kind": "realtime_no_origin_block",
            "status_code": status,
            "severity": "medium",
            "preview": body[:200],
        }
    return None


def scan_realtime_endpoints(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    for path in _WS_PATHS:
        hit = probe_socketio(http_request, path)
        if hit:
            findings.append(hit)
            seen.add(path)
        origin_hit = probe_origin_bypass(http_request, path)
        if origin_hit and path not in seen:
            findings.append(origin_hit)
    for path in _SSE_PATHS:
        hit = probe_sse(http_request, path)
        if hit:
            findings.append(hit)
        origin_hit = probe_origin_bypass(http_request, path)
        if origin_hit:
            findings.append(origin_hit)
    return findings


__all__ = ["scan_realtime_endpoints", "probe_socketio", "probe_sse", "probe_origin_bypass"]
