#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP server auth abuse: unauthenticated tools/list and SSE message endpoints."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

_SSE_PATHS = ("/sse", "/mcp/sse", "/mcp")
_JSONRPC_TOOLS_LIST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {},
}


def probe_mcp_sse(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
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
    body = str(getattr(response, "text", "") or "")
    if status != 200:
        return None
    if "event: endpoint" in body or "text/event-stream" in str(getattr(response, "headers", {})).lower():
        endpoint_match = re.search(r"data:\s*(\S+)", body)
        return {
            "kind": "mcp_sse_exposed",
            "path": path,
            "message_endpoint": endpoint_match.group(1) if endpoint_match else "",
            "preview": body[:300],
            "severity": "high",
        }
    return None


def probe_mcp_jsonrpc(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(
        method="POST",
        path=path,
        data=json.dumps(_JSONRPC_TOOLS_LIST),
        headers={"Content-Type": "application/json"},
        allow_redirects=False,
        timeout=10,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    if status not in (200, 202):
        return None
    lowered = body.lower()
    if "tools" in lowered and ("jsonrpc" in lowered or "result" in lowered):
        tools = []
        try:
            data = json.loads(body)
            result = data.get("result") or {}
            if isinstance(result, dict):
                tools = [str(t.get("name") or "") for t in (result.get("tools") or []) if isinstance(t, dict)][:15]
        except Exception:
            pass
        return {
            "kind": "mcp_tools_list_unauth",
            "path": path,
            "tools": tools,
            "preview": body[:500],
            "severity": "critical",
        }
    return None


def scan_mcp_auth_surface(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in _SSE_PATHS:
        hit = probe_mcp_sse(http_request, path)
        if hit:
            findings.append(hit)
            endpoint = str(hit.get("message_endpoint") or "").strip()
            if endpoint:
                rpc_hit = probe_mcp_jsonrpc(http_request, endpoint if endpoint.startswith("/") else f"/{endpoint}")
                if rpc_hit:
                    findings.append(rpc_hit)
    for path in ("/mcp", "/api/mcp", "/message", "/mcp/message"):
        hit = probe_mcp_jsonrpc(http_request, path)
        if hit:
            findings.append(hit)
    return findings


__all__ = ["scan_mcp_auth_surface", "probe_mcp_sse", "probe_mcp_jsonrpc"]
