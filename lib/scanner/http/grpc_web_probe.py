#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gRPC-Web and HTTP-transported gRPC method enumeration."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

_GRPC_WEB_PATHS = (
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/grpc.health.v1.Health/Check",
    "/grpc.health.v1.Health/Watch",
)

_COMMON_SERVICE_PREFIXES = (
    "/api/grpc/",
    "/grpc/",
    "/.grpc/",
    "/v1/grpc/",
)

_GRPC_CONTENT_TYPES = (
    "application/grpc-web+proto",
    "application/grpc-web-text",
    "application/grpc",
    "application/grpc+proto",
)


def _response_headers(response: Any) -> Dict[str, str]:
    raw = getattr(response, "headers", None) or {}
    return {str(k): str(v) for k, v in raw.items()}


def probe_grpc_web_path(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    headers = {
        "Content-Type": "application/grpc-web+proto",
        "Accept": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
    }
    response = http_request(
        method="POST",
        path=path,
        data=b"\x00\x00\x00\x00\x00",
        headers=headers,
        allow_redirects=False,
        timeout=12,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    if status not in (200, 400, 415, 500):
        return None
    resp_headers = _response_headers(response)
    header_blob = "\n".join(f"{k}: {v}" for k, v in resp_headers.items()).lower()
    body = str(getattr(response, "text", "") or "")
    grpcish = any(ct in header_blob for ct in _GRPC_CONTENT_TYPES)
    grpcish = grpcish or "grpc-status" in header_blob or "grpc-message" in header_blob
    if not grpcish and status not in (200, 500):
        return None
    return {
        "path": path,
        "kind": "grpc_web_endpoint",
        "status_code": status,
        "grpc_headers": [h for h in resp_headers if "grpc" in h.lower()],
        "severity": "medium" if status == 200 else "info",
        "preview": body[:200] if body else header_blob[:200],
    }


def probe_grpc_web_options(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(method="OPTIONS", path=path, allow_redirects=False, timeout=10)
    if not response:
        return None
    headers = _response_headers(response)
    allow = str(headers.get("Access-Control-Allow-Headers") or headers.get("access-control-allow-headers") or "")
    if not any(ct in allow.lower() for ct in ("grpc", "x-grpc-web")):
        return None
    return {
        "path": path,
        "kind": "grpc_web_cors",
        "status_code": int(getattr(response, "status_code", 0) or 0),
        "allow_headers": allow[:200],
        "severity": "info",
    }


def extract_grpc_paths_from_js(text: str) -> List[str]:
    paths: List[str] = []
    seen = set()
    for match in re.finditer(r"['\"](/[A-Za-z0-9_.]+/[A-Za-z0-9_]+)['\"]", text or ""):
        path = match.group(1)
        parts = path.strip("/").split("/")
        if len(parts) != 2:
            continue
        service, method = parts
        if "." not in service and "grpc" not in service.lower():
            continue
        if path in seen or len(path) > 120:
            continue
        seen.add(path)
        paths.append(path)
    return paths[:15]


def scan_grpc_web_surface(
    http_request: Callable[..., Any],
    homepage_html: str = "",
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    paths = list(_GRPC_WEB_PATHS)
    paths.extend(extract_grpc_paths_from_js(homepage_html or ""))
    for prefix in _COMMON_SERVICE_PREFIXES:
        paths.append(prefix.rstrip("/") + "/health")

    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        opt = probe_grpc_web_options(http_request, path)
        if opt:
            findings.append(opt)
        hit = probe_grpc_web_path(http_request, path)
        if hit:
            findings.append(hit)
    return findings


__all__ = [
    "extract_grpc_paths_from_js",
    "probe_grpc_web_path",
    "scan_grpc_web_surface",
]
