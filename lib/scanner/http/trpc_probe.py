#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tRPC and OpenAPI procedure enumeration for Next.js apps."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

_TRPC_BASE_PATHS = (
    "/api/trpc",
    "/trpc",
    "/api/trpc/health",
)

_COMMON_PROCEDURES = (
    "health",
    "healthcheck",
    "ping",
    "user.me",
    "user.getSession",
    "auth.getSession",
    "auth.session",
    "post.list",
    "posts.list",
    "hello",
)

_OPENAPI_PATHS = (
    "/openapi.json",
    "/api/openapi.json",
    "/api/trpc-openapi.json",
    "/swagger.json",
    "/api/swagger.json",
)


def probe_trpc_procedure(
    http_request: Callable[..., Any],
    base_path: str,
    procedure: str,
) -> Optional[Dict[str, Any]]:
    base = base_path.rstrip("/")
    if base.endswith("/health") and procedure != "health":
        base = base.rsplit("/", 1)[0]
    input_payload = quote(json.dumps({"json": None}))
    path = f"{base}/{procedure}?input={input_payload}"
    response = http_request(method="GET", path=path, allow_redirects=False, timeout=12)
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    if status not in (200, 400, 401, 403, 404, 405):
        return None
    if status == 404 and "NOT_FOUND" not in body.upper():
        return None
    indicators = []
    if status == 200:
        indicators.append("procedure_responded_200")
    if "result" in body and "data" in body:
        indicators.append("trpc_result_envelope")
    if "error" in body and "json" in body:
        indicators.append("trpc_error_envelope")
    if not indicators:
        return None
    return {
        "path": path,
        "procedure": procedure,
        "status_code": status,
        "indicators": indicators,
        "preview": body[:400],
        "severity": "high" if status == 200 else "medium",
    }


def probe_trpc_batch_amplification(
    http_request: Callable[..., Any],
    base_path: str,
    *,
    batch_size: int = 25,
) -> Optional[Dict[str, Any]]:
    """Detect tRPC batch endpoints that amplify work (DoS / resource exhaustion risk)."""
    base = base_path.rstrip("/")
    if base.endswith("/health"):
        base = base.rsplit("/", 1)[0]
    procs = ",".join(["health"] * max(3, min(batch_size, 40)))
    input_map = quote(
        json.dumps({str(i): {"json": None} for i in range(procs.count(",") + 1)})
    )
    single_path = f"{base}/health?input={quote(json.dumps({'json': None}))}"
    batch_path = f"{base}/{procs}?batch=1&input={input_map}"

    single = http_request(method="GET", path=single_path, allow_redirects=False, timeout=15)
    batch = http_request(method="GET", path=batch_path, allow_redirects=False, timeout=20)
    if not batch:
        return None
    batch_status = int(getattr(batch, "status_code", 0) or 0)
    if batch_status != 200:
        return None
    batch_body = str(getattr(batch, "text", "") or "")
    if not batch_body.strip().startswith("["):
        return None
    single_len = len(str(getattr(single, "text", "") or "")) if single else 0
    batch_len = len(batch_body)
    ratio = round(batch_len / max(single_len, 1), 2)
    proc_count = procs.count(",") + 1
    severity = "high" if proc_count >= 10 and ratio >= 3 else "medium"
    return {
        "path": batch_path,
        "kind": "trpc_batch_amplification",
        "procedure_count": proc_count,
        "single_response_bytes": single_len,
        "batch_response_bytes": batch_len,
        "amplification_ratio": ratio,
        "status_code": batch_status,
        "preview": batch_body[:300],
        "severity": severity,
    }


def probe_trpc_batch(
    http_request: Callable[..., Any],
    base_path: str,
) -> Optional[Dict[str, Any]]:
    base = base_path.rstrip("/")
    procs = "health,ping"
    input_map = quote(json.dumps({"0": {"json": None}, "1": {"json": None}}))
    path = f"{base}/{procs}?batch=1&input={input_map}"
    response = http_request(method="GET", path=path, allow_redirects=False, timeout=12)
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return None
    body = str(getattr(response, "text", "") or "")
    if not body.strip().startswith("["):
        return None
    return {
        "path": path,
        "kind": "trpc_batch",
        "status_code": 200,
        "preview": body[:400],
        "severity": "medium",
    }


def probe_openapi(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in _OPENAPI_PATHS:
        response = http_request(method="GET", path=path, allow_redirects=False, timeout=10)
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        body = str(getattr(response, "text", "") or "")
        try:
            data = json.loads(body)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        paths = list((data.get("paths") or {}).keys())[:25]
        if paths:
            findings.append(
                {
                    "kind": "openapi_exposed",
                    "path": path,
                    "routes": paths,
                    "route_count": len(paths),
                    "severity": "high",
                }
            )
    return findings


def scan_trpc_surface(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    findings.extend(probe_openapi(http_request))
    bases = list(_TRPC_BASE_PATHS)
    seen_procs = set()
    for base in bases:
        batch = probe_trpc_batch(http_request, base)
        if batch:
            findings.append(batch)
        for proc in _COMMON_PROCEDURES:
            if proc in seen_procs:
                continue
            hit = probe_trpc_procedure(http_request, base, proc)
            if hit:
                seen_procs.add(proc)
                findings.append(hit)
    # Extract procedure names embedded in homepage bundles is done at module level
    return findings


def extract_trpc_procedures_from_js(text: str) -> List[str]:
    procs: List[str] = []
    seen = set()
    for match in re.finditer(r'["\']([a-z][a-z0-9_]*\.[a-z][a-z0-9_.]*)["\']', text or "", re.I):
        name = match.group(1)
        if name in seen or len(name) > 60:
            continue
        if any(name.startswith(p) for p in ("user.", "auth.", "post.", "admin.", "api.")):
            seen.add(name)
            procs.append(name)
    return procs[:20]


__all__ = [
    "extract_trpc_procedures_from_js",
    "probe_trpc_batch_amplification",
    "probe_trpc_procedure",
    "scan_trpc_surface",
]
