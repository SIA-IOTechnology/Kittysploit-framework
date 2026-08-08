#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed serverless function URLs and unauthenticated invoke surfaces."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

_URL_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
    (r"https://[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws/?", "aws_lambda_url", "high"),
    (r"https://[a-z0-9-]+\.cloudfunctions\.net/?", "gcp_cloud_function", "medium"),
    (r"https://[a-z0-9-]+\.[a-z0-9-]+\.azurewebsites\.net/api/", "azure_function", "medium"),
    (r"https://[a-z0-9-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com/", "aws_api_gateway", "medium"),
)

_PROBE_PATHS = (
    "/api",
    "/api/health",
    "/api/hello",
    "/.well-known/openapi.json",
)

_COMPILED_URL = [(re.compile(rx), kind, sev) for rx, kind, sev in _URL_PATTERNS]


def extract_serverless_urls(text: str, source: str = "/") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    for regex, kind, severity in _COMPILED_URL:
        for match in regex.finditer(text or ""):
            url = match.group(0).rstrip("/")
            if url in seen:
                continue
            seen.add(url)
            findings.append(
                {
                    "source": source,
                    "kind": kind,
                    "severity": severity,
                    "url": url,
                }
            )
    return findings


def probe_function_endpoint(
    http_request: Callable[..., Any],
    path: str,
) -> Optional[Dict[str, Any]]:
    response = http_request(method="GET", path=path, allow_redirects=True, timeout=12)
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    if status not in (200, 201, 204, 401, 403):
        return None
    body = str(getattr(response, "text", "") or "")
    headers = {str(k).lower(): str(v) for k, v in (getattr(response, "headers", None) or {}).items()}
    indicators: List[str] = []
    if "x-amzn-requestid" in headers or "x-amz-request-id" in headers:
        indicators.append("aws_lambda_response")
    if "x-azure-ref" in headers or "x-ms-middleware-request-id" in headers:
        indicators.append("azure_function_response")
    if "x-cloud-trace-context" in headers:
        indicators.append("gcp_function_response")
    if status in (200, 201, 204) and body:
        lowered = body.lower()
        if any(m in lowered for m in ("function", "serverless", "lambda", "cloud function")):
            indicators.append("serverless_body_marker")
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                indicators.append("json_api_response")
        except Exception:
            pass
    if status in (200, 201, 204) and not indicators:
        if len(body) < 5000 and body.strip():
            indicators.append("unauthenticated_http_200")
    if not indicators:
        return None
    return {
        "path": path,
        "status_code": status,
        "indicators": indicators,
        "preview": body[:400],
        "severity": "high" if status in (200, 201, 204) else "medium",
    }


def scan_serverless_surface(
    http_request: Callable[..., Any],
    homepage_html: str = "",
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if homepage_html:
        findings.extend(extract_serverless_urls(homepage_html, "/"))
    for path in _PROBE_PATHS:
        hit = probe_function_endpoint(http_request, path)
        if hit:
            findings.append(hit)
    return findings


__all__ = [
    "extract_serverless_urls",
    "probe_function_endpoint",
    "scan_serverless_surface",
]
