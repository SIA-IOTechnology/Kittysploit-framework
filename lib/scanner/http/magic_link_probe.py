#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magic link and passwordless authentication surface detection."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

_MAGIC_PATHS = (
    "/api/auth/signin/email",
    "/api/auth/magic-link",
    "/api/auth/magic-link/send",
    "/api/magic-link",
    "/api/magic-link/send",
    "/auth/magic-link",
    "/auth/magic-link/send",
    "/auth/passwordless",
    "/auth/passwordless/start",
    "/api/auth/passwordless",
    "/api/auth/passwordless/start",
    "/api/v1/auth/magic-link",
    "/api/v1/auth/passwordless",
    "/login/magic",
    "/login/magic-link",
    "/auth/send-magic-link",
    "/api/auth/send-magic-link",
    "/auth/signin/email",
    "/auth/login/email",
    "/api/auth/email",
    "/api/auth/otp",
    "/auth/v1/otp",
)

_RESPONSE_MARKERS = (
    "magic link",
    "magic-link",
    "passwordless",
    "check your email",
    "email sent",
    "sign-in link",
    "signin link",
    "verification email",
    "otp",
    "one-time",
    "login link",
)

_JSON_FIELD_MARKERS = (
    "email",
    "redirect",
    "callback",
    "token",
    "url",
    "message",
    "success",
)


def _looks_like_magic_response(status: int, body: str, headers: Dict[str, str]) -> bool:
    text = (body or "").lower()
    if status not in (200, 201, 202, 400, 422):
        return False
    if any(m in text for m in _RESPONSE_MARKERS):
        return True
    if text.strip().startswith("{"):
        try:
            data = json.loads(body)
        except Exception:
            return False
        blob = json.dumps(data).lower()
        if any(m in blob for m in _RESPONSE_MARKERS):
            return True
        if isinstance(data, dict) and any(k in data for k in ("url", "redirect", "ok", "success")):
            if "email" in blob or "magic" in blob or "link" in blob:
                return True
    ctype = str(headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if "json" in ctype and status in (200, 400, 422) and "email" in text:
        return True
    return False


def probe_magic_link_get(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(method="GET", path=path, allow_redirects=False, timeout=10)
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    headers = dict(getattr(response, "headers", None) or {})
    lowered = body.lower()
    form_markers = ("type=\"email\"", "name=\"email\"", "magic", "passwordless", "sign-in link")
    if status == 200 and any(m in lowered for m in form_markers):
        return {
            "path": path,
            "method": "GET",
            "kind": "magic_link_form",
            "status_code": status,
            "severity": "medium",
            "preview": body[:300],
        }
    return None


def probe_magic_link_post(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    payload = json.dumps({"email": "security-probe@example.com", "callbackUrl": "https://example.com"})
    response = http_request(
        method="POST",
        path=path,
        data=payload,
        headers={"Content-Type": "application/json"},
        allow_redirects=False,
        timeout=12,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    headers = dict(getattr(response, "headers", None) or {})
    if not _looks_like_magic_response(status, body, headers):
        return None
    severity = "high" if status in (200, 201, 202) else "medium"
    return {
        "path": path,
        "method": "POST",
        "kind": "magic_link_endpoint",
        "status_code": status,
        "severity": severity,
        "preview": body[:400],
    }


def extract_magic_link_hints(text: str) -> List[str]:
    hints: List[str] = []
    body = text or ""
    for match in re.finditer(
        r"(?i)(/api/auth/[a-z0-9/_-]*(?:magic|passwordless|email|otp)[a-z0-9/_-]*)",
        body,
    ):
        val = match.group(1).strip()
        if val not in hints and len(val) < 80:
            hints.append(val)
    return hints[:10]


def scan_magic_link_surface(http_request: Callable[..., Any], homepage_html: str = "") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    paths = list(_MAGIC_PATHS)
    paths.extend(extract_magic_link_hints(homepage_html or ""))
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        get_hit = probe_magic_link_get(http_request, path)
        if get_hit:
            findings.append(get_hit)
        post_hit = probe_magic_link_post(http_request, path)
        if post_hit:
            findings.append(post_hit)
    return findings


__all__ = ["scan_magic_link_surface", "probe_magic_link_get", "probe_magic_link_post", "extract_magic_link_hints"]
