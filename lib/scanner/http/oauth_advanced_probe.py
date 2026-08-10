#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advanced OAuth/OIDC probes: PKCE optional, refresh token endpoints, token reuse signals."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Callable, Dict, List, Optional

_OAUTH_PATHS = (
    "/oauth/authorize",
    "/oauth2/authorize",
    "/authorize",
    "/auth/authorize",
    "/.well-known/openid-configuration",
)

_TOKEN_PATHS = (
    "/oauth/token",
    "/oauth2/token",
    "/auth/token",
    "/token",
    "/api/auth/token",
)

_OAUTH_PAGE_MARKERS = (
    "oauth",
    "openid",
    "client_id",
    "redirect_uri",
    "response_type",
    "authorization",
    "authorize",
    "scope=",
    "unsupported_response_type",
    "invalid_client",
    "invalid_request",
)

_REFRESH_JSON_MARKERS = (
    "unsupported_grant_type",
    "invalid_grant",
    "invalid_client",
    "invalid_request",
    "refresh_token",
)


def _paths_csv(raw: str, default: str) -> List[str]:
    text = str(raw or "").strip() or default
    return [p.strip() for p in text.split(",") if p.strip()][:12]


def _looks_like_oauth_surface(text: str) -> bool:
    low = text.lower()
    hits = sum(1 for m in _OAUTH_PAGE_MARKERS if m in low)
    return hits >= 2


def probe_oidc_config(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(method="GET", path=path, allow_redirects=False, timeout=10)
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return None
    body = str(getattr(response, "text", "") or "")
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not isinstance(data, dict) or "issuer" not in data:
        return None
    if not (data.get("authorization_endpoint") or data.get("token_endpoint")):
        return None
    return {
        "kind": "oidc_discovery",
        "path": path,
        "issuer": str(data.get("issuer") or ""),
        "token_endpoint": str(data.get("token_endpoint") or ""),
        "authorization_endpoint": str(data.get("authorization_endpoint") or ""),
        "supports_pkce": "code_challenge_methods_supported" in data,
        "code_challenge_methods": data.get("code_challenge_methods_supported") or [],
    }


def probe_pkce_optional(http_request: Callable[..., Any], auth_path: str) -> Optional[Dict[str, Any]]:
    params = {
        "response_type": "code",
        "client_id": "kittysploit-probe",
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "state": "probe",
    }
    query = urllib.parse.urlencode(params)
    sep = "&" if "?" in auth_path else "?"
    response = http_request(
        method="GET",
        path=f"{auth_path}{sep}{query}",
        allow_redirects=False,
        timeout=10,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    location = ""
    headers = getattr(response, "headers", None) or {}
    try:
        location = str(headers.get("Location") or headers.get("location") or "")
    except Exception:
        location = ""
    body = str(getattr(response, "text", "") or "")
    combined = (body + "\n" + location).lower()

    # Soft HTML 200/404 catch-alls on routers must not count as OAuth.
    if not _looks_like_oauth_surface(combined):
        return None
    if "code_challenge" in combined:
        return None
    if status not in (200, 302, 400):
        return None
    # Reject generic login portals that only mention "authorize" once in nav text.
    if status == 200 and "<html" in combined and "client_id" not in combined and "oauth" not in combined:
        return None
    return {
        "kind": "pkce_not_required",
        "path": auth_path,
        "status_code": status,
        "severity": "high",
        "indicator": "authorize_without_pkce",
    }


def probe_refresh_endpoint(http_request: Callable[..., Any], token_path: str) -> Optional[Dict[str, Any]]:
    payload = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "refresh_token": "invalid-probe-token",
            "client_id": "kittysploit-probe",
        }
    )
    response = http_request(
        method="POST",
        path=token_path,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        allow_redirects=False,
        timeout=10,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    if status not in (200, 400, 401):
        return None

    data = None
    try:
        data = json.loads(body)
    except Exception:
        data = None

    # Prefer structured OAuth token errors; avoid HTML soft pages.
    if isinstance(data, dict):
        err = str(data.get("error") or "").lower()
        blob = json.dumps(data).lower()
        if err or any(m in blob for m in _REFRESH_JSON_MARKERS):
            return {
                "kind": "refresh_token_endpoint",
                "path": token_path,
                "status_code": status,
                "severity": "medium" if status == 401 else "high",
                "preview": body[:300],
                "indicator": "refresh_grant_accepted_or_parsed",
            }
        return None

    low = body.lower()
    if any(m in low for m in _REFRESH_JSON_MARKERS) and _looks_like_oauth_surface(low):
        return {
            "kind": "refresh_token_endpoint",
            "path": token_path,
            "status_code": status,
            "severity": "medium",
            "preview": body[:300],
            "indicator": "refresh_grant_text_error",
        }
    return None


def scan_oauth_advanced(
    http_request: Callable[..., Any],
    *,
    oauth_paths: str = "",
    token_paths: str = "",
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in _paths_csv(oauth_paths, ",".join(_OAUTH_PATHS)):
        if "openid-configuration" in path:
            hit = probe_oidc_config(http_request, path)
            if hit:
                findings.append(hit)
        else:
            hit = probe_pkce_optional(http_request, path)
            if hit:
                findings.append(hit)
    for path in _paths_csv(token_paths, ",".join(_TOKEN_PATHS)):
        hit = probe_refresh_endpoint(http_request, path)
        if hit:
            findings.append(hit)
    return findings


__all__ = ["scan_oauth_advanced", "probe_oidc_config", "probe_pkce_optional", "probe_refresh_endpoint"]
