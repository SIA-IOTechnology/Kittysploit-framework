#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PocketBase admin API enumeration and collection abuse."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_ADMIN_PATHS = (
    "/api/admins",
    "/api/settings",
    "/api/health",
    "/api/collections",
    "/api/collections/users/records",
    "/api/collections/_superusers/records",
)


def discover_pocketbase_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in re.finditer(
        r"(?i)POCKETBASE_(?:ADMIN_EMAIL|ADMIN_PASSWORD|URL|BASE_URL)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        line = match.group(0).upper()
        val = match.group(1).strip()
        if "EMAIL" in line:
            creds["admin_email"] = val
        elif "PASSWORD" in line:
            creds["admin_password"] = val
        elif "URL" in line:
            creds["base_url"] = val.rstrip("/")
    return creds


def probe_pocketbase_endpoint(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(method="GET", path=path, allow_redirects=False, timeout=10)
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    if status not in (200, 401, 403):
        return None
    body = str(getattr(response, "text", "") or "")
    if status == 401 and "authorization" not in body.lower():
        return None
    kind = "pocketbase_api"
    severity = "medium"
    if path == "/api/collections" and status == 200:
        kind = "pocketbase_collections_exposed"
        severity = "high"
    if path == "/api/settings" and status == 200:
        kind = "pocketbase_settings_exposed"
        severity = "high"
    if "records" in path and status == 200:
        kind = "pocketbase_records_exposed"
        severity = "critical"
    return {
        "path": path,
        "kind": kind,
        "status_code": status,
        "preview": body[:400],
        "severity": severity,
    }


def auth_pocketbase_admin(
    http_request: Callable[..., Any],
    email: str,
    password: str,
) -> Tuple[Optional[str], Dict[str, Any]]:
    payload = json.dumps({"identity": email, "password": password})
    response = http_request(
        method="POST",
        path="/api/admins/auth-with-password",
        data=payload,
        headers={"Content-Type": "application/json"},
        allow_redirects=False,
        timeout=12,
    )
    if not response:
        return None, {"ok": False, "detail": "no_response"}
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    if status != 200:
        return None, {"ok": False, "detail": f"http_{status}", "preview": body[:200]}
    try:
        data = json.loads(body)
    except Exception:
        return None, {"ok": False, "detail": "invalid_json"}
    token = str(data.get("token") or "")
    if not token:
        return None, {"ok": False, "detail": "missing_token"}
    return token, {"ok": True, "admin": data.get("admin"), "severity": "critical"}


def enum_pocketbase_with_token(
    http_request: Callable[..., Any],
    token: str,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    headers = {"Authorization": token}
    for path in ("/api/collections", "/api/admins", "/api/settings"):
        response = http_request(method="GET", path=path, headers=headers, allow_redirects=False, timeout=10)
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        body = str(getattr(response, "text", "") or "")
        findings.append(
            {
                "path": path,
                "kind": "pocketbase_authenticated_enum",
                "status_code": 200,
                "preview": body[:400],
                "severity": "critical",
            }
        )
    return findings


def enumerate_pocketbase(
    http_request: Callable[..., Any],
    homepage_html: str = "",
    *,
    admin_email: str = "",
    admin_password: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_pocketbase_credentials(homepage_html or "")
    if admin_email:
        creds["admin_email"] = admin_email
    if admin_password:
        creds["admin_password"] = admin_password

    findings: List[Dict[str, Any]] = []
    for path in _ADMIN_PATHS:
        hit = probe_pocketbase_endpoint(http_request, path)
        if hit:
            findings.append(hit)

    email = creds.get("admin_email") or ""
    password = creds.get("admin_password") or ""
    if email and password:
        token, auth_hit = auth_pocketbase_admin(http_request, email, password)
        auth_hit["kind"] = "pocketbase_admin_auth"
        auth_hit["email_masked"] = mask_secret(email)
        findings.append(auth_hit)
        if token:
            findings.extend(enum_pocketbase_with_token(http_request, token))

    return findings, creds


__all__ = [
    "auth_pocketbase_admin",
    "discover_pocketbase_credentials",
    "enumerate_pocketbase",
    "probe_pocketbase_endpoint",
]
