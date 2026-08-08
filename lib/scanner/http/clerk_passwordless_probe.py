#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Clerk passwordless sign-in surface probes."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_CLERK_PK_RE = re.compile(r"\b(pk_(live|test)_[A-Za-z0-9]{20,})\b")
_FRONTEND_API_RE = re.compile(
    r"(?i)(?:CLERK_(?:FRONTEND_API|FAPI)|NEXT_PUBLIC_CLERK_(?:FRONTEND_API|DOMAIN))\s*[=:]\s*['\"]([^'\"]+)['\"]",
)
_PROBE_EMAIL = "security-probe@example.com"


def discover_clerk_passwordless_config(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _CLERK_PK_RE.finditer(body):
        creds["clerk_publishable_key"] = match.group(1)
    for match in _FRONTEND_API_RE.finditer(body):
        val = match.group(1).strip().rstrip("/")
        if val.startswith("http"):
            from urllib.parse import urlparse

            creds["clerk_frontend_api"] = urlparse(val).netloc or val
        else:
            creds["clerk_frontend_api"] = val.replace("https://", "").replace("http://", "")
    for match in re.finditer(
        r"(?i)NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["clerk_publishable_key"] = match.group(1).strip()
    return creds


def _frontend_host(creds: Dict[str, str]) -> str:
    host = (creds.get("clerk_frontend_api") or "").strip()
    if host:
        return host if not host.startswith("http") else host.replace("https://", "").replace("http://", "")
    pk = creds.get("clerk_publishable_key") or ""
    if "live" in pk:
        return "clerk.accounts.dev"
    return "clerk.accounts.dev"


def probe_clerk_passwordless(
    session,
    creds: Dict[str, str],
    email: str = _PROBE_EMAIL,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    host = _frontend_host(creds)
    base = f"https://{host}"
    pk = creds.get("clerk_publishable_key") or ""

    try:
        client_resp = session.get(
            f"{base}/v1/client",
            headers={"Accept": "application/json"},
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return {"platform": "clerk", "ok": False, "detail": str(exc)}

    if int(getattr(client_resp, "status_code", 0) or 0) != 200:
        return {"platform": "clerk", "ok": False, "detail": f"client_http_{client_resp.status_code}"}

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if pk:
        headers["Authorization"] = pk

    strategies = ("email_link", "email_code", "reset_password_email_code")
    findings_detail = []
    for strategy in strategies:
        payload = {"identifier": email, "strategy": strategy}
        try:
            response = session.post(
                f"{base}/v1/client/sign_ins",
                headers=headers,
                json=payload,
                timeout=12,
                verify=verify_ssl,
            )
        except Exception:
            continue
        status = int(getattr(response, "status_code", 0) or 0)
        text = str(getattr(response, "text", "") or "")
        if status in (200, 201, 422):
            findings_detail.append({"strategy": strategy, "status_code": status, "preview": text[:200]})
        if status in (200, 201) and ("email" in text.lower() or "sign_in" in text.lower()):
            return {
                "platform": "clerk",
                "ok": True,
                "kind": "passwordless_signin_accepted",
                "strategy": strategy,
                "frontend_api": host,
                "status_code": status,
                "severity": "high",
                "preview": text[:400],
            }

    if findings_detail:
        return {
            "platform": "clerk",
            "ok": True,
            "kind": "passwordless_surface_active",
            "frontend_api": host,
            "strategies": findings_detail,
            "severity": "medium",
        }
    return {"platform": "clerk", "ok": False, "detail": "no_passwordless_response"}


def enumerate_clerk_passwordless(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    publishable_key: str = "",
    frontend_api: str = "",
    email: str = _PROBE_EMAIL,
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_clerk_passwordless_config(homepage_html or "")
    if publishable_key:
        creds["clerk_publishable_key"] = publishable_key
    if frontend_api:
        creds["clerk_frontend_api"] = frontend_api

    findings: List[Dict[str, Any]] = []
    if not creds.get("clerk_publishable_key") and not creds.get("clerk_frontend_api"):
        return findings, creds

    hit = probe_clerk_passwordless(session, creds, email, verify_ssl=verify_ssl)
    if creds.get("clerk_publishable_key"):
        hit["key_masked"] = mask_secret(creds["clerk_publishable_key"])
    if hit.get("ok"):
        findings.append(hit)
    return findings, creds


__all__ = [
    "discover_clerk_passwordless_config",
    "enumerate_clerk_passwordless",
    "probe_clerk_passwordless",
]
