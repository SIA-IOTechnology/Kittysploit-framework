#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Auth0 passwordless email link/code probes."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_PROBE_EMAIL = "security-probe@example.com"


def discover_auth0_passwordless_config(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in re.finditer(
        r"(?i)(?:AUTH0_(?:DOMAIN|ISSUER)|NEXT_PUBLIC_AUTH0_DOMAIN)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        domain = match.group(1).strip().rstrip("/")
        if domain.startswith("http"):
            from urllib.parse import urlparse

            domain = urlparse(domain).netloc or domain
        creds["auth0_domain"] = domain.replace("https://", "").replace("http://", "")
    for match in re.finditer(
        r"(?i)(?:AUTH0_CLIENT_ID|NEXT_PUBLIC_AUTH0_CLIENT_ID)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["auth0_client_id"] = match.group(1).strip()
    for match in re.finditer(
        r"(?i)AUTH0_(?:PASSWORDLESS|CONNECTION)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["auth0_connection"] = match.group(1).strip()
    return creds


def probe_auth0_passwordless(
    session,
    domain: str,
    client_id: str,
    email: str = _PROBE_EMAIL,
    connection: str = "email",
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = f"https://{domain}/passwordless/start"
    payload = {
        "client_id": client_id,
        "connection": connection,
        "email": email,
        "send": "link",
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        response = session.post(url, json=payload, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "auth0", "ok": False, "detail": str(exc)}
    status = int(getattr(response, "status_code", 0) or 0)
    text = str(getattr(response, "text", "") or "")
    if status in (200, 201):
        return {
            "platform": "auth0",
            "ok": True,
            "kind": "auth0_passwordless_link_sent",
            "domain": domain,
            "connection": connection,
            "status_code": status,
            "preview": text[:300],
            "severity": "high",
        }
    if status == 400 and ("email" in text.lower() or "connection" in text.lower()):
        return {
            "platform": "auth0",
            "ok": True,
            "kind": "auth0_passwordless_endpoint_active",
            "domain": domain,
            "status_code": status,
            "preview": text[:300],
            "severity": "medium",
        }
    return {"platform": "auth0", "ok": False, "detail": f"http_{status}", "preview": text[:200]}


def probe_auth0_passwordless_code(
    session,
    domain: str,
    client_id: str,
    email: str = _PROBE_EMAIL,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = f"https://{domain}/passwordless/start"
    payload = {
        "client_id": client_id,
        "connection": "email",
        "email": email,
        "send": "code",
    }
    try:
        response = session.post(url, json=payload, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "auth0", "ok": False, "detail": str(exc)}
    status = int(getattr(response, "status_code", 0) or 0)
    if status in (200, 201):
        return {
            "platform": "auth0",
            "ok": True,
            "kind": "auth0_passwordless_code_sent",
            "domain": domain,
            "severity": "high",
        }
    return {"platform": "auth0", "ok": False, "detail": f"http_{status}"}


def enumerate_auth0_passwordless(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    domain: str = "",
    client_id: str = "",
    email: str = _PROBE_EMAIL,
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_auth0_passwordless_config(homepage_html or "")
    if domain:
        creds["auth0_domain"] = domain
    if client_id:
        creds["auth0_client_id"] = client_id

    findings: List[Dict[str, Any]] = []
    dom = creds.get("auth0_domain") or ""
    cid = creds.get("auth0_client_id") or ""
    conn = creds.get("auth0_connection") or "email"
    if not dom or not cid:
        return findings, creds

    link = probe_auth0_passwordless(session, dom, cid, email, conn, verify_ssl=verify_ssl)
    link["client_id_masked"] = mask_secret(cid)
    if link.get("ok"):
        findings.append(link)
    else:
        code = probe_auth0_passwordless_code(session, dom, cid, email, verify_ssl=verify_ssl)
        if code.get("ok"):
            findings.append(code)
        else:
            findings.append(link)
    return findings, creds


__all__ = [
    "discover_auth0_passwordless_config",
    "enumerate_auth0_passwordless",
    "probe_auth0_passwordless",
]
