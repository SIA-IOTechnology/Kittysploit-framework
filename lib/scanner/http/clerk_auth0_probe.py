#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Discover Clerk / Auth0 credentials and enumerate Management API surfaces."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from lib.scanner.http.vibe_secrets_probe import extract_vibe_secrets, mask_secret

_CLERK_SECRET_RE = re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{20,}\b")
_CLERK_DOMAIN_RE = re.compile(
    r"(?i)(?:CLERK_(?:FRONTEND_API|PUBLISHABLE_KEY|JWT_KEY)|clerk\.accounts)\S*['\"]?\s*[=:]?\s*['\"]?(https?://[^'\"\\s]+|pk_[^'\"\\s]+)",
)
_AUTH0_DOMAIN_RE = re.compile(
    r"(?i)(?:AUTH0_(?:DOMAIN|ISSUER|CLIENT_ID)|NEXT_PUBLIC_AUTH0_DOMAIN)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)
_AUTH0_SECRET_RE = re.compile(
    r"(?i)(?:AUTH0_(?:CLIENT_SECRET|SECRET))\s*[=:]\s*['\"]([^'\"]+)['\"]",
)
_AUTH0_MGMT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def discover_clerk_auth0_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _CLERK_SECRET_RE.finditer(body):
        creds["clerk_secret_key"] = match.group(0)
    for match in _AUTH0_DOMAIN_RE.finditer(body):
        domain = match.group(1).strip().rstrip("/")
        if domain.startswith("http"):
            from urllib.parse import urlparse
            domain = urlparse(domain).hostname or domain
        creds["auth0_domain"] = domain.replace("https://", "").replace("http://", "")
    for match in _AUTH0_SECRET_RE.finditer(body):
        creds["auth0_client_secret"] = match.group(1).strip()
    for match in re.finditer(
        r"(?i)(?:AUTH0_CLIENT_ID|NEXT_PUBLIC_AUTH0_CLIENT_ID)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["auth0_client_id"] = match.group(1).strip()
    for match in _AUTH0_MGMT_RE.finditer(body):
        token = match.group(0)
        if "auth0" in body.lower() or creds.get("auth0_domain"):
            creds.setdefault("auth0_management_token", token)
    return creds


def enum_clerk_users(session, secret_key: str, *, verify_ssl: bool = True) -> Dict[str, Any]:
    url = "https://api.clerk.com/v1/users"
    headers = {"Authorization": f"Bearer {secret_key}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, params={"limit": 10}, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "clerk", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "clerk", "ok": False, "detail": "key_rejected"}
    if response.status_code != 200:
        return {"platform": "clerk", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "clerk", "ok": False, "detail": "invalid_json"}
    users = data if isinstance(data, list) else data.get("data") or []
    emails = []
    for user in users[:10]:
        if not isinstance(user, dict):
            continue
        for email in user.get("email_addresses") or []:
            if isinstance(email, dict) and email.get("email_address"):
                emails.append(str(email["email_address"]))
    return {
        "platform": "clerk",
        "ok": True,
        "users_count": len(users),
        "sample_emails": emails[:5],
        "severity": "critical",
    }


def auth0_get_management_token(
    session,
    domain: str,
    client_id: str,
    client_secret: str,
    *,
    verify_ssl: bool = True,
) -> Tuple[Optional[str], str]:
    url = f"https://{domain}/oauth/token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": f"https://{domain}/api/v2/",
        "grant_type": "client_credentials",
    }
    try:
        response = session.post(url, json=payload, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return None, str(exc)
    if response.status_code != 200:
        return None, f"http_{response.status_code}"
    try:
        data = response.json()
        return str(data.get("access_token") or ""), "ok"
    except Exception:
        return None, "invalid_json"


def enum_auth0_users(
    session,
    domain: str,
    token: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = f"https://{domain}/api/v2/users"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, params={"per_page": 10}, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "auth0", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "auth0", "ok": False, "detail": "token_rejected"}
    if response.status_code != 200:
        return {"platform": "auth0", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        users = response.json()
    except Exception:
        return {"platform": "auth0", "ok": False, "detail": "invalid_json"}
    if not isinstance(users, list):
        return {"platform": "auth0", "ok": False, "detail": "unexpected_shape"}
    emails = [str(u.get("email") or "") for u in users if isinstance(u, dict) and u.get("email")][:5]
    return {
        "platform": "auth0",
        "ok": True,
        "users_count": len(users),
        "sample_emails": emails,
        "severity": "critical",
    }


def enumerate_clerk_auth0(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    clerk_secret: str = "",
    auth0_domain: str = "",
    auth0_client_id: str = "",
    auth0_client_secret: str = "",
    auth0_token: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    discovered = discover_clerk_auth0_credentials(homepage_html or "")
    creds = {**discovered}
    if clerk_secret:
        creds["clerk_secret_key"] = clerk_secret
    if auth0_domain:
        creds["auth0_domain"] = auth0_domain
    if auth0_client_id:
        creds["auth0_client_id"] = auth0_client_id
    if auth0_client_secret:
        creds["auth0_client_secret"] = auth0_client_secret
    if auth0_token:
        creds["auth0_management_token"] = auth0_token

    findings: List[Dict[str, Any]] = []
    clerk_key = creds.get("clerk_secret_key") or ""
    if clerk_key:
        hit = enum_clerk_users(session, clerk_key, verify_ssl=verify_ssl)
        hit["key_masked"] = mask_secret(clerk_key)
        findings.append(hit)

    domain = (creds.get("auth0_domain") or "").strip()
    token = creds.get("auth0_management_token") or ""
    if domain and not token:
        cid = creds.get("auth0_client_id") or ""
        csec = creds.get("auth0_client_secret") or ""
        if cid and csec:
            token, detail = auth0_get_management_token(
                session, domain, cid, csec, verify_ssl=verify_ssl
            )
            if token:
                creds["auth0_management_token"] = token
            else:
                findings.append({"platform": "auth0", "ok": False, "detail": f"token_error:{detail}"})
    if domain and token:
        hit = enum_auth0_users(session, domain, token, verify_ssl=verify_ssl)
        findings.append(hit)

    return findings, creds


__all__ = [
    "discover_clerk_auth0_credentials",
    "enumerate_clerk_auth0",
    "enum_clerk_users",
    "enum_auth0_users",
]
