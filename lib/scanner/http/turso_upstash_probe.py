#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Turso / Upstash credential discovery and API enumeration."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from lib.scanner.http.vibe_secrets_probe import extract_vibe_secrets, mask_secret

_TURSO_TOKEN_RE = re.compile(r"\b[a-f0-9]{64}\b")
_UPSTASH_REST_RE = re.compile(
    r"(?i)(https://[a-z0-9-]+\.upstash\.io)",
)
_UPSTASH_TOKEN_RE = re.compile(
    r"(?i)(?:UPSTASH_(?:REDIS|QSTASH)_?(?:REST_)?TOKEN|QSTASH_TOKEN)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)
_UPSTASH_URL_RE = re.compile(
    r"(?i)(?:UPSTASH_REDIS_REST_URL)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)


def discover_turso_upstash(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for finding in extract_vibe_secrets(body[:600_000], source="/"):
        service = str(finding.get("service") or "")
        var_name = str(finding.get("var_name") or "").upper()
        if service == "turso" and "AUTH_TOKEN" in var_name:
            for match in re.finditer(
                r"(?i)TURSO_(?:AUTH_TOKEN|DATABASE_URL|DB_URL)\s*[=:]\s*['\"]([^'\"]+)['\"]",
                body,
            ):
                if "libsql" in match.group(1) or "turso" in match.group(1):
                    creds.setdefault("turso_database_url", match.group(1))
                else:
                    creds.setdefault("turso_auth_token", match.group(1))
    for match in _UPSTASH_URL_RE.finditer(body):
        creds["upstash_redis_url"] = match.group(1).rstrip("/")
    for match in _UPSTASH_REST_RE.finditer(body):
        creds.setdefault("upstash_redis_url", match.group(1).rstrip("/"))
    for match in _UPSTASH_TOKEN_RE.finditer(body):
        creds["upstash_token"] = match.group(1).strip()
    for match in re.finditer(
        r"(?i)(?:TURSO_AUTH_TOKEN|tursoAuthToken)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["turso_auth_token"] = match.group(1).strip()
    return creds


def enum_upstash_redis(
    session,
    base_url: str,
    token: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/ping"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = session.get(url, headers=headers, timeout=10, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "upstash", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "upstash", "ok": False, "detail": "token_rejected"}
    if response.status_code != 200:
        return {"platform": "upstash", "ok": False, "detail": f"http_{response.status_code}"}
    return {
        "platform": "upstash",
        "ok": True,
        "endpoint": url,
        "response": (response.text or "")[:200],
        "severity": "critical",
    }


def enum_turso_databases(
    session,
    api_token: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = "https://api.turso.tech/v1/databases"
    headers = {"Authorization": f"Bearer {api_token}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "turso", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "turso", "ok": False, "detail": "token_rejected"}
    if response.status_code != 200:
        return {"platform": "turso", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "turso", "ok": False, "detail": "invalid_json"}
    dbs = data.get("databases") if isinstance(data, dict) else data
    names = [str(d.get("Name") or d.get("name") or "") for d in (dbs or []) if isinstance(d, dict)][:15]
    return {
        "platform": "turso",
        "ok": True,
        "databases": names,
        "count": len(names),
        "severity": "critical",
    }


def enumerate_turso_upstash(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    turso_token: str = "",
    upstash_url: str = "",
    upstash_token: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_turso_upstash(homepage_html or "")
    if turso_token:
        creds["turso_auth_token"] = turso_token
    if upstash_url:
        creds["upstash_redis_url"] = upstash_url
    if upstash_token:
        creds["upstash_token"] = upstash_token

    findings: List[Dict[str, Any]] = []
    ttoken = creds.get("turso_auth_token") or ""
    if ttoken:
        hit = enum_turso_databases(session, ttoken, verify_ssl=verify_ssl)
        hit["token_masked"] = mask_secret(ttoken)
        findings.append(hit)

    uurl = creds.get("upstash_redis_url") or ""
    utoken = creds.get("upstash_token") or ""
    if uurl and utoken:
        hit = enum_upstash_redis(session, uurl, utoken, verify_ssl=verify_ssl)
        hit["token_masked"] = mask_secret(utoken)
        findings.append(hit)
    elif uurl:
        findings.append(
            {
                "platform": "upstash",
                "ok": False,
                "detail": "redis_rest_url_without_token",
                "endpoint": uurl,
                "severity": "medium",
            }
        )

    return findings, creds


__all__ = [
    "discover_turso_upstash",
    "enumerate_turso_upstash",
    "enum_turso_databases",
    "enum_upstash_redis",
]
