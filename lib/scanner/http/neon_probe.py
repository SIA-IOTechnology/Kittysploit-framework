#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Neon database URL and Management API validation probes."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from lib.scanner.http.vibe_secrets_probe import mask_secret

_NEON_URL_RE = re.compile(
    r"(?i)(postgres(?:ql)?://[^\s\"'<>]+@[a-z0-9.-]+\.neon\.tech[^\s\"'<>]*)",
)
_NEON_API_KEY_RE = re.compile(
    r"(?i)(?:NEON_(?:API_)?KEY|neonApiKey)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)


def discover_neon_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _NEON_URL_RE.finditer(body):
        creds["database_url"] = match.group(1).strip()
    for match in re.finditer(
        r"(?i)(?:NEON_DATABASE_URL|DATABASE_URL)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        val = match.group(1).strip()
        if "neon.tech" in val:
            creds["database_url"] = val
    for match in _NEON_API_KEY_RE.finditer(body):
        creds["api_key"] = match.group(1).strip()
    return creds


def parse_neon_host(database_url: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    try:
        parsed = urlparse(database_url)
        info["host"] = parsed.hostname or ""
        info["database"] = (parsed.path or "").lstrip("/") or "neondb"
        info["user"] = parsed.username or ""
        if parsed.hostname and parsed.hostname.endswith(".neon.tech"):
            info["project_hint"] = parsed.hostname.split(".")[0]
    except Exception:
        pass
    return info


def enum_neon_management_api(
    session,
    api_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = "https://console.neon.tech/api/v2/projects"
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "neon", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "neon", "ok": False, "detail": "key_rejected"}
    if response.status_code != 200:
        return {"platform": "neon", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "neon", "ok": False, "detail": "invalid_json"}
    projects = data.get("projects") if isinstance(data, dict) else []
    names = [str(p.get("name") or p.get("id") or "") for p in (projects or [])[:10] if isinstance(p, dict)]
    return {
        "platform": "neon",
        "ok": True,
        "kind": "neon_projects_listed",
        "projects": names,
        "count": len(projects or []),
        "severity": "critical",
    }


def validate_neon_database_url(database_url: str) -> Dict[str, Any]:
    meta = parse_neon_host(database_url)
    if not meta.get("host"):
        return {"platform": "neon", "ok": False, "detail": "invalid_url"}
    return {
        "platform": "neon",
        "ok": True,
        "kind": "neon_database_url_discovered",
        "host": meta.get("host"),
        "database": meta.get("database"),
        "user": meta.get("user"),
        "project_hint": meta.get("project_hint"),
        "severity": "critical",
        "note": "Live SQL validation requires postgres driver; URL contains embedded credentials",
    }


def enumerate_neon(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    database_url: str = "",
    api_key: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_neon_credentials(homepage_html or "")
    if database_url:
        creds["database_url"] = database_url
    if api_key:
        creds["api_key"] = api_key

    findings: List[Dict[str, Any]] = []
    url = creds.get("database_url") or ""
    key = creds.get("api_key") or ""

    if url:
        hit = validate_neon_database_url(url)
        hit["url_masked"] = mask_secret(url)
        findings.append(hit)

    if key:
        mgmt = enum_neon_management_api(session, key, verify_ssl=verify_ssl)
        mgmt["key_masked"] = mask_secret(key)
        if mgmt.get("ok"):
            findings.append(mgmt)
        elif not url:
            findings.append(mgmt)

    return findings, creds


__all__ = [
    "discover_neon_credentials",
    "enumerate_neon",
    "enum_neon_management_api",
    "validate_neon_database_url",
]
