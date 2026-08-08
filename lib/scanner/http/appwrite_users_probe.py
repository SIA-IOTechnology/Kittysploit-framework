#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Appwrite API key discovery and user enumeration."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_APPWRITE_KEY_RE = re.compile(
    r"(?i)(?:APPWRITE_(?:API_KEY|KEY|SECRET)|standard\.[A-Za-z0-9]{20,})\b",
)


def discover_appwrite_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in re.finditer(
        r"(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?APPWRITE_(?:ENDPOINT|URL)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["appwrite_endpoint"] = match.group(1).strip().rstrip("/")
    for match in re.finditer(
        r"(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?APPWRITE_PROJECT(?:_ID)?\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["appwrite_project"] = match.group(1).strip()
    for match in re.finditer(
        r"(?i)APPWRITE_(?:API_KEY|KEY|SECRET)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["appwrite_api_key"] = match.group(1).strip()
    for match in re.finditer(r"\bstandard\.[A-Za-z0-9]{20,}\b", body):
        creds.setdefault("appwrite_api_key", match.group(0))
    return creds


def _headers(project: str, api_key: str) -> Dict[str, str]:
    return {
        "X-Appwrite-Project": project,
        "X-Appwrite-Key": api_key,
        "Accept": "application/json",
    }


def enum_appwrite_users(
    session,
    endpoint: str,
    project_id: str,
    api_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    base = endpoint.rstrip("/")
    url = f"{base}/v1/users"
    try:
        response = session.get(
            url,
            headers=_headers(project_id, api_key),
            params={"limit": 10},
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return {"platform": "appwrite", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "appwrite", "ok": False, "detail": "key_rejected"}
    if response.status_code != 200:
        return {"platform": "appwrite", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "appwrite", "ok": False, "detail": "invalid_json"}
    users_raw = data.get("users") if isinstance(data, dict) else data
    users: List[Dict[str, str]] = []
    for user in (users_raw or [])[:10]:
        if not isinstance(user, dict):
            continue
        users.append(
            {
                "id": str(user.get("$id") or user.get("id") or ""),
                "email": str(user.get("email") or ""),
                "name": str(user.get("name") or ""),
            }
        )
    return {
        "platform": "appwrite",
        "ok": True,
        "kind": "appwrite_users_listed",
        "endpoint": base,
        "user_count": len(users_raw or []),
        "sample_users": users[:5],
        "severity": "critical",
    }


def enum_appwrite_teams(
    session,
    endpoint: str,
    project_id: str,
    api_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    base = endpoint.rstrip("/")
    url = f"{base}/v1/teams"
    try:
        response = session.get(
            url,
            headers=_headers(project_id, api_key),
            params={"limit": 5},
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return {"platform": "appwrite", "ok": False, "detail": str(exc)}
    if response.status_code != 200:
        return {"platform": "appwrite", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "appwrite", "ok": False, "detail": "invalid_json"}
    teams = data.get("teams") if isinstance(data, dict) else []
    names = [str(t.get("name") or "") for t in (teams or [])[:5] if isinstance(t, dict)]
    return {
        "platform": "appwrite",
        "ok": True,
        "kind": "appwrite_teams_listed",
        "teams": names,
        "severity": "high",
    }


def enumerate_appwrite_users(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    endpoint: str = "",
    project_id: str = "",
    api_key: str = "",
    target_endpoint: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_appwrite_credentials(homepage_html or "")
    if endpoint:
        creds["appwrite_endpoint"] = endpoint
    elif target_endpoint:
        creds.setdefault("appwrite_endpoint", target_endpoint.rstrip("/"))
    if project_id:
        creds["appwrite_project"] = project_id
    if api_key:
        creds["appwrite_api_key"] = api_key

    findings: List[Dict[str, Any]] = []
    ep = creds.get("appwrite_endpoint") or ""
    proj = creds.get("appwrite_project") or ""
    key = creds.get("appwrite_api_key") or ""
    if not ep or not proj or not key:
        return findings, creds

    users = enum_appwrite_users(session, ep, proj, key, verify_ssl=verify_ssl)
    users["key_masked"] = mask_secret(key)
    if users.get("ok"):
        findings.append(users)
        teams = enum_appwrite_teams(session, ep, proj, key, verify_ssl=verify_ssl)
        if teams.get("ok"):
            findings.append(teams)
    else:
        findings.append(users)
    return findings, creds


__all__ = [
    "discover_appwrite_credentials",
    "enumerate_appwrite_users",
    "enum_appwrite_users",
    "enum_appwrite_teams",
]
