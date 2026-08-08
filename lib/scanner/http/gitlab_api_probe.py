#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitLab API token discovery and abuse probes."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from lib.scanner.http.vibe_secrets_probe import mask_secret

_GLPAT_RE = re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")
_GITLAB_TOKEN_ENV_RE = re.compile(
    r"(?i)(?:GITLAB_(?:TOKEN|PRIVATE_TOKEN|PAT|API_TOKEN)|CI_JOB_TOKEN|CI_REGISTRY_PASSWORD)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)


def discover_gitlab_tokens(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _GLPAT_RE.finditer(body):
        creds["gitlab_token"] = match.group(0)
    for match in _GITLAB_TOKEN_ENV_RE.finditer(body):
        val = match.group(1).strip()
        if val.startswith("glpat-") or len(val) >= 20:
            creds["gitlab_token"] = val
    for match in re.finditer(
        r"(?i)(?:GITLAB_(?:URL|HOST|BASE_URL)|CI_SERVER_URL)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["gitlab_base_url"] = match.group(1).strip().rstrip("/")
    return creds


def _normalize_base(base: str) -> str:
    url = (base or "https://gitlab.com").strip().rstrip("/")
    if not url.startswith("http"):
        url = f"https://{url}"
    return url


def enum_gitlab_user(session, token: str, base_url: str = "", *, verify_ssl: bool = True) -> Dict[str, Any]:
    base = _normalize_base(base_url)
    headers = {"PRIVATE-TOKEN": token, "Accept": "application/json"}
    url = f"{base}/api/v4/user"
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "gitlab", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "gitlab", "ok": False, "detail": "token_rejected"}
    if response.status_code != 200:
        return {"platform": "gitlab", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "gitlab", "ok": False, "detail": "invalid_json"}
    return {
        "platform": "gitlab",
        "ok": True,
        "kind": "gitlab_user",
        "username": str(data.get("username") or ""),
        "email": str(data.get("email") or ""),
        "is_admin": bool(data.get("is_admin")),
        "base_url": base,
        "severity": "critical" if data.get("is_admin") else "high",
    }


def enum_gitlab_projects(
    session,
    token: str,
    base_url: str = "",
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    base = _normalize_base(base_url)
    headers = {"PRIVATE-TOKEN": token, "Accept": "application/json"}
    url = f"{base}/api/v4/projects"
    try:
        response = session.get(
            url,
            headers=headers,
            params={"membership": "true", "per_page": 10},
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return {"platform": "gitlab", "ok": False, "detail": str(exc)}
    if response.status_code != 200:
        return {"platform": "gitlab", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "gitlab", "ok": False, "detail": "invalid_json"}
    names = [str(p.get("path_with_namespace") or p.get("name") or "") for p in (data or [])[:10] if isinstance(p, dict)]
    return {
        "platform": "gitlab",
        "ok": True,
        "kind": "gitlab_projects",
        "projects": names,
        "count": len(data or []),
        "base_url": base,
        "severity": "high",
    }


def enumerate_gitlab_token(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    token: str = "",
    base_url: str = "",
    fallback_base: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_gitlab_tokens(homepage_html or "")
    if token:
        creds["gitlab_token"] = token
    if base_url:
        creds["gitlab_base_url"] = base_url
    elif fallback_base and not creds.get("gitlab_base_url"):
        parsed = urlparse(fallback_base if "://" in fallback_base else f"https://{fallback_base}")
        creds["gitlab_base_url"] = f"{parsed.scheme}://{parsed.netloc}"

    findings: List[Dict[str, Any]] = []
    glpat = creds.get("gitlab_token") or ""
    base = creds.get("gitlab_base_url") or "https://gitlab.com"
    if not glpat:
        return findings, creds

    user_hit = enum_gitlab_user(session, glpat, base, verify_ssl=verify_ssl)
    user_hit["token_masked"] = mask_secret(glpat)
    if user_hit.get("ok"):
        findings.append(user_hit)
        findings.append(enum_gitlab_projects(session, glpat, base, verify_ssl=verify_ssl))
    else:
        findings.append(user_hit)
    return findings, creds


__all__ = [
    "discover_gitlab_tokens",
    "enumerate_gitlab_token",
    "enum_gitlab_projects",
    "enum_gitlab_user",
]
