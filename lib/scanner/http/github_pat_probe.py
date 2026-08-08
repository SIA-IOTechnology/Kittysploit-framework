#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitHub personal access token discovery and repository enumeration."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_GITHUB_PAT_RE = re.compile(
    r"\b(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,})\b"
)
_GITHUB_TOKEN_ENV_RE = re.compile(
    r"(?i)(?:GITHUB_(?:TOKEN|PAT|API_TOKEN|ACCESS_TOKEN)|GH_TOKEN|NPM_TOKEN)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)

_GITHUB_API = "https://api.github.com"
_GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def discover_github_tokens(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _GITHUB_PAT_RE.finditer(body):
        creds["github_token"] = match.group(1)
    for match in _GITHUB_TOKEN_ENV_RE.finditer(body):
        val = match.group(1).strip()
        if val.startswith(("ghp_", "github_pat_", "gho_", "ghs_")) or len(val) >= 30:
            creds["github_token"] = val
    return creds


def _headers(token: str) -> Dict[str, str]:
    out = dict(_GITHUB_HEADERS)
    out["Authorization"] = f"Bearer {token}"
    return out


def enum_github_user(
    session,
    token: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    try:
        response = session.get(
            f"{_GITHUB_API}/user",
            headers=_headers(token),
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return {"platform": "github", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "github", "ok": False, "detail": "token_rejected"}
    if response.status_code != 200:
        return {"platform": "github", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "github", "ok": False, "detail": "invalid_json"}
    return {
        "platform": "github",
        "ok": True,
        "kind": "github_user",
        "login": str(data.get("login") or ""),
        "email": str(data.get("email") or ""),
        "name": str(data.get("name") or ""),
        "public_repos": data.get("public_repos"),
        "severity": "high",
    }


def enum_github_repos(
    session,
    token: str,
    *,
    per_page: int = 10,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    try:
        response = session.get(
            f"{_GITHUB_API}/user/repos",
            headers=_headers(token),
            params={
                "per_page": max(1, min(per_page, 30)),
                "sort": "updated",
                "affiliation": "owner,collaborator,organization_member",
            },
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return {"platform": "github", "ok": False, "detail": str(exc)}
    if response.status_code != 200:
        return {"platform": "github", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        repos = response.json()
    except Exception:
        return {"platform": "github", "ok": False, "detail": "invalid_json"}
    if not isinstance(repos, list):
        return {"platform": "github", "ok": False, "detail": "unexpected_shape"}
    private_count = sum(1 for r in repos if isinstance(r, dict) and r.get("private"))
    names = [
        f"{r.get('full_name')}{' [private]' if r.get('private') else ''}"
        for r in repos[:per_page]
        if isinstance(r, dict)
    ]
    return {
        "platform": "github",
        "ok": True,
        "kind": "github_repos",
        "repos": names,
        "count": len(repos),
        "private_in_page": private_count,
        "severity": "critical" if private_count else "high",
    }


def enum_github_orgs(
    session,
    token: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    try:
        response = session.get(
            f"{_GITHUB_API}/user/orgs",
            headers=_headers(token),
            params={"per_page": 10},
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return {"platform": "github", "ok": False, "detail": str(exc)}
    if response.status_code != 200:
        return {"platform": "github", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        orgs = response.json()
    except Exception:
        return {"platform": "github", "ok": False, "detail": "invalid_json"}
    names = [str(o.get("login") or "") for o in (orgs or [])[:10] if isinstance(o, dict)]
    return {
        "platform": "github",
        "ok": True,
        "kind": "github_orgs",
        "organizations": names,
        "count": len(orgs or []),
        "severity": "high" if names else "medium",
    }


def enumerate_github_pat(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    token: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_github_tokens(homepage_html or "")
    if token:
        creds["github_token"] = token

    findings: List[Dict[str, Any]] = []
    pat = creds.get("github_token") or ""
    if not pat:
        return findings, creds

    user = enum_github_user(session, pat, verify_ssl=verify_ssl)
    user["token_masked"] = mask_secret(pat)
    if not user.get("ok"):
        findings.append(user)
        return findings, creds

    findings.append(user)
    findings.append(enum_github_repos(session, pat, verify_ssl=verify_ssl))
    orgs = enum_github_orgs(session, pat, verify_ssl=verify_ssl)
    if orgs.get("ok"):
        findings.append(orgs)

    return findings, creds


__all__ = [
    "discover_github_tokens",
    "enumerate_github_pat",
    "enum_github_orgs",
    "enum_github_repos",
    "enum_github_user",
]
