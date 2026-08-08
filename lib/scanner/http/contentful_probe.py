#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contentful Management API enumeration using leaked tokens."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_CONTENTFUL_TOKEN_RE = re.compile(r"\b(CFPAT-[A-Za-z0-9_-]{20,}|CFPAT-[A-Za-z0-9_-]+)\b")
_SPACE_ID_RE = re.compile(
    r"(?i)(?:CONTENTFUL_(?:SPACE|DELIVERY|MANAGEMENT|PREVIEW)_?(?:ID|KEY|TOKEN)|spaceId)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)
_SPACE_ID_RAW = re.compile(r"\bspace[_-]?id['\"]?\s*[:=]\s*['\"]([a-z0-9]{8,14})['\"]", re.I)


def discover_contentful_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _CONTENTFUL_TOKEN_RE.finditer(body):
        creds["management_token"] = match.group(1)
    for match in _SPACE_ID_RE.finditer(body):
        val = match.group(1).strip()
        if len(val) <= 20 and not val.startswith("CF"):
            creds["space_id"] = val
    for match in _SPACE_ID_RAW.finditer(body):
        creds.setdefault("space_id", match.group(1))
    for match in re.finditer(
        r"(?i)CONTENTFUL_(?:MANAGEMENT|DELIVERY|PREVIEW)_?(?:ACCESS_)?TOKEN\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        token = match.group(1).strip()
        if token.startswith("CFPAT-"):
            creds["management_token"] = token
        else:
            creds.setdefault("delivery_token", token)
    return creds


def enum_contentful_space(
    session,
    space_id: str,
    token: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    url = f"https://api.contentful.com/spaces/{space_id}"
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "contentful", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "contentful", "ok": False, "detail": "token_rejected"}
    if response.status_code != 200:
        return {"platform": "contentful", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        meta = response.json()
    except Exception:
        meta = {}
    entries_url = f"https://api.contentful.com/spaces/{space_id}/entries"
    try:
        entries_resp = session.get(
            entries_url,
            headers=headers,
            params={"limit": 5},
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return {"platform": "contentful", "ok": True, "space_name": meta.get("name"), "entries_error": str(exc)}
    entry_titles = []
    if entries_resp.status_code == 200:
        try:
            data = entries_resp.json()
            for item in (data.get("items") or [])[:5]:
                fields = (item.get("fields") or {}) if isinstance(item, dict) else {}
                for val in fields.values():
                    if isinstance(val, dict) and val.get("en-US"):
                        entry_titles.append(str(val["en-US"])[:80])
                        break
        except Exception:
            pass
    return {
        "platform": "contentful",
        "ok": True,
        "space_id": space_id,
        "space_name": meta.get("name"),
        "entries_accessible": entries_resp.status_code == 200,
        "sample_entries": entry_titles[:3],
        "severity": "critical",
    }


def enumerate_contentful(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    space_id: str = "",
    management_token: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_contentful_credentials(homepage_html or "")
    if space_id:
        creds["space_id"] = space_id
    if management_token:
        creds["management_token"] = management_token
    findings: List[Dict[str, Any]] = []
    sid = creds.get("space_id") or ""
    token = creds.get("management_token") or creds.get("delivery_token") or ""
    if sid and token:
        hit = enum_contentful_space(session, sid, token, verify_ssl=verify_ssl)
        hit["token_masked"] = mask_secret(token)
        findings.append(hit)
    elif token:
        findings.append(
            {
                "platform": "contentful",
                "ok": False,
                "detail": "token_without_space_id",
                "token_masked": mask_secret(token),
                "severity": "medium",
            }
        )
    return findings, creds


__all__ = ["discover_contentful_credentials", "enumerate_contentful", "enum_contentful_space"]
