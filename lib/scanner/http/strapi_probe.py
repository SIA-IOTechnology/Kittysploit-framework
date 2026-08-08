#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strapi CMS user and content enumeration probes."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

_USER_PATHS = (
    "/api/users",
    "/api/users-permissions/users",
    "/users",
    "/api/user",
    "/api/auth/local/register",
)

_CONTENT_PATHS = (
    "/api/articles",
    "/api/posts",
    "/api/pages",
    "/api/upload/files",
)


def _parse_users(body: str) -> List[Dict[str, str]]:
    users: List[Dict[str, str]] = []
    try:
        data = json.loads(body)
    except Exception:
        return users
    items = data
    if isinstance(data, dict):
        items = data.get("data") or data.get("users") or data.get("results") or []
    if not isinstance(items, list):
        return users
    for item in items[:10]:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else item
        users.append(
            {
                "id": str(item.get("id") or attrs.get("id") or ""),
                "username": str(attrs.get("username") or item.get("username") or ""),
                "email": str(attrs.get("email") or item.get("email") or ""),
            }
        )
    return users


def probe_strapi_users(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(method="GET", path=path, allow_redirects=False, timeout=12)
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    if status not in (200, 201):
        return None
    body = str(getattr(response, "text", "") or "")
    if not body.strip().startswith(("{", "[")):
        return None
    users = _parse_users(body)
    if not users and '"email"' not in body.lower() and '"username"' not in body.lower():
        return None
    return {
        "path": path,
        "kind": "strapi_users_exposed",
        "user_count": len(users) or "unknown",
        "sample_users": users[:5],
        "status_code": status,
        "preview": body[:400],
        "severity": "critical" if users else "high",
    }


def probe_strapi_content(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(method="GET", path=path, allow_redirects=False, timeout=12)
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return None
    body = str(getattr(response, "text", "") or "")
    if not body.strip().startswith("{"):
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    count = 0
    if isinstance(data, dict):
        items = data.get("data") or data.get("results") or []
        if isinstance(items, list):
            count = len(items)
    if count == 0 and "data" not in body:
        return None
    return {
        "path": path,
        "kind": "strapi_content_exposed",
        "item_count": count,
        "preview": body[:300],
        "severity": "medium",
    }


def enumerate_strapi(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in _USER_PATHS:
        hit = probe_strapi_users(http_request, path)
        if hit:
            findings.append(hit)
    if not any(f.get("kind") == "strapi_users_exposed" for f in findings):
        for path in _CONTENT_PATHS:
            hit = probe_strapi_content(http_request, path)
            if hit:
                findings.append(hit)
    return findings


__all__ = ["enumerate_strapi", "probe_strapi_content", "probe_strapi_users"]
