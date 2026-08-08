#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Payload CMS REST and GraphQL enumeration probes."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

_USER_PATHS = (
    "/api/users",
    "/api/admins",
    "/api/graphql",
)

_COLLECTION_PATHS = (
    "/api/posts",
    "/api/pages",
    "/api/media",
    "/api/products",
    "/api/categories",
)


def _parse_users(body: str) -> List[Dict[str, str]]:
    users: List[Dict[str, str]] = []
    try:
        data = json.loads(body)
    except Exception:
        return users
    items = data
    if isinstance(data, dict):
        items = data.get("docs") or data.get("users") or data.get("data") or []
    if not isinstance(items, list):
        return users
    for item in items[:10]:
        if not isinstance(item, dict):
            continue
        users.append(
            {
                "id": str(item.get("id") or ""),
                "email": str(item.get("email") or ""),
                "role": str(item.get("role") or ""),
            }
        )
    return users


def probe_payload_users(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = http_request(method="GET", path=path, allow_redirects=False, timeout=12)
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return None
    body = str(getattr(response, "text", "") or "")
    if not body.strip().startswith("{"):
        return None
    users = _parse_users(body)
    if not users and "email" not in body.lower() and "docs" not in body:
        return None
    return {
        "path": path,
        "kind": "payloadcms_users_exposed",
        "sample_users": users[:5],
        "user_count": len(users) if users else "unknown",
        "preview": body[:400],
        "severity": "critical" if users else "high",
    }


def probe_payload_collection(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
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
    docs = data.get("docs") if isinstance(data, dict) else None
    if not isinstance(docs, list):
        return None
    return {
        "path": path,
        "kind": "payloadcms_collection_exposed",
        "document_count": len(docs),
        "preview": body[:300],
        "severity": "medium",
    }


def probe_payload_graphql(http_request: Callable[..., Any]) -> Optional[Dict[str, Any]]:
    query = json.dumps({"query": "{ Users { docs { id email } } }"})
    response = http_request(
        method="POST",
        path="/api/graphql",
        data=query,
        headers={"Content-Type": "application/json"},
        allow_redirects=False,
        timeout=12,
    )
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return None
    body = str(getattr(response, "text", "") or "")
    if "email" not in body.lower() and "docs" not in body.lower():
        return None
    return {
        "path": "/api/graphql",
        "kind": "payloadcms_graphql_users",
        "preview": body[:400],
        "severity": "critical" if "email" in body.lower() else "high",
    }


def enumerate_payloadcms(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in _USER_PATHS:
        if path == "/api/graphql":
            continue
        hit = probe_payload_users(http_request, path)
        if hit:
            findings.append(hit)
    gql = probe_payload_graphql(http_request)
    if gql:
        findings.append(gql)
    if not any(f.get("kind") == "payloadcms_users_exposed" for f in findings):
        for path in _COLLECTION_PATHS:
            hit = probe_payload_collection(http_request, path)
            if hit:
                findings.append(hit)
    return findings


__all__ = ["enumerate_payloadcms", "probe_payload_collection", "probe_payload_graphql", "probe_payload_users"]
