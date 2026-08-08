#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strapi GraphQL introspection and user enumeration."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

_STRAPI_GRAPHQL_PATHS = (
    "/graphql",
    "/api/graphql",
    "/strapi/graphql",
)

_INTROSPECTION = """
query StrapiIntro {
  __schema {
    queryType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

_USER_QUERIES = (
    """
    query Users {
      usersPermissionsUsers { data { id attributes { username email } } }
    }
    """,
    """
    query UsersAlt {
      users { id username email }
    }
    """,
    """
    query Me {
      me { id username email }
    }
    """,
)


def _gql_post(http_request: Callable[..., Any], path: str, query: str) -> Optional[Any]:
    return http_request(
        method="POST",
        path=path,
        data=json.dumps({"query": query}),
        headers={"Content-Type": "application/json"},
        allow_redirects=False,
        timeout=15,
    )


def probe_strapi_introspection(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = _gql_post(http_request, path, _INTROSPECTION)
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return None
    body = str(getattr(response, "text", "") or "")
    if "__schema" not in body:
        return None
    try:
        types = json.loads(body).get("data", {}).get("__schema", {}).get("types") or []
    except Exception:
        types = []
    user_types = [
        str(t.get("name"))
        for t in types
        if isinstance(t, dict) and "user" in str(t.get("name", "")).lower()
    ][:10]
    return {
        "path": path,
        "kind": "strapi_graphql_introspection",
        "user_related_types": user_types,
        "type_count": len(types),
        "severity": "high",
        "preview": body[:400],
    }


def probe_strapi_graphql_users(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    for query in _USER_QUERIES:
        response = _gql_post(http_request, path, query)
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        body = str(getattr(response, "text", "") or "")
        if "email" not in body.lower() and "username" not in body.lower():
            continue
        if '"errors"' in body and "users" not in body.lower():
            continue
        users: List[Dict[str, str]] = []
        try:
            data = json.loads(body).get("data") or {}
            items = (
                (data.get("usersPermissionsUsers") or {}).get("data")
                or data.get("users")
                or ([data.get("me")] if data.get("me") else [])
            )
            if isinstance(items, list):
                for item in items[:10]:
                    if not isinstance(item, dict):
                        continue
                    attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else item
                    users.append(
                        {
                            "id": str(item.get("id") or attrs.get("id") or ""),
                            "username": str(attrs.get("username") or ""),
                            "email": str(attrs.get("email") or ""),
                        }
                    )
        except Exception:
            pass
        return {
            "path": path,
            "kind": "strapi_graphql_users",
            "sample_users": users[:5],
            "user_count": len(users) if users else "unknown",
            "severity": "critical" if users else "high",
            "preview": body[:400],
        }
    return None


def enumerate_strapi_graphql(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in _STRAPI_GRAPHQL_PATHS:
        intro = probe_strapi_introspection(http_request, path)
        if intro:
            findings.append(intro)
        users = probe_strapi_graphql_users(http_request, path)
        if users:
            findings.append(users)
    return findings


__all__ = ["enumerate_strapi_graphql", "probe_strapi_graphql_users", "probe_strapi_introspection"]
