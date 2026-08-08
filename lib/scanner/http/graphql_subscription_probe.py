#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GraphQL subscription and alias amplification abuse probes."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

SUBSCRIPTION_INTROSPECTION = """
query SubTypes {
  __schema {
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind } }
      }
    }
  }
}
"""

ALIAS_AMPLIFICATION_QUERY = """
query AliasAmp {
  a1: __typename
  a2: __typename
  a3: __typename
  a4: __typename
  a5: __typename
  a6: __typename
  a7: __typename
  a8: __typename
  a9: __typename
  a10: __typename
}
"""


def gql_post(
    http_request: Callable[..., Any],
    path: str,
    query: str,
) -> Optional[Any]:
    return http_request(
        method="POST",
        path=path,
        data=json.dumps({"query": query}),
        headers={"Content-Type": "application/json"},
        allow_redirects=False,
        timeout=15,
    )


def probe_subscriptions(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = gql_post(http_request, path, SUBSCRIPTION_INTROSPECTION)
    if not response or int(getattr(response, "status_code", 0) or 0) not in (200, 400):
        return None
    body = str(getattr(response, "text", "") or "")
    if "subscriptionType" not in body:
        return None
    try:
        data = json.loads(body).get("data", {}).get("__schema", {})
        sub_name = (data.get("subscriptionType") or {}).get("name")
        sub_fields: List[str] = []
        if sub_name:
            for ttype in data.get("types") or []:
                if str(ttype.get("name")) == sub_name:
                    sub_fields = [str(f.get("name")) for f in (ttype.get("fields") or []) if f][:12]
        return {
            "kind": "graphql_subscriptions",
            "path": path,
            "subscription_type": sub_name or "",
            "subscription_fields": sub_fields,
            "severity": "medium" if sub_name else "low",
            "preview": body[:500],
        }
    except Exception:
        return {"kind": "graphql_subscriptions", "path": path, "preview": body[:300], "severity": "low"}


def probe_alias_amplification(http_request: Callable[..., Any], path: str) -> Optional[Dict[str, Any]]:
    response = gql_post(http_request, path, ALIAS_AMPLIFICATION_QUERY)
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return None
    body = str(getattr(response, "text", "") or "")
    if body.count("__typename") >= 5:
        return {
            "kind": "graphql_alias_amplification",
            "path": path,
            "alias_count": body.count("__typename"),
            "severity": "medium",
            "preview": body[:300],
        }
    return None


def scan_graphql_subscription_abuse(
    http_request: Callable[..., Any],
    graphql_path: str = "/graphql",
) -> List[Dict[str, Any]]:
    path = graphql_path if graphql_path.startswith("/") else f"/{graphql_path}"
    findings: List[Dict[str, Any]] = []
    sub = probe_subscriptions(http_request, path)
    if sub:
        findings.append(sub)
    alias = probe_alias_amplification(http_request, path)
    if alias:
        findings.append(alias)
    return findings


__all__ = [
    "scan_graphql_subscription_abuse",
    "probe_subscriptions",
    "probe_alias_amplification",
]
