#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GraphQL introspection and lightweight abuse probe.

Runs full introspection when enabled, surfaces sensitive queries (users, admin,
password), and tests batching / alias amplification signals.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.module_result import finalize_http_scanner_run, target_base_url


class Module(Auxiliary, Http_client):

    __info__ = {
        "name": "GraphQL Introspection Abuse",
        "description": (
            "Confirm GraphQL introspection, enumerate schema types/fields, and flag "
            "sensitive queries (users, admin, secrets) for follow-up exploitation."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "api", "graphql", "introspection", "scanner"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "endpoints", "tech_hints"],
            "chain": {
                "consumes_capabilities": ["graphql_endpoint"],
                "produces_capabilities": [
                    {"capability": "db_access", "from_detail": "sensitive_query"},
                ],
                "option_bindings": {
                    "graphql_path": "graphql_endpoint",
                },
                "suggested_followups": [
                    "auxiliary/scanner/http/sqli_engine",
                    "post/http/gather/authenticated_surface",
                ],
            },
        },
    }

    graphql_path = OptString("/graphql", "GraphQL endpoint path", True)
    max_types = OptInteger(40, "Maximum schema types to list", False)
    test_batching = OptBool(True, "Probe alias/batch amplification", False)

    INTROSPECTION_QUERY = """
    query IntrospectionKitty {
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

    SENSITIVE_FIELD_MARKERS = (
        "password", "secret", "token", "admin", "credential",
        "apikey", "api_key", "private", "ssn", "email",
    )

    def _gql_post(self, path: str, query: str, variables: Optional[dict] = None) -> Optional[Any]:
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        return self.http_request(
            method="POST",
            path=path,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            allow_redirects=False,
            timeout=15,
        )

    def _parse_types(self, body: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(body)
            types = data.get("data", {}).get("__schema", {}).get("types") or []
            return [t for t in types if isinstance(t, dict)]
        except Exception:
            return []

    def _sensitive_fields(self, types: List[Dict[str, Any]]) -> List[str]:
        found: List[str] = []
        for ttype in types[: int(self.max_types or 40)]:
            name = str(ttype.get("name") or "")
            if name.startswith("__"):
                continue
            for field in ttype.get("fields") or []:
                if not isinstance(field, dict):
                    continue
                fname = str(field.get("name") or "").lower()
                if any(m in fname for m in self.SENSITIVE_FIELD_MARKERS):
                    found.append(f"{name}.{field.get('name')}")
        return found[:24]

    def run(self):
        path = str(self.graphql_path or "/graphql").strip() or "/graphql"
        print_status(f"GraphQL introspection probe at {path}")

        response = self._gql_post(path, self.INTROSPECTION_QUERY)
        if not response or response.status_code not in (200, 400):
            print_warning("GraphQL endpoint not responsive to introspection")
            return finalize_http_scanner_run(
                self,
                [],
                title="GraphQL introspection",
                severity="info",
                category="api",
                findings_key="graphql_findings",
            )

        body = response.text or ""
        if "__schema" not in body and "data" not in body:
            print_warning("Introspection disabled or blocked")
            return finalize_http_scanner_run(
                self,
                [],
                title="GraphQL introspection",
                severity="low",
                category="api",
                findings_key="graphql_findings",
            )

        types = self._parse_types(body)
        sensitive = self._sensitive_fields(types)
        type_names = [str(t.get("name")) for t in types if t.get("name") and not str(t.get("name")).startswith("__")]

        print_success(f"Introspection enabled — {len(type_names)} types, {len(sensitive)} sensitive fields")
        for item in sensitive[:8]:
            print_info(f"  sensitive: {item}")

        batch_ok = False
        if bool(self.test_batching):
            batch_query = "query B { a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename }"
            batch_resp = self._gql_post(path, batch_query)
            batch_ok = bool(batch_resp and batch_resp.status_code == 200 and "__typename" in (batch_resp.text or ""))

        hits = [{
            "vulnerable": True,
            "path": path,
            "indicator": "graphql_introspection",
            "status_code": response.status_code,
            "type_count": len(type_names),
            "sensitive_fields": sensitive,
            "sensitive_query": sensitive[0] if sensitive else "",
            "graphql_endpoint": path,
            "batching": "yes" if batch_ok else "no",
            "content_preview": body[:800],
        }]

        chain_extra = {
            "graphql_endpoint": path,
            "sensitive_query": sensitive[0] if sensitive else "",
            "sensitive_fields": ",".join(sensitive[:12]),
        }

        return finalize_http_scanner_run(
            self,
            hits,
            title="GraphQL introspection enabled",
            severity="high" if sensitive else "medium",
            category="api",
            findings_key="graphql_findings",
            hit_mapper=lambda hit: {
                "method": "POST",
                "request_url": target_base_url(self, path=str(hit.get("path") or path)),
                "status_code": hit.get("status_code"),
                "evidence_snippet": hit.get("content_preview") or hit.get("indicator"),
                "indicators": [hit.get("indicator")] if hit.get("indicator") else [],
                "graphql_endpoint": hit.get("graphql_endpoint"),
            },
            vulnerability_info_extra=chain_extra,
        )
