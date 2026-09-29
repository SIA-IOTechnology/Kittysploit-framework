#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect F5 BIG-IP CVE-2026-94127 APM OAuth UserInfo heap overflow surface."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "F5 BIG-IP CVE-2026-94127 APM OAuth Detect",
        "description": (
            "Detects CVE-2026-94127 exposure when a BIG-IP virtual server combines an "
            "APM access policy with an OAuth Authorization Server profile. Probes the "
            "OAuth UserInfo endpoint for expected invalid_token responses and parses "
            "BIG-IP version hints from /mgmt/tm/sys/version when reachable."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-94127"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-94127",
            "https://my.f5.com/manage/s/article/K000162605",
        ],
        "tags": [
            "web",
            "scanner",
            "f5",
            "big-ip",
            "apm",
            "oauth",
            "heap-overflow",
            "cve-2026-94127",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.25,
            "value": 1.1,
            "requires": {
                "tech_hints_any": ["f5", "big-ip", "bigip"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "OAuth UserInfo overflow"},
                ],
                "suggested_followups": [],
            },
        },
    }

    userinfo_paths = OptString(
        "/f5-oauth2/v1/userinfo,/oauth2/userinfo,/v1/userinfo",
        "Comma-separated OAuth UserInfo paths to probe",
        False,
        advanced=True,
    )

    _VERSION_RE = re.compile(r'"version"\s*:\s*"([^"]+)"', re.IGNORECASE)

    def _oauth_userinfo(self) -> tuple[bool, str]:
        for raw in str(self.userinfo_paths or "").split(","):
            path = raw.strip()
            if not path:
                continue
            response = self.http_request(
                method="GET",
                path=path,
                headers={"Authorization": "Bearer invalid"},
                allow_redirects=False,
            )
            if not response:
                continue
            body = (response.text or "").lower()
            if any(token in body for token in ("invalid_token", "access token is invalid", "oauth")):
                return True, path
            if "big-ip" in str(response.headers.get("Server", "")).lower():
                return True, path
        return False, ""

    def _bigip_version(self) -> str:
        response = self.http_request(
            method="GET",
            path="/mgmt/tm/sys/version",
            headers={"Accept": "application/json"},
            allow_redirects=False,
        )
        if not response or int(response.status_code or 0) != 200:
            return ""
        match = self._VERSION_RE.search(response.text or "")
        return match.group(1) if match else ""

    def run(self):
        exposed, hit = self._oauth_userinfo()
        if not exposed:
            return False
        version = self._bigip_version()
        self.set_info(
            severity="critical",
            cve="CVE-2026-94127",
            reason="BIG-IP OAuth UserInfo endpoint reachable (APM OAuth RCE surface)",
            path=hit,
            version=version or "unknown",
        )
        return True
