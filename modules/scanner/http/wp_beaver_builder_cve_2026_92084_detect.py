#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Beaver Builder Lite CVE-2026-92084 exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "beaver-builder-lite-version"
_PATCHED = (2, 11, 0, 6)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Beaver Builder CVE-2026-92084 detect",
        "description": (
            "Detects Beaver Builder Lite <= 2.11.0.5 (CVE-2026-92084): Sidebar module "
            "widget output may execute registered shortcodes via layout-wide do_shortcode()."
        ),
        "author": ["Wordfence", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-92084"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-92084",
            "https://github.com/Hassham1/CVE-2026-92084-beaver-builder-shortcode-poc",
        ],
        "tags": ["wordpress", "beaver-builder", "shortcode", "scanner", "cve-2026-92084"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/wp_beaver_builder_cve_2026_92084_shortcode",
                ],
            },
        },
    }

    path = OptString("/", "WordPress base path", required=False)

    def run(self):
        base = self.wp_normalize_base_path(self.path)
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if not version:
            readme = self.wp_plugin_path(base, _PLUGIN, "readme.txt")
            response = self.http_request(method="GET", path=readme, allow_redirects=True)
            if response and int(response.status_code or 0) == 200:
                version = self.wp_extract_version_from_readme(response.text or "") or ""
        if version and self.wp_version_to_tuple(version) >= _PATCHED:
            return False

        home = self.http_request(method="GET", path=base if base != "/" else "/", allow_redirects=True)
        if not home:
            return False
        body = home.text or ""
        if "fl-builder-content" not in body and _PLUGIN not in body.lower():
            main = self.wp_plugin_path(base, _PLUGIN, "fl-builder.php")
            check = self.http_request(method="GET", path=main, allow_redirects=True)
            if not check or int(check.status_code or 0) != 200:
                return False

        self.set_info(
            severity="critical",
            reason="Beaver Builder Lite at or below 2.11.0.5",
            version=version or "unknown",
        )
        return True
