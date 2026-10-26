#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Unlimited Elements for Elementor CVE-2026-103355 exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN_SLUG = "unlimited-elements-for-elementor"
_PATCHED = (2, 0, 21)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Unlimited Elements CVE-2026-103355 detect",
        "description": (
            "Detects Unlimited Elements for Elementor <= 2.0.20 (CVE-2026-103355): "
            "terms-listing widget may concatenate parent-term IDs into SQL unvalidated."
        ),
        "author": ["Patchstack", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-103355"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-103355",
            "https://patchstack.com/database/wordpress/plugin/unlimited-elements-for-elementor/vulnerability/wordpress-unlimited-elements-for-elementor-free-widgets-addons-templates-plugin-2-0-20-sql-injection-vulnerability-2",
            "https://github.com/Hassham1/CVE-2026-103355-unlimited-elements-sqli-poc",
        ],
        "tags": ["wordpress", "elementor", "sqli", "scanner", "cve-2026-103355"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/wp_plugin_unlimited_elements_cve_2026_103355_sqli",
                ],
            },
        },
    }

    path = OptString("/", "WordPress base path", required=False)

    def run(self):
        base = self.wp_normalize_base_path(self.path)
        readme = self.wp_plugin_path(base, _PLUGIN_SLUG, "readme.txt")
        version = self.wp_plugin_version(_PLUGIN_SLUG, base) or ""
        if not version:
            response = self.http_request(method="GET", path=readme, allow_redirects=True)
            if not response or int(response.status_code or 0) != 200:
                return False
            version = self.wp_extract_version_from_readme(response.text or "") or ""

        if version and self.wp_version_to_tuple(version) >= _PATCHED:
            return False

        main_php = self.wp_plugin_path(base, _PLUGIN_SLUG, "unlimited-elements-for-elementor.php")
        main_resp = self.http_request(method="GET", path=main_php, allow_redirects=True)
        if not version and (not main_resp or int(main_resp.status_code or 0) != 200):
            return False

        self.set_info(
            severity="critical",
            reason="Unlimited Elements for Elementor at or below 2.0.20",
            version=version or "unknown",
            plugin=_PLUGIN_SLUG,
        )
        return True
