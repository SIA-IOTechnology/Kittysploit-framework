#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Podlove Podcast Publisher CVE-2026-13001 (<= 4.5.1)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.podlove_probe import PODLOVE_PATCHED_VERSION, PODLOVE_PLUGIN_SLUGS, Podlove
from lib.protocols.http.wordpress import Wordpress


class Module(Scanner, Http_client, Wordpress, Podlove):
    __info__ = {
        "name": "WordPress Podlove Podcast Publisher CVE-2026-13001 Detect",
        "description": (
            "Detects Podlove Podcast Publisher <= 4.5.1 vulnerable to unauthenticated "
            "file upload via image cache extension bypass (CVE-2026-13001). "
            "Fixed in 4.5.2."
        ),
        "author": ["Talal Nasraddeen", "Wordfence", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-13001"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-13001",
            "https://www.cve.org/CVERecord?id=CVE-2026-13001",
            "https://wordpress.org/plugins/podlove-podcasting-plugin-for-wordpress/",
        ],
        "modules": ["exploits/multi/http/wp_podlove_cve_2026_13001_rce"],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "wp-plugin",
            "podlove",
            "file-upload",
            "rce",
            "cve-2026-13001",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "exploit_paths"],
            "chain": {
                "produces_capabilities": ["rce"],
                "suggested_followups": [
                    "exploits/multi/http/wp_podlove_cve_2026_13001_rce",
                ],
            },
        },
    }

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(getattr(self, "path", "/"))

    def _probe_version(self) -> tuple[str, str]:
        for slug in PODLOVE_PLUGIN_SLUGS:
            readme_path = self.wp_plugin_path(self._wp_base(), slug, "readme.txt")
            response = self.http_request(
                method="GET",
                path=readme_path,
                allow_redirects=True,
                timeout=int(self.timeout or 15),
            )
            if not response or int(response.status_code or 0) != 200:
                continue
            body = response.text or ""
            if "podlove" not in body.lower():
                continue
            version = self.wp_extract_version_from_readme(body) or ""
            return slug, version
        return "", ""

    def run(self):
        slug, version = self._probe_version()
        if not slug:
            return False

        if version:
            try:
                vulnerable = self.wp_version_to_tuple(version) <= self.wp_version_to_tuple(
                    "4.5.1"
                )
            except Exception:
                vulnerable = None
        else:
            vulnerable = None

        if vulnerable is True:
            severity = "critical"
            reason = (
                f"Podlove Podcast Publisher {version} <= 4.5.1 "
                f"(CVE-2026-13001, fixed in {PODLOVE_PATCHED_VERSION})"
            )
        elif vulnerable is False:
            severity = "info"
            reason = (
                f"Podlove {version} detected; patched for CVE-2026-13001 "
                f"(>= {PODLOVE_PATCHED_VERSION})"
            )
        else:
            severity = "high"
            reason = (
                f"Podlove plugin detected ({slug}) version unknown; "
                f"CVE-2026-13001 if <= 4.5.1"
            )

        print_status(f"Podlove {slug} version={version or 'unknown'} vuln={vulnerable}")
        self.set_info(
            severity=severity,
            reason=reason,
            plugin=slug,
            version=version or "unknown",
            vulnerable=vulnerable,
            cve="CVE-2026-13001",
        )
        return True
