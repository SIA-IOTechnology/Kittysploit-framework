#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2024-5450 — Bug Library plugin detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Bug Library CVE-2024-5450 detect",
        "description": "Detects Bug Library < 2.1.1 and public submission surface.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2024-5450",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-5450"],
        "tags": ["wordpress", "bug-library", "scanner", "cve-2024-5450"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/bug_library_cve_2024_5450_upload_rce",
                ],
            },
        },
    }

    def run(self):
        ver = self.wp_plugin_version("bug-library", self.path)
        r = self.http_request(
            method="GET",
            path=self.wp_path("/wp-content/plugins/bug-library/stylesheet.css", self.path),
        )
        if not r or int(r.status_code or 0) != 200:
            return False
        if ver and not self.wp_version_in_range(ver, (0, 0, 0), (2, 1, 0)):
            return False
        popup = self.http_request(
            method="GET",
            path=self.wp_path("/", self.path),
            params={"bug_library_popup_content": "true"},
        )
        has_form = popup and "attachimage" in (popup.text or "").lower()
        self.set_info(
            severity="critical" if has_form else "high",
            cve="CVE-2024-5450",
            reason=f"Bug Library {ver or 'unknown'} — attachment upload form reachable"
            if has_form
            else f"Bug Library {ver or 'unknown'} installed",
            version=ver or "unknown",
        )
        return True