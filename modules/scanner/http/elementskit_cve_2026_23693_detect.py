#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ElementsKit Lite < 3.7.9 unauth Mailchimp REST proxy (CVE-2026-23693)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "elementskit-lite"
_VULN_HIGH = (3, 7, 8)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "ElementsKit CVE-2026-23693 Mailchimp proxy detect",
        "description": "Detects unauthenticated /elementskit/v1/widget/mailchimp/subscribe route.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-23693",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-23693"],
        "modules": ["auxiliary/admin/http/elementskit_cve_2026_23693_mailchimp_proxy"],
        "tags": ["web", "scanner", "wordpress", "elementskit", "cve-2026-23693"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/elementskit_cve_2026_23693_mailchimp_proxy"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        probe = self.http_request(
            method="POST",
            path=self._join("/wp-json/elementskit/v1/widget/mailchimp/subscribe"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data="email=detect@example.com&list=invalid&apikey=0000000000000000000000000000000-us1",
            allow_redirects=False,
        )
        body = probe.text or "" if probe else ""
        if not probe:
            return False
        if any(x in body for x in ("rest_forbidden", "rest_cannot_access", "rest_not_logged_in", "rest_no_route")):
            return False
        if int(probe.status_code or 0) == 200 and "application/json" in str(probe.headers).lower():
            self.set_info(
                severity="high",
                reason="Mailchimp subscribe REST accepts unauthenticated POST",
                cve="CVE-2026-23693",
            )
            return True
        return False
