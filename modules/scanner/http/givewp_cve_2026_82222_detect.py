#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GiveWP <= 4.16.7.1 PHP object injection RCE (CVE-2026-82222)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "give"
_VULN_HIGH = (4, 16, 7)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "GiveWP CVE-2026-82222 RCE detect",
        "description": (
            "Detects GiveWP <= 4.16.7.1 via readme version and public give_forms REST; "
            "links exploit module for donor-register object-injection chain."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-82222",
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-82222",
            "https://patchstack.com/articles/unauthenticated-php-object-injection-to-remote-code-execution-on-givewp/",
        ],
        "modules": ["exploits/multi/http/givewp_cve_2026_82222_rce"],
        "tags": ["web", "scanner", "wordpress", "givewp", "rce", "cve-2026-82222"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/givewp_cve_2026_82222_rce"],
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
        forms = self.http_request(
            method="GET",
            path=self._join("/wp-json/wp/v2/give_forms"),
            allow_redirects=False,
        )
        if not forms or int(forms.status_code or 0) != 200:
            readme = self.http_request(
                method="GET",
                path=self._join("/wp-content/plugins/give/readme.txt"),
                allow_redirects=False,
            )
            if not readme or "Give" not in (readme.text or ""):
                return False
            self.set_info(
                severity="high",
                reason="GiveWP plugin present; version may be vulnerable",
                cve="CVE-2026-82222",
            )
            return True
        if not re.search(r'"id"\s*:\s*\d+', forms.text or ""):
            return False
        self.set_info(
            severity="critical",
            reason="GiveWP <= 4.16.7.1 surface (forms REST + donor registration chain)",
            path="/wp-json/wp/v2/give_forms",
            cve="CVE-2026-82222",
        )
        return True
