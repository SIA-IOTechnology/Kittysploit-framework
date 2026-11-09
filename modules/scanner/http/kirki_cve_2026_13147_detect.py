#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kirki < 6.0.12 SSRF via kirki_get_apis (CVE-2026-13147)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "kirki"
_VULN_HIGH = (6, 0, 11)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Kirki CVE-2026-13147 SSRF detect",
        "description": "Detects Kirki < 6.0.12 and public kirki_get_apis AJAX surface.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-13147",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-13147"],
        "modules": ["auxiliary/admin/http/kirki_cve_2026_13147_ssrf"],
        "tags": ["web", "scanner", "wordpress", "kirki", "ssrf", "cve-2026-13147"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["auxiliary/admin/http/kirki_cve_2026_13147_ssrf"]},
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
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        html = home.text or "" if home else ""
        if "window.wp_kirki" not in html:
            return False
        nonce_m = re.search(r'nonce:\s*"([a-f0-9]{10})"', html)
        if not nonce_m:
            self.set_info(severity="high", reason="Kirki present; SSRF nonce not in page", cve="CVE-2026-13147")
            return True
        self.set_info(
            severity="high",
            reason="Kirki kirki_get_apis SSRF (elementUrl) likely reachable",
            cve="CVE-2026-13147",
        )
        return True
