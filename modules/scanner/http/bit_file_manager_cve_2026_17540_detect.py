#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bit File Manager < 6.9.1 auth file read/delete (CVE-2026-17540)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "file-manager"
_VULN_HIGH = (6, 9, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Bit File Manager CVE-2026-17540 detect",
        "description": (
            "Detects Bit File Manager (file-manager) <= 6.9.0; read requires subscriber+ (auxiliary)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-17540",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-17540"],
        "modules": ["auxiliary/admin/http/bit_file_manager_cve_2026_17540_file_read"],
        "tags": ["web", "scanner", "wordpress", "file-manager", "cve-2026-17540"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/bit_file_manager_cve_2026_17540_file_read"],
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
        readme = self.http_request(
            method="GET",
            path=self._join("/wp-content/plugins/file-manager/readme.txt"),
            allow_redirects=False,
        )
        body = readme.text or "" if readme else ""
        if not readme or int(readme.status_code or 0) != 200:
            return False
        if "file-manager" not in body.lower() and "bit" not in body.lower():
            return False
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        self.set_info(
            severity="high",
            reason="Bit File Manager vulnerable to subscriber file read",
            cve="CVE-2026-17540",
        )
        return True
