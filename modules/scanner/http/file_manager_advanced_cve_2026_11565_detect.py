#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advanced File Manager < 5.4.13 auth file read (CVE-2026-11565)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "file-manager-advanced"
_VULN_HIGH = (5, 4, 12)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "File Manager Advanced CVE-2026-11565 detect",
        "description": (
            "Detects plugin <= 5.4.12; file read requires subscriber+ credentials (see auxiliary)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-11565",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-11565"],
        "modules": ["auxiliary/admin/http/file_manager_advanced_cve_2026_11565_file_read"],
        "tags": ["web", "scanner", "wordpress", "file-manager", "cve-2026-11565"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/file_manager_advanced_cve_2026_11565_file_read"],
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
            path=self._join("/wp-content/plugins/file-manager-advanced/readme.txt"),
            allow_redirects=False,
        )
        if not readme or "File Manager" not in (readme.text or ""):
            return False
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        self.set_info(
            severity="high",
            reason="File Manager Advanced vulnerable to subscriber file read",
            cve="CVE-2026-11565",
        )
        return True
