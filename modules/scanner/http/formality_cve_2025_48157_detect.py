#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Formality <= 1.5.9 authenticated LFI (CVE-2025-48157)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "formality"
_VULN_HIGH = (1, 5, 9)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Formality CVE-2025-48157 detect",
        "description": "Detects Formality plugin <= 1.5.9 (LFI via download.php; needs creds to confirm).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-48157",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-48157"],
        "modules": ["auxiliary/admin/http/formality_cve_2025_48157_lfi_read"],
        "tags": ["web", "scanner", "wordpress", "formality", "lfi", "cve-2025-48157"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/formality_cve_2025_48157_lfi_read"],
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
            path=self._join("/wp-content/plugins/formality/readme.txt"),
            allow_redirects=False,
        )
        if not readme or "Formality" not in (readme.text or ""):
            return False
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        dl = self._join("/wp-content/uploads/formality/storage/download.php")
        probe = self.http_request(method="GET", path=dl, allow_redirects=False)
        if probe and int(probe.status_code or 0) in (200, 400, 403, 500):
            self.set_info(
                severity="high",
                reason="Formality download.php reachable (LFI with session)",
                path=dl,
                cve="CVE-2025-48157",
            )
            return True
        self.set_info(severity="high", reason="Formality <= 1.5.9 installed", cve="CVE-2025-48157")
        return True
