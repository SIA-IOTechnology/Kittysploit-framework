#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WooCommerce Wholesale Lead Capture <= 2.0.3.1 privesc (CVE-2026-27542)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "woocommerce-wholesale-lead-capture"
_VULN_HIGH = (2, 0, 3)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Wholesale Lead Capture CVE-2026-27542 detect",
        "description": "Detects unauthenticated wwlc_create_user AJAX returning registration form schema.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-27542",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-27542"],
        "modules": ["auxiliary/admin/http/wholesale_lead_cve_2026_27542_admin_register"],
        "tags": ["web", "scanner", "wordpress", "woocommerce", "privesc", "cve-2026-27542"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/wholesale_lead_cve_2026_27542_admin_register"],
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
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"action": "wwlc_create_user"},
            allow_redirects=False,
        )
        body = (resp.text or "").strip() if resp else ""
        if (
            resp
            and int(resp.status_code or 0) == 200
            and body not in ("-1", "0", "")
            and "wwlc_firstname" in body
            and "wwlc_email" in body
        ):
            self.set_info(
                severity="critical",
                reason="WWLC wwlc_create_user exposed without auth",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2026-27542",
            )
            return True
        return False
