#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMS Alert <= 3.9.5 account takeover surface (CVE-2026-11387)."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "sms-alert"
_VULN_HIGH = (3, 9, 5)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "SMS Alert CVE-2026-11387 privilege escalation detect",
        "description": (
            "CVE-2026-11387: smsalert-change-password-form can reset passwords when "
            "OTP password reset is enabled (version <= 3.9.5)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-11387",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-11387",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-11387.yaml",
        ],
        "tags": ["web", "scanner", "wordpress", "sms-alert", "priv-esc", "cve-2026-11387"],
        "agent": {
            "risk": "passive",
            "approval_required": False,
            "produces": ["risk_signals"],
        },
    }

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, "/") or ""
        readme = self.http_request(
            method="GET",
            path=f"/wp-content/plugins/{_PLUGIN}/readme.txt",
            allow_redirects=True,
        )
        if not readme or int(readme.status_code) != 200:
            return False
        body = (readme.text or "").lower()
        if "sms alert" not in body and "sms-alert" not in body:
            return False
        if not version:
            version = self.wp_extract_version_from_readme(readme.text or "") or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        login = self.http_request(method="GET", path="/wp-login.php", allow_redirects=True)
        login_body = (login.text or "").lower() if login else ""
        otp_hint = "wc_reset_password" in login_body or "smsalert" in login_body
        severity = "high" if otp_hint else "medium"
        self.set_info(
            severity=severity,
            cve="CVE-2026-11387",
            reason=(
                f"SMS Alert {version or 'unknown'} <= 3.9.5; "
                + ("OTP/lost-password surface visible — " if otp_hint else "")
                + "no password reset attempted (avoid false positives)"
            ),
            version=version or "unknown",
        )
        return True
