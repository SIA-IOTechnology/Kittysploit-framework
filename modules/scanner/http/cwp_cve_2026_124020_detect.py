#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-124020 — Control Web Panel reset-link Host header poisoning."""

from kittysploit import *
from lib.protocols.http.control_web_panel import Control_web_panel
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Control_web_panel):
    __info__ = {
        "name": "CWP CVE-2026-124020 password-reset poisoning detect",
        "description": "CWP < 1.30.6 lostpass uses attacker-controlled Host in reset URLs.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-124020"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-124020"],
        "tags": ["cwp", "centos-webpanel", "password-reset", "cve-2026-124020"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/cwp_cve_2026_124020_reset_poison",
                ],
            },
        },
    }

    port = OptPort(2083, "CWP user panel port", required=False)
    test_username = OptString("admin", "Username for lostpass oracle", required=False, advanced=True)
    test_email = OptString("", "Email paired with username", required=False, advanced=True)

    def run(self):
        resp = self.http_request(method="GET", path="/login/index.php")
        if not resp or int(resp.status_code or 0) >= 500:
            return False
        body = (resp.text or "").lower()
        if "cwp" not in body and "centos web panel" not in body and "cwpsrv" not in body:
            return False
        user = str(self.test_username or "admin")
        email = str(self.test_email or "").strip()
        if email and self.cwp_lostpass_check(user, email):
            self.set_info(
                severity="critical",
                cve="CVE-2026-124020",
                reason="CWP lostpass oracle OK — Host poison chain applicable",
            )
            return True
        self.set_info(
            severity="high",
            cve="CVE-2026-124020",
            reason="Control Web Panel login surface (set email for oracle)",
        )
        return True