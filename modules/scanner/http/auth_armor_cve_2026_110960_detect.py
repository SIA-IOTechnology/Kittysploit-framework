#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-110960 — Auth Armor WordPress plugin detect."""

from __future__ import annotations

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Auth Armor CVE-2026-110960 detect",
        "description": "Auth Armor Passwordless Login <= 1.0.3 unauth AJAX surface.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-110960"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-110960"],
        "tags": ["wordpress", "auth-armor", "cve-2026-110960"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/auth_armor_cve_2026_110960_takeover",
                ],
            },
        },
    }

    def run(self):
        version = ""
        for path in (
            "/wp-content/plugins/auth-armor-passwordless-login/readme.txt",
            "/wp-content/plugins/auth-armor-passwordless-login/auth-armor.php",
        ):
            resp = self.http_request("GET", path)
            if not resp or "Auth Armor" not in (resp.text or ""):
                continue
            text = resp.text or ""
            match = re.search(r"Stable tag:\s*([\w.\-]+)", text) or re.search(
                r"Version:\s*([\w.\-]+)", text
            )
            if match:
                version = match.group(1)
            self.set_info(
                severity="critical",
                cve="CVE-2026-110960",
                reason=f"Auth Armor {version or 'detected'}",
                version=version or "unknown",
            )
            return True
        return False