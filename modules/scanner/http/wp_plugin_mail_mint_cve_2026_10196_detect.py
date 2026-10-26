#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Mail Mint WordPress plugin CVE-2026-10196 exposure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_NONCE_RE = re.compile(r'"nonce"\s*:\s*"([a-f0-9]{6,14})"', re.I)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Mail Mint CVE-2026-10196 Detect",
        "description": (
            "Detects Mail Mint ≤ 1.31.0 (CVE-2026-10196): plugin readme version and "
            "public mint-mail REST nonce on the site front page."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-10196"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-10196",
            "https://github.com/0xCyp1337/CVE-2026-10196",
        ],
        "tags": ["web", "scanner", "wordpress", "mail-mint", "cve-2026-10196"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/wp_plugin_mail_mint_cve_2026_10196_rce",
                ],
            },
        },
    }

    def run(self):
        readme_path = self.wp_plugin_path(
            self.wp_normalize_base_path(self.path), "mail-mint", "readme.txt"
        )
        version = ""
        response = self.http_request(method="GET", path=readme_path, allow_redirects=True)
        if response and int(response.status_code or 0) == 200:
            version = self.wp_extract_version_from_readme(response.text or "") or ""
            if version and self.wp_version_to_tuple(version) > (1, 31, 0):
                return False

        home = self.http_request(method="GET", path="/", allow_redirects=True)
        if not home:
            return False
        if not _NONCE_RE.search(home.text or ""):
            return False
        form_match = re.search(r'data-form-id="(\d+)"', home.text or "")

        self.set_info(
            severity="critical",
            reason="Mail Mint plugin with harvestable REST nonce",
            version=version or "unknown",
            form_id=form_match.group(1) if form_match else "1",
            path="/wp-json/mint-mail/v1/mint-form-submit",
        )
        return True
