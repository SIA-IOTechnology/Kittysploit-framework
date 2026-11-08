#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Magento CVE-2026-48356 WYSIWYG upload surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Magento CVE-2026-48356 WYSIWYG Upload Detect",
        "description": (
            "Detects Adobe Commerce / Magento 2.4.x REST and WYSIWYG upload endpoints "
            "associated with CVE-2026-48356 (unrestricted file upload to pub/media)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-48356"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-48356",
            "https://github.com/Ghost-Bx1/cve-2026-48356-magento-file-upload-rce",
        ],
        "tags": ["web", "scanner", "magento", "upload", "wysiwyg", "cve-2026-48356", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "requires": {"tech_hints_any": ["magento"]},
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/magento_cve_2026_48356_rce",
                ],
            },
        },
    }

    def run(self):
        rest = self.http_request(method="GET", path="/rest/V1/store/storeConfigs", allow_redirects=False)
        if not rest or int(rest.status_code or 0) not in (200, 401, 403):
            print_status("Magento REST not detected")
            return False
        body = (rest.text or "").lower()
        if "magento" not in body and int(rest.status_code or 0) == 200:
            print_status("REST answered but Magento fingerprint weak")
        wysiwyg = self.http_request(
            method="OPTIONS",
            path="/rest/V1/wysiwyg/image/upload",
            allow_redirects=False,
        )
        surface = bool(wysiwyg and int(wysiwyg.status_code or 0) not in (404, 410))
        if surface or int(rest.status_code or 0) in (200, 401):
            self.add_vulnerability(
                cve="CVE-2026-48356",
                reason="Magento REST + WYSIWYG upload path present",
                confidence="medium",
            )
            print_success("CVE-2026-48356 surface detected")
            return True
        return False
