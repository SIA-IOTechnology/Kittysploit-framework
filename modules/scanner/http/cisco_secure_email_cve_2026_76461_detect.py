#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Cisco Secure Email Gateway CVE-2026-76461 AsyncOS parsing SQLi surface."""

import re
from typing import Optional

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Cisco Secure Email CVE-2026-76461 Detect",
        "description": (
            "Detects on-prem Cisco Secure Email Gateway (AsyncOS) appliances exposed to "
            "CVE-2026-76461 pre-authentication SQL injection in email parsing. "
            "Fingerprints the ESA/IronPort login panel and parses AsyncOS release markers "
            "to flag branches before fixed builds 15.5.5-014 / 16.0.4-302 / 16.5.0-780."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-76461"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-76461",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX",
        ],
        "tags": [
            "web",
            "scanner",
            "cisco",
            "asyncos",
            "esa",
            "email",
            "sqli",
            "cve-2026-76461",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.15,
            "value": 1.1,
            "requires": {
                "tech_hints_any": ["cisco", "ironport", "asyncos", "email"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "SMTP email parsing SQLi"},
                ],
                "suggested_followups": [
                    "scanner/http/cisco_esa_detect",
                ],
            },
        },
    }

    _VERSION_RE = re.compile(r"AsyncOS\s+(\d+\.\d+\.\d+[-\w.]*)", re.IGNORECASE)

    @staticmethod
    def _likely_affected(version: str) -> Optional[bool]:
        text = (version or "").strip()
        if not text:
            return None
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", text)
        if not match:
            return None
        major, minor, patch = (int(x) for x in match.groups())
        if major < 15:
            return True
        if major == 15 and minor == 5:
            return patch < 5
        if major == 16 and minor == 0:
            return patch < 4
        if major == 16 and minor == 5:
            return patch < 0 or "780" not in text
        if major == 16:
            return True
        return None

    def run(self):
        response = self.http_request(method="GET", path="/login", allow_redirects=True)
        if not response or int(response.status_code or 0) != 200:
            return False
        body = response.text or ""
        markers = (
            "Email Security Appliance",
            "Email Security Virtual Appliance",
            "IronPort C",
            "action:Login",
        )
        if not any(marker in body for marker in markers):
            return False
        version_match = self._VERSION_RE.search(body)
        version = version_match.group(1) if version_match else ""
        affected = self._likely_affected(version)
        if affected is False:
            return False
        severity = "critical" if affected is True else "high"
        self.set_info(
            severity=severity,
            cve="CVE-2026-76461",
            reason=(
                f"AsyncOS {version} appears pre-fix for CVE-2026-76461"
                if affected
                else "Cisco Secure Email Gateway detected; AsyncOS version unknown"
            ),
            version=version or "unknown",
            path="/login",
        )
        return True
