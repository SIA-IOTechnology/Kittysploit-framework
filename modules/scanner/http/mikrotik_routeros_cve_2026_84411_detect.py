#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect MikroTik RouterOS WebFig jsproxy (CVE-2026-84411 exposure)."""

from kittysploit import *
from lib.protocols.http.routeros_webfig import RouterOSWebFig


class Module(Scanner, RouterOSWebFig):
    __info__ = {
        "name": "MikroTik RouterOS WebFig jsproxy Detect (CVE-2026-84411)",
        "description": (
            "Non-destructive probe of RouterOS POST /jsproxy (Content-Type: msg). "
            "Confirms WebFig jsproxy attack surface for CVE-2026-84411 / CVE-2026-67278 family."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-84411", "CVE-2026-67278"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-84411",
            "https://github.com/s-b-repo/cve_2026_84411_poc-",
        ],
        "tags": ["web", "scanner", "mikrotik", "routeros", "webfig", "jsproxy", "cve-2026-84411"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "requires": {"tech_hints_any": ["mikrotik", "routeros"]},
            "chain": {
                "suggested_followups": [
                    "exploits/linux/http/mikrotik_routeros_cve_2026_84411_jsproxy",
                ],
            },
        },
    }

    def run(self):
        if not self.routeros_webfig_host():
            print_error("Target is required")
            return False
        ok, reason = self.routeros_jsproxy_probe()
        if ok:
            self.add_vulnerability(
                cve="CVE-2026-84411",
                reason=reason,
                confidence="high",
            )
            print_success(f"jsproxy exposed — {reason}")
            return True
        print_status(f"Not vulnerable: {reason}")
        return False
