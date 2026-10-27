#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for Puppet Enterprise — CVE-2025-5459 Patch-Bypass Variant → keytool Shell Injection → Root RCE"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Puppet Enterprise \u2014 CVE-2025-5459 Patch-Bypass Variant \u2192 keytool Shell Injection \u2014 Detect",
        "description": "Fingerprint / reachability check for Puppet Enterprise \u2014 CVE-2025-5459 Patch-Bypass Variant \u2192 keytool Shell Injection \u2192 Root RCE",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "puppet"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/puppet_keytool_injection_root_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["puppet", "keytool"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches puppet advisory surface",
                confidence="medium",
            )
            return True
        code = int(getattr(resp, "status_code", 0) or 0)
        if code and code < 500:
            self.set_info(
                severity="medium",
                reason="HTTP service reachable — run matching exploit module for validation",
                confidence="low",
            )
            return True
        return False
