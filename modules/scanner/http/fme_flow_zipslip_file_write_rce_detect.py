#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for FME Flow Zip-Slip Arbitrary File Write → Code Execution as LocalSystem"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "FME Flow Zip-Slip Arbitrary File Write \u2192 Code Execution as LocalSystem \u2014 Detect",
        "description": "Fingerprint / reachability check for FME Flow Zip-Slip Arbitrary File Write \u2192 Code Execution as LocalSystem",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "safesoftware"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/fme_flow_zipslip_file_write_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["safesoftware", "zipslip"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches safesoftware advisory surface",
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
