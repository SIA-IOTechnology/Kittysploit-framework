#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for Titan MFT Server 26.0.0 - Unauthenticated First-Run Administrator Setup Chained to Job Post-Command """

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Titan MFT Server 26.0.0 - Unauthenticated First-Run Administrator Setup Chained  \u2014 Detect",
        "description": "Fingerprint / reachability check for Titan MFT Server 26.0.0 - Unauthenticated First-Run Administrator Setup Chained to Job Post-Command Injection in the WebAdmin Blazor Application (CWE-306, CWE-78)",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "southriver"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/linux/http/southriver_titan_mft_firstrun_admin_setup_job_command_injection_system_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["southriver", "firstrun"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches southriver advisory surface",
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
