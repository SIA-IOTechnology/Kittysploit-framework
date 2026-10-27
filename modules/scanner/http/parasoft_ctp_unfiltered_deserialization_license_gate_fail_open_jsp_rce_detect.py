#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for Parasoft Continuous Testing Platform 10.7.5-SNAPSHOT - Unfiltered Java Deserialization in the Databa"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Parasoft Continuous Testing Platform 10.7.5-SNAPSHOT - Unfiltered Java Deseriali \u2014 Detect",
        "description": "Fingerprint / reachability check for Parasoft Continuous Testing Platform 10.7.5-SNAPSHOT - Unfiltered Java Deserialization in the Database Restore Path Behind a Raw-URI License Gate Bypass and a Fail-Open Authentication Gate, Reaching A",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "parasoft"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/parasoft_ctp_unfiltered_deserialization_license_gate_fail_open_jsp_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["parasoft", "unfiltered"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches parasoft advisory surface",
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
