#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for Teltonika RutOS ipsec status logread command injection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Teltonika RutOS ipsec status logread injection — Detect",
        "description": (
            "Fingerprint RutOS VuCI web UI and ipsec/openvpn API surface "
            "for authenticated logread command-injection advisory."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "teltonika", "rutos"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/linux/router/teltonika_rutos_ipsec_status_logread_rce",
                ],
            },
        },
    }

    port = OptPort(80, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ("teltonika", "rutos", "vuci", "webui")
        if any(h in body for h in hints):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches Teltonika RutOS web UI",
                confidence="medium",
            )
            return True
        probe = self.http_request("GET", "/api/login", allow_redirects=False)
        if probe and int(getattr(probe, "status_code", 0) or 0) in (200, 401, 405):
            self.set_info(
                severity="high",
                reason="RutOS-style /api/login endpoint present",
                confidence="medium",
            )
            return True
        code = int(getattr(resp, "status_code", 0) or 0)
        if code and code < 500:
            self.set_info(
                severity="medium",
                reason="HTTP service reachable — validate with Teltonika exploit module",
                confidence="low",
            )
            return True
        return False
