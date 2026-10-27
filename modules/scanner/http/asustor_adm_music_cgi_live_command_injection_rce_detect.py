#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for Asustor ADM 3.5.9 (AS602T) — Post-Authentication Command Injection in `music.cgi` `act=live` → Comma"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Asustor ADM 3.5.9 (AS602T) \u2014 Post-Authentication Command Injection in `music.cgi \u2014 Detect",
        "description": "Fingerprint / reachability check for Asustor ADM 3.5.9 (AS602T) \u2014 Post-Authentication Command Injection in `music.cgi` `act=live` \u2192 Command Execution in the CGI Process",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "asustor"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/linux/http/asustor_adm_music_cgi_live_command_injection_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["asustor", "music"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches asustor advisory surface",
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
