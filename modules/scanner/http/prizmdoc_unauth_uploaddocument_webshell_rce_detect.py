#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for Accusoft / Apryse PrizmDoc for Java (VirtualViewer) 5.22.1 — Unauthenticated `uploadDocument` Arbitr"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Accusoft / Apryse PrizmDoc for Java (VirtualViewer) 5.22.1 \u2014 Unauthenticated `up \u2014 Detect",
        "description": "Fingerprint / reachability check for Accusoft / Apryse PrizmDoc for Java (VirtualViewer) 5.22.1 \u2014 Unauthenticated `uploadDocument` Arbitrary File Write to JSP Webshell to Root RCE",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "accusoft"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/prizmdoc_unauth_uploaddocument_webshell_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["accusoft", "unauth"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches accusoft advisory surface",
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
