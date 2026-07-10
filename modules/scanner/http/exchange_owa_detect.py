#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Microsoft Exchange OWA/ECP exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Exchange OWA Detection",
        "description": "Detects Outlook Web App and Exchange Control Panel endpoints.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "exchange", "owa", "microsoft", "panel"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def run(self):
        for path in ("/owa/", "/owa/auth/logon.aspx", "/ecp/", "/autodiscover/autodiscover.xml"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            if (
                "outlook" in body
                or "exchange" in body
                or "owalogocontainer" in body
                or "x-owa-version" in headers
                or "microsoft-iis" in headers.get("server", "")
                and "logon" in body
            ):
                self.set_info(severity="info", reason="Microsoft Exchange OWA/ECP detected", path=path)
                return True
        return False
