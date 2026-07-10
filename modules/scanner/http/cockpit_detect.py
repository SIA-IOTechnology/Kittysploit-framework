#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Cockpit Linux server management UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Cockpit Detection",
        "description": "Detects Cockpit Project web console on /cockpit or port 9090.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "cockpit", "linux", "panel"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    port = OptPort(9090, "Cockpit HTTPS port (9090 default)", True)
    ssl = OptBool(True, "Use HTTPS", required=False)

    def run(self):
        for path in ("/cockpit/login", "/login", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or not is_html_response(r):
                continue
            body = (r.text or "").lower()
            if "cockpit" in body and ("login" in body or "server" in body):
                self.set_info(severity="medium", reason="Cockpit management UI detected", path=path)
                return True
        return False
