#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Webmin server administration panel."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Webmin Detection",
        "description": "Detects Webmin login and session endpoints.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "webmin", "linux", "panel"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    port = OptPort(10000, "Webmin port (10000 default)", True)
    ssl = OptBool(True, "Use HTTPS", required=False)

    def run(self):
        for path in ("/session_login.cgi", "/webmin/", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or not is_html_response(r):
                continue
            body = (r.text or "").lower()
            if "webmin" in body and ("login" in body or "password" in body):
                self.set_info(severity="medium", reason="Webmin panel detected", path=path)
                return True
        return False
