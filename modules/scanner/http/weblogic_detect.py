#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Oracle WebLogic console."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "WebLogic Console Detection",
        "description": "Detects Oracle WebLogic administration console login pages.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "weblogic", "oracle", "java", "panel"],
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
        for path in ("/console/login/LoginForm.jsp", "/console", "/wls-wsat/CoordinatorPortType"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            if "weblogic" in body or "oracle" in body and "console" in body:
                self.set_info(severity="info", reason="WebLogic console detected", path=path)
                return True
        return False
