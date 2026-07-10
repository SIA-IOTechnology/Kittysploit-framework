#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed SonarQube instances."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SonarQube Detection",
        "description": "Detects SonarQube system status API and login UI.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "sonarqube", "devops", "panel"],
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
        for path in ("/api/system/status", "/api/server/version", "/sessions/new"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            if "sonarqube" in body or "sonar" in body and "version" in body:
                severity = "low" if path.startswith("/api/") and r.status_code == 200 else "info"
                self.set_info(severity=severity, reason="SonarQube instance detected", path=path)
                return True
        return False
