#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Atlassian Jira instances."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Jira Detection",
        "description": "Detects Jira dashboards and serverInfo API exposure.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "jira", "atlassian", "panel"],
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
        for path in ("/rest/api/2/serverInfo", "/login.jsp", "/secure/Dashboard.jspa"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            if "jira" in body or "atlassian" in body or "servertitle" in body:
                severity = "low" if path.startswith("/rest/api") and r.status_code == 200 else "info"
                self.set_info(severity=severity, reason="Jira instance detected", path=path)
                return True
        return False
