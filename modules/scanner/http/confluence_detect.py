#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Atlassian Confluence instances."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Confluence Detection",
        "description": "Detects Confluence wiki UI and status endpoints.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "confluence", "atlassian", "panel"],
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
        for path in ("/wiki", "/status", "/login.action"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            if "confluence" in body or "atlassian" in body or "spaces" in body and "wiki" in path:
                self.set_info(severity="info", reason="Confluence instance detected", path=path)
                return True
        return False
