#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Portainer container management UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Portainer Detection",
        "description": "Detects Portainer API status and web UI exposure.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "portainer", "docker", "panel"],
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
        for path in ("/api/status", "/api/endpoints", "/#!/auth"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            if "portainer" in body or (path == "/api/status" and r.status_code == 200 and "version" in body):
                self.set_info(severity="medium", reason="Portainer management UI detected", path=path)
                return True
        return False
