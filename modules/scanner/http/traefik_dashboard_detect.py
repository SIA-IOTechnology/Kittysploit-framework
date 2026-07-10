#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Traefik dashboard and API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Traefik Dashboard Detection",
        "description": "Detects Traefik reverse-proxy dashboard and /api/overview exposure.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "traefik", "proxy", "panel", "misconfig"],
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
        for path in ("/api/overview", "/dashboard/", "/dashboard/#/"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            if "traefik" in body or "traefik" in headers.get("server", ""):
                severity = "high" if path.startswith("/api/") and r.status_code == 200 else "medium"
                self.set_info(severity=severity, reason="Traefik dashboard/API detected", path=path)
                return True
        return False
