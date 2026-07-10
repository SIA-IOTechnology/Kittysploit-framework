#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Netlify-hosted sites via platform headers."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Netlify Detection",
        "description": "Detects Netlify CDN/deploy platform response headers.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "netlify", "cdn", "saas", "hosting"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        host = str(self.target or "").lower()
        if host.endswith(".netlify.app") or host.endswith(".netlify.com"):
            self.set_info(severity="info", reason="Netlify hostname detected", host=host)
            return True

        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if not r:
            return False
        headers = {k.lower(): v for k, v in r.headers.items()}
        if "x-nf-request-id" in headers or "server" in headers and "netlify" in headers["server"].lower():
            self.set_info(severity="info", reason="Netlify platform headers detected")
            return True
        return False
