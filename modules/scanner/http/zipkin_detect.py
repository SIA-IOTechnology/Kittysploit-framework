#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Zipkin distributed tracing UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Zipkin Detection",
        "description": "Detects Zipkin /api/v2/services endpoint.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "zipkin", "tracing", "observability", "panel"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def run(self):
        for path in ("/api/v2/services", "/zipkin/api/v2/services"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            if isinstance(data, list):
                self.set_info(severity="info", reason="Zipkin API detected", path=path)
                return True
        return False
