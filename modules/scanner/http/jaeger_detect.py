#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Jaeger tracing UI and API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Jaeger Detection",
        "description": "Detects Jaeger query API and UI.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "jaeger", "tracing", "observability", "panel"],
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
        r = self.http_request(method="GET", path="/api/services", allow_redirects=False)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict) and "data" in data:
                    self.set_info(severity="info", reason="Jaeger query API detected")
                    return True
                if isinstance(data, list):
                    self.set_info(severity="info", reason="Jaeger services API detected")
                    return True
            except Exception:
                pass
            data, err = parse_json_response(r)
            if not err and data:
                self.set_info(severity="info", reason="Jaeger API detected")
                return True
        return False
