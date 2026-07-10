#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify unauthenticated Grafana API access."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Grafana Unauthenticated API Verification",
        "description": "Confirms anonymous Grafana datasources/org/search API access.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["grafana", "monitoring", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["devops_panel", "unauth_read"]},
        },
    }

    def run(self):
        for path in ("/api/datasources", "/api/org", "/api/search?type=dash-db"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if err or data is None:
                continue
            if isinstance(data, list) and data:
                self.set_info(
                    severity="high",
                    reason="Grafana API returned data without authentication",
                    path=path,
                    count=len(data),
                    confidence="high",
                )
                return True
            if isinstance(data, dict) and any(k in data for k in ("id", "name", "orgId")):
                self.set_info(
                    severity="high",
                    reason="Grafana org API readable without authentication",
                    path=path,
                    confidence="high",
                )
                return True
        return False
