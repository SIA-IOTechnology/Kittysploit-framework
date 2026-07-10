#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Graylog log management API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Graylog Detection",
        "description": "Detects Graylog system and cluster API endpoints.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "graylog", "logging", "observability", "panel"],
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
        for path in ("/api/system", "/api/cluster", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            data, err = parse_json_response(r) if path.startswith("/api") else (None, "skip")
            if not err and data and any(key in data for key in ("cluster_id", "version", "node_id", "lifecycle")):
                self.set_info(severity="medium", reason="Graylog API detected", path=path)
                return True
            body = (r.text or "").lower()
            if "graylog" in body and ("sign in" in body or "/api/" in body):
                self.set_info(severity="medium", reason="Graylog UI detected", path=path)
                return True
        return False
