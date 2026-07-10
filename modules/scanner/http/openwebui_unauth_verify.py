#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify Open WebUI unauthenticated config and model access."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Open WebUI Unauth Verification",
        "description": "Confirms Open WebUI /api/config or /api/models without authentication.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["openwebui", "llm", "ai", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["ai_panel", "unauth_read"]},
        },
    }

    def run(self):
        for path in ("/api/config", "/api/models", "/api/v1/models"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if err or data is None:
                continue
            if isinstance(data, dict) and any(k in data for k in ("name", "version", "default_models", "status")):
                self.set_info(
                    severity="high",
                    reason="Open WebUI API readable without authentication",
                    path=path,
                    confidence="high",
                )
                return True
            if isinstance(data, dict) and "data" in data:
                self.set_info(
                    severity="high",
                    reason="Open WebUI model list readable without authentication",
                    path=path,
                    confidence="high",
                )
                return True
        return False
