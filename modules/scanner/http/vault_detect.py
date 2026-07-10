#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect HashiCorp Vault API and UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "HashiCorp Vault Detection",
        "description": "Detects Vault /v1/sys/health and UI exposure.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "vault", "hashicorp", "secrets", "panel"],
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
        r = self.http_request(method="GET", path="/v1/sys/health", allow_redirects=False)
        data, err = parse_json_response(r) if r else (None, "bad_status")
        if err or not data:
            return False
        if "initialized" in data and "sealed" in data:
            sealed = bool(data.get("sealed"))
            self.set_info(
                severity="medium",
                reason=f"HashiCorp Vault API detected (sealed={sealed})",
                sealed=sealed,
                version=str(data.get("version") or ""),
            )
            return True
        return False
