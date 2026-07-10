#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Gitea git forge."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Gitea Detection",
        "description": "Detects Gitea version API and login UI.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "modules": [
            "auxiliary/admin/http/gitea_cve_2026_20896_auth_bypass",
        ],
        "tags": ["web", "scanner", "gitea", "git", "devops", "panel"],
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
        r = self.http_request(method="GET", path="/api/v1/version", allow_redirects=False)
        data, err = parse_json_response(r) if r else (None, "bad_status")
        if not err and data and data.get("version"):
            self.set_info(
                severity="info",
                reason=f"Gitea API detected (version={data.get('version')})",
                version=str(data.get("version")),
            )
            return True
        return False
