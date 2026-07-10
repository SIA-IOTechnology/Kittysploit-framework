#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Keycloak identity provider."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Keycloak Detection",
        "description": "Detects Keycloak OpenID configuration and admin console.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "keycloak", "iam", "oidc", "panel"],
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
        for path in (
            "/realms/master/.well-known/openid-configuration",
            "/auth/realms/master/.well-known/openid-configuration",
        ):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if err or not data:
                continue
            issuer = str(data.get("issuer") or "")
            if "keycloak" in issuer.lower() or data.get("authorization_endpoint"):
                self.set_info(severity="info", reason="Keycloak OIDC provider detected", path=path)
                return True
        return False
