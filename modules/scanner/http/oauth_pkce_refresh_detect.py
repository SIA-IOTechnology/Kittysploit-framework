#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OAuth/OIDC advanced misconfig: PKCE optional, refresh token endpoints, OIDC discovery."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.oauth_advanced_probe import scan_oauth_advanced


class Module(Scanner, Http_client):
    __info__ = {
        "name": "OAuth PKCE / Refresh Token Misconfiguration Detection",
        "description": (
            "Extends JWT/OAuth coverage with PKCE-not-required authorize flows, refresh "
            "token grant endpoints, and OpenID Connect discovery metadata."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "oauth", "oidc", "pkce", "jwt", "auth", "misconfig"],
        "references": [
            "https://oauth.net/2/pkce/",
            "https://datatracker.ietf.org/doc/html/rfc6749#section-6",
        ],
        "modules": ["auxiliary/scanner/http/jwt_oauth_probe"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 10,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "endpoints", "tech_hints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.2,
            "chain": {
                "suggested_followups": ["auxiliary/scanner/http/jwt_oauth_probe"],
            },
        },
    }

    oauth_paths = OptString(
        "/oauth/authorize,/oauth2/authorize,/authorize,/.well-known/openid-configuration",
        "OAuth authorize / OIDC discovery paths (comma-separated)",
        False,
    )
    token_paths = OptString(
        "/oauth/token,/oauth2/token,/auth/token,/api/auth/token",
        "OAuth token endpoints (comma-separated)",
        False,
    )

    def run(self):
        findings = scan_oauth_advanced(
            self.http_request,
            oauth_paths=str(self.oauth_paths or ""),
            token_paths=str(self.token_paths or ""),
        )
        if not findings:
            return False
        high = [f for f in findings if f.get("severity") == "high" or f.get("kind") == "pkce_not_required"]
        self.set_info(
            severity="high" if high else "medium",
            reason=f"OAuth advanced misconfiguration ({len(findings)} signal(s))",
            path=findings[0].get("path") or "/oauth/authorize",
            findings=findings[:12],
        )
        return True
