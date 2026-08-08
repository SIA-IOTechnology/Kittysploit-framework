#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed magic link and passwordless authentication endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.magic_link_probe import scan_magic_link_surface
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Magic Link / Passwordless Auth Surface Detection",
        "description": (
            "Probes common magic-link and passwordless paths (NextAuth, custom APIs) "
            "for exposed email submission endpoints and sign-in link flows."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "auth", "magic-link", "passwordless", "oauth"],
        "modules": ["scanner/http/nextjs_detect", "auxiliary/scanner/http/login_page_detector"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 24,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.1,
        },
    }

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request)
        homepage = next((t for p, t in bodies if p == "/"), "")
        findings = scan_magic_link_surface(self.http_request, homepage)
        if not findings:
            return False

        high = [f for f in findings if f.get("severity") in ("critical", "high")]
        paths = sorted({f"{f.get('method', 'GET')} {f.get('path')}" for f in findings})

        self.set_info(
            severity="high" if high else "medium",
            reason=f"Magic link/passwordless surface: {len(findings)} endpoint(s)",
            path=findings[0].get("path") or "/api/auth/signin/email",
            findings=findings[:15],
            endpoints=paths[:15],
        )
        return True
