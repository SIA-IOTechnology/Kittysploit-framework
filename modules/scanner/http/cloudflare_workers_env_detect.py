#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Cloudflare Workers/Pages configuration and env leaks."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.cloudflare_workers_probe import extract_cloudflare_workers_findings


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Cloudflare Workers Environment Leak Detection",
        "description": (
            "Scans wrangler.toml/json, .dev.vars, and Workers config paths for API tokens, "
            "account IDs, and secret vars embedded in client-accessible assets."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "cloudflare", "workers", "serverless", "secrets", "exposure"],
        "references": ["https://developers.cloudflare.com/workers/wrangler/"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "secret_exposure"],
            "cost": 0.7,
            "noise": 0.3,
            "value": 1.1,
        },
    }

    def run(self):
        findings = extract_cloudflare_workers_findings(self.http_request)
        secrets = [f for f in findings if f.get("severity") in ("critical", "high")]
        if not secrets:
            return False
        self.set_info(
            severity="critical" if any(f.get("severity") == "critical" for f in secrets) else "high",
            reason=f"Cloudflare Workers config/secrets exposed ({len(secrets)} hit(s))",
            path=secrets[0].get("path") or "/wrangler.toml",
            findings=secrets[:15],
        )
        return True
