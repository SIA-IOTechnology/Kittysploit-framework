#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep Vercel/Netlify preview deploy environment leak detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.vercel_env_probe import scan_vercel_env_leaks


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Vercel Preview Environment Leak Detection",
        "description": (
            "Deep-scans Vercel/Netlify preview deploys for production secrets in env.js, "
            "vercel.json, .vercel/project.json, and Next.js bundles. Flags env mismatches."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["web", "scanner", "vercel", "netlify", "preview", "secrets", "env", "misconfig"],
        "modules": [
            "scanner/http/preview_deploy_prod_secrets_detect",
            "scanner/http/vercel_detect",
            "scanner/http/vercel_config_file_detect",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 16,
            "reversible": True,
            "approval_required": False,
            "produces": ["secret_exposure", "risk_signals"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.3,
        },
    }

    def run(self):
        host = str(self.target or "").strip()
        findings, deploy_info = scan_vercel_env_leaks(self.http_request, host=host)
        if not findings:
            return False

        critical = [f for f in findings if f.get("severity") == "critical"]
        self.set_info(
            severity="critical" if critical else "high",
            reason=(
                f"Vercel/Netlify env leak: {len(findings)} signal(s) "
                f"({deploy_info.get('deploy_type')}/{deploy_info.get('platform')})"
            ),
            deploy_type=deploy_info.get("deploy_type"),
            platform=deploy_info.get("platform"),
            findings=findings[:20],
        )
        return True
