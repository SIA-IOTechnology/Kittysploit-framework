#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detect production secrets on Railway, Render, and Fly.io deployments.

Complements preview_deploy_prod_secrets_detect (Vercel/Netlify) for alternate PaaS hosts.
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.paas_deploy_probe import classify_paas_deployment, normalize_host
from lib.scanner.http.preview_deploy_probe import (
    collect_preview_http_bodies,
    is_production_grade_secret,
)
from lib.scanner.http.supabase_probe import extract_supabase_findings
from lib.scanner.http.vibe_secrets_probe import extract_vibe_secrets


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Railway / Render / Fly.io Production Secrets Detection",
        "description": (
            "Classifies Railway, Render, and Fly.io deploy contexts and flags production-grade "
            "API keys, database URLs, and Supabase service_role tokens in client bundles."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": [
            "web",
            "scanner",
            "railway",
            "render",
            "fly",
            "paas",
            "preview",
            "secrets",
            "exposure",
            "nocode",
            "vibe",
        ],
        "modules": [
            "scanner/http/vibe_stack_secrets_detect",
            "scanner/http/preview_deploy_prod_secrets_detect",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "secret_exposure"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.2,
        },
    }

    def run(self):
        target = str(getattr(self, "target", None) or getattr(self, "rhost", None) or "")
        if hasattr(target, "value"):
            target = str(target.value or "")
        host = normalize_host(target)
        if not host:
            return False

        bodies = collect_preview_http_bodies(self.http_request)
        homepage = next((t for p, t in bodies if p == "/"), "")
        deploy = classify_paas_deployment(host, body=homepage)
        if deploy.get("platform") == "unknown":
            return False

        prod_secrets = []
        for path, text in bodies:
            for finding in extract_vibe_secrets(text[:600_000], source=path):
                if is_production_grade_secret(finding):
                    prod_secrets.append(finding)
            prod_secrets.extend(
                f for f in extract_supabase_findings(text[:600_000], source=path)
                if is_production_grade_secret(f)
            )

        if not prod_secrets and deploy.get("deploy_type") not in ("preview", "staging"):
            self.set_info(
                severity="info",
                reason=f"{deploy['platform']} deployment identified (no prod secrets in bundle)",
                path="/",
                platform=deploy["platform"],
                deploy_type=deploy.get("deploy_type"),
            )
            return True

        if not prod_secrets:
            return False

        self.set_info(
            severity="critical",
            reason=(
                f"{deploy['platform']} {deploy.get('deploy_type')} deploy leaks "
                f"{len(prod_secrets)} production-grade secret(s)"
            ),
            path=prod_secrets[0].get("source") or "/",
            platform=deploy["platform"],
            deploy_type=deploy.get("deploy_type"),
            findings=prod_secrets[:20],
        )
        return True
