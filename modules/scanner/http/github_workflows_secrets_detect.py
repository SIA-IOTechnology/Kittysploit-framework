#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed GitHub Actions workflow files and CI secret references."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.github_workflows_probe import extract_github_workflow_findings


class Module(Scanner, Http_client):
    __info__ = {
        "name": "GitHub Actions Workflow Secrets Detection",
        "description": (
            "Probes common /.github/workflows/*.yml paths for exposed CI definitions "
            "and flags inline secrets, ${{ secrets.* }} references, PATs, and private keys."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "github", "ci", "cd", "secrets", "exposure", "misconfig"],
        "references": ["https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "secret_exposure"],
            "cost": 0.8,
            "noise": 0.35,
            "value": 1.2,
        },
    }

    def run(self):
        findings = extract_github_workflow_findings(self.http_request)
        critical = [f for f in findings if f.get("severity") == "critical"]
        if not findings:
            return False
        self.set_info(
            severity="critical" if critical else "high",
            reason=f"{len(findings)} GitHub Actions workflow secret signal(s)",
            path=findings[0].get("path") or "/.github/workflows/",
            findings=findings[:20],
        )
        return True
