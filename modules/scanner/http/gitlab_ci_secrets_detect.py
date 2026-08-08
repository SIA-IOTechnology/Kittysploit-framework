#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep GitLab CI YAML exposure with embedded secret extraction."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.gitlab_ci_probe import scan_gitlab_ci


class Module(Scanner, Http_client):
    __info__ = {
        "name": "GitLab CI Secrets Detection",
        "description": (
            "Probes extended GitLab CI paths (.gitlab-ci.yml, ci/*.yml) and extracts "
            "embedded secrets, CI variable references, tokens, and cloud credentials."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "gitlab", "cicd", "secrets", "exposure"],
        "modules": ["scanner/http/gitlab_ci_yml_detect"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["secret_exposure", "risk_signals"],
            "cost": 0.9,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    def run(self):
        findings = scan_gitlab_ci(self.http_request)
        if not findings:
            return False

        worst = max(findings, key=lambda f: len(f.get("secrets") or []))
        secrets = worst.get("secrets") or []
        critical = [s for s in secrets if s.get("severity") == "critical"]

        self.set_info(
            severity="critical" if critical else "high",
            reason=f"GitLab CI exposed: {len(secrets)} secret/variable indicator(s) in {worst.get('path')}",
            path=worst.get("path") or "/.gitlab-ci.yml",
            findings=findings,
            secrets=secrets[:15],
        )
        return True
