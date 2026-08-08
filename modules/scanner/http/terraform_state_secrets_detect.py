#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Terraform state files and extract sensitive values."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.terraform_state_probe import scan_terraform_state


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Terraform State Secrets Detection",
        "description": (
            "Probes common terraform.tfstate paths on the web root and extracts "
            "passwords, API keys, private keys, and connection strings from state JSON."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["web", "scanner", "terraform", "iac", "secrets", "exposure", "cloud"],
        "modules": ["auxiliary/osint/terraform_state_exposure_detector"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["secret_exposure", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.3,
        },
    }

    def run(self):
        findings = scan_terraform_state(self.http_request)
        if not findings:
            return False

        worst = max(findings, key=lambda f: f.get("secret_count", 0))
        secrets = worst.get("secrets") or []

        self.set_info(
            severity="critical" if secrets else "high",
            reason=f"Terraform state exposed at {worst.get('path')} ({len(secrets)} sensitive value(s))",
            path=worst.get("path") or "/terraform.tfstate",
            findings=findings,
            secrets=secrets[:15],
        )
        return True
