#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed serverless function URLs and unauthenticated invoke endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.serverless_probe import extract_serverless_urls, scan_serverless_surface


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Serverless Function URL Detection",
        "description": (
            "Finds AWS Lambda Function URLs, GCP Cloud Functions, and Azure Functions "
            "references in page source and probes common /api paths for unauthenticated invoke."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "serverless", "aws", "lambda", "azure", "gcp", "cloud"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 0.8,
            "noise": 0.35,
            "value": 1.0,
        },
    }

    def run(self):
        home = self.http_request(method="GET", path="/", allow_redirects=True)
        homepage = str(getattr(home, "text", "") or "") if home else ""
        findings = scan_serverless_surface(self.http_request, homepage_html=homepage)
        if homepage:
            findings.extend(extract_serverless_urls(homepage, "/"))
        if not findings:
            return False
        high = [f for f in findings if f.get("severity") == "high" or f.get("url")]
        self.set_info(
            severity="high" if high else "medium",
            reason=f"Serverless surface detected ({len(findings)} signal(s))",
            path=findings[0].get("path") or findings[0].get("source") or "/",
            findings=findings[:15],
        )
        return True
