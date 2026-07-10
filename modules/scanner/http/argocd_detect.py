#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Argo CD GitOps UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Argo CD Detection",
        "description": "Detects Argo CD version API and login UI exposure.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "argocd", "kubernetes", "gitops", "panel"],
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
        for path in ("/api/v1/version", "/login", "/api/version"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            if "argocd" in body or "argo cd" in body or "argoproj" in body:
                severity = "medium" if path.startswith("/api/") and r.status_code == 200 else "info"
                self.set_info(severity=severity, reason="Argo CD instance detected", path=path)
                return True
        return False
